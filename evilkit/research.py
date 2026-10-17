"""Passive vulnerability research: scrape public vuln-intel sources on the fly.

This module is a stdlib-only web scraper aimed at one job — turn a CVE id, a
software/version string, or a public advisory URL into structured vulnerability
context the agent can act on mid-run. Three properties hold by construction:

* passive only: every request goes to public vulnerability-intelligence
  infrastructure (NVD, Exploit-DB, the operator's own searchsploit index) or,
  for ``research_scrape``, to a public web page the operator names. No tool
  here probes the authorised target — that is the pentest server's job;
* SSRF-guarded: a URL is fetched only after its hostname resolves to a
  globally routable address. Loopback, RFC1918, link-local, CGNAT, benchmark
  and other reserved ranges are refused before any bytes are sent, and the
  same check runs again on every redirect;
* bounded: every fetch has a timeout and a byte cap, and every tool returns
  structured JSON rather than raw HTML, so a run never drowns the agent in a
  page.

The module doubles as an MCP stdio server (``python -m evilkit.research``) so
the launched Kimi session can call the same four tools directly.
"""

from __future__ import annotations

import datetime as _dt
import html
import ipaddress
import json
import re
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from html.parser import HTMLParser

__all__ = [
    "ScrapeError",
    "ResearchError",
    "is_safe_url",
    "classify_query",
    "scrape_page",
    "cve_lookup",
    "search_cve",
    "search_exploits",
    "run_research",
    "write_findings",
    "serve",
]

RESEARCH_VERSION = 1

#: The MCP tools exposed to the launched session, and the CLI's --only/--skip set.
TOOLS = ("research_cve", "research_search", "research_exploits", "research_scrape")

_DEFAULT_UA = "evilkit-research/1.0 (+https://github.com/Bowie1969/evilkit)"
_DEFAULT_TIMEOUT = 30.0
_DEFAULT_MAX_BYTES = 1_048_576  # 1 MiB, plenty for an HTML page or NVD JSON

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EXPLOITDB_SEARCH = "https://www.exploit-db.com/search"

#: A URL is fetched only when its host resolves to a globally routable address.
#: ``ipaddress`` labels the entire private/reserved space ``is_global=False``,
#: which covers the SSRF standbys: loopback, RFC1918, 169.254.0.0/16 (metadata),
#: 100.64.0.0/10 (CGNAT), 198.18.0.0/15 (benchmarking) and the documentation
#: ranges. Nothing outside the public internet is reachable through this module.


class ScrapeError(RuntimeError):
    """A fetch was refused, failed, or returned an unusable response."""


class ResearchError(ValueError):
    """A research query cannot be classified or an argument is invalid."""


# ---------------------------------------------------------------- URL safety


def is_safe_url(url: str) -> bool:
    """Return True when ``url`` is an http(s) URL resolving to public addresses.

    Rejects non-http(s) schemes, URLs carrying userinfo (credentials), empty
    hosts, and any host whose resolved address set is not entirely globally
    routable. A hostname is checked by resolving it, so ``localhost``,
    ``host.docker.internal`` and internal service names are refused here rather
    than at connect time.
    """
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    if parsed.scheme.lower() not in ("http", "https"):
        return False
    if parsed.username or parsed.password:
        return False
    host = parsed.hostname
    if not host:
        return False

    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except OSError:
        return False
    if not infos:
        return False
    for info in infos:
        try:
            address = ipaddress.ip_address(info[4][0])
        except ValueError:
            return False
        if not address.is_global:
            return False
    return True


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects only while the next hop is itself a safe public URL."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not is_safe_url(newurl):
            raise ScrapeError(f"refusing redirect to an unsafe URL: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_SafeRedirectHandler())


def _safe_open(
    url: str,
    *,
    timeout: float = _DEFAULT_TIMEOUT,
    max_bytes: int = _DEFAULT_MAX_BYTES,
    fetch=None,
) -> tuple[int, str, str, bytes]:
    """Fetch ``url`` after a safety check; return (status, final_url, type, body).

    ``fetch`` exists for tests: a callable ``(url, timeout, max_bytes) ->
    (status, final_url, content_type, bytes)`` replaces the real network path.
    """
    if fetch is not None:
        return fetch(url, timeout, max_bytes)

    if not is_safe_url(url):
        raise ScrapeError(f"refusing unsafe URL: {url}")

    request = urllib.request.Request(url, headers={"User-Agent": _DEFAULT_UA})
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            status = getattr(response, "status", 200)
            content_type = response.headers.get_content_type() or ""
            body = response.read(max_bytes + 1)
    except (urllib.error.URLError, ssl.SSLError, OSError) as exc:
        raise ScrapeError(f"could not fetch {url}: {exc}") from exc
    except urllib.error.HTTPError as exc:
        raise ScrapeError(f"fetch {url}: HTTP {exc.code}") from exc

    if len(body) > max_bytes:
        raise ScrapeError(f"response from {url} exceeds {max_bytes} bytes")
    return status, response.geturl(), content_type, body


def _decode(body: bytes, content_type: str) -> str:
    """Decode bytes to text, tolerating a wrong charset rather than failing."""
    charset = None
    match = re.search(r"charset=([\w-]+)", content_type, re.IGNORECASE)
    if match:
        charset = match.group(1)
    for candidate in (charset, "utf-8", "latin-1"):
        if not candidate:
            continue
        try:
            return body.decode(candidate)
        except (LookupError, UnicodeDecodeError):
            continue
    return body.decode("utf-8", errors="replace")


# -------------------------------------------------------------- HTML scraping


@dataclass
class _ScrapedPage:
    title: str = ""
    text: str = ""
    links: list[dict] = None  # type: ignore[assignment]
    headings: list[str] = None  # type: ignore[assignment]
    forms: list[dict] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self.links = self.links or []
        self.headings = self.headings or []
        self.forms = self.forms or []


class _HTMLText(HTMLParser):
    """Extract title, readable text, links, headings and forms from HTML."""

    _SKIP_TAGS = {"script", "style", "noscript", "template", "svg"}
    _BLOCK_TAGS = {
        "p", "div", "section", "article", "li", "tr", "h1", "h2", "h3",
        "h4", "h5", "h6", "pre", "blockquote", "table", "ul", "ol",
    }
    _HEADING_TAGS = {"h1", "h2", "h3", "h4", "h5", "h6"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.links: list[dict] = []
        self.headings: list[str] = []
        self.forms: list[dict] = []

        self._in_title = False
        self._title_parts: list[str] = []
        self._skip_depth = 0
        self._text_parts: list[str] = []
        self._heading_parts: list[str] | None = None
        self._link_href: str | None = None
        self._link_parts: list[str] = []
        self._form: dict | None = None

    # -- text fan-out ----------------------------------------------------

    def _push(self, data: str) -> None:
        self._text_parts.append(data)
        if self._in_title:
            self._title_parts.append(data)
        if self._heading_parts is not None:
            self._heading_parts.append(data)
        if self._link_href is not None:
            self._link_parts.append(data)

    @staticmethod
    def _collapse(parts: list[str]) -> str:
        return " ".join(" ".join(parts).split())

    # -- parse hooks -----------------------------------------------------

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        attrs = dict(attrs)
        if tag in self._SKIP_TAGS:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return

        if tag == "title":
            self._in_title = True
            self._title_parts = []
        elif tag == "a":
            self._link_href = attrs.get("href")
            self._link_parts = []
        elif tag in self._HEADING_TAGS:
            self._heading_parts = []
        elif tag in self._BLOCK_TAGS:
            self._text_parts.append("\n")
        elif tag == "form":
            self._form = {
                "action": attrs.get("action", ""),
                "method": (attrs.get("method") or "GET").upper(),
                "inputs": [],
            }
        elif tag == "input":
            # HTML5 void elements arrive here without a closing slash.
            if self._form is not None and attrs.get("name"):
                self._form["inputs"].append(attrs["name"])
        elif tag in ("br", "hr"):
            self._text_parts.append("\n")

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in self._SKIP_TAGS:
            self._skip_depth = max(0, self._skip_depth - 1)
            return
        if self._skip_depth:
            return

        if tag == "title":
            self.title = self._collapse(self._title_parts)
            self._in_title = False
        elif tag == "a":
            if self._link_href is not None:
                self.links.append(
                    {"href": self._link_href, "text": self._collapse(self._link_parts)}
                )
            self._link_href = None
            self._link_parts = []
        elif tag in self._HEADING_TAGS:
            if self._heading_parts is not None:
                heading = self._collapse(self._heading_parts)
                if heading:
                    self.headings.append(heading)
            self._heading_parts = None
        elif tag in self._BLOCK_TAGS:
            self._text_parts.append("\n")
        elif tag == "form":
            if self._form is not None:
                self.forms.append(self._form)
            self._form = None

    def handle_startendtag(self, tag, attrs):
        tag = tag.lower()
        if tag in ("br", "hr"):
            self._text_parts.append("\n")
        elif tag == "input" and self._form is not None:
            name = dict(attrs).get("name")
            if name:
                self._form["inputs"].append(name)

    def handle_data(self, data):
        if not self._skip_depth:
            self._push(data)

    def handle_entityref(self, name):
        if not self._skip_depth:
            self._push(html.unescape(f"&{name};"))

    def finish(self) -> str:
        """Return the visible document text, block-separated and trimmed."""
        lines = []
        for part in " ".join(self._text_parts).splitlines():
            stripped = part.strip()
            if stripped:
                lines.append(stripped)
        return "\n".join(lines)


def scrape_page(
    url: str,
    *,
    timeout: float = _DEFAULT_TIMEOUT,
    max_bytes: int = _DEFAULT_MAX_BYTES,
    fetch=None,
) -> dict:
    """Fetch and parse a public page into structured text, links and forms.

    Returns a dict with ``title``, ``text`` (whitespace-normalised), ``links``,
    ``headings``, ``forms`` and the fetch metadata. HTML is parsed with the
    stdlib parser only; no scripts run, so a scrape is inert.
    """
    status, final_url, content_type, body = _safe_open(
        url, timeout=timeout, max_bytes=max_bytes, fetch=fetch
    )
    text = _decode(body, content_type)
    parser = _HTMLText()
    try:
        parser.feed(text)
    except Exception:
        # A pathological page must not break the run; return what we have.
        pass
    page_text = parser.finish()
    return {
        "url": url,
        "final_url": final_url,
        "status": status,
        "content_type": content_type,
        "size": len(body),
        "title": parser.title,
        "text": page_text[:200_000],
        "headings": parser.headings[:100],
        "links": parser.links[:500],
        "forms": parser.forms[:50],
    }


# -------------------------------------------------------------------- NVD API


def _nvd_url(**params: str) -> str:
    query = urllib.parse.urlencode(params)
    return f"{NVD_BASE}?{query}"


def _nvd_get(params: dict, *, timeout: float, api_key: str, fetch=None) -> dict:
    if api_key:
        params["apiKey"] = api_key
    url = _nvd_url(**params)
    status, _final, content_type, body = _safe_open(
        url, timeout=timeout, fetch=fetch
    )
    try:
        data = json.loads(_decode(body, content_type))
    except json.JSONDecodeError as exc:
        raise ScrapeError(f"NVD returned non-JSON for {url}") from exc
    if not isinstance(data, dict):
        raise ScrapeError(f"NVD returned an unexpected response for {url}")
    return data


def _metric_best(metrics: dict) -> dict | None:
    """Pick the most useful CVSS metric object NVD returned, preferring v3.1."""
    for version in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(version) or []
        for entry in entries:
            if isinstance(entry, dict) and "cvssData" in entry:
                return entry
    return None


def _flatten_cve(vuln: dict) -> dict:
    cve = vuln.get("cve", {})
    metrics = cve.get("metrics", {}) or {}
    metric = _metric_best(metrics)
    cvss_data = (metric or {}).get("cvssData", {}) or {}

    descriptions = cve.get("descriptions", []) or []
    description = next(
        (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
        descriptions[0].get("value", "") if descriptions else "",
    )

    weaknesses: list[str] = []
    for problem in cve.get("weaknesses", []) or []:
        for desc in problem.get("description", []) or []:
            value = desc.get("value", "")
            if value and value not in weaknesses:
                weaknesses.append(value)

    configurations = cve.get("configurations", []) or []
    cpes: list[str] = []
    for config in configurations:
        for node in config.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                criteria = match.get("criteria", "")
                if criteria and criteria not in cpes:
                    cpes.append(criteria)

    references = [r.get("url", "") for r in cve.get("references", []) or []]
    references = [u for u in references if u]

    severity = cvss_data.get("baseSeverity") or ""

    return {
        "id": cve.get("id", ""),
        "source": cve.get("sourceIdentifier", ""),
        "published": cve.get("published", ""),
        "last_modified": cve.get("lastModified", ""),
        "status": cve.get("vulnStatus", ""),
        "description": description,
        "severity": severity,
        "cvss_version": cvss_data.get("version", ""),
        "cvss_vector": cvss_data.get("vectorString", ""),
        "base_score": cvss_data.get("baseScore"),
        "exploitability_score": (metric or {}).get("exploitabilityScore"),
        "impact_score": (metric or {}).get("impactScore"),
        "weaknesses": weaknesses,
        "cpes": cpes,
        "references": references,
    }


def cve_lookup(
    cve_id: str,
    *,
    timeout: float = _DEFAULT_TIMEOUT,
    nvd_api_key: str = "",
    fetch=None,
) -> dict:
    """Return structured, current data for one CVE from the NVD API."""
    identifier = cve_id.strip().upper()
    if not _CVE_RE.match(identifier):
        raise ResearchError(f"not a CVE id: {cve_id!r}")

    data = _nvd_get(
        {"cveId": identifier}, timeout=timeout, api_key=nvd_api_key, fetch=fetch
    )
    vulnerabilities = data.get("vulnerabilities", []) or []
    if not vulnerabilities:
        raise ScrapeError(f"{identifier} has no NVD record (or the id is invalid)")
    return _flatten_cve(vulnerabilities[0])


def search_cve(
    query: str,
    *,
    timeout: float = _DEFAULT_TIMEOUT,
    nvd_api_key: str = "",
    fetch=None,
) -> dict:
    """Keyword-search NVD; return the top matches with id, score and summary."""
    keyword = query.strip()
    if not keyword:
        raise ResearchError("empty search query")

    data = _nvd_get(
        {"keywordSearch": keyword, "resultsPerPage": "20"},
        timeout=timeout,
        api_key=nvd_api_key,
        fetch=fetch,
    )
    results: list[dict] = []
    for vuln in data.get("vulnerabilities", []) or []:
        flat = _flatten_cve(vuln)
        results.append(
            {
                "id": flat["id"],
                "description": flat["description"][:500],
                "severity": flat["severity"],
                "base_score": flat["base_score"],
            }
        )
    return {
        "query": keyword,
        "total": data.get("totalResults", len(results)),
        "results": results,
    }


# ----------------------------------------------------------- exploit sources


def _searchsploit(query: str) -> list[dict]:
    """Query the local searchsploit index; return [] when unavailable or empty."""
    binary = shutil.which("searchsploit")
    if not binary:
        return []
    try:
        proc = subprocess.run(
            [binary, "--json", query],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (subprocess.TimeoutExpired, OSError):
        return []
    if proc.returncode != 0:
        return []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []

    results: list[dict] = []
    for entry in data.get("RESULTS_EXPLOIT", []) or []:
        def _get(*keys):
            for key in keys:
                value = entry.get(key)
                if value:
                    return value
            return ""

        results.append(
            {
                "id": str(_get("EDB-ID", "id", "exploit_id")),
                "title": str(_get("Title", "title")),
                "path": str(_get("Path", "path")),
                "date": str(_get("Date", "date")),
                "type": str(_get("Type", "type")),
                "platform": str(_get("Platform", "platform")),
                "author": str(_get("Author", "author")),
                "port": str(_get("Port", "port")),
            }
        )
    return results


def _scrape_exploitdb(query: str, *, timeout: float, fetch=None) -> list[dict]:
    """Best-effort scrape of the Exploit-DB search results page.

    Exploit-DB sits behind Cloudflare, so this is a fallback for machines
    without searchsploit installed and may return nothing on a challenge page.
    """
    url = f"{EXPLOITDB_SEARCH}?{urllib.parse.urlencode({'q': query})}"
    try:
        status, _final, content_type, body = _safe_open(
            url, timeout=timeout, fetch=fetch
        )
    except ScrapeError:
        return []
    html_text = _decode(body, content_type)

    results: list[dict] = []
    # The results table has rows with data attributes and an EDB link of the
    # form /exploits/50592. Match those anchors and their row's title cell.
    row_re = re.compile(
        r'<a[^>]+href="/exploits/(\d+)"[^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL
    )
    for match in row_re.finditer(html_text):
        edb_id = match.group(1)
        title = re.sub(r"<[^>]+>", "", match.group(2))
        title = html.unescape(" ".join(title.split()))
        if title:
            results.append(
                {
                    "id": f"EDB-{edb_id}",
                    "title": title,
                    "path": f"https://www.exploit-db.com/exploits/{edb_id}",
                    "date": "",
                    "type": "",
                    "platform": "",
                    "author": "",
                    "port": "",
                }
            )
    return results


def search_exploits(
    query: str,
    *,
    timeout: float = _DEFAULT_TIMEOUT,
    fetch=None,
) -> dict:
    """Return public exploits for ``query`` from searchsploit and/or Exploit-DB."""
    keyword = query.strip()
    if not keyword:
        raise ResearchError("empty exploit query")

    local = _searchsploit(keyword)
    source = "searchsploit"
    results = local
    if not results:
        remote = _scrape_exploitdb(keyword, timeout=timeout, fetch=fetch)
        if remote:
            source = "exploitdb"
            results = remote
    return {"query": keyword, "source": source if results else "none", "results": results}


# ------------------------------------------------------------------ research


def classify_query(text: str) -> str:
    """Return cve|url|keyword for a research query, or raise ResearchError."""
    token = text.strip()
    if not token:
        raise ResearchError("empty query")
    if _CVE_RE.match(token):
        return "cve"
    if _URL_RE.match(token):
        return "url"
    return "keyword"


_TOOL_PLAN: dict[str, tuple[str, ...]] = {
    "cve": ("research_cve",),
    "url": ("research_scrape",),
    "keyword": ("research_search", "research_exploits"),
}

_TOOL_RUNNERS = {
    "research_cve": lambda args, ctx: cve_lookup(
        args["cve_id"], timeout=ctx["timeout"], nvd_api_key=ctx["nvd_api_key"],
        fetch=ctx["fetch"],
    ),
    "research_search": lambda args, ctx: search_cve(
        args["query"], timeout=ctx["timeout"], nvd_api_key=ctx["nvd_api_key"],
        fetch=ctx["fetch"],
    ),
    "research_exploits": lambda args, ctx: search_exploits(
        args["query"], timeout=ctx["timeout"], fetch=ctx["fetch"],
    ),
    "research_scrape": lambda args, ctx: scrape_page(
        args["url"], timeout=ctx["timeout"], max_bytes=ctx["max_bytes"],
        fetch=ctx["fetch"],
    ),
}

_TOOL_ARGS = {
    "cve": {"research_cve": lambda q: {"cve_id": q}},
    "url": {"research_scrape": lambda q: {"url": q}},
    "keyword": {
        "research_search": lambda q: {"query": q},
        "research_exploits": lambda q: {"query": q},
    },
}


def run_research(
    query: str,
    *,
    only: list[str] | None = None,
    skip: list[str] | None = None,
    timeout: float = _DEFAULT_TIMEOUT,
    max_bytes: int = _DEFAULT_MAX_BYTES,
    nvd_api_key: str = "",
    fetch=None,
    on_event=None,
) -> dict:
    """Run the passive research plan for ``query`` and return the findings doc.

    ``fetch`` replaces the network layer for tests, as in :func:`scrape_page`.
    """
    only_set = {t.strip() for t in (only or []) if t.strip()} or None
    skip_set = {t.strip() for t in (skip or []) if t.strip()} or None

    kind = classify_query(query)
    tools = _TOOL_PLAN[kind]
    if only_set:
        tools = tuple(t for t in tools if t in only_set)
    if skip_set:
        tools = tuple(t for t in tools if t not in skip_set)

    def _emit(message: str) -> None:
        if on_event:
            on_event(message)

    context = {
        "timeout": timeout,
        "max_bytes": max_bytes,
        "nvd_api_key": nvd_api_key,
        "fetch": fetch,
    }

    runs: list[dict] = []
    findings: list[dict] = []
    for tool in tools:
        args = _TOOL_ARGS[kind][tool](query)
        _emit(f"{tool} {query} ...")
        try:
            result = _TOOL_RUNNERS[tool](args, context)
        except (ScrapeError, ResearchError) as exc:
            runs.append({"tool": tool, "status": "error", "detail": str(exc)})
            _emit(f"{tool} {query}: error ({str(exc)[:80]})")
            continue
        except Exception as exc:  # a tool must never take the run down
            runs.append(
                {"tool": tool, "status": "error",
                 "detail": f"{type(exc).__name__}: {exc}"}
            )
            _emit(f"{tool} {query}: error ({type(exc).__name__})")
            continue
        runs.append({"tool": tool, "status": "ok"})
        findings.append({"source": tool, "data": result})
        _emit(f"{tool} {query}: ok")

    return {
        "research_version": RESEARCH_VERSION,
        "timestamp": _dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "query": query,
        "kind": kind,
        "runs": runs,
        "findings": findings,
    }


def write_findings(findings: dict, path) -> str:
    from pathlib import Path

    target = Path(path)
    target.write_text(json.dumps(findings, indent=2) + "\n", encoding="utf-8")
    return str(target)


# ------------------------------------------------------------ MCP stdio server


_MCP_TOOLS = [
    {
        "name": "research_cve",
        "description": "Look up a single CVE on the public NVD API and return its CVSS score/vector, description, CPEs, weaknesses and references.",
        "inputSchema": {
            "type": "object",
            "properties": {"cve_id": {"type": "string", "description": "CVE id, e.g. CVE-2021-44228"}},
            "required": ["cve_id"],
        },
    },
    {
        "name": "research_search",
        "description": "Keyword-search NVD (product, vendor or version) and return the top matching CVEs with severity and summary.",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string", "description": "e.g. 'apache 2.4.49'"}},
            "required": ["query"],
        },
    },
    {
        "name": "research_exploits",
        "description": "Search public exploit sources (local searchsploit, then Exploit-DB) for a product/version string.",
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    {
        "name": "research_scrape",
        "description": "Fetch a public http(s) page and return its title, readable text, links, headings and forms. Refuses non-public URLs.",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
]


def _mcp_run(tool_name: str, arguments: dict) -> dict:
    """Execute one MCP tool with a fresh context (env decides the NVD key)."""
    api_key = ""
    import os

    for key in ("NVD_API_KEY", "EVILKIT_NVD_API_KEY"):
        if os.environ.get(key):
            api_key = os.environ[key]
            break

    if tool_name == "research_cve":
        return cve_lookup(arguments.get("cve_id", ""), nvd_api_key=api_key)
    if tool_name == "research_search":
        return search_cve(arguments.get("query", ""), nvd_api_key=api_key)
    if tool_name == "research_exploits":
        return search_exploits(arguments.get("query", ""))
    if tool_name == "research_scrape":
        return scrape_page(arguments.get("url", ""))
    raise ResearchError(f"unknown tool: {tool_name}")


def _handle_request(request: dict) -> dict:
    method = request.get("method")
    params = request.get("params", {}) or {}
    req_id = request.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": "evilkit-research", "version": "1.0.0"},
                "capabilities": {"tools": {}},
            },
        }
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": _MCP_TOOLS}}
    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments", {}) or {}
        try:
            result = _mcp_run(str(name), arguments)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {"type": "text", "text": json.dumps(result, indent=2)}
                    ],
                    "isError": False,
                },
            }
        except (ScrapeError, ResearchError) as exc:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": str(exc)}],
                    "isError": True,
                },
            }
        except Exception as exc:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [
                        {"type": "text", "text": f"{type(exc).__name__}: {exc}"}
                    ],
                    "isError": True,
                },
            }
    if method == "notifications/initialized":
        return {"jsonrpc": "2.0", "id": req_id, "result": None}
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"unknown method: {method}"},
    }


def serve() -> None:
    """Run as an MCP stdio server until stdin closes.

    Mirrors the malware-generator server's fd hygiene: JSON-RPC shares fd 1 with
    any stray print, so stdout is redirected to stderr and the protocol stream
    is written through a dup'd descriptor.
    """
    import os

    try:
        protocol_fd = os.dup(1)
        os.dup2(2, 1)
        sys.stdout = sys.stderr
    except OSError:
        protocol_fd = 1

    def _write(obj: dict) -> None:
        os.write(protocol_fd, (json.dumps(obj) + "\n").encode())

    for line in sys.stdin:
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue
        try:
            _write(_handle_request(request))
        except Exception as exc:
            _write(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32000, "message": f"handler error: {exc}"},
                }
            )


if __name__ == "__main__":
    serve()

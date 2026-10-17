"""Tests for evilkit.research — the passive vuln-research scraper and CLI."""

from __future__ import annotations

import json
import os
import socket
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _helpers import EvilkitTestCase, SCOPE_ENV_KEY  # noqa: E402

from evilkit import research as research_mod  # noqa: E402
from evilkit import mcpscope  # noqa: E402


# ---------------------------------------------------------------- fixtures


def _nvd_vuln() -> dict:
    """One NVD 2.0 vulnerability, shaped like the real API response."""
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "version": "2.0",
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-44228",
                    "sourceIdentifier": "security@apache.org",
                    "published": "2021-12-10T10:15:09.143",
                    "lastModified": "2023-11-07T03:39:38.667",
                    "vulnStatus": "Analyzed",
                    "descriptions": [
                        {"lang": "en", "value": "JNDI lookup allows RCE"}
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "source": "nvd@nist.gov",
                                "type": "Primary",
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                    "baseScore": 10.0,
                                    "baseSeverity": "CRITICAL",
                                },
                                "exploitabilityScore": 3.9,
                                "impactScore": 6.0,
                            }
                        ]
                    },
                    "weaknesses": [
                        {"type": "Primary",
                         "description": [{"lang": "en", "value": "CWE-502"}]}
                    ],
                    "configurations": [
                        {"nodes": [{"cpeMatch": [
                            {"vulnerable": True,
                             "criteria": "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*"}
                        ]}]}
                    ],
                    "references": [
                        {"url": "https://logging.apache.org/log4j/2.x/security.html"}
                    ],
                }
            }
        ],
    }


def _fake_fetch(status=200, content_type="application/json", body=b"{}", final_url=None):
    """Return a fetch callable matching research._safe_open's contract."""
    def fetch(url, timeout=None, max_bytes=None):
        return status, final_url or url, content_type, body
    return fetch


_PAGE_HTML = b"""\
<html><head><title>Test Advisory</title></head>
<body>
<h1>Header One</h1>
<a href="/x">a link</a>
<form action="/login" method="post"><input name="user"><input name="pass"></form>
<p>Some paragraph text.</p>
</body></html>
"""


class TestIsSafeUrl(unittest.TestCase):
    def test_scheme_and_userinfo_refused_without_resolving(self):
        self.assertFalse(research_mod.is_safe_url("ftp://example.com/x"))
        self.assertFalse(research_mod.is_safe_url("file:///etc/passwd"))
        self.assertFalse(research_mod.is_safe_url("http://user:pass@example.com/"))
        self.assertFalse(research_mod.is_safe_url("http://"))

    def test_loopback_and_metadata_refused(self):
        for url in (
            "http://127.0.0.1/",
            "http://localhost/",
            "http://[::1]/",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.5/admin",
            "http://192.168.1.1/",
        ):
            with self.subTest(url=url):
                self.assertFalse(research_mod.is_safe_url(url))

    def test_public_address_allowed_when_resolved(self):
        with mock.patch.object(
            research_mod.socket, "getaddrinfo",
            return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 80))],
        ):
            self.assertTrue(research_mod.is_safe_url("https://example.com/x"))

    def test_any_private_resolved_address_refuses(self):
        infos = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 443)),
        ]
        with mock.patch.object(research_mod.socket, "getaddrinfo", return_value=infos):
            self.assertFalse(research_mod.is_safe_url("https://example.com/x"))


class TestClassifyQuery(unittest.TestCase):
    def test_shapes(self):
        self.assertEqual(research_mod.classify_query("CVE-2021-44228"), "cve")
        self.assertEqual(research_mod.classify_query("cve-2021-44228"), "cve")
        self.assertEqual(research_mod.classify_query("https://example.com/x"), "url")
        self.assertEqual(research_mod.classify_query("apache 2.4.49"), "keyword")

    def test_empty_refused(self):
        with self.assertRaises(research_mod.ResearchError):
            research_mod.classify_query("   ")


class TestScrapePage(unittest.TestCase):
    def test_html_extraction(self):
        page = research_mod.scrape_page(
            "https://example.com/advisory", fetch=_fake_fetch(
                content_type="text/html; charset=utf-8", body=_PAGE_HTML)
        )
        self.assertEqual(page["title"], "Test Advisory")
        self.assertEqual(page["headings"], ["Header One"])
        self.assertIn({"href": "/x", "text": "a link"}, page["links"])
        self.assertEqual(page["forms"], [
            {"action": "/login", "method": "POST", "inputs": ["user", "pass"]}
        ])
        self.assertIn("Some paragraph text.", page["text"])


class TestNvd(unittest.TestCase):
    def test_cve_lookup_flattens_metric(self):
        cve = research_mod.cve_lookup(
            "CVE-2021-44228",
            fetch=_fake_fetch(body=json.dumps(_nvd_vuln()).encode()),
        )
        self.assertEqual(cve["id"], "CVE-2021-44228")
        self.assertEqual(cve["severity"], "CRITICAL")
        self.assertEqual(cve["base_score"], 10.0)
        self.assertEqual(cve["cvss_version"], "3.1")
        self.assertEqual(cve["weaknesses"], ["CWE-502"])
        self.assertIn("cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*", cve["cpes"])

    def test_cve_lookup_rejects_bad_id(self):
        with self.assertRaises(research_mod.ResearchError):
            research_mod.cve_lookup("not-a-cve")

    def test_search_cve_returns_rows(self):
        data = _nvd_vuln()
        data["totalResults"] = 1
        result = research_mod.search_cve(
            "log4j", fetch=_fake_fetch(body=json.dumps(data).encode())
        )
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["results"][0]["id"], "CVE-2021-44228")

    def test_cve_lookup_empty_record_is_an_error(self):
        with self.assertRaises(research_mod.ScrapeError):
            research_mod.cve_lookup(
                "CVE-2021-44228",
                fetch=_fake_fetch(body=b'{"vulnerabilities": []}'),
            )


class TestSearchExploits(unittest.TestCase):
    def test_exploitdb_scrape_parses_edb_links(self):
        html = b'<a href="/exploits/50592" title="x">Log4j RCE</a>'
        with mock.patch.object(research_mod, "_searchsploit", return_value=[]):
            result = research_mod.search_exploits(
                "log4j", fetch=_fake_fetch(content_type="text/html", body=html)
            )
        self.assertEqual(result["source"], "exploitdb")
        self.assertEqual(result["results"][0]["id"], "EDB-50592")
        self.assertIn("Log4j RCE", result["results"][0]["title"])

    def test_empty_query_refused(self):
        with self.assertRaises(research_mod.ResearchError):
            research_mod.search_exploits("   ")


class TestRunResearch(unittest.TestCase):
    def test_cve_query_runs_one_tool(self):
        findings = research_mod.run_research(
            "CVE-2021-44228",
            fetch=_fake_fetch(body=json.dumps(_nvd_vuln()).encode()),
        )
        self.assertEqual(findings["kind"], "cve")
        self.assertEqual([r["tool"] for r in findings["runs"]], ["research_cve"])
        self.assertEqual(findings["findings"][0]["source"], "research_cve")
        self.assertEqual(findings["findings"][0]["data"]["id"], "CVE-2021-44228")

    def test_keyword_query_runs_two_tools(self):
        findings = research_mod.run_research(
            "log4j",
            fetch=_fake_fetch(body=json.dumps(_nvd_vuln()).encode()),
        )
        tools = [r["tool"] for r in findings["runs"]]
        self.assertEqual(tools, ["research_search", "research_exploits"])

    def test_url_query_scrapes(self):
        findings = research_mod.run_research(
            "https://example.com/advisory",
            fetch=_fake_fetch(content_type="text/html", body=_PAGE_HTML),
        )
        self.assertEqual(findings["kind"], "url")
        self.assertEqual([r["tool"] for r in findings["runs"]], ["research_scrape"])

    def test_only_and_skip(self):
        findings = research_mod.run_research(
            "log4j",
            only=["research_search"],
            fetch=_fake_fetch(body=json.dumps(_nvd_vuln()).encode()),
        )
        self.assertEqual([r["tool"] for r in findings["runs"]], ["research_search"])

        findings = research_mod.run_research(
            "log4j",
            skip=["research_exploits"],
            fetch=_fake_fetch(body=json.dumps(_nvd_vuln()).encode()),
        )
        self.assertEqual([r["tool"] for r in findings["runs"]], ["research_search"])

    def test_failure_is_recorded_not_fatal(self):
        def failing(url, timeout=None, max_bytes=None):
            raise research_mod.ScrapeError("boom")

        findings = research_mod.run_research("CVE-2021-44228", fetch=failing)
        self.assertEqual(findings["runs"][0]["status"], "error")
        self.assertIn("boom", findings["runs"][0]["detail"])
        self.assertEqual(findings["findings"], [])

    def test_invalid_query_raises(self):
        with self.assertRaises(research_mod.ResearchError):
            research_mod.run_research("   ")


class TestMCPProtocol(unittest.TestCase):
    def test_initialize_and_tools_list(self):
        init = research_mod._handle_request(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        )
        self.assertEqual(init["result"]["serverInfo"]["name"], "evilkit-research")

        listed = research_mod._handle_request(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        )
        names = {t["name"] for t in listed["result"]["tools"]}
        self.assertEqual(names, set(research_mod.TOOLS))

    def test_tools_call_returns_json_text(self):
        with mock.patch.object(
            research_mod, "cve_lookup",
            return_value={"id": "CVE-2021-44228", "severity": "CRITICAL"},
        ):
            result = research_mod._handle_request({
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": {"name": "research_cve",
                           "arguments": {"cve_id": "CVE-2021-44228"}},
            })
        self.assertFalse(result["result"]["isError"])
        text = result["result"]["content"][0]["text"]
        self.assertEqual(json.loads(text)["id"], "CVE-2021-44228")

    def test_tools_call_error_is_flagged(self):
        with mock.patch.object(
            research_mod, "cve_lookup", side_effect=research_mod.ScrapeError("nope")
        ):
            result = research_mod._handle_request({
                "jsonrpc": "2.0", "id": 4, "method": "tools/call",
                "params": {"name": "research_cve",
                           "arguments": {"cve_id": "CVE-2021-44228"}},
            })
        self.assertTrue(result["result"]["isError"])


class TestResearchCli(EvilkitTestCase):
    def setUp(self):
        super().setUp()
        self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))

    def _findings(self):
        return {
            "research_version": 1, "timestamp": "t", "query": "CVE-2021-44228",
            "kind": "cve",
            "runs": [{"tool": "research_cve", "status": "ok"}],
            "findings": [
                {"source": "research_cve",
                 "data": {"id": "CVE-2021-44228", "severity": "CRITICAL",
                          "base_score": 10.0, "cvss_version": "3.1"}}
            ],
        }

    def test_research_command_writes_findings(self):
        with mock.patch.object(
            research_mod, "run_research", return_value=self._findings()
        ):
            code, out, _err = self.call_main(
                ["research", "CVE-2021-44228",
                 "--json", str(self.tmp / "r.json")])
        self.assertEqual(code, 0)
        self.assertIn("CVE-2021-44228", out)
        self.assertIn("CRITICAL", out)
        written = json.loads((self.tmp / "r.json").read_text(encoding="utf-8"))
        self.assertEqual(written["kind"], "cve")

    def test_research_empty_query_is_usage_error(self):
        code, _out, err = self.call_main(["research"])
        self.assertEqual(code, 2)
        self.assertIn("QUERY", err)

    def test_research_attach_writes_server_next_to_scope(self):
        with mock.patch.object(
            research_mod, "run_research", return_value=self._findings()
        ):
            code, out, _err = self.call_main(
                ["research", "CVE-2021-44228", "--json", str(self.tmp / "r.json"),
                 "--attach"])
        self.assertEqual(code, 0)
        self.assertIn("research MCP server attached", out)
        servers = json.loads(Path(".mcp.json").read_text(encoding="utf-8"))["mcpServers"]
        self.assertEqual(servers["pentest"]["env"][SCOPE_ENV_KEY], "10.0.0.0/24")
        self.assertEqual(servers["research"]["type"], "stdio")
        self.assertEqual(servers["research"]["args"], ["-m", "evilkit.research"])
        self.assertIn("PYTHONPATH", servers["research"]["env"])

    def test_research_attach_without_mcp_json_is_error(self):
        (self.tmp / ".mcp.json").unlink()
        with mock.patch.object(
            research_mod, "run_research", return_value=self._findings()
        ):
            code, _out, err = self.call_main(
                ["research", "CVE-2021-44228", "--json", str(self.tmp / "r.json"),
                 "--attach"])
        self.assertEqual(code, 1)
        self.assertIn(".mcp.json", err)


class TestEnsureResearchServer(EvilkitTestCase):
    def setUp(self):
        super().setUp()
        self.write_mcp_json(self.pentest_fixture("10.0.0.0/24"))

    def test_idempotent_and_additive(self):
        path = Path(".mcp.json")
        command = [sys.executable, "-m", "evilkit.research"]
        self.assertTrue(mcpscope.ensure_research_server(path, command))
        self.assertFalse(mcpscope.ensure_research_server(path, command))
        servers = json.loads(path.read_text(encoding="utf-8"))["mcpServers"]
        self.assertEqual(servers["research"]["type"], "stdio")
        self.assertEqual(servers["research"]["args"], ["-m", "evilkit.research"])
        # pentest scope untouched
        self.assertEqual(servers["pentest"]["env"][SCOPE_ENV_KEY], "10.0.0.0/24")


class TestResearchConfig(EvilkitTestCase):
    def test_defaults_and_env_key(self):
        from evilkit import config as config_mod

        config, problems = config_mod.load()
        self.assertEqual(problems, [])
        self.assertEqual(config.research.timeout_each, 30.0)
        self.assertEqual(config.research.max_bytes, 1_048_576)
        self.assertEqual(config.research.resolved_api_key(), "")

        with mock.patch.dict(os.environ, {"NVD_API_KEY": "abc"}):
            self.assertEqual(config.research.resolved_api_key(), "abc")

    def test_table_coercion_and_dump(self):
        from evilkit import config as config_mod

        config, problems = config_mod.load(self.config_file)
        self.assertEqual(problems, [])
        config.research.nvd_api_key = "key-123"
        config.research.timeout_each = 12.5
        dumped = config_mod.dumps(config)
        self.assertIn("[research]", dumped)
        self.assertIn("nvd_api_key", dumped)
        self.assertIn("max_bytes", dumped)

        # Round-trip the dumped config back through the parser.
        target = self.tmp / "env" / "config" / "written.toml"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(dumped, encoding="utf-8")
        reloaded, reload_problems = config_mod.load(target)
        self.assertEqual(reloaded.research.nvd_api_key, "key-123")
        self.assertEqual(reloaded.research.timeout_each, 12.5)
        self.assertEqual(reload_problems, [])

    def test_bad_research_values_are_reported(self):
        from evilkit import config as config_mod

        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        self.config_file.write_text(
            "[research]\ntimeout_each = -1\nmax_bytes = 0\n"
            "unknown_key = true\n",
            encoding="utf-8",
        )
        config, problems = config_mod.load(self.config_file)
        self.assertTrue(any("[research] timeout_each" in p for p in problems))
        self.assertTrue(any("[research] max_bytes" in p for p in problems))
        self.assertTrue(any("unknown [research] key" in p for p in problems))
        self.assertEqual(config.research.timeout_each, 30.0)


if __name__ == "__main__":
    unittest.main()

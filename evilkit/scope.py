"""Scope string parsing and normalisation.

A scope is a comma-separated list of targets. Each target may be an IPv4/IPv6
address, a CIDR block, or a hostname.

This module is a typo guard, not an access control. The pentest tool server
enforces the real boundary from its own launch environment; everything here
exists so a fat-fingered scope is rejected before it is written anywhere.
"""

from __future__ import annotations

import ipaddress
import re
import socket

__all__ = ["ScopeError", "parse_scope", "normalise_scope", "SOLO_SCOPE", "SOLO_ALIASES"]

SOLO_SCOPE = "127.0.0.1/32"

SOLO_ALIASES = frozenset({"", "solo", "none", "off"})

_HOST_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOSTNAME_RE = re.compile(rf"^{_HOST_LABEL}(?:\.{_HOST_LABEL})*\.?$")

_FORBIDDEN_RE = re.compile(r"[\s\"'`$;&|<>(){}\[\]\\!*?~^#\x00-\x1f]")
#: Digits and dots only: a mistyped address cannot be read as a hostname.
_DOTTED_NUMERIC_RE = re.compile(r"[0-9.]+")


class ScopeError(ValueError):
    """Raised when a scope string cannot be understood as a target list."""


def _clean_token(token: str) -> str:
    token = token.strip()
    if not token:
        raise ScopeError("empty entry in scope list")
    if token.startswith("*."):
        raise ScopeError(
            f"{token!r} uses wildcard matching, which the tool server cannot enforce"
        )
    if _FORBIDDEN_RE.search(token):
        raise ScopeError(f"{token!r} contains characters that are not valid in a target")
    if len(token) > 253:
        raise ScopeError(f"{token!r} is too long to be a host or network")
    return token


def _normalise_network(token: str, allow_any: bool) -> str:
    """Canonicalise a CIDR token, refusing one whose host bits widen it."""
    try:
        network = ipaddress.ip_network(token, strict=True)
    except ValueError as exc:
        try:
            relaxed = ipaddress.ip_network(token, strict=False)
        except ValueError:
            raise ScopeError(f"{token!r} is not a valid network") from exc
        raise ScopeError(
            f"{token!r} has host bits set; did you mean {relaxed}?"
        ) from exc

    if network.prefixlen == 0 and not allow_any:
        raise ScopeError(
            f"{token!r} covers every address; pass --allow-any to confirm that is intended"
        )
    return str(network)


def _is_legacy_numeric(token: str) -> bool:
    """True when only a legacy numeric resolver form explains this token.

    ``curl`` and friends read ``0x7f000001`` and ``0x7f.1`` as 127.0.0.1, so a
    token accepted as a hostname here would authorise a host nobody typed.
    """
    try:
        socket.inet_aton(token)
    except OSError:
        return False
    return True


def _normalise_token(token: str, allow_any: bool) -> str:
    if "/" in token:
        return _normalise_network(token, allow_any)

    try:
        address = ipaddress.ip_address(token)
    except ValueError:
        pass
    else:
        return f"{address}/{address.max_prefixlen}"

    if _DOTTED_NUMERIC_RE.fullmatch(token):
        raise ScopeError(f"{token!r} looks like an IP address but is not valid")

    if _is_legacy_numeric(token):
        raise ScopeError(
            f"{token!r} is a legacy numeric address form that resolvers read as a "
            "different host; write it as a dotted-quad address instead"
        )

    if not _HOSTNAME_RE.match(token):
        raise ScopeError(f"{token!r} is not a valid host, IP or CIDR")
    return token.lower().rstrip(".")


def parse_scope(raw: str, *, allow_any: bool = False) -> list[str]:
    """Split a raw scope string into normalised target entries."""
    if raw is None:
        raise ScopeError("scope is required")
    text = raw.strip()
    if text.lower() in SOLO_ALIASES:
        return [SOLO_SCOPE]
    entries = [
        _normalise_token(_clean_token(part), allow_any) for part in text.split(",")
    ]
    seen: dict[str, None] = {}
    for entry in entries:
        seen.setdefault(entry, None)
    return list(seen)


def normalise_scope(raw: str, *, allow_any: bool = False) -> str:
    """Return the canonical, comma-joined form of ``raw``."""
    return ",".join(parse_scope(raw, allow_any=allow_any))

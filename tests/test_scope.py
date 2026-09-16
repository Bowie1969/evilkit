"""Tests for evilkit.scope — parsing and normalisation of scope strings."""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _helpers import EvilkitTestCase  # noqa: E402

from evilkit.scope import (  # noqa: E402
    SOLO_ALIASES,
    SOLO_SCOPE,
    ScopeError,
    normalise_scope,
    parse_scope,
)


class ScopeTestCase(EvilkitTestCase):
    """Scope parsing is pure, but the shared harness keeps every test hermetic."""


class TestScopeNormalisation(ScopeTestCase):
    ACCEPTED = [
        # IPv4 addresses and networks
        ("10.0.0.5", "10.0.0.5/32"),
        ("10.0.0.5/32", "10.0.0.5/32"),
        ("10.0.0.0/24", "10.0.0.0/24"),
        ("10.0.0.0/255.255.255.0", "10.0.0.0/24"),
        ("255.255.255.255", "255.255.255.255/32"),
        # hostnames, lowercased, trailing dot dropped
        ("app.lan", "app.lan"),
        ("APP.LAN", "app.lan"),
        ("App.Lan.", "app.lan"),
        ("localhost", "localhost"),
        ("host1.example.co.uk", "host1.example.co.uk"),
        # IPv6
        ("::1", "::1/128"),
        ("fe80::1", "fe80::1/128"),
        ("2001:db8::/32", "2001:db8::/32"),
    ]

    def test_accepted_forms_normalise_as_documented(self):
        for raw, expected in self.ACCEPTED:
            with self.subTest(raw=raw):
                self.assertEqual(normalise_scope(raw), expected)
                self.assertEqual(parse_scope(raw), [expected])

    def test_bare_address_becomes_a_single_host_network(self):
        self.assertEqual(parse_scope("10.0.0.5"), ["10.0.0.5/32"])

    def test_netmask_notation_is_collapsed_to_a_prefix_length(self):
        self.assertEqual(normalise_scope("10.0.0.0/255.255.255.0"), "10.0.0.0/24")

    def test_mixed_list_is_normalised_and_comma_joined(self):
        self.assertEqual(
            normalise_scope("10.0.0.5, 10.0.0.0/24, APP.LAN, ::1"),
            "10.0.0.5/32,10.0.0.0/24,app.lan,::1/128",
        )

    def test_duplicates_are_collapsed_and_first_seen_order_is_kept(self):
        self.assertEqual(
            parse_scope("10.0.0.0/24,10.0.0.5,10.0.0.0/255.255.255.0,10.0.0.5/32"),
            ["10.0.0.0/24", "10.0.0.5/32"],
        )

    def test_surrounding_whitespace_on_each_entry_is_stripped(self):
        self.assertEqual(
            parse_scope("  10.0.0.5 ,\t10.0.0.6  "),
            ["10.0.0.5/32", "10.0.0.6/32"],
        )


class TestSoloAliases(ScopeTestCase):
    def test_solo_scope_constant(self):
        self.assertEqual(SOLO_SCOPE, "127.0.0.1/32")

    def test_documented_aliases_are_present(self):
        self.assertTrue({"", "solo", "none", "off"} <= set(SOLO_ALIASES))

    def test_every_alias_in_any_case_yields_the_locked_down_default(self):
        for alias in sorted(SOLO_ALIASES):
            for spelling in {alias.lower(), alias.upper(), alias.title()}:
                with self.subTest(alias=spelling):
                    self.assertEqual(normalise_scope(spelling), SOLO_SCOPE)

    def test_alias_surrounded_by_whitespace_still_matches(self):
        self.assertEqual(normalise_scope("  solo  "), SOLO_SCOPE)

    def test_explicit_solo_spellings_from_the_spec(self):
        for spelling in ("", "solo", "Solo", "SOLO"):
            with self.subTest(spelling=spelling):
                self.assertEqual(parse_scope(spelling), [SOLO_SCOPE])


class TestRejectedScopes(ScopeTestCase):
    REJECTED = [
        # empty entries in a list
        "10.0.0.5, ,10.0.0.6",
        "10.0.0.5,",
        ",10.0.0.5",
        " , ",
        # shell metacharacters
        "10.0.0.5;whoami",
        "10.0.0.5|cat /etc/passwd",
        "10.0.0.5&&whoami",
        "10.0.0.5&whoami",
        "10.0.0.5$USER",
        "$(id)",
        "`id`",
        "10.0.0.5>out",
        "10.0.0.5<in",
        # quotes
        '10.0.0.5"',
        "10.0.0.5'",
        '"10.0.0.5"',
        # a command smuggled in behind a valid target
        "10.0.0.0/24;rm -rf /",
        "10.0.0.0/24 rm -rf /",
        "10.0.0.0/24,rm -rf /",
        "rm -rf /",
        # wildcard scope tokens: the tool server cannot match them
        "*",
        " * ",
        "**",
        "foo*",
        "example.*",
        "*.example.com",
        "*.corp.example.com",
        "*.example.com*",
        "*.*.example.com",
        "?",
        "10.0.0.*",
        # malformed networks
        "10.0.0.0/99",
        "10.0.0.0/-1",
        "10.0.0.0/",
        # malformed hostnames
        "-bad.example.com",
        "bad-.example.com",
        "under_score.example.com",
        "a" * 64 + ".example.com",
        ("a" * 63 + ".") * 4 + "com",
    ]

    def test_rejected_forms_raise_scope_error(self):
        for raw in self.REJECTED:
            with self.subTest(raw=raw):
                with self.assertRaises(ScopeError):
                    normalise_scope(raw)

    def test_scope_error_is_a_value_error(self):
        self.assertTrue(issubclass(ScopeError, ValueError))

    def test_none_scope_is_rejected(self):
        with self.assertRaises(ScopeError):
            parse_scope(None)

    def test_rejection_message_never_echoes_a_usable_target(self):
        # A rejected scope must fail loudly rather than silently drop the bad half.
        with self.assertRaises(ScopeError) as ctx:
            parse_scope("10.0.0.0/24,rm -rf /")
        self.assertIn("rm -rf /", str(ctx.exception))


class TestHostBitsAreRejected(ScopeTestCase):
    """A /N token widens silently unless the network is aligned."""

    def test_a_network_with_host_bits_set_is_rejected(self):
        for raw in ("10.0.0.5/24", "10.0.0.5/255.255.255.0", "2001:db8::1/64"):
            with self.subTest(raw=raw):
                with self.assertRaises(ScopeError):
                    normalise_scope(raw)

    def test_the_rejection_names_the_corrected_network(self):
        with self.assertRaises(ScopeError) as ctx:
            normalise_scope("10.0.0.5/24")
        self.assertIn("did you mean 10.0.0.0/24?", str(ctx.exception))

    def test_netmask_notation_with_host_bits_names_the_prefix_form(self):
        with self.assertRaises(ScopeError) as ctx:
            normalise_scope("10.0.0.5/255.255.255.0")
        self.assertIn("did you mean 10.0.0.0/24?", str(ctx.exception))

    def test_an_aligned_network_is_still_accepted(self):
        self.assertEqual(normalise_scope("10.0.0.0/24"), "10.0.0.0/24")
        self.assertEqual(normalise_scope("10.0.0.0/255.255.255.0"), "10.0.0.0/24")

    def test_a_bare_address_still_becomes_a_single_host(self):
        self.assertEqual(normalise_scope("10.0.0.5"), "10.0.0.5/32")
        self.assertEqual(normalise_scope("::1"), "::1/128")


class TestWholeAddressSpace(ScopeTestCase):
    def test_a_zero_prefix_is_refused_by_default(self):
        for raw in ("0.0.0.0/0", "::/0", "0.0.0.0/0.0.0.0"):
            with self.subTest(raw=raw):
                with self.assertRaises(ScopeError):
                    normalise_scope(raw)

    def test_the_refusal_says_how_to_proceed(self):
        with self.assertRaises(ScopeError) as ctx:
            normalise_scope("0.0.0.0/0")
        self.assertIn("--allow-any", str(ctx.exception))

    def test_allow_any_permits_it(self):
        self.assertEqual(normalise_scope("0.0.0.0/0", allow_any=True), "0.0.0.0/0")
        self.assertEqual(normalise_scope("::/0", allow_any=True), "::/0")
        self.assertEqual(parse_scope("0.0.0.0/0", allow_any=True), ["0.0.0.0/0"])

    def test_allow_any_relaxes_nothing_else(self):
        with self.assertRaises(ScopeError):
            normalise_scope("10.0.0.5/24", allow_any=True)
        with self.assertRaises(ScopeError):
            normalise_scope("*.example.com", allow_any=True)


class TestLegacyNumericAddresses(ScopeTestCase):
    """inet_aton forms that resolvers read as a host nobody typed."""

    def test_legacy_numeric_forms_are_rejected(self):
        for raw in ("0x7f000001", "0x7f.1", "127.1", "0x7F.0.0.1", "0", "2130706433"):
            with self.subTest(raw=raw):
                with self.assertRaises(ScopeError):
                    normalise_scope(raw)

    def test_a_real_hostname_is_still_accepted(self):
        self.assertEqual(normalise_scope("app.example.com"), "app.example.com")
        self.assertEqual(normalise_scope("localhost"), "localhost")

    def test_a_real_dotted_quad_is_still_a_single_host(self):
        self.assertEqual(normalise_scope("127.0.0.1"), "127.0.0.1/32")
        self.assertEqual(normalise_scope("10.0.0.5"), "10.0.0.5/32")


class TestWildcardsAreRejected(ScopeTestCase):
    def test_a_wildcard_token_is_rejected(self):
        for raw in ("*.corp.example.com", "*.EXAMPLE.com.", "*.example.com"):
            with self.subTest(raw=raw):
                with self.assertRaises(ScopeError):
                    normalise_scope(raw)

    def test_the_refusal_explains_that_the_tool_server_cannot_match_it(self):
        with self.assertRaises(ScopeError) as ctx:
            normalise_scope("*.corp.example.com")
        message = str(ctx.exception)
        self.assertIn("wildcard", message)
        self.assertIn("tool server", message)

    def test_a_bare_star_is_still_rejected(self):
        for raw in ("*", " * ", "**", "10.0.0.*", "example.*", "?"):
            with self.subTest(raw=raw):
                with self.assertRaises(ScopeError):
                    normalise_scope(raw)


class TestScopeTypos(ScopeTestCase):
    def test_out_of_range_ipv4_typos_are_rejected(self):
        """Regression: a dotted-quad typo used to be accepted as a hostname.

        A token whose octets are out of range satisfies the hostname regex, so it
        used to fall through to the "valid hostname" branch. This module is
        documented as a typo guard, so 999.1.1.1 must be rejected.
        """
        accepted = []
        for token in ("999.1.1.1", "10.0.0.256", "192.168.1.300", "1.2.3.4.5"):
            try:
                accepted.append(token + " -> " + normalise_scope(token))
            except ScopeError:
                pass
        self.assertEqual(accepted, [], "these out-of-range targets must be rejected")


if __name__ == "__main__":
    unittest.main()

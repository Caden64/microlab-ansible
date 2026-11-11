"""Behavior tests for the MicroLab DNS reconciliation and acceptance logic.

These tests are intentionally host-free: they import the pure filter plugin,
feed it mock Technitium API records, and inspect the task wiring.  No DNS
server, API, firewall, CA, or inventory host is contacted.
"""

from __future__ import annotations

import importlib.util
import json
import re
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DNS_ROLE = ROOT / "roles/technitium_dns"
VALIDATOR = ROOT / "roles/baseline/files/microlab_validate.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


dns = load_module(
    "micolab_dns_filters", DNS_ROLE / "filter_plugins/microlab_ip.py"
)
fixture = load_module("micolab_dns_fixture", DNS_ROLE / "files/dns_fixture.py")

MANAGED = "micolab-managed"


def api_a(name: str, address: str, ttl: int = 300, comments: str = MANAGED) -> dict:
    return {
        "name": name,
        "type": "A",
        "rData": {"ipAddress": address},
        "ttl": ttl,
        "comments": comments,
    }


def api_aaaa(name: str, address: str, ttl: int = 300, comments: str = MANAGED) -> dict:
    return {
        "name": name,
        "type": "AAAA",
        "rData": {"ipAddress": address},
        "ttl": ttl,
        "comments": comments,
    }


def api_ns(name: str, target: str, ttl: int = 3600, comments: str = MANAGED) -> dict:
    return {
        "name": name,
        "type": "NS",
        "rData": {"nameServer": target},
        "ttl": ttl,
        "comments": comments,
    }


def api_fwd(
    zone: str,
    forwarder: str,
    comments: str = "",
    protocol: str = "Udp",
    priority: int = 0,
    dnssec: bool = False,
) -> dict:
    return {
        "name": zone,
        "type": "FWD",
        "ttl": 0,
        "comments": comments,
        "rData": {
            "protocol": protocol,
            "forwarder": forwarder,
            "priority": priority,
            "dnssecValidation": dnssec,
            "proxyType": "DefaultProxy",
        },
    }


def desired(name: str, rtype: str, value: str, ttl: int = 300) -> dict:
    return {"name": name, "type": rtype, "value": value, "ttl": ttl}


def apply_plan(current: list[dict], plan: dict) -> list[dict]:
    """Apply a plan to a mock API record list, as the API would."""
    result = [dict(record) for record in current]
    for item in plan["add"]:
        record = {
            "name": item["name"],
            "type": item["type"],
            "ttl": item["ttl"],
            "comments": MANAGED,
        }
        if item["type"] in ("A", "AAAA"):
            record["rData"] = {"ipAddress": item["value"]}
        else:
            record["rData"] = {"nameServer": item["value"]}
        result.append(record)

    for change in plan["update"]:
        item = change["desired"]
        for record in result:
            if dns.record_key(record.get("name"), record.get("type"), dns.record_value(record)) == item["key"]:
                record["ttl"] = item["ttl"]
                record["comments"] = MANAGED

    for stale in plan["delete"]:
        stale_key = stale["micolab_key"]
        result = [
            record
            for record in result
            if dns.record_key(record.get("name"), record.get("type"), dns.record_value(record))
            != stale_key
        ]
    return result


class TemplateSourceTests(unittest.TestCase):
    """Sol finding 1: every template/copy source must exist in its role."""

    SRC_RE = re.compile(r"(?m)^\s+src:\s*([A-Za-z0-9_./-]+)\s*$")

    def test_all_role_task_sources_exist(self) -> None:
        for task_file in sorted(ROOT.glob("roles/*/tasks/*.yml")):
            role_dir = task_file.parents[1]
            text = task_file.read_text()
            for source in self.SRC_RE.findall(text):
                if source.startswith(("/", "~")) or "{{" in source:
                    continue
                if source.endswith(".j2"):
                    candidates = [role_dir / "templates" / source]
                else:
                    candidates = [
                        role_dir / "files" / source,
                        role_dir / "templates" / source,
                    ]
                with self.subTest(task_file=task_file, source=source):
                    self.assertTrue(
                        any(path.is_file() for path in candidates),
                        f"{task_file} references missing source {source}",
                    )

    def test_baseline_firewall_template_name_matches_file(self) -> None:
        text = (ROOT / "roles/baseline/tasks/main.yml").read_text()
        self.assertIn("src: microlab-firewall.nft.j2", text)
        self.assertNotIn("src: micolab-firewall.nft.j2", text)
        self.assertTrue(
            (ROOT / "roles/baseline/templates/microlab-firewall.nft.j2").is_file()
        )


class ResolverRollbackTests(unittest.TestCase):
    """Sol finding 2: first-run backup must be usable by the rescue path."""

    def setUp(self) -> None:
        self.text = (DNS_ROLE / "tasks/resolver.yml").read_text()

    def test_backup_is_rechecked_before_the_switch(self) -> None:
        copy_at = self.text.index("Preserve the pre-deployment resolver configuration")
        recheck_at = self.text.index("Re-check the backup after a possible first-run creation")
        switch_at = self.text.index("Switch the host resolver only after all DNS gates")
        self.assertLess(copy_at, recheck_at)
        self.assertLess(recheck_at, switch_at)
        self.assertIn("checksum_algorithm: sha256", self.text)
        self.assertIn("micolab_dns_resolv_backup_ready.stat.checksum", self.text)

    def test_rescue_does_not_use_the_pre_copy_stat(self) -> None:
        rescue_at = self.text.index("rescue:")
        rescue_text = self.text[rescue_at:]
        self.assertIn("micolab_dns_resolv_backup_ready", rescue_text)
        self.assertNotIn("micolab_dns_resolv_backup_stat.stat.exists", rescue_text)
        self.assertIn("did NOT restore", rescue_text)
        self.assertIn("Verify the restored resolver content", rescue_text)

    def test_block_uses_the_yaml_keyword_not_a_fqcn_module(self) -> None:
        self.assertNotIn("ansible.builtin.block:", self.text)
        self.assertIn("  block:", self.text)

    def test_first_run_backup_restores_exact_initial_content(self) -> None:
        # Model the task sequence: copy to backup, mutate resolv.conf, then
        # restore from the backup on failure.  The assertion is byte equality,
        # which is what the checksum comparison enforces on the host.
        initial = b"nameserver 192.0.2.53\nsearch lab.example\noptions edns0\n"
        with tempfile.TemporaryDirectory() as tmp:
            resolv = Path(tmp) / "resolv.conf"
            backup = Path(tmp) / "resolv.conf.microlab.bak"
            resolv.write_bytes(initial)

            # First run: no backup exists, so create it before switching.
            self.assertFalse(backup.exists())
            backup.write_bytes(resolv.read_bytes())
            self.assertTrue(backup.exists())

            # Switch, then fail the getent gate and restore in rescue.
            resolv.write_text("nameserver 127.0.0.1\noptions edns0\n")
            resolv.write_bytes(backup.read_bytes())

            self.assertEqual(resolv.read_bytes(), initial)
            self.assertEqual(backup.read_bytes(), initial)


class RecordPlanTests(unittest.TestCase):
    """Sol finding 3: plan against the complete desired RRset identity set."""

    def test_multi_valued_a_records_are_not_treated_as_stale(self) -> None:
        current = [
            api_a("ca.microlab.hnh", "192.0.2.10"),
            api_a("ca.microlab.hnh", "192.0.2.11"),
        ]
        wanted = [
            desired("ca.microlab.hnh", "A", "192.0.2.10"),
            desired("ca.microlab.hnh", "A", "192.0.2.11"),
        ]
        plan = dns.plan_records(wanted, current)
        self.assertEqual(plan["pending"], 0, plan)
        self.assertEqual(plan["delete"], [])

    def test_add_missing_and_delete_only_stale_same_rrset(self) -> None:
        current = [
            api_a("ca.microlab.hnh", "192.0.2.10"),
            api_a("ca.microlab.hnh", "192.0.2.99"),
        ]
        wanted = [
            desired("ca.microlab.hnh", "A", "192.0.2.10"),
            desired("ca.microlab.hnh", "A", "192.0.2.11"),
        ]
        plan = dns.plan_records(wanted, current)
        self.assertEqual([item["value"] for item in plan["add"]], ["192.0.2.11"])
        self.assertEqual(
            [item["micolab_value"] for item in plan["delete"]], ["192.0.2.99"]
        )
        self.assertEqual(plan["update"], [])

        after = apply_plan(current, plan)
        self.assertEqual(dns.plan_records(wanted, after)["pending"], 0)

    def test_multi_valued_ns_preserves_unknown_ns(self) -> None:
        current = [
            api_ns("hnh", "ns1.microlab.hnh."),
            api_ns("hnh", "old.microlab.hnh."),
            api_ns("hnh", "human.example.", comments=""),
        ]
        wanted = [
            desired("hnh", "NS", "ns1.microlab.hnh", 3600),
            desired("hnh", "NS", "ns2.microlab.hnh", 3600),
        ]
        plan = dns.plan_records(wanted, current)
        self.assertEqual([item["value"] for item in plan["add"]], ["ns2.microlab.hnh"])
        self.assertEqual(
            [item["micolab_value"] for item in plan["delete"]], ["old.microlab.hnh"]
        )
        preserved = {item["micolab_value"] for item in plan["preserve"]}
        self.assertIn("human.example", preserved)

    def test_ipv6_text_normalisation_prevents_churn(self) -> None:
        current = [api_aaaa("ca.microlab.hnh", "2001:db8::10")]
        wanted = [
            desired("ca.microlab.hnh", "AAAA", "2001:0db8:0:0:0:0:0:10")
        ]
        self.assertEqual(dns.plan_records(wanted, current)["pending"], 0)

    def test_ttl_drift_updates_owned_exact_record(self) -> None:
        current = [api_a("ca.microlab.hnh", "192.0.2.10", ttl=120)]
        wanted = [desired("ca.microlab.hnh", "A", "192.0.2.10", ttl=300)]
        plan = dns.plan_records(wanted, current)
        self.assertEqual(plan["add"], [])
        self.assertEqual(len(plan["update"]), 1)
        self.assertEqual(plan["update"][0]["desired"]["ttl"], 300)

    def test_unowned_exact_record_is_not_claimed_or_duplicated(self) -> None:
        current = [api_a("ca.microlab.hnh", "192.0.2.10", comments="")]
        wanted = [desired("ca.microlab.hnh", "A", "192.0.2.10")]
        plan = dns.plan_records(wanted, current)
        self.assertEqual(plan["pending"], 0)
        self.assertEqual(len(plan["preserve"]), 1)

    def test_identity_keeps_raw_ns_value_for_api_mutations(self) -> None:
        identity = dns.record_identity(api_ns("hnh", "ns1.microlab.hnh."))
        self.assertEqual(identity["micolab_value"], "ns1.microlab.hnh")
        self.assertEqual(identity["micolab_raw_value"], "ns1.microlab.hnh.")

    def test_unknown_record_types_are_never_deleted(self) -> None:
        current = [
            {
                "name": "txt.microlab.hnh",
                "type": "TXT",
                "rData": {"text": "hello"},
                "ttl": 300,
                "comments": MANAGED,
            }
        ]
        plan = dns.plan_records([], current)
        self.assertEqual(plan["delete"], [])
        self.assertEqual(plan["pending"], 0)

    def test_rerun_after_plan_is_idempotent(self) -> None:
        current = [
            api_a("ca.microlab.hnh", "192.0.2.10", ttl=120),
            api_a("ca.microlab.hnh", "192.0.2.99"),
            api_aaaa("ca.microlab.hnh", "2001:db8::10"),
        ]
        wanted = [
            desired("ca.microlab.hnh", "A", "192.0.2.10", ttl=300),
            desired("ca.microlab.hnh", "A", "192.0.2.11"),
            desired("ca.microlab.hnh", "AAAA", "2001:0db8:0:0:0:0:0:10"),
        ]
        first = dns.plan_records(wanted, current)
        after = apply_plan(current, first)
        second = dns.plan_records(wanted, after)
        self.assertEqual(second["pending"], 0, second)
        self.assertEqual(second["delete"], [])


class AclCanonicalizationTests(unittest.TestCase):
    """Sol finding 4: compare canonical ACLs without losing order/deny."""

    def test_host_sized_cidrs_match_bare_api_form(self) -> None:
        self.assertEqual(dns.canonical_cidr("192.0.2.10/32"), "192.0.2.10")
        self.assertEqual(dns.canonical_cidr("192.0.2.10"), "192.0.2.10")
        self.assertEqual(dns.canonical_cidr("2001:db8::1/128"), "2001:db8::1")
        self.assertEqual(dns.canonical_cidr("2001:0db8:0:0:0:0:0:1"), "2001:db8::1")

    def test_deny_marker_and_order_are_preserved(self) -> None:
        entries = ["!192.0.2.10/32", "192.0.2.0/24", "!2001:db8::1/128"]
        self.assertEqual(
            dns.normalize_acl(entries),
            ["!192.0.2.10", "192.0.2.0/24", "!2001:db8::1"],
        )
        merged = dns.merge_acl(entries, ["192.0.2.0/24", "198.51.100.0/24"])
        self.assertEqual(
            merged["entries"],
            ["!192.0.2.10", "192.0.2.0/24", "!2001:db8::1", "198.51.100.0/24"],
        )
        self.assertEqual(merged["conflicts"], [])

    def test_merge_is_idempotent_after_api_canonicalization(self) -> None:
        current = ["192.0.2.10", "2001:db8::1"]
        desired_entries = ["192.0.2.10/32", "2001:0db8:0:0:0:0:0:1/128"]
        first = dns.merge_acl(current, desired_entries)
        second = dns.merge_acl(first["entries"], desired_entries)
        self.assertEqual(first["entries"], current)
        self.assertEqual(second["entries"], first["entries"])
        self.assertEqual(second["conflicts"], [])

    def test_broad_allow_before_deny_is_reported_not_sorted_away(self) -> None:
        conflicts = dns.acl_conflicts(["10.0.0.0/8", "!10.1.0.0/16"])
        self.assertEqual(len(conflicts), 1)
        self.assertIn("shadows", conflicts[0])

    def test_existing_deny_before_desired_allow_is_reported(self) -> None:
        merged = dns.merge_acl(["!10.1.0.0/16"], ["10.1.0.0/16"])
        self.assertEqual(merged["entries"], ["!10.1.0.0/16", "10.1.0.0/16"])
        self.assertEqual(len(merged["conflicts"]), 1)

    def test_required_network_must_be_effectively_allowed(self) -> None:
        self.assertEqual(
            dns.acl_unallowed(["192.0.2.10"], ["192.0.2.10"]), []
        )
        self.assertEqual(
            dns.acl_unallowed(["192.0.2.10"], ["!192.0.2.10"]), ["192.0.2.10"]
        )
        self.assertEqual(
            dns.acl_unallowed(["192.0.2.10"], ["192.0.2.0/24"]), []
        )

    def test_ip_in_networks_handles_ipv6(self) -> None:
        self.assertTrue(
            dns.ip_in_networks("2001:db8::5", ["2001:db8::/32"])
        )
        self.assertFalse(
            dns.ip_in_networks("2001:db9::5", ["2001:db8::/32"])
        )

    def test_probe_classification_requires_matching_source(self) -> None:
        recursion = ["192.0.2.0/24"]
        authoritative = ["203.0.113.0/24"]
        firewall = ["192.0.2.0/24", "203.0.113.0/24"]
        good = [
            {"host": "a", "access": "recursion-allowed", "source_address": "192.0.2.5"},
            {"host": "b", "access": "recursion-denied", "source_address": "203.0.113.5"},
            {"host": "c", "access": "firewall-denied", "source_address": "198.51.100.5"},
        ]
        self.assertEqual(
            dns.probe_classification_errors(
                good, recursion, authoritative, firewall
            ),
            [],
        )
        bad = [
            {"host": "a", "access": "recursion-allowed", "source_address": "198.51.100.5"},
            {"host": "b", "access": "recursion-denied", "source_address": "192.0.2.5"},
            {"host": "c", "access": "firewall-denied", "source_address": "203.0.113.5"},
        ]
        errors = dns.probe_classification_errors(
            bad, recursion, authoritative, firewall
        )
        self.assertEqual(len(errors), 4, errors)


class AclEffectiveDenialTests(unittest.TestCase):
    """Authoritative-only networks must be denied, not merely absent."""

    def test_broad_existing_allow_covering_authoritative_only_fails(self) -> None:
        # Reproduction from the review: 10.0.0.0/8 exists and 10.99.0.0/24 is
        # authoritative-only. Appending managed entries must not hide the
        # fact that first-match allows the narrower network to recurse.
        entries = ["10.0.0.0/8"]
        self.assertFalse(dns.acl_network_denied(entries, "10.99.0.0/24"))
        self.assertEqual(
            dns.acl_deny_conflicts(entries, ["10.99.0.0/24"]),
            ["10.99.0.0/24 is allowed by first-match entry 10.0.0.0/8"],
        )

    def test_deny_before_broad_allow_is_effective(self) -> None:
        entries = ["!10.99.0.0/24", "10.0.0.0/8"]
        self.assertTrue(dns.acl_network_denied(entries, "10.99.0.0/24"))
        self.assertEqual(dns.acl_deny_conflicts(entries, ["10.99.0.0/24"]), [])

    def test_partial_allow_inside_authoritative_only_fails(self) -> None:
        entries = ["10.99.0.0/25", "10.0.0.0/8"]
        self.assertFalse(dns.acl_network_denied(entries, "10.99.0.0/24"))
        conflicts = dns.acl_deny_conflicts(entries, ["10.99.0.0/24"])
        self.assertEqual(len(conflicts), 1)
        self.assertIn("partly allowed", conflicts[0])

    def test_partial_deny_inside_authoritative_only_is_not_full_denial(self) -> None:
        entries = ["!10.99.0.128/25", "10.0.0.0/8"]
        self.assertFalse(dns.acl_network_denied(entries, "10.99.0.0/24"))

    def test_no_overlapping_entry_is_default_deny(self) -> None:
        self.assertTrue(dns.acl_network_denied(["192.0.2.0/24"], "10.99.0.0/24"))
        self.assertTrue(dns.acl_network_denied([], "10.99.0.0/24"))

    def test_covering_deny_wins_even_with_later_allows(self) -> None:
        entries = ["!10.0.0.0/8", "10.99.0.0/24", "192.0.2.0/24"]
        self.assertTrue(dns.acl_network_denied(entries, "10.99.0.0/24"))

    def test_ipv6_first_match_denial(self) -> None:
        self.assertFalse(
            dns.acl_network_denied(["2001:db8::/32"], "2001:db8:99::/48")
        )
        self.assertTrue(
            dns.acl_network_denied(
                ["!2001:db8:99::/48", "2001:db8::/32"],
                "2001:db8:99::/48",
            )
        )

    def test_every_authoritative_only_network_is_checked(self) -> None:
        auth_only = ["10.99.0.0/24", "198.51.100.0/24", "2001:db8:99::/48"]
        entries = ["10.0.0.0/8", "198.51.100.0/24", "2001:db8::/32"]
        undennied = dns.acl_undennied(auth_only, entries)
        self.assertEqual(set(undennied), set(auth_only))
        conflicts = dns.acl_deny_conflicts(entries, auth_only)
        self.assertEqual(len(conflicts), 3, conflicts)
        self.assertTrue(any("198.51.100.0/24" in item for item in conflicts))
        self.assertTrue(any("2001:db8:99::/48" in item for item in conflicts))

    def test_authoritative_only_network_with_no_overlap_is_default_denied(self) -> None:
        self.assertEqual(
            dns.acl_undennied(
                ["10.99.0.0/24", "198.51.100.0/24"],
                ["10.0.0.0/8"],
            ),
            ["10.99.0.0/24"],
        )


class RecursionFixtureResponderTests(unittest.TestCase):
    """The offline fixture must answer without the AA flag."""

    ZONE = "fixture.microlab.internal"
    NAME = "dialog.fixture.microlab.internal"
    ANSWER = "192.0.2.80"

    @staticmethod
    def query(name: str, qtype: int = 1, qclass: int = 1) -> bytes:
        qname = b"".join(
            bytes([len(label)]) + label.encode("ascii")
            for label in name.split(".")
        ) + b"\x00"
        return (
            struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
            + qname
            + struct.pack("!HH", qtype, qclass)
        )

    def response(self, name: str, qtype: int = 1) -> bytes:
        result = fixture.build_response(
            self.query(name, qtype), self.ZONE, self.NAME, self.ANSWER
        )
        self.assertIsNotNone(result)
        return result

    @staticmethod
    def flags(response: bytes) -> int:
        return struct.unpack("!H", response[2:4])[0]

    def test_known_name_returns_noerror_and_a_answer_without_aa(self) -> None:
        response = self.response(self.NAME)
        flags = self.flags(response)
        self.assertEqual(flags & 0x000F, fixture.RCODE_NOERROR)
        self.assertTrue(flags & 0x8000)
        self.assertTrue(flags & 0x0080)  # RA
        self.assertFalse(flags & 0x0400)  # AA clear
        self.assertEqual(struct.unpack("!H", response[6:8])[0], 1)  # ANCOUNT
        self.assertIn(socket.inet_aton(self.ANSWER), response)

    def test_other_name_inside_zone_is_nxdomain(self) -> None:
        flags = self.flags(self.response("missing." + self.ZONE))
        self.assertEqual(flags & 0x000F, fixture.RCODE_NXDOMAIN)

    def test_name_outside_zone_is_refused(self) -> None:
        flags = self.flags(self.response("www.example.com"))
        self.assertEqual(flags & 0x000F, fixture.RCODE_REFUSED)

    def test_aaaa_for_fixture_name_is_noerror_nodata(self) -> None:
        response = self.response(self.NAME, qtype=fixture.QTYPE_AAAA)
        flags = self.flags(response)
        self.assertEqual(flags & 0x000F, fixture.RCODE_NOERROR)
        self.assertFalse(flags & 0x0400)
        self.assertEqual(struct.unpack("!H", response[6:8])[0], 0)


class FixtureForwarderPlanTests(unittest.TestCase):
    """Ownership and safe-resume rules for the fixture forwarder zone."""

    ZONE = "fixture.microlab.internal"
    UPSTREAM = "127.0.0.1:5353"
    MARKER = "micolab-managed:fixture-forwarder"

    def plan(self, records: list[dict], upstream: str | None = None) -> dict:
        return dns.fixture_forwarder_plan(
            records, self.ZONE, self.MARKER, upstream or self.UPSTREAM
        )

    def test_owned_current_record_is_zero_change(self) -> None:
        plan = self.plan([api_fwd(self.ZONE, self.UPSTREAM, self.MARKER)])
        self.assertEqual(plan["errors"], [])
        self.assertEqual(plan["state"], "owned-current")
        self.assertIsNone(plan["update"])

    def test_owned_endpoint_change_updates_only_the_owned_record(self) -> None:
        plan = self.plan(
            [
                api_fwd(self.ZONE, "127.0.0.1:5300", self.MARKER, priority=7),
                {"name": "keep", "type": "TXT", "ttl": 60, "rData": {"text": "x"}},
            ],
            upstream="127.0.0.1:5353",
        )
        self.assertEqual(plan["errors"], [])
        self.assertEqual(plan["state"], "owned-update")
        self.assertEqual(plan["update"]["forwarder"], "127.0.0.1:5300")
        self.assertEqual(plan["update"]["newForwarder"], self.UPSTREAM)
        self.assertEqual(plan["update"]["forwarderPriority"], "7")
        self.assertEqual(plan["update"]["comments"], self.MARKER)

    def test_unowned_forwarder_fails_closed_without_an_update(self) -> None:
        plan = self.plan([api_fwd(self.ZONE, self.UPSTREAM)])
        self.assertEqual(plan["state"], "conflict")
        self.assertTrue(plan["errors"])
        self.assertIsNone(plan["update"])

    def test_marker_on_another_comment_line_does_not_claim_the_record(self) -> None:
        plan = self.plan(
            [api_fwd(self.ZONE, self.UPSTREAM, "not " + self.MARKER)]
        )
        self.assertEqual(plan["state"], "conflict")
        self.assertEqual(len(plan["unknown"]), 1)

    def test_multiple_unknown_forwarders_fail_closed(self) -> None:
        plan = self.plan(
            [
                api_fwd(self.ZONE, "127.0.0.1:5300"),
                api_fwd(self.ZONE, "127.0.0.1:5301"),
            ]
        )
        self.assertEqual(plan["state"], "conflict")
        self.assertEqual(len(plan["unknown"]), 2)
        self.assertIsNone(plan["update"])

    def test_owned_plus_unknown_forwarder_is_ambiguous(self) -> None:
        plan = self.plan(
            [
                api_fwd(self.ZONE, self.UPSTREAM, self.MARKER),
                api_fwd(self.ZONE, "127.0.0.1:5300"),
            ]
        )
        self.assertEqual(plan["state"], "conflict")
        self.assertEqual(len(plan["owned"]), 1)
        self.assertEqual(len(plan["unknown"]), 1)
        self.assertIsNone(plan["update"])

    def test_multiple_owned_forwarders_fail_closed(self) -> None:
        plan = self.plan(
            [
                api_fwd(self.ZONE, self.UPSTREAM, self.MARKER),
                api_fwd(self.ZONE, "127.0.0.1:5300", self.MARKER),
            ]
        )
        self.assertEqual(plan["state"], "conflict")
        self.assertTrue(any("exactly one" in item for item in plan["errors"]))

    def test_owned_non_udp_or_dnssec_record_fails_closed(self) -> None:
        for overrides in (
            {"protocol": "Tcp"},
            {"dnssec": True},
        ):
            with self.subTest(overrides=overrides):
                plan = self.plan(
                    [api_fwd(self.ZONE, self.UPSTREAM, self.MARKER, **overrides)]
                )
                self.assertEqual(plan["state"], "conflict")
                self.assertIsNone(plan["update"])

    def test_owned_record_at_wrong_name_fails_closed(self) -> None:
        record = api_fwd(self.ZONE, self.UPSTREAM, self.MARKER)
        record["name"] = "other." + self.ZONE
        plan = self.plan([record])
        self.assertEqual(plan["state"], "conflict")
        self.assertIsNone(plan["update"])

    def test_empty_zone_is_reported_for_safe_resume_only(self) -> None:
        plan = self.plan(
            [
                {
                    "name": self.ZONE,
                    "type": "SOA",
                    "ttl": 900,
                    "rData": {"primaryNameServer": "ns1.example"},
                }
            ]
        )
        self.assertEqual(plan["state"], "empty")
        self.assertEqual(plan["errors"], [])


class DigParsingTests(unittest.TestCase):
    """Sol finding 7: prove AA and recursion from the actual dig response."""

    AA_A = """
; <<>> DiG 9.18 <<>> +noall +answer +comments @127.0.0.1 ca.microlab.hnh A
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1234
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; ANSWER SECTION:
ca.microlab.hnh. 300 IN A 192.0.2.10
"""

    NO_AA = """
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1234
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; ANSWER SECTION:
example.com. 60 IN A 93.184.216.34
"""

    REFUSED = """
;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 1234
;; flags: qr rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
"""

    TIMEOUT = ";; communications error to 192.0.2.1#53: timed out\n"

    def test_aa_and_answer_value(self) -> None:
        self.assertEqual(dns.dns_status(self.AA_A), "NOERROR")
        self.assertTrue(dns.dns_has_aa(self.AA_A))
        self.assertIn("192.0.2.10", dns.dns_answer_values(self.AA_A))
        self.assertFalse(dns.dns_has_aa(self.NO_AA))

    def test_refused_and_timeout_are_distinct(self) -> None:
        self.assertEqual(dns.dns_status(self.REFUSED), "REFUSED")
        self.assertFalse(dns.dns_has_aa(self.REFUSED))
        self.assertEqual(dns.dns_status(self.TIMEOUT), "")
        self.assertTrue(dns.dns_no_reply(9, self.TIMEOUT))
        self.assertFalse(dns.dns_no_reply(0, self.REFUSED))

    def test_bind_failure_is_not_a_firewall_drop(self) -> None:
        bind_failure = (
            ";; couldn't get address for '203.0.113.5': "
            "bind: Cannot assign requested address\n"
        )
        self.assertFalse(dns.dns_no_reply(9, bind_failure))

    def test_soa_mname(self) -> None:
        output = """
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; ANSWER SECTION:
hnh. 3600 IN SOA ns1.microlab.hnh. hostmaster.microlab.hnh. 1 3600 600 86400 300
"""
        self.assertEqual(dns.dns_soa_mname(output), "ns1.microlab.hnh")
        self.assertTrue(dns.dns_has_aa(output))


class DnsWiringTests(unittest.TestCase):
    """Static checks for the remaining Sol findings."""

    def test_no_unconditional_changed_when_in_dns_role(self) -> None:
        for task_file in sorted((DNS_ROLE / "tasks").glob("*.yml")):
            with self.subTest(task_file=task_file):
                self.assertNotIn(
                    "changed_when: true",
                    task_file.read_text(),
                    f"{task_file} still claims changed unconditionally",
                )

    def test_every_api_post_redacts_output(self) -> None:
        for task_file in sorted((DNS_ROLE / "tasks").glob("*.yml")):
            text = task_file.read_text()
            for block in re.split(r"(?m)^- name:", text):
                if "method: POST" not in block:
                    continue
                with self.subTest(task_file=task_file, task=block.splitlines()[0] if block.splitlines() else ""):
                    self.assertIn("no_log: true", block)

    def test_health_asserts_aa_and_local_fixture_recursion(self) -> None:
        text = (DNS_ROLE / "tasks/health.yml").read_text()
        self.assertIn("micolab_dns_has_aa", text)
        self.assertIn("micolab_dns_status", text)
        self.assertIn("micolab_dns_soa_mname", text)
        self.assertIn("micolab_dns_fixture_name", text)
        self.assertIn("micolab_dns_fixture_expected_ip", text)
        self.assertIn("local-recursion-fixture-noerror", text)
        self.assertIn("micolab_dns_local_gates", text)
        self.assertNotIn("example.com", text)
        # SERVFAIL must not be accepted as offline recursion success.
        fixture_probe = text.split("Probe the controlled local recursion fixture", 1)[1]
        fixture_probe = fixture_probe.split("Probe an optional connected public name", 1)[0]
        self.assertNotIn("SERVFAIL", fixture_probe.replace("SERVFAIL is not accepted", ""))

    def test_acceptance_records_fixture_identity_and_results(self) -> None:
        text = (DNS_ROLE / "tasks/resolver.yml").read_text()
        self.assertIn("'local_gates': micolab_dns_local_gates", text)
        self.assertIn("'local_recursion_status'", text)
        self.assertIn("'local_recursion_fixture': micolab_dns_local_recursion_fixture", text)
        self.assertIn("'fixture_upstream_verified'", text)
        self.assertIn("'public_recursion_check'", text)
        self.assertIn("'external_gates': micolab_dns_external_gates", text)
        self.assertIn("'unexecuted_gates': micolab_dns_unexecuted_gates", text)
        self.assertIn("'external_acl_override'", text)

    def test_remote_probes_use_three_explicit_classes_and_same_fixture(self) -> None:
        text = (DNS_ROLE / "tasks/remote_probes.yml").read_text()
        for access in ("recursion-allowed", "recursion-denied", "firewall-denied"):
            self.assertIn(access, text)
        self.assertIn("micolab_dns_authoritative_only_cidrs", text)
        self.assertIn("micolab_dns_firewall_dns_cidrs", text)
        self.assertIn("micolab_dns_fixture_name", text)
        self.assertIn("micolab_dns_fixture_expected_ip", text)
        self.assertNotIn("example.com", text)

    def test_fixture_is_validated_before_settings_and_zone_mutation(self) -> None:
        text = (DNS_ROLE / "tasks/main.yml").read_text()
        fixture_at = text.index("Include the controlled offline recursion fixture upstream")
        settings_at = text.index("Include settings convergence")
        zone_at = text.index("Include authoritative zone convergence")
        fixture_zone_at = text.index("conditional-forwarder zone for the recursion fixture")
        self.assertLess(fixture_at, settings_at)
        self.assertLess(settings_at, zone_at)
        self.assertLess(zone_at, fixture_zone_at)

    def test_fixture_forwarder_zone_is_not_authoritative(self) -> None:
        text = (DNS_ROLE / "tasks/fixture_zone.yml").read_text()
        self.assertIn("type: Forwarder", text)
        self.assertIn("initializeForwarder", text)
        self.assertIn("forwarder: \"{{ micolab_dns_fixture_upstream }}\"", text)
        self.assertNotIn("type: Primary", text)

    def test_fixture_forwarder_zone_mirrors_recursion_acl_for_refused(self) -> None:
        # Technitium handles FWD in the authoritative path, so the zone needs
        # the same allow ACL to produce a real REFUSED for denied clients.
        text = (DNS_ROLE / "tasks/fixture_zone.yml").read_text()
        self.assertIn("queryAccess: UseSpecifiedNetworkACL", text)
        self.assertIn(
            "queryAccessNetworkACL: \"{{ micolab_dns_required_recursion_acl | join(',') }}\"",
            text,
        )
        self.assertIn("== micolab_dns_required_recursion_acl", text)
        self.assertIn("zones/options/get", text)

    def test_fixture_ownership_is_read_and_gated_before_any_fwd_mutation(self) -> None:
        text = (DNS_ROLE / "tasks/fixture_zone.yml").read_text()
        read_at = text.index("Read every record in the recursion fixture forwarder zone")
        plan_at = text.index("Plan only the owned fixture forwarder record")
        refuse_at = text.index("Refuse unowned or conflicting fixture forwarder records")
        update_at = text.index("Converge only the owned fixture FWD record")
        add_at = text.index("Add the owned fixture FWD record")
        acl_at = text.index("Read the fixture forwarder zone options")
        self.assertLess(read_at, plan_at)
        self.assertLess(plan_at, refuse_at)
        self.assertLess(refuse_at, update_at)
        self.assertLess(read_at, add_at)
        self.assertLess(refuse_at, acl_at)
        self.assertIn("micolab_fixture_forwarder_plan", text)
        self.assertIn("micolab_dns_fixture_zone_marker", text)
        self.assertIn("initializeForwarder: \"false\"", text)
        self.assertNotIn("initializeForwarder: \"true\"", text)
        self.assertIn("micolab_dns_fixture_zone_state_path", text)
        self.assertIn("micolab_dns_fixture_upstream_verified", text)
        self.assertIn("comments: \"{{ micolab_dns_fixture_zone_marker }}\"", text)

    def test_fixture_upstream_script_copy_notifies_restart_before_gates(self) -> None:
        text = (DNS_ROLE / "tasks/fixture_upstream.yml").read_text()
        copy_at = text.index("Install the offline recursion fixture responder")
        flush_at = text.index("Apply a fixture unit change before validating it")
        active_at = text.index("Confirm the fixture service is active")
        copy_block = text[copy_at:text.index("- name:", copy_at + 1)]
        self.assertIn(
            "notify: Restart the MicroLab offline recursion fixture", copy_block
        )
        self.assertLess(copy_at, flush_at)
        self.assertLess(flush_at, active_at)
        handlers = (DNS_ROLE / "handlers/main.yml").read_text()
        self.assertIn("Restart the MicroLab offline recursion fixture", handlers)

    def test_fixture_service_is_isolated_loopback_only(self) -> None:
        template = (DNS_ROLE / "templates/microlab-dns-fixture.service.j2").read_text()
        self.assertIn("--listen {{ micolab_dns_fixture_listen_address }}", template)
        self.assertIn("RestrictAddressFamilies=AF_INET", template)
        self.assertIn("DynamicUser=yes", template)
        self.assertNotIn("0.0.0.0", template)
        upstream = (DNS_ROLE / "tasks/fixture_upstream.yml").read_text()
        self.assertIn("No Technitium setting, zone, record, or", upstream)
        self.assertIn("micolab_dns_health_retries", upstream)

    def test_settings_deny_authoritative_only_before_and_after_readback(self) -> None:
        text = (DNS_ROLE / "tasks/settings.yml").read_text()
        self.assertGreaterEqual(text.count("micolab_acl_deny_conflicts"), 2)
        self.assertIn("micolab_dns_recursion_deny_conflicts", text)
        self.assertIn("micolab_dns_verified_recursion_deny_conflicts", text)
        self.assertIn("existing broad allow", text)
        self.assertIn("will not delete", text)

    def test_settings_trusts_exactly_the_caddy_ipv4_proxy_and_real_ip_header(self) -> None:
        text = (DNS_ROLE / "tasks/settings.yml").read_text()
        self.assertIn(
            'webServiceReverseProxyAddresses: "{{ micolab_dns_admin_reverse_proxy_address }}"',
            text,
        )
        self.assertIn(
            'webServiceRealIpHeader: "{{ micolab_dns_admin_real_ip_header }}"',
            text,
        )
        self.assertIn(
            "micolab_dns_verified_reverse_proxies\n        == [micolab_dns_admin_reverse_proxy_address | micolab_canonical_cidr]",
            text,
        )
        group_vars = (ROOT / "group_vars/all.yml").read_text()
        self.assertIn('micolab_dns_admin_reverse_proxy_address: "127.0.0.1"', group_vars)
        self.assertIn('micolab_dns_admin_real_ip_header: "X-Real-IP"', group_vars)
        self.assertNotIn('webServiceReverseProxyAddresses: "::1"', text)
        # Proxy trust is replaced, never merged with arbitrary current entries.
        self.assertNotIn("webServiceReverseProxyAddresses | micolab_acl_merge", text)
        self.assertNotIn("micolab_dns_admin_reverse_proxy_address | micolab_acl_merge", text)

        main = (DNS_ROLE / "tasks/main.yml").read_text()
        self.assertIn("micolab_dns_post_restart_reverse_proxies", main)
        self.assertIn("micolab_dns_post_restart_real_ip_header", main)
        self.assertIn("micolab_dns_post_restart_recursion_deny_conflicts", main)
        self.assertIn("micolab_caddy_admin_upstream_host", main)
        self.assertIn("micolab_dns_admin_real_ip_header | lower == 'x-real-ip'", main)

    def test_docs_describe_ca_and_dns_first_pass_with_deferred_doh(self) -> None:
        docs = (ROOT / "docs/dns.md").read_text()
        self.assertIn("both the CA and DNS vhosts rendered", docs)
        self.assertIn("6b.", docs)
        self.assertIn("deferred", docs)
        self.assertLess(docs.index("6b."), docs.index("7. `forgejo`"))

    def test_validator_defaults_match_the_real_group_names(self) -> None:
        payload = json.dumps(
            {"groups": ["micolab_management", "microlab_challenge"]}
        )
        result = subprocess.run(
            [sys.executable, str(VALIDATOR), "-"],
            input=payload,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertIn(
            "must not be a member of 'microlab_challenge'", result.stderr
        )

        management_only = subprocess.run(
            [sys.executable, str(VALIDATOR), "-"],
            input=json.dumps({"groups": []}),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertIn(
            "must be a member of 'micolab_management'", management_only.stderr
        )

    def test_firewall_separates_dns_and_web_clients(self) -> None:
        template = (ROOT / "roles/baseline/templates/microlab-firewall.nft.j2").read_text()
        self.assertIn("micolab_dns_authoritative_only_cidrs", template)
        self.assertIn("set web_clients4", template)
        self.assertIn("@web_clients4 tcp dport { 80, 443 }", template)
        self.assertIn("@dns_clients4 udp dport", template)

    def test_settings_canonicalize_acl_and_reject_shadowing(self) -> None:
        text = (DNS_ROLE / "tasks/settings.yml").read_text()
        self.assertIn("micolab_acl_normalize", text)
        self.assertIn("micolab_acl_merge", text)
        self.assertIn("micolab_acl_unallowed", text)
        self.assertIn("micolab_acl_conflicts", text)
        self.assertIn("reject('equalto', '')", text)

    def test_record_plan_uses_bracket_access_for_update_key(self) -> None:
        text = (DNS_ROLE / "tasks/records.yml").read_text()
        # `plan.update` resolves to the dict method in Jinja/Ansible and fails
        # at runtime; the plan keys must use bracket access.
        self.assertIn("micolab_dns_record_plan['update']", text)
        self.assertIn("micolab_dns_record_plan['add']", text)
        self.assertIn("micolab_dns_record_plan['delete']", text)
        self.assertNotIn("micolab_dns_record_plan.update", text)

    def test_group_vars_and_docs_describe_authoritative_only_and_fixture(self) -> None:
        group_vars = (ROOT / "group_vars/all.yml").read_text()
        docs = (ROOT / "docs/dns.md").read_text()
        self.assertIn("micolab_dns_authoritative_only_cidrs", group_vars)
        self.assertIn("micolab_dns_authoritative_only_cidrs", docs)
        self.assertIn("firewall-denied", docs)
        self.assertIn("recursion-denied", docs)
        for name in (
            "micolab_dns_fixture_upstream",
            "micolab_dns_fixture_zone",
            "micolab_dns_fixture_name",
            "micolab_dns_fixture_expected_ip",
        ):
            self.assertIn(name, group_vars)
            self.assertIn(name, docs)
        self.assertIn("micolab_dns_admin_reverse_proxy_address", group_vars)
        self.assertIn("micolab_dns_admin_real_ip_header", group_vars)

    def test_baseline_validator_rejects_overlapping_authoritative_only(self) -> None:
        text = (ROOT / "roles/baseline/files/microlab_validate.py").read_text()
        self.assertIn("authoritative_only_cidrs", text)
        self.assertIn("must not overlap", text)

    def test_baseline_validator_requires_the_offline_fixture(self) -> None:
        text = (ROOT / "roles/baseline/files/microlab_validate.py").read_text()
        for name in (
            "micolab_dns_fixture_upstream",
            "micolab_dns_fixture_zone",
            "micolab_dns_fixture_name",
            "micolab_dns_fixture_expected_ip",
        ):
            self.assertIn(name, text)
        baseline_tasks = (ROOT / "roles/baseline/tasks/main.yml").read_text()
        self.assertIn("dns_fixture_upstream", baseline_tasks)
        self.assertIn("dns_fixture_listen_endpoint", baseline_tasks)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Fail closed unless the active inet input chain drops non-lo HTTP DoH early.

This observes the managed table only. It does not prove external reachability,
other network namespaces, or a packet's path through an upstream router.
"""
import json
import sys


def contained(document, table):
    entries = document.get("nftables", [])
    chains = [e["chain"] for e in entries if "chain" in e]
    if not any(c.get("family") == "inet" and c.get("table") == table
               and c.get("name") == "input" and c.get("hook") == "input"
               and c.get("policy") == "drop" for c in chains):
        return False
    required = [
        {"match": {"op": "!=", "left": {"meta": {"key": "iifname"}}, "right": "lo"}},
        {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 8053}},
        {"drop": None},
    ]
    loopback = [
        {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "lo"}},
        {"accept": None},
    ]
    for entry in entries:
        rule = entry.get("rule", {})
        if (rule.get("family"), rule.get("table"), rule.get("chain")) != ("inet", table, "input"):
            continue
        expr = [e for e in rule.get("expr", []) if "counter" not in e]
        if expr == required:
            return True
        # Reject any earlier rule except the known loopback-only accept.
        # This intentionally fails on unexpected rules rather than approximating
        # nftables semantics (jumps, sets, maps, verdicts or NAT).
        if expr != loopback:
            return False
    return False


if __name__ == "__main__":
    if len(sys.argv) != 2 or not contained(json.load(sys.stdin), sys.argv[1]):
        sys.exit("Missing early non-loopback 8053 drop in the active inet input chain")
    print("Active inet firewall drops non-loopback TCP/8053 before other ingress rules")

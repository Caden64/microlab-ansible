"""Network classification helpers for the verify role's external ACL probes.

The verify role must not accept a probe whose source address belongs to a
different policy class than the one it claims.  For DoT in particular:

* an ``allowed`` probe has to run from a network that is both firewall-admitted
  for 853/tcp and present in Technitium's recursion ACL;
* a ``denied`` probe has to run from a firewall-admitted network that is
  deliberately excluded from the recursion ACL
  (``micolab_dns_authoritative_only_cidrs``), so a positive DNS REFUSED is
  evidence of the recursion policy rather than of a firewall drop.

This module is dependency-free and deliberately separate from the
technitium_dns filter plugin so the verify role can run on its own.
"""

from __future__ import annotations

from ipaddress import ip_address, ip_network
from typing import Any, Mapping


def _text(value: object) -> str:
    return "" if value is None else str(value).strip()


def _entries(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return [_text(item) for item in value if _text(item)]  # type: ignore[union-attr]


def ip_in_networks(value: object, networks: object) -> bool:
    """Return True when an address is inside any supplied CIDR."""
    try:
        address = ip_address(_text(value))
    except ValueError:
        return False
    for entry in _entries(networks):
        raw = entry[1:].strip() if entry.startswith("!") else entry
        try:
            network = ip_network(raw, strict=False)
        except ValueError:
            continue
        if address.version == network.version and address in network:
            return True
    return False


def source_class(
    source: object,
    firewall_admitted: object,
    recursion_allowed: object,
    authoritative_only: object,
) -> str:
    """Classify a probe source address for test diagnostics.

    ``firewall-denied`` means the source cannot reach the DNS listener at all,
    so a timeout is expected and cannot prove the recursion ACL.
    """
    if not ip_in_networks(source, firewall_admitted):
        return "firewall-denied"
    if ip_in_networks(source, recursion_allowed):
        return "recursion-allowed"
    if ip_in_networks(source, authoritative_only):
        return "recursion-denied"
    return "firewall-admitted-unclassified"


def probe_classification_errors(
    probes: object,
    firewall_admitted: object,
    recursion_allowed: object,
    authoritative_only: object,
) -> list[str]:
    """Return errors for DoT probes whose source class is not what they claim.

    Non-DoT probes are not checked here: their denial evidence is an HTTP
    status (DoH/admin/CA), not a DNS recursion policy.  Every DoT probe must
    still declare ``source_address`` and ``access`` so the classification is
    explicit rather than assumed from the delegated host's default route.
    """
    errors: list[str] = []
    for index, probe in enumerate(probes or []):  # type: ignore[union-attr]
        if not isinstance(probe, Mapping):
            errors.append(f"probe[{index}] must be a mapping")
            continue
        if _text(probe.get("check")) != "dot":
            continue
        label = (
            _text(probe.get("name"))
            or _text(probe.get("host"))
            or f"probe[{index}]"
        )
        expect = _text(probe.get("expect"))
        access = _text(probe.get("access"))
        source = probe.get("source_address")
        if not _text(source):
            errors.append(
                f"{label}: DoT probe must declare source_address so its "
                "firewall and recursion class is known"
            )
            continue
        if not ip_in_networks(source, firewall_admitted):
            errors.append(
                f"{label}: DoT source {source!r} is outside the "
                "firewall-admitted DNS networks; a timeout from it cannot "
                "prove an ACL"
            )
        if expect == "allowed":
            if access != "recursion-allowed":
                errors.append(
                    f"{label}: allowed DoT probe declares access {access!r}; "
                    "it must be recursion-allowed"
                )
            if not ip_in_networks(source, recursion_allowed):
                errors.append(
                    f"{label}: allowed DoT source {source!r} is not in the "
                    "recursion-allowed networks"
                )
            if ip_in_networks(source, authoritative_only):
                errors.append(
                    f"{label}: allowed DoT source {source!r} is also in "
                    "micolab_dns_authoritative_only_cidrs; it would receive "
                    "REFUSED instead of an answer"
                )
        elif expect == "denied":
            if access != "recursion-denied":
                errors.append(
                    f"{label}: denied DoT probe declares access {access!r}; "
                    "it must be recursion-denied"
                )
            if not ip_in_networks(source, authoritative_only):
                errors.append(
                    f"{label}: denied DoT source {source!r} is not in "
                    "micolab_dns_authoritative_only_cidrs"
                )
            if ip_in_networks(source, recursion_allowed):
                errors.append(
                    f"{label}: denied DoT source {source!r} is also in the "
                    "recursion-allowed networks; it cannot prove REFUSED"
                )
        else:
            errors.append(
                f"{label}: DoT probe expectation {expect!r} is not "
                "allowed or denied"
            )
    return errors


class FilterModule:
    def filters(self) -> dict[str, Any]:
        return {
            "micolab_verify_ip_in_networks": ip_in_networks,
            "micolab_verify_source_class": source_class,
            "micolab_verify_probe_classification_errors": (
                probe_classification_errors
            ),
        }

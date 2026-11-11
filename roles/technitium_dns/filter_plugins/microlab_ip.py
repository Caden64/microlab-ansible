"""Dependency-free IP, ACL, record, and dig helpers for idempotence.

The functions here are deliberately pure so they can be unit-tested without a
Technitium instance.  They mirror the parts of TechnitiumLibrary that matter to
this role:

* ``NetworkAddress`` masks host bits, prints IPv4 ``/32`` and IPv6 ``/128``
  without a prefix, and prints IPv6 in compressed form.
* ``NetworkAccessControl`` parses a leading ``!`` as a deny marker and uses
  first-match-wins semantics.
* Zone records expose their value under ``rData.ipAddress`` (A/AAAA) or
  ``rData.nameServer`` (NS).

Keeping these rules in one place prevents the task files from comparing raw
inventory strings with API-normalised strings.
"""

from __future__ import annotations

import re
from ipaddress import ip_address, ip_network
from typing import Any, Iterable, Mapping

MANAGED_RECORD_TYPES = ("A", "AAAA", "NS")
_MANAGED_COMMENT = "micolab-managed"
_STATUS_RE = re.compile(r"status:\s*([A-Z]+)", re.IGNORECASE)


def _text(value: object) -> str:
    return "" if value is None else str(value).strip()


def canonical_ip(value: object) -> str:
    """Return the canonical text form of an IPv4/IPv6 address.

    Inventory authors may write an expanded IPv6 address while Technitium
    returns the compressed form.  Without canonicalization an otherwise
    identical record would be deleted and re-added on every run.
    """
    try:
        return str(ip_address(_text(value)))
    except ValueError:
        return _text(value)


def canonical_cidr(value: object) -> str:
    """Canonicalise one ACL entry exactly as Technitium prints it.

    ``NetworkAddress.ToString()`` omits ``/32`` and ``/128`` and
    ``IPAddress.ToString()`` compresses IPv6.  Host bits are masked because
    ``NetworkAddress`` stores the network address.  A leading ``!`` is a deny
    marker and is preserved.
    """
    raw = _text(value)
    deny = raw.startswith("!")
    if deny:
        raw = raw[1:].strip()
    if not raw:
        raise ValueError("empty network ACL entry")
    try:
        net = ip_network(raw, strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid network ACL entry {value!r}: {exc}") from exc

    if net.version == 4 and net.prefixlen == 32:
        text = str(net.network_address)
    elif net.version == 6 and net.prefixlen == 128:
        text = str(net.network_address)
    else:
        text = str(net)
    return ("!" if deny else "") + text


def _acl_entries(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        values: Iterable[object] = value.split(",")
    else:
        values = value  # type: ignore[assignment]
    return [_text(item) for item in values if _text(item)]


def normalize_acl(value: object) -> list[str]:
    """Canonicalise, strip blanks, and de-duplicate without reordering."""
    result: list[str] = []
    seen: set[str] = set()
    for entry in _acl_entries(value):
        canonical = canonical_cidr(entry)
        if canonical not in seen:
            seen.add(canonical)
            result.append(canonical)
    return result


def _acl_network(entry: str):
    deny = entry.startswith("!")
    raw = entry[1:].strip() if deny else entry
    return deny, ip_network(raw, strict=False)


def acl_conflicts(entries: object) -> list[str]:
    """Return order-dependent ACL conflicts.

    Technitium evaluates the ACL first-match-wins.  A later entry with the
    opposite polarity that is contained by an earlier entry can never take
    effect.  Reporting this is important because silently appending a desired
    allow behind a broad deny (or vice versa) would make the role claim a
    policy it did not actually install.
    """
    normalized = normalize_acl(entries)
    conflicts: list[str] = []
    for index, earlier in enumerate(normalized):
        deny_earlier, net_earlier = _acl_network(earlier)
        for later in normalized[index + 1 :]:
            deny_later, net_later = _acl_network(later)
            if deny_earlier == deny_later:
                continue
            if net_later.version != net_earlier.version:
                continue
            if net_later.subnet_of(net_earlier):
                conflicts.append(
                    f"{earlier} precedes {later}; first-match order shadows {later}"
                )
    return conflicts


def merge_acl(current: object, desired: object) -> dict[str, Any]:
    """Merge desired entries behind current entries without reordering.

    Current entries are preserved exactly in order.  Desired entries are
    appended only when their canonical form is not already present.  The
    result includes any first-match conflicts so the caller can fail closed
    instead of installing an ACL whose effective policy differs from the
    intent.
    """
    current_entries = normalize_acl(current)
    desired_entries = normalize_acl(desired)
    merged = list(current_entries)
    for entry in desired_entries:
        if entry not in merged:
            merged.append(entry)
    return {
        "entries": merged,
        "added": [entry for entry in desired_entries if entry not in current_entries],
        "conflicts": acl_conflicts(merged),
    }


def acl_network_allowed(entries: object, network: object) -> bool:
    """Return whether every address in ``network`` is allowed by first match."""
    try:
        target = ip_network(_text(network), strict=False)
    except ValueError:
        return False

    for entry in normalize_acl(entries):
        deny, net = _acl_network(entry)
        if net.version != target.version:
            continue
        if target.subnet_of(net):
            return not deny
        if net.subnet_of(target):
            # A narrower entry only covers part of the target.  A deny here
            # means part of the requested network is denied, so it cannot be
            # reported as fully allowed.  An allow here is not enough proof on
            # its own, so keep looking for a covering entry.
            if deny:
                return False
            continue
    return False


def acl_unallowed(required: object, entries: object) -> list[str]:
    """Return required networks that the ordered ACL does not allow."""
    return [
        entry
        for entry in _acl_entries(required)
        if not acl_network_allowed(entries, entry)
    ]


def acl_network_denied(entries: object, network: object) -> bool:
    """Return whether first-match ACL semantics deny every address in network.

    A network is only fully denied when the first entry that covers any part
    of it is either an explicit covering deny or there is no covering allow at
    all (the ACL default is deny).  A narrower allow inside the network means
    part of it is admitted, so the answer is False even if another covering
    deny appears later.
    """
    try:
        target = ip_network(_text(network), strict=False)
    except ValueError:
        return False

    for entry in normalize_acl(entries):
        deny, net = _acl_network(entry)
        if net.version != target.version:
            continue
        if target.subnet_of(net):
            return deny
        if net.subnet_of(target) and not deny:
            # An earlier allow covers part of the target.  A later covering
            # deny cannot undo that first-match decision for those addresses.
            return False
    return True


def acl_undennied(networks: object, entries: object) -> list[str]:
    """Return networks that are not effectively denied by the ordered ACL."""
    return [
        entry
        for entry in _acl_entries(networks)
        if not acl_network_denied(entries, entry)
    ]


def acl_deny_conflicts(entries: object, networks: object) -> list[str]:
    """Explain why an ordered ACL does not deny every requested network.

    The messages name the existing first-match allow entry so an operator can
    see the exact conflict.  This function never edits the ACL: broad or
    unknown current entries are preserved and the caller fails closed.
    """
    conflicts: list[str] = []
    normalized = normalize_acl(entries)
    for entry in _acl_entries(networks):
        try:
            target = ip_network(entry, strict=False)
        except ValueError:
            conflicts.append(f"{entry!r} is not a valid network")
            continue
        for acl_entry in normalized:
            deny, net = _acl_network(acl_entry)
            if net.version != target.version:
                continue
            if target.subnet_of(net):
                if not deny:
                    conflicts.append(
                        f"{entry} is allowed by first-match entry {acl_entry}"
                    )
                break
            if net.subnet_of(target) and not deny:
                conflicts.append(
                    f"{entry} is partly allowed by first-match entry {acl_entry}"
                )
                break
    return conflicts


def ip_in_networks(value: object, networks: object) -> bool:
    """Return True when an address is inside any supplied network."""
    try:
        address = ip_address(_text(value))
    except ValueError:
        return False
    for entry in _acl_entries(networks):
        raw = entry[1:].strip() if entry.startswith("!") else entry
        try:
            net = ip_network(raw, strict=False)
        except ValueError:
            continue
        if address.version == net.version and address in net:
            return True
    return False


def probe_classification_errors(
    probes: object,
    recursion_allowed: object,
    authoritative_only: object,
    firewall_dns: object,
) -> list[str]:
    """Return classification errors for remote acceptance probes.

    The source address must belong to the class the probe claims.  Without
    this check a "recursion-denied" probe could accidentally run from an
    admin/client address and prove the wrong policy.
    """
    errors: list[str] = []
    for index, probe in enumerate(probes or []):
        if not isinstance(probe, Mapping):
            errors.append(f"probe[{index}] must be a mapping")
            continue
        host = _text(probe.get("host")) or f"probe[{index}]"
        access = _text(probe.get("access"))
        source = probe.get("source_address")
        if access == "recursion-allowed":
            if not ip_in_networks(source, recursion_allowed):
                errors.append(
                    f"{host}: recursion-allowed source {source!r} is not in the recursion ACL"
                )
        elif access == "recursion-denied":
            if not ip_in_networks(source, authoritative_only):
                errors.append(
                    f"{host}: recursion-denied source {source!r} is not in "
                    "micolab_dns_authoritative_only_cidrs"
                )
            if ip_in_networks(source, recursion_allowed):
                errors.append(
                    f"{host}: recursion-denied source {source!r} is also in the recursion ACL"
                )
        elif access == "firewall-denied":
            if ip_in_networks(source, firewall_dns):
                errors.append(
                    f"{host}: firewall-denied source {source!r} is admitted by the firewall"
                )
        else:
            errors.append(f"{host}: unknown access class {access!r}")
    return errors


def record_value(record: Mapping[str, Any]) -> str:
    """Return the canonical RDATA value for a supported zone record."""
    rtype = _text(record.get("type")).upper()
    rdata = record.get("rData") or record.get("rdata") or {}
    if not isinstance(rdata, Mapping):
        rdata = {}

    if rtype in ("A", "AAAA"):
        return canonical_ip(rdata.get("ipAddress", record.get("value", "")))
    if rtype == "NS":
        raw = rdata.get("nameServer", record.get("value", ""))
    elif rtype == "CNAME":
        raw = rdata.get("cname", record.get("value", ""))
    elif rtype == "PTR":
        raw = rdata.get("ptrName", record.get("value", ""))
    else:
        raw = record.get("value", next(iter(rdata.values()), ""))
    return _text(raw).rstrip(".").lower()


def record_key(name: object, rtype: object, value: object) -> str:
    """Build the same identity string used by the desired record set."""
    record_type = _text(rtype).upper()
    if record_type in ("A", "AAAA"):
        canonical_value = canonical_ip(value)
    else:
        canonical_value = _text(value).rstrip(".").lower()
    return (
        f"{_text(name).rstrip('.').lower()}|{record_type}|{canonical_value}"
    )


def record_identity(
    record: Mapping[str, Any], managed_comment: str = _MANAGED_COMMENT
) -> dict[str, Any]:
    """Attach canonical identity and ownership fields to an API record."""
    identity = dict(record)
    record_type = _text(identity.get("type")).upper()
    rdata = identity.get("rData") or identity.get("rdata") or {}
    if not isinstance(rdata, Mapping):
        rdata = {}
    if record_type in ("A", "AAAA"):
        raw_value = _text(rdata.get("ipAddress", identity.get("value", "")))
    elif record_type == "NS":
        raw_value = _text(rdata.get("nameServer", identity.get("value", "")))
    else:
        raw_value = _text(identity.get("value", next(iter(rdata.values()), "")))
    value = record_value(identity)
    identity["micolab_type"] = record_type
    identity["micolab_value"] = value
    identity["micolab_raw_value"] = raw_value
    identity["micolab_key"] = record_key(identity.get("name", ""), record_type, value)
    identity["micolab_owned"] = _text(identity.get("comments")) == managed_comment
    return identity


def plan_records(
    desired: object,
    current: object,
    managed_comment: str = _MANAGED_COMMENT,
) -> dict[str, Any]:
    """Plan an idempotent record reconciliation from a complete desired set.

    The plan is computed against *all* desired identities at once.  That is the
    critical difference from a per-record loop: an RRset with several desired
    values never treats one desired value as stale while processing another.

    Ownership rules:

    * an exact record (owned or unowned) satisfies the desired identity;
    * an owned exact record is updated only for TTL/comment drift;
    * an unowned exact record is preserved and never claimed;
    * only owned A/AAAA/NS records whose complete identity is absent from the
      desired set are deleted.
    """
    desired_items: list[dict[str, Any]] = []
    for item in desired or []:
        record_type = _text(item.get("type")).upper()
        value = (
            canonical_ip(item.get("value"))
            if record_type in ("A", "AAAA")
            else _text(item.get("value")).rstrip(".").lower()
        )
        desired_item = dict(item)
        desired_item["type"] = record_type
        desired_item["value"] = value
        desired_item["key"] = record_key(
            desired_item.get("name", ""), record_type, value
        )
        desired_item["ttl"] = int(desired_item.get("ttl", 0) or 0)
        desired_items.append(desired_item)

    current_items = [
        record_identity(record, managed_comment) for record in (current or [])
    ]
    by_key: dict[str, list[dict[str, Any]]] = {}
    for record in current_items:
        by_key.setdefault(record["micolab_key"], []).append(record)

    desired_keys = {item["key"] for item in desired_items}
    add: list[dict[str, Any]] = []
    update: list[dict[str, Any]] = []
    preserve: list[dict[str, Any]] = []
    preserved_ids: set[int] = set()

    for item in desired_items:
        matches = by_key.get(item["key"], [])
        if not matches:
            add.append(item)
            continue
        owned = [record for record in matches if record["micolab_owned"]]
        if not owned:
            preserve.extend(matches)
            preserved_ids.update(id(record) for record in matches)
            continue
        for record in owned:
            current_ttl = int(record.get("ttl", 0) or 0)
            current_comment = _text(record.get("comments"))
            if current_ttl != item["ttl"] or current_comment != managed_comment:
                update.append({"desired": item, "current": record})

    delete = [
        record
        for record in current_items
        if record["micolab_owned"]
        and record["micolab_type"] in MANAGED_RECORD_TYPES
        and record["micolab_key"] not in desired_keys
    ]

    # Report every unowned record that will be left in place, including
    # unknown types and unowned values that are not part of the desired set.
    for record in current_items:
        if not record["micolab_owned"] and id(record) not in preserved_ids:
            preserve.append(record)
            preserved_ids.add(id(record))

    return {
        "add": add,
        "update": update,
        "delete": delete,
        "preserve": preserve,
        "pending": len(add) + len(update) + len(delete),
        "desired": desired_items,
        "current": current_items,
    }


FIXTURE_FORWARDER_MARKER = "micolab-managed:fixture-forwarder"


def _comment_has_marker(comments: object, marker: str) -> bool:
    """Return True when a comment line is exactly the ownership marker."""
    wanted = _text(marker)
    if not wanted:
        return False
    return any(line.strip() == wanted for line in _text(comments).splitlines())


def fixture_forwarder_plan(
    records: object,
    zone: object,
    marker: str = FIXTURE_FORWARDER_MARKER,
    upstream: object = "",
) -> dict[str, Any]:
    """Plan the one owned Conditional Forwarder FWD record for the fixture.

    The fixture zone is only considered owned when its apex FWD record carries
    the exact marker comment.  The caller must read every record in the zone
    before calling this function and must not mutate anything when ``errors``
    is non-empty.

    * an owned FWD to a different upstream is updated in place;
    * an owned FWD to the configured upstream is left alone;
    * an unowned FWD, several owned FWDs, or a non-UDP/DNSSEC-validating
      owned FWD is a conflict and fails closed (nothing is replaced);
    * a zone with no FWD is reported as ``empty`` so the caller can resume a
      crash only when its exact creation marker proves ownership.
    """
    zone_name = _text(zone).rstrip(".").lower()
    wanted_marker = _text(marker)
    wanted_upstream = _text(upstream)
    fwd_records = [
        dict(record)
        for record in (records or [])
        if _text(record.get("type")).upper() == "FWD"
    ]
    owned = [
        record
        for record in fwd_records
        if _comment_has_marker(record.get("comments"), wanted_marker)
    ]
    unknown = [
        record
        for record in fwd_records
        if not _comment_has_marker(record.get("comments"), wanted_marker)
    ]

    errors: list[str] = []
    if len(owned) > 1:
        errors.append(
            f"{len(owned)} FWD records carry the fixture ownership marker; "
            "the fixture supports exactly one owned forwarder"
        )
    if unknown:
        described = []
        for record in unknown:
            rdata = record.get("rData") or {}
            if not isinstance(rdata, Mapping):
                rdata = {}
            described.append(
                f"{record.get('name', '')}->{rdata.get('forwarder', '')}"
            )
        errors.append(
            "unowned FWD record(s) exist in the fixture zone: "
            + ", ".join(described)
            + "; refusing to add, replace, or forward alongside a resource "
            "this role does not own"
        )

    state = "conflict" if errors else ("owned" if owned else "empty")
    update: dict[str, Any] | None = None

    if owned and not errors:
        record = owned[0]
        rdata = record.get("rData") or {}
        if not isinstance(rdata, Mapping):
            rdata = {}
        name = _text(record.get("name")).rstrip(".").lower()
        forwarder = _text(rdata.get("forwarder"))
        protocol = _text(rdata.get("protocol") or "Udp")
        dnssec_validation = bool(rdata.get("dnssecValidation", False))
        priority = int(rdata.get("priority", 0) or 0)

        if name != zone_name:
            errors.append(
                f"owned FWD record name {name!r} is not the fixture apex "
                f"{zone_name!r}"
            )
        if protocol.lower() != "udp":
            errors.append(
                f"owned FWD protocol {protocol!r} is not Udp; the local "
                "fixture only serves UDP"
            )
        if dnssec_validation:
            errors.append(
                "owned FWD has DNSSEC validation enabled; the local unsigned "
                "fixture cannot satisfy it"
            )
        if not forwarder:
            errors.append("owned FWD record has an empty forwarder")
        if bool(record.get("disabled", False)):
            errors.append("owned FWD record is disabled")

        if errors:
            state = "conflict"
        elif forwarder == wanted_upstream:
            state = "owned-current"
        else:
            state = "owned-update"
            update = {
                "domain": zone_name,
                "zone": zone_name,
                "type": "FWD",
                "ttl": str(int(record.get("ttl", 0) or 0)),
                "forwarder": forwarder,
                "newForwarder": wanted_upstream,
                "protocol": protocol,
                "newProtocol": protocol,
                "dnssecValidation": "true" if dnssec_validation else "false",
                "forwarderPriority": str(priority),
                "disable": "true" if bool(record.get("disabled", False)) else "false",
                # Preserve the complete current comment, including any human
                # note alongside the ownership marker.
                "comments": _text(record.get("comments")),
            }
            proxy_type = _text(rdata.get("proxyType"))
            if proxy_type:
                update["proxyType"] = proxy_type
                if proxy_type.lower() in ("http", "socks5"):
                    update["proxyAddress"] = _text(rdata.get("proxyAddress"))
                    update["proxyPort"] = str(int(rdata.get("proxyPort", 0) or 0))
                    update["proxyUsername"] = _text(rdata.get("proxyUsername"))
                    update["proxyPassword"] = _text(rdata.get("proxyPassword"))

    return {
        "state": state,
        "errors": errors,
        "owned": owned,
        "unknown": unknown,
        "records": fwd_records,
        "update": update,
        "zone": zone_name,
        "upstream": wanted_upstream,
        "marker": wanted_marker,
    }


def dns_status(output: object) -> str:
    """Extract the DNS RCODE from a dig header, or an empty string."""
    match = _STATUS_RE.search(_text(output))
    return match.group(1).upper() if match else ""


def dns_has_aa(output: object) -> bool:
    """Return True when a dig response has the authoritative-answer flag."""
    for line in _text(output).splitlines():
        if line.strip().lower().startswith(";; flags:"):
            flags = line.split("flags:", 1)[1].split(";", 1)[0].split()
            return "aa" in {flag.lower() for flag in flags}
    return False


def dns_answer_values(output: object) -> list[str]:
    """Return canonical RDATA tokens from dig's ANSWER section.

    The caller uses ``+noall +answer +comments`` so the same response proves
    the RCODE, the AA flag, and the answer value.
    """
    values: list[str] = []
    for line in _text(output).splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(";"):
            continue
        parts = stripped.split()
        if len(parts) < 5:
            continue
        raw = parts[-1]
        canonical = canonical_ip(raw)
        values.append((canonical if canonical else raw).rstrip(".").lower())
    return values


def dns_soa_mname(output: object) -> str:
    """Return the MNAME from the first SOA answer line, lower-case, no dot."""
    for line in _text(output).splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(";"):
            continue
        parts = stripped.split()
        for index, part in enumerate(parts):
            if index >= 3 and part.upper() == "SOA" and index + 1 < len(parts):
                return parts[index + 1].rstrip(".").lower()
    return ""


def dns_no_reply(rc: object, output: object) -> bool:
    """Return True for a firewall-style drop (non-zero dig rc, no RCODE).

    A source-bind failure is not evidence that the firewall dropped the
    packet, so it is rejected explicitly.
    """
    try:
        failed = int(rc) != 0
    except (TypeError, ValueError):
        return False
    if not failed or dns_status(output):
        return False
    lowered = _text(output).lower()
    for marker in (
        "bind:",
        "couldn't get address",
        "cannot assign requested address",
        "network is unreachable",
        "no route to host",
    ):
        if marker in lowered:
            return False
    return True


class FilterModule:
    def filters(self):
        return {
            "micolab_canonical_ip": canonical_ip,
            "micolab_canonical_cidr": canonical_cidr,
            "micolab_acl_normalize": normalize_acl,
            "micolab_acl_conflicts": acl_conflicts,
            "micolab_acl_merge": merge_acl,
            "micolab_acl_network_allowed": acl_network_allowed,
            "micolab_acl_unallowed": acl_unallowed,
            "micolab_acl_network_denied": acl_network_denied,
            "micolab_acl_undennied": acl_undennied,
            "micolab_acl_deny_conflicts": acl_deny_conflicts,
            "micolab_ip_in_networks": ip_in_networks,
            "micolab_probe_classification_errors": probe_classification_errors,
            "micolab_record_value": record_value,
            "micolab_record_key": record_key,
            "micolab_record_identity": record_identity,
            "micolab_record_plan": plan_records,
            "micolab_fixture_forwarder_plan": fixture_forwarder_plan,
            "micolab_dns_status": dns_status,
            "micolab_dns_has_aa": dns_has_aa,
            "micolab_dns_answer_values": dns_answer_values,
            "micolab_dns_soa_mname": dns_soa_mname,
            "micolab_dns_no_reply": dns_no_reply,
        }

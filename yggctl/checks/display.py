"""checks.display"""

"""Fail-closed structured health checks, including PID-bound underlay proof."""

from pathlib import Path
import ipaddress
import math
import json
import re
import stat
import errno
import os
import time
import urllib.parse

from core import (
    Failure,
    NODE,
    STACK,
    TIMER,
    KEYS,
    read_regular,
    logged,
    event,
    digest,
    safe_config,
    endpoint,
    peer_uri,
)

# The collector runs once a minute and retains 10,000 samples (about a week), so a
# frozen file keeps serving history long after collection stopped. 72 h is the longest
# report window, PEER_DOWN_MINUTES is 10; 15 minutes tolerates a short collector outage
# while still failing a file that a stopped or never-triggered collector left behind.
# There is no runtime override: this project fixes paths, units and thresholds in code
# and deliberately reads no environment variables.

@logged
def runtime_display(data):
    """Normalize ONLY the unordered trailing rich-rule display, never nft order.

    All zone fields and every rule byte stay significant. This is not a policy
    parser: unsupported formatting, duplicates or control bytes fail closed.
    """
    marker = b"  rich rules: \n"
    if (
        not isinstance(data, bytes)
        or len(data) > 65536
        or not data.endswith(b"\n")
        or data.count(marker) != 1
        or any(c < 32 and c not in (9, 10) for c in data)
        or b"\x7f" in data
    ):
        raise Failure("invalid_runtime_display")
    prefix, tail = data.split(marker)
    rules = tail.splitlines(keepends=True)
    if (
        len(rules) > 256
        or len(rules) != len(set(rules))
        or any(
            not r.startswith(b"\trule ") or not r.endswith(b"\n") or b"\t" in r[1:] for r in rules
        )
    ):
        raise Failure("invalid_runtime_rich_rules")
    return prefix + marker + b"".join(sorted(rules))

@logged
def quic_relay(data):
    """Only the connected local daemon's supported IPv4/UDP443 QUIC endpoint."""
    if not isinstance(data, bytes) or len(data) > 65536:
        raise Failure("invalid_mullvad_status")
    try:
        status = json.loads(data)
        tunnel = status["details"]["endpoint"]
        obfuscation = tunnel["obfuscation"]
        single = obfuscation["Single"]
        relay = single["endpoint"]
        address = relay["address"]
        if (
            status["state"] != "connected"
            or tunnel["protocol"] != "udp"
            or tunnel["tunnel_interface"] != "wg0-mullvad"
            or set(obfuscation) != {"Single"}
            or single["obfuscation_type"] != "Quic"
            or relay["protocol"] != "udp"
            or not isinstance(address, str)
            or not address.endswith(":443")
        ):
            raise ValueError
        ip = ipaddress.IPv4Address(address[:-4])
        if not ip.is_global or address != f"{ip}:443":
            raise ValueError
    except (ValueError, KeyError, TypeError, AttributeError):
        raise Failure("unsupported_mullvad_relay_status") from None
    return str(ip).encode("ascii")

@logged
def relay_display(reference, current, relay, tunnel=None):
    """Replace three relay slots and optional two INPUT slots; all other bytes exact.

    No nft parsing/canonicalization: order, ports, marks, interfaces and verdicts
    remain significant. The caller must first anchor reference to the old SHA.
    """
    for data in (reference, current):
        if (
            not isinstance(data, bytes)
            or len(data) > 65536
            or not data.endswith(b"\n")
            or any(c < 32 and c not in (9, 10) for c in data)
            or b"\x7f" in data
        ):
            raise Failure("invalid_mullvad_display")
    slots = (
        (b"ip saddr ", b" udp sport 443 meta mark set 0x6d6f6c65"),
        (b"ip daddr ", b" udp dport 443 meta mark 0x6d6f6c65 accept"),
        (b"ip saddr ", b" udp sport 443 ct state established accept"),
    )
    addresses = []
    for prefix, suffix in slots:
        pattern = b"^\\t\\t" + re.escape(prefix) + rb"([0-9.]+)" + re.escape(suffix) + b"\\n"
        matches = re.findall(pattern, reference, re.MULTILINE)
        if len(matches) != 1:
            raise Failure("unsupported_mullvad_reference_slots")
        addresses.extend(matches)
    old = addresses[0]
    if len(set(addresses)) != 1 or reference.count(old) != 3:
        raise Failure("unsupported_mullvad_reference_slots")
    try:
        # IPv4Address(str) already rejects non-canonical dotted decimal (including
        # leading zeroes). Rechecking str(parsed) introduced unreachable branches;
        # retain both strict parses and their shared fail-closed error boundary.
        ipaddress.IPv4Address(old.decode("ascii"))
        ipaddress.IPv4Address(relay.decode("ascii"))
    except (ValueError, UnicodeError, AttributeError):
        raise Failure("invalid_mullvad_relay_address") from None
    candidate = reference.replace(old, relay)
    if tunnel is not None:
        if (
            not isinstance(tunnel, tuple)
            or len(tunnel) != 2
            or any(not isinstance(a, str) for a in tunnel)
        ):
            raise Failure("unsupported_mullvad_tunnel_address")
        # Anchor slots to the INPUT chain of the accepted reference, not arbitrary drop rules.
        marker = b"\tchain input {\n"
        if reference.count(marker) != 1:
            raise Failure("unsupported_mullvad_tunnel_slots")
        body = reference.split(marker, 1)[1].split(b"\t}\n", 1)[0]
        for family, address in zip((b"ip", b"ip6"), tunnel, strict=True):
            pattern = rb"(?m)^\t\t" + family + rb" daddr ([0-9a-f:.]+) drop\n"
            matches = list(re.finditer(pattern, reference))
            if len(matches) != 1 or matches[0][0] not in body:
                raise Failure("unsupported_mullvad_tunnel_slots")
            previous = matches[0][1]
            try:
                version = 4 if family == b"ip" else 6
                for value in (previous.decode("ascii"), address):
                    parsed = ipaddress.ip_address(value)
                    network = "10.0.0.0/8" if version == 4 else "fc00::/7"
                    if (
                        parsed.version != version
                        or str(parsed) != value
                        or parsed not in ipaddress.ip_network(network)
                    ):
                        raise ValueError
            except (ValueError, UnicodeError, TypeError):
                raise Failure("unsupported_mullvad_tunnel_address") from None
            candidate = candidate.replace(
                matches[0][0],
                b"\t\t" + family + b" daddr " + address.encode("ascii") + b" drop\n",
                1,
            )
    return candidate == current

@logged
def tunnel_addresses(data):
    """Independent kernel observation, not addresses learned from the nft table."""
    if not isinstance(data, bytes) or len(data) > 65536:
        raise Failure("unsupported_mullvad_interface_addresses")
    try:
        rows = json.loads(data)
        if not isinstance(rows, list) or len(rows) != 1:
            raise ValueError
        row = rows[0]
        if (
            row["ifname"] != "wg0-mullvad"
            or not isinstance(row["flags"], list)
            or "UP" not in row["flags"]
        ):
            raise ValueError
        found: dict[str, list[str]] = {"inet": [], "inet6": []}
        for addr in row["addr_info"]:
            if addr.get("scope") != "global":
                continue
            family = addr["family"]
            if (
                family not in found
                or any(addr.get(f) for f in ("tentative", "dadfailed", "deprecated"))
                or not isinstance(addr.get("flags", []), list)
                or any(f in addr.get("flags", []) for f in ("tentative", "dadfailed", "deprecated"))
            ):
                raise ValueError
            ip = ipaddress.ip_address(addr["local"])
            version = 4 if family == "inet" else 6
            network = "10.0.0.0/8" if version == 4 else "fc00::/7"
            if (
                ip.version != version
                or str(ip) != addr["local"]
                or ip not in ipaddress.ip_network(network)
                or addr.get("valid_life_time", 1) == 0
            ):
                raise ValueError
            found[family].append(str(ip))
        if any(len(values) != 1 for values in found.values()):
            raise ValueError
        return found["inet"][0], found["inet6"][0]
    except (ValueError, KeyError, TypeError, AttributeError):
        raise Failure("unsupported_mullvad_interface_addresses") from None


"""checks.policy"""

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
def policy(ctx):
    return {
        "FW_RUNTIME_SHA": digest(
            ctx.run(["/usr/bin/firewall-cmd", "--zone=public", "--list-all"]).stdout
        ),
        "FW_PERMANENT_SHA": digest(
            ctx.run(["/usr/bin/firewall-cmd", "--permanent", "--zone=public", "--list-all"]).stdout
        ),
        "NFT_MULLVAD_SHA": digest(
            ctx.run(["/usr/sbin/nft", "list", "table", "inet", "mullvad"]).stdout
        ),
    }

@logged
def baseline(ctx):
    values = {}
    for line in read_regular(ctx.p.etc / "baseline.env").decode().splitlines():
        if line and not line.startswith("#"):
            k, _, v = line.partition("=")
            if k in values or k not in {
                "FW_RUNTIME_SHA",
                "FW_PERMANENT_SHA",
                "NFT_MULLVAD_SHA",
                "BASELINE_AT",
            }:
                raise Failure("invalid_baseline")
            values[k] = v
    for k in policy_keys():
        if not re.fullmatch("[0-9a-f]{64}", values.get(k, "")):
            raise Failure("missing_baseline_hash")
    return values

@logged
def policy_keys():
    return ("FW_RUNTIME_SHA", "FW_PERMANENT_SHA", "NFT_MULLVAD_SHA")

@logged
def trusted(path):
    """Reject a writable or symlink ancestor, not just the leaf owner."""
    path = Path(path)
    for p in (path, *path.parents):
        s = p.lstat()
        if s.st_uid != 0 or s.st_mode & 0o022 or stat.S_ISLNK(s.st_mode):
            raise Failure("untrusted_deployment_path")
    return True

@logged
def state_member(path, *, directory=False, mode=None, optional=False):
    """Admit existing privileged state without silently repairing its permissions."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        if optional:
            return
        raise
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not expected_type(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o022
        or (not directory and info.st_nlink != 1)
        or (mode is not None and stat.S_IMODE(info.st_mode) != mode)
    ):
        raise Failure("untrusted_state_custody")
    for name in (
        ("system.posix_acl_access", "system.posix_acl_default")
        if directory
        else ("system.posix_acl_access",)
    ):
        event("external_start", "state_acl_read")
        try:
            os.getxattr(path, name, follow_symlinks=False)
        except OSError as exc:
            if exc.errno != errno.ENODATA:
                event("external_error", "state_acl_read", type(exc).__name__)
                raise Failure("state_acl_unavailable") from None
            event("external_exit", "state_acl_read", "absent")
        else:
            event("external_exit", "state_acl_read", "present")
            raise Failure("state_extended_acl_requires_review")

@logged
def state_custody(ctx):
    """Root-only state is pre-provisioned; role-owned research/atlas are separate."""
    import checks as checks_pkg

    root = ctx.p.state
    for path in (root, *root.parents):
        checks_pkg.state_member(path, directory=True)
    for name, mode in (
        (".console.lock", 0o600),
        (".worker.lock", 0o600),
        ("alert-state.json", 0o600),
        ("alerts-forwarded.json", 0o600),
        ("simplex-attempts.json", 0o600),
        ("alerts.jsonl", 0o640),
        ("metrics.jsonl", 0o640),
        ("notify.state", 0o644),
    ):
        checks_pkg.state_member(root / name, mode=mode, optional=True)
    event("state", "state_custody", "existing_permissions_accepted_no_repair")

@logged
def nft_relay_gate(ctx, expected, observed):
    path = ctx.p.etc / "baseline-nft-mullvad.txt"
    if ctx.require_root:
        trusted(path)
    try:
        reference = read_regular(path, limit=65536)
    except OSError:
        raise Failure("mullvad_reference_unavailable") from None
    if digest(reference) != expected:
        raise Failure("mullvad_reference_not_accepted_baseline")
    relay = quic_relay(ctx.run(["/usr/bin/mullvad", "status", "--json"]).stdout)
    current = ctx.run(["/usr/sbin/nft", "list", "table", "inet", "mullvad"]).stdout
    if digest(current) != observed:
        raise Failure("mullvad_display_changed_during_check")
    if not relay_display(reference, current, relay):
        command = ["/usr/sbin/ip", "-j", "addr", "show", "dev", "wg0-mullvad"]
        before = tunnel_addresses(ctx.run(command).stdout)
        current = ctx.run(["/usr/sbin/nft", "list", "table", "inet", "mullvad"]).stdout
        if digest(current) != observed:
            raise Failure("mullvad_display_changed_during_check")
        if not relay_display(reference, current, relay, before):
            raise Failure("policy_baseline_drift_do_not_auto_accept")
        if tunnel_addresses(ctx.run(command).stdout) != before:
            raise Failure("mullvad_interface_changed_during_check")
    if quic_relay(ctx.run(["/usr/bin/mullvad", "status", "--json"]).stdout) != relay:
        raise Failure("mullvad_relay_changed_during_check")
    event("state", "mullvad_policy", "legacy_anchored_local_quic_and_tunnel_addresses")

@logged
def policy_gate(ctx):
    expected = baseline(ctx)
    observed = policy(ctx)
    if observed["FW_PERMANENT_SHA"] != expected["FW_PERMANENT_SHA"]:
        raise Failure("policy_baseline_drift_do_not_auto_accept")
    if observed["NFT_MULLVAD_SHA"] != expected["NFT_MULLVAD_SHA"]:
        nft_relay_gate(ctx, expected["NFT_MULLVAD_SHA"], observed["NFT_MULLVAD_SHA"])
    if observed["FW_RUNTIME_SHA"] == expected["FW_RUNTIME_SHA"]:
        event("state", "runtime_policy", "exact_legacy_hash")
        return
    # Legacy SHA is authoritative; never enroll a current observation as accepted.
    path = ctx.p.etc / "baseline-runtime-public.txt"
    if ctx.require_root:
        trusted(path)
    reference = read_regular(path, limit=65536)
    if digest(reference) != expected["FW_RUNTIME_SHA"]:
        raise Failure("runtime_reference_not_accepted_baseline")
    current = ctx.run(["/usr/bin/firewall-cmd", "--zone=public", "--list-all"]).stdout
    if digest(current) != observed["FW_RUNTIME_SHA"]:
        raise Failure("runtime_display_changed_during_check")
    if runtime_display(reference) != runtime_display(current):
        raise Failure("policy_baseline_drift_do_not_auto_accept")
    event("state", "runtime_policy", "legacy_anchored_rule_permutation")

@logged
def nft_gate(ctx):
    data = json.loads(ctx.run(["/usr/sbin/nft", "-j", "list", "tables"]).stdout)
    if any(e.get("table", {}).get("name") in ("ygglab", "yggstack-gate") for e in data["nftables"]):
        raise Failure("transient_gate_left_active")

@logged
def masked_gate(ctx):
    for u in ("yggdrasil.service", "yggdrasil-default-config.service"):
        v = ctx.unit(u)
        if v.get("UnitFileState") != "masked" or v.get("ActiveState") != "inactive":
            raise Failure("packaged_unit_unmasked_or_running")


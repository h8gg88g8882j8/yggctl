"""checks.runtime"""

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

COLLECTOR_MAX_AGE_MINUTES = 15

@logged
def peers(ctx, stack=False):
    rows = ctx.api("getPeers", stack=stack).get("peers")
    if not isinstance(rows, list) or any(
        not isinstance(p, dict) or type(p.get("up")) is not bool for p in rows
    ):
        raise Failure("invalid_peer_schema")
    for p in rows:
        if not isinstance(p.get("remote"), str):
            raise Failure("invalid_peer_remote")
        for field in ("latency", "bytes_recvd", "bytes_sent"):
            value = p.get(field, 0)
            # NaN passes `value < 0`, is written back by json.dumps as a bare NaN token
            # and breaks every non-Python reader of metrics.jsonl (research already
            # rejects non-finite latency).
            try:
                valid = type(value) in (int, float) and math.isfinite(value) and value >= 0
            except OverflowError:
                # JSON integers may exceed float range; latency conversion and
                # downstream numerical consumers cannot represent those values.
                valid = False
            if not valid:
                raise Failure("invalid_peer_counter")
    return rows

@logged
def identified(peer):
    """A row is a peer only after the handshake gave it a public key.

    getPeers reports up:true as soon as the transport connects, with an empty key,
    so transport-only rows must not feed availability, alerts or convergence waits.
    """
    public_key = peer.get("key")
    return (
        peer.get("up") is True
        and isinstance(public_key, str)
        and re.fullmatch(r"[0-9a-f]{64}", public_key) is not None
    )

@logged
def service_gate(ctx, unit):
    u = ctx.unit(unit)
    if (
        u.get("ActiveState") != "active"
        or u.get("SubState") != "running"
        or int(u.get("NRestarts", "1"))
    ):
        raise Failure("unit_not_stably_running")

@logged
def peer_gate(ctx, stack):
    rows = peers(ctx, stack)
    expected = set(ctx.config("yggstack.conf" if stack else "yggdrasil-lab.conf")["Peers"])
    # A transport-only link reports up:true before the handshake and carries no public key;
    # it is not a peer (research/atlas already skip such rows for the same reason).
    up = {endpoint(p.get("remote", "")) for p in rows if identified(p) and not p.get("inbound")}
    if len(up & {endpoint(p) for p in expected}) < 2:
        raise Failure("less_than_two_configured_peers_up")

@logged
def multicast_gate(ctx, stack):
    if ctx.api("getMulticastInterfaces", stack=stack).get("multicast_interfaces") != []:
        raise Failure("multicast_unknown_or_nonempty")

@logged
def tun_gate(ctx):
    if ctx.api("getTun").get("enabled") is not False:
        raise Failure("tun_unknown_or_enabled")

@logged
def collector_freshness(ctx):
    """Require recent, non-future file metadata as a bounded freshness heuristic.

    systemd reports a oneshot that never ran as ActiveState=inactive, Result=success and
    ExecMainStatus=0, so service state alone cannot prove that samples are still written.
    A missing, empty, non-regular or future-stamped file is not such evidence either.
    """
    path = ctx.p.state / "metrics.jsonl"
    try:
        info = path.lstat()
    except OSError:
        raise Failure("collector_data_missing") from None
    if not stat.S_ISREG(info.st_mode) or info.st_size == 0:
        raise Failure("collector_data_missing")
    # Do not turn a future timestamp into freshness by taking its absolute age.
    # This checks file-write metadata, not sample correctness or authenticity.
    age = time.time() - info.st_mtime
    if age < 0:
        raise Failure("collector_data_future_timestamp")
    if age > COLLECTOR_MAX_AGE_MINUTES * 60:
        raise Failure("collector_data_stale")

@logged
def timer_gate(ctx):
    t = ctx.unit(TIMER)
    if t.get("ActiveState") != "active":
        raise Failure("collector_timer_inactive")
    # An active timer that never fired renders LastTriggerUSec as an empty value, not as
    # "0"; "n/a" is systemd's other rendering of "no value" and a missing or non-string
    # property is not proof of a trigger.
    triggered = t.get("LastTriggerUSec")
    if not isinstance(triggered, str) or triggered.strip().lower() in ("", "0", "n/a"):
        raise Failure("collector_never_fired")
    u = ctx.unit("ygg-metrics.service")
    if u.get("ActiveState") == "failed" or u.get("ExecMainStatus") != "0":
        raise Failure("collector_failed")
    collector_freshness(ctx)


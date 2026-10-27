"""checks.check"""

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
def check(ctx, emit=True):
    import checks as checks_pkg

    ctx.root()
    gates = [
        ("config/keys/admin", checks_pkg.guard),
        ("integrity/root trust", checks_pkg.integrity),
        ("listeners", checks_pkg.sockets),
        ("underlay own sockets", checks_pkg.underlay),
    ]
    for u in (NODE, STACK):
        gates.append((u, lambda c, u=u: checks_pkg.service_gate(c, u)))
    for stack in (False, True):
        gates.append(
            ("stack peers" if stack else "node peers", lambda c, s=stack: checks_pkg.peer_gate(c, s))
        )
        gates.append(
            (
                "stack no multicast" if stack else "node no multicast",
                lambda c, s=stack: checks_pkg.multicast_gate(c, s),
            )
        )
    gates += [
        ("no TUN", checks_pkg.tun_gate),
        ("firewall baseline", checks_pkg.policy_gate),
        ("no transient gates", checks_pkg.nft_gate),
        ("packaged masked", checks_pkg.masked_gate),
        ("collector timer", checks_pkg.timer_gate),
    ]
    failures = []
    start = time.monotonic()
    for i, (label, fn) in enumerate(gates, 1):
        try:
            fn(ctx)
            result = "PASS"
        except (Failure, OSError, ValueError, KeyError) as exc:
            failures.append(label)
            result = f"FAIL {exc}" if isinstance(exc, Failure) else "FAIL unavailable/invalid"
        if emit:
            print(f"[{i}/{len(gates)}] {label}: {result}; remaining={len(gates) - i}", flush=True)
    if emit:
        print(
            f"CHECK {'FAIL' if failures else 'PASS'} processed={len(gates)} errors={len(failures)} "
            f"elapsed={time.monotonic() - start:.2f}s"
        )
    if failures:
        raise Failure("health_gates_failed")
    return len(gates)


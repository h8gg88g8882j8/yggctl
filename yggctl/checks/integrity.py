"""checks.integrity"""

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

from .policy import trusted, state_member

@logged
def integrity(ctx):
    import checks as checks_pkg

    if "integrity" in ctx.parent_verified:
        return 0
    manifest = checks_pkg.read_regular(ctx.p.etc / "integrity.manifest").decode()
    checked = set()
    for line in manifest.splitlines():
        m = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not m:
            raise Failure("invalid_integrity_manifest")
        path = Path(m[2])
        if not path.is_absolute():
            path = ctx.p.etc / path
        if path in checked:
            raise Failure("duplicate_integrity_member")
        if ctx.require_root:
            import checks as checks_pkg

            checks_pkg.trusted(path)
        if digest(checks_pkg.read_regular(path, limit=256 * 1024 * 1024)) != m[1]:
            raise Failure("integrity_mismatch")
        checked.add(path)
    required = {
        Path(ctx.p.node),
        Path(ctx.p.stack),
        ctx.p.units / NODE,
        ctx.p.units / STACK,
        ctx.p.etc / "yggdrasil-lab.conf",
        ctx.p.etc / "yggstack.conf",
        ctx.p.etc / "gate.nft",
        ctx.p.etc / "gate-yggstack.nft",
    }
    if ctx.require_root:
        required |= {
            ctx.p.units / TIMER,
            ctx.p.units / "ygg-metrics.service",
            Path("/usr/bin/yggctl"),
            ctx.p.runtime / "main.py",
            ctx.p.runtime / "core.py",
            ctx.p.runtime / "management.py",
            ctx.p.runtime / "recovery.py",
            ctx.p.runtime / "tests.py",
            ctx.p.runtime / "test_support.py",
            ctx.p.runtime / "rotate.py",
            ctx.p.runtime / "sandbox.py",
            ctx.p.runtime / "broker.py",
            ctx.p.runtime / "simplex_sender.py",
            ctx.p.units / "ygg-alert-forward.service",
            ctx.p.units / "ygg-alert-forward.path",
            Path("/etc/sysusers.d/ygglab-worker.conf"),
            Path("/usr/local/bin/yggctl"),
            Path(ctx.p.decoder),
            ctx.p.etc / "mode",
            ctx.p.etc / "baseline.env",
        }
        required.add(ctx.p.etc / "baseline-runtime-public.txt")
        required.add(ctx.p.etc / "baseline-nft-mullvad.txt")
        required |= {
            ctx.p.runtime / "checks" / n
            for n in (
                "__init__.py",
                "check.py",
                "display.py",
                "integrity.py",
                "policy.py",
                "runtime.py",
                "underlay.py",
            )
        }
        required |= {
            ctx.p.runtime / "telemetry" / n
            for n in (
                "__init__.py",
                "patchable.py",
                "peers.py",
                "storage.py",
                "alerts.py",
                "notify.py",
                "collect.py",
                "trend.py",
            )
        }
        required |= {
            ctx.p.runtime / "research" / n
            for n in ("__init__.py", "model.py", "metrics.py", "tests.py")
        }
        required |= {
            ctx.p.runtime / "atlas" / n
            for n in (
                "__init__.py",
                "store.py",
                "protocol.py",
                "catalogue.py",
                "acquisition.py",
                "analysis.py",
                "viewer.py",
                "tests.py",
            )
        }
    if not required <= checked:
        raise Failure("integrity_coverage_incomplete")
    return len(checked)


"""telemetry.collect"""

"""Bounded, serialized samples and truthful missing-data reporting."""
from .patchable import API


import datetime as dt
import hashlib
import json
import math
import os
import secrets
import stat
import statistics
import time
from collections import Counter
from typing import Any

from core import (
    Failure,
    NODE,
    STACK,
    logged,
    read_regular,
    atomic,
    timestamp,
    event,
    public_peer_uri,
    METRIC_RETENTION,
    METRICS_LIMIT,
)
import simplex_sender



@logged
def collect(ctx):
    ctx.root()
    with ctx.locked():
        uptimes = {}
        sample = {
            "schema": 2,
            "ts": API.timestamp(),
            "mode": None,
            "act": "unknown",
            "up": None,
            "peers": [],
            "peers_observed": False,
            "stack_up": None,
            "errors": [],
        }
        try:
            sample["mode"] = ctx.mode()
            for stack, unit in ((False, NODE), (True, STACK)):
                active = ctx.unit(unit).get("ActiveState", "unknown")
                ps = API.peers(ctx, stack)  # Exactly one coherent admin query per instance.
                if stack:
                    sample["stack_up"] = sum(API.identified(p) for p in ps)
                else:
                    uptimes = {API.peer_label(p.get("remote")): p.get("uptime") for p in ps}
                    sample["act"] = active
                    sample["up"] = sum(API.identified(p) for p in ps)
                    sample["peers"] = [
                        {
                            "r": API.peer_label(p.get("remote")),
                            "up": API.identified(p),
                            "rtt": p.get("latency", 0) / 1e6,
                            "rx": p.get("bytes_recvd", 0),
                            "tx": p.get("bytes_sent", 0),
                        }
                        for p in ps
                    ]
                    sample["peers_observed"] = True
                if active != "active":
                    sample["errors"].append("stack_inactive" if stack else "node_inactive")
        except (Failure, OSError, ValueError) as exc:
            sample["errors"].append(str(exc) if isinstance(exc, Failure) else "metric_unavailable")
        if sample["up"] == 0 or sample["stack_up"] == 0:
            sample["errors"].append("no_up_peers")
        if API.ambiguous_peer_labels(sample["peers"]):
            sample["errors"].append("ambiguous_peer_labels")
        metric_failed = False
        try:
            API.append(ctx, "metrics.jsonl", sample)
        except (Failure, OSError):
            metric_failed = True
            sample["errors"].append("metric_write_failed")
            API.event("error", "collect", "history_write_failed_alerts_continue")
        enabled = API.notify_state(ctx) == "on"
        if enabled:
            # Drain first: a full recoverable outbox must not block its own retry.
            try:
                API.flush_peer_alerts(ctx)
            except (Failure, OSError):
                # Queue recovery must not hide an observation already obtained.
                # Stage under the same lock, retaining pending IDs and all state
                # validation/capacity checks. Do not retry or acknowledge the
                # failed queue here; surface its original error after staging.
                API.peer_alerts(ctx, sample, uptimes)
                try:
                    API.stage_health_alert(ctx, sample)
                except (Failure, OSError) as exc:
                    API.event("error", "health_outbox", type(exc).__name__)
                raise
        API.peer_alerts(ctx, sample, uptimes)
        if enabled:
            API.stage_health_alert(ctx, sample)
            API.flush_peer_alerts(ctx)
        API.warn_alert_admission(ctx)
        if metric_failed:
            raise Failure("metric_write_failed_alerts_processed")
        if sample["errors"]:
            raise Failure("sample_recorded_with_unknown_or_degraded_health")
        print("[1/1] sample recorded; processed=2 instances errors=0 remaining=0")
        return sample

@logged
def window(ctx, hours=24, *, future=None):
    now = dt.datetime.now(dt.timezone.utc)
    start = now - dt.timedelta(hours=hours)
    found, invalid = [], 0
    for r in API.rows(ctx):
        try:
            at = dt.datetime.fromisoformat(r["ts"])
            if at.tzinfo is None:
                raise ValueError()
        except (KeyError, ValueError, TypeError):
            invalid += 1
            API.event("state", "metric_window", "invalid_timestamp_skipped")
            continue
        if future is not None and at > now:
            future.append(at)
        if start <= at <= now:
            found.append((at, r))
    if not found:
        raise Failure(f"no_samples_in_window:invalid_records={invalid}")
    return sorted(found, key=lambda x: x[0]), invalid

@logged
def stats(ctx, hours=24, graph=False):
    values, invalid = API.window(ctx, hours)
    unknown = sum(r.get("up") is None or bool(r.get("errors")) for _, r in values)
    gaps = sum(
        max(0, round((b[0] - a[0]).total_seconds() / 60) - 1) for a, b in zip(values, values[1:])
    )
    # One pass over the window instead of a scan of every record for every peer name.
    index: dict[str, dict[int, dict[str, Any]]] = {}
    for position, (_, row) in enumerate(values):
        for peer in row.get("peers", []):
            index.setdefault(peer["r"], {}).setdefault(position, peer)
    names = sorted(index)
    print(
        f"window={hours}h samples={len(values)} unknown_records={unknown} "
        f"invalid_records={invalid} missing_minutes_between_samples={gaps}; "
        f"observed availability is NOT wall-clock uptime"
    )
    for name in names:
        by_position = index[name]
        matches = [by_position.get(position) for position in range(len(values))]
        known = [p for p in matches if p is not None]
        up = sum(p["up"] for p in known)
        latency = [p["rtt"] for p in known if p["up"] and p.get("rtt", 0) > 0]
        median = statistics.median(latency) if latency else "unknown"
        print(
            f"{API.peer_label(name)}: observed_avail={100 * up / len(known):.1f}% present={len(known)} "
            f"absent={len(matches) - len(known)} median_ms={median}"
        )
        if graph:
            # Bin the entire requested time window, not simply the last 60 samples.
            end = dt.datetime.now(dt.timezone.utc)
            begin = end - dt.timedelta(hours=hours)
            bins: list[list[dict[str, Any] | None]] = [[] for _ in range(60)]
            span = max(1, (end - begin).total_seconds())
            for (at, _), p in zip(values, matches):
                bins[min(59, int((at - begin).total_seconds() * 60 / span))].append(p)
            marks = (
                "?"
                if not b or all(p is None for p in b)
                else "."
                if not any(p and p["up"] for p in b)
                else "#"
                for b in bins
            )
            print("".join(marks))
            print("60 time bins: # observed up, . observed down, ? unknown; NOT RTT bars")

@logged
def watch(ctx, count=5, interval=2):
    start, errors = time.monotonic(), 0
    for i in range(count):
        try:
            node = sum(API.identified(p) for p in API.peers(ctx))
            stack = sum(API.identified(p) for p in API.peers(ctx, True))
        except (Failure, OSError, ValueError, KeyError):
            node = stack = "unknown"
            errors += 1
            API.event("error", "watch_sample", "unavailable_unknown")
        print(
            f"[{i + 1}/{count}] node_up={node} stack_up={stack} errors={errors} "
            f"elapsed={time.monotonic() - start:.1f}s ETA={(count - i - 1) * interval}s "
            f"speed=1/{interval}s remaining={count - i - 1}",
            flush=True,
        )
        if i + 1 < count:
            time.sleep(interval)
    print(f"processed={count} errors={errors} elapsed={time.monotonic() - start:.1f}s")
    if errors:
        raise Failure(f"watch_samples_failed:count={errors}")


"""telemetry.alerts"""

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



PEER_DOWN_MINUTES = 10

UNSTABLE_RECONNECTS = 3  # reconnects within the last hour that make a peer "unstable"

UNSTABLE_REPEAT_HOURS = 6  # at most one "unstable" alert per peer in this time

PEER_STATE_LIMIT = 1 << 20

PEER_PENDING_LIMIT = 1000  # no larger than the queue's ordinary-alert retention capacity

PEER_ALERT_KINDS = ("ygg-peer-down", "ygg-peer-up", "ygg-peer-unstable")

HEALTH_ALERT_KIND = "ygg-health"

@logged
def load_peer_state(ctx):
    """Accept legacy state, but never silently discard a damaged durable outbox."""
    try:
        raw = ctx.read_state("alert-state.json", API.PEER_STATE_LIMIT)
        state = json.loads(b"{}" if raw is None else raw)
    except ValueError:
        raise Failure("alert_state_invalid") from None
    if not isinstance(state, dict):
        raise Failure("alert_state_invalid")
    if "admission_incomplete" in state and not isinstance(state["admission_incomplete"], bool):
        raise Failure("alert_state_invalid")
    pending = state.get("pending", [])
    if not isinstance(pending, list) or len(pending) > API.PEER_PENDING_LIMIT:
        raise Failure("alert_pending_invalid")
    seen = set()
    for item in pending:
        if not isinstance(item, dict) or not isinstance(item.get("ts"), str) or "id" not in item:
            raise Failure("alert_pending_invalid")
        if item.get("kind") == HEALTH_ALERT_KIND:
            if (
                set(item) != {"ts", "id", "kind", "key", "errors"}
                or not isinstance(item.get("key"), str)
                or len(item["key"]) != len("collect:2026010100")
                or not item["key"].startswith("collect:")
                or not item["key"][8:].isascii()
                or not item["key"][8:].isdigit()
                or not isinstance(item.get("errors"), list)
                or not item["errors"]
                or any(not isinstance(error, str) for error in item["errors"])
            ):
                raise Failure("alert_pending_invalid")
        elif item.get("kind") not in PEER_ALERT_KINDS or not isinstance(item.get("peer"), str):
            raise Failure("alert_pending_invalid")
        aid = API.alert_id(item)
        if aid in seen:
            raise Failure("alert_pending_duplicate_id")
        seen.add(aid)
    return state

@logged
def save_peer_state(ctx, state):
    data = (json.dumps(state, sort_keys=True) + "\n").encode()
    if len(data) > API.PEER_STATE_LIMIT:
        raise Failure("alert_state_size_limit")
    API.atomic(ctx.p.state / "alert-state.json", data, 0o600)

@logged
def mark_alert_admission_incomplete(ctx, state):
    """Record a refused alert intent before returning the original capacity error."""
    if not state.get("admission_incomplete", False):
        state["admission_incomplete"] = True
        API.save_peer_state(ctx, state)

@logged
def warn_alert_admission(ctx):
    if API.load_peer_state(ctx).get("admission_incomplete", False):
        print(
            "WARNING alert_admission_incomplete=yes; notification_history_may_be_incomplete=yes",
            flush=True,
        )

@logged
def sync_alert_queue(ctx):
    """Even a complete record observed after a failed fsync needs a new durability barrier."""
    fd = os.open(
        ctx.p.state / "alerts.jsonl", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    )
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Failure("alert_queue_not_regular")
        os.fsync(fd)
    finally:
        os.close(fd)
    parent = os.open(ctx.p.state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)

@logged
def flush_peer_alerts(ctx):
    """Replay durable pending events under the shared producer/forwarder lock.

    A crash after append but before acknowledgement reuses the same ID, checks the
    queued content and syncs both queue and directory before clearing pending.
    This is queue recovery, not exactly-once external delivery or a human ACK.
    """
    with ctx.locked():
        state = API.load_peer_state(ctx)
        pending = state.get("pending", [])
        if not pending:
            return
        queued = {API.alert_id(row): row for row in API.rows(ctx, "alerts.jsonl")}
        for item in pending:
            # Do not copy a legacy private credential into the group-readable
            # queue, or mutate its stable-ID payload implicitly during replay.
            if item["kind"] in PEER_ALERT_KINDS and item["peer"] != API.peer_label(item["peer"]):
                raise Failure("legacy_peer_pending_requires_privacy_review")
            aid = item["id"]
            if aid in queued:
                if queued[aid] != item:
                    raise Failure("alert_pending_id_conflict")
                API.event("state", "peer_outbox", "already_queued")
            else:
                API.append(ctx, "alerts.jsonl", item, API.PEER_PENDING_LIMIT)
                API.event("alert", "peer_outbox", item["kind"])
        # Appending a later event may compact away an earlier already-queued
        # pending event. Acknowledge against the final queue, not the snapshot
        # taken before these writes; retain exact IDs and payloads for retry.
        queued = {API.alert_id(row): row for row in API.rows(ctx, "alerts.jsonl")}
        remaining = [item for item in pending if queued.get(item["id"]) != item]
        API.sync_alert_queue(ctx)
        state["pending"] = remaining
        API.save_peer_state(ctx, state)
        if remaining:
            API.event("state", "peer_outbox", "retained_after_queue_rotation")
            raise Failure("alert_pending_retained_after_queue_rotation")
        API.event("state", "peer_outbox", "acknowledged")

@logged
def peer_alerts(ctx, sample, uptimes=None):
    with ctx.locked():
        return API.stage_peer_alerts(ctx, sample, uptimes)

@logged
def stage_health_alert(ctx, sample):
    """Save one original degraded observation per hour before queue I/O."""
    if not sample["errors"]:
        return
    key = "collect:" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d%H")
    state = API.load_peer_state(ctx)
    pending = state.get("pending", [])
    if any(item.get("kind") == HEALTH_ALERT_KIND and item["key"] == key for item in pending):
        return
    if any(item.get("key") == key for item in API.rows(ctx, "alerts.jsonl")):
        return
    if len(pending) >= API.PEER_PENDING_LIMIT:
        API.mark_alert_admission_incomplete(ctx, state)
        raise Failure("alert_pending_limit")
    state["pending"] = pending + [
        {
            "ts": sample["ts"],
            "id": secrets.token_hex(8),
            "kind": HEALTH_ALERT_KIND,
            "key": key,
            "errors": sample["errors"],
        }
    ]
    API.save_peer_state(ctx, state)
    API.event("state", "health_outbox", "staged")

def peer_alert_retain_unobserved(ctx, state, sample):
    """Keep durable tracking when the peer list was not observed this sample."""
    if sample.get("peers_observed", True) is not True:
        if not state.get("observation_gap"):
            state["observation_gap"] = True
            API.save_peer_state(ctx, state)
        API.event("state", "peer_observation", "unknown_tracking_retained")
        return True
    return False

def peer_alert_sample_peers(sample, uptimes):
    """Label peers for this sample and split ambiguous labels from comparable ones."""
    now = dt.datetime.fromisoformat(sample["ts"])
    peers = [
        dict(p, r=API.peer_label(p["r"]))
        for p in sample.get("peers", [])
        if isinstance(p.get("r"), str) and p.get("r")
    ]
    labeled_uptimes = {API.peer_label(k): v for k, v in (uptimes or {}).items()}
    ambiguous = API.ambiguous_peer_labels(peers)
    up, total = sum(bool(p.get("up")) for p in peers), len(peers)
    observed = [p for p in peers if p["r"] not in ambiguous]
    return now, labeled_uptimes, ambiguous, up, total, observed

def peer_alert_retain_ambiguous(down, ambiguous, tracked):
    """Do not let one link recover another's episode; retain tracking across ambiguity."""
    for label in ambiguous:
        if isinstance(down.get(label), dict):
            tracked[label] = dict(down[label], observation_gap=True)
    if ambiguous:
        API.event("state", "peer_observation", "ambiguous_labels_tracking_retained")

def peer_alert_track_observed_peer(p, down, gap, now, sample, up, total, changes, tracked):
    """Apply down/up transitions for one unambiguous peer label."""
    entry = candidate if isinstance(candidate := down.get(p["r"]), dict) else {}
    try:
        since = dt.datetime.fromisoformat(entry.get("since", sample["ts"]))
    except (TypeError, ValueError):
        since = now
    uncertain = bool(entry.get("observation_gap")) or gap
    if uncertain and not entry.get("alerted"):
        # No uninterrupted downtime can be proved across a missing query.
        # Keep already-alerted episodes to avoid a duplicate down event,
        # but start a fresh confirmation interval for unalerted episodes.
        since = now
    minutes = max(0, int((now - since).total_seconds() // 60))
    if p.get("up"):
        if entry.get("alerted"):
            changes.append(
                {
                    "kind": "ygg-peer-up",
                    "peer": p["r"],
                    "minutes": minutes,
                    "up": up,
                    "total": total,
                }
            )
            if uncertain:
                changes[-1]["observation_gap"] = True
        return
    alerted = bool(entry.get("alerted"))
    if not alerted and minutes >= PEER_DOWN_MINUTES:
        changes.append(
            {
                "kind": "ygg-peer-down",
                "peer": p["r"],
                "minutes": minutes,
                "up": up,
                "total": total,
            }
        )
        alerted = True
    tracked[p["r"]] = {"since": since.isoformat(), "alerted": alerted}
    if alerted and uncertain:
        tracked[p["r"]]["observation_gap"] = True

def peer_alert_merge_ambiguous_reconnects(starts, unstable, ambiguous, new_starts, new_unstable):
    for label in ambiguous:
        if label in starts:
            new_starts[label] = starts[label]
        if label in unstable:
            new_unstable[label] = unstable[label]

def peer_alert_persist(ctx, state, sample, changes, tracked, new_starts, new_unstable):
    pending = state.get("pending", [])
    enqueue = bool(changes) and API.notify_state(ctx) == "on"
    if enqueue:
        if len(pending) + len(changes) > API.PEER_PENDING_LIMIT:
            API.mark_alert_admission_incomplete(ctx, state)
            raise Failure("alert_pending_limit")
        pending = pending + [
            {"ts": sample["ts"], "id": secrets.token_hex(16), **change} for change in changes
        ]
    new_state = {
        "down": tracked,
        "starts": new_starts,
        "unstable": new_unstable,
        "pending": pending,
    }
    if "admission_incomplete" in state:
        new_state["admission_incomplete"] = state["admission_incomplete"]
    if new_state != state:
        API.save_peer_state(ctx, new_state)
        API.event("state", "peer_outbox", "staged" if enqueue else "tracking_saved")

@logged
def stage_peer_alerts(ctx, sample, uptimes=None):
    """Changes worth an alert: a peer down for PEER_DOWN_MINUTES, its recovery, and a peer
    that reconnected UNSTABLE_RECONNECTS times within an hour (from the node's per-peer
    uptime, which also catches drops shorter than the sampling interval). State lives in
    alert-state.json and is rewritten only when something changes. The caller holds
    ctx.locked(). When notifications are enabled, events and transitions are saved
    together in that one atomic file, before anything is appended to the queue."""
    state = API.load_peer_state(ctx)
    # A failed query is not an observed empty peer set. Retain both tracking and
    # pending content; collect may still replay the durable outbox independently.
    # Legacy direct callers supplying an actual peer list remain observed.
    if API.peer_alert_retain_unobserved(ctx, state, sample):
        return []
    gap = bool(state.get("observation_gap"))
    down = state.get("down", {}) if isinstance(state.get("down"), dict) else {}
    starts = state.get("starts", {}) if isinstance(state.get("starts"), dict) else {}
    unstable = state.get("unstable", {}) if isinstance(state.get("unstable"), dict) else {}
    now, labeled_uptimes, ambiguous, up, total, observed = API.peer_alert_sample_peers(
        sample, uptimes
    )
    changes, tracked = [], {}
    API.peer_alert_retain_ambiguous(down, ambiguous, tracked)
    for p in observed:
        API.peer_alert_track_observed_peer(p, down, gap, now, sample, up, total, changes, tracked)
    new_starts, new_unstable = API.reconnects(
        starts, unstable, labeled_uptimes, now, observed, up, total, changes
    )
    API.peer_alert_merge_ambiguous_reconnects(
        starts, unstable, ambiguous, new_starts, new_unstable
    )
    API.peer_alert_persist(ctx, state, sample, changes, tracked, new_starts, new_unstable)
    return changes

@logged
def reconnects(starts, unstable, uptimes, now, peers, up, total, changes):
    """Record each connection start (now - uptime) once and flag peers that reconnect too often."""
    hour_ago = now - dt.timedelta(hours=1)
    new_starts, new_unstable = {}, {}
    for p in peers:
        uri = p["r"]
        seen = []
        for value in starts.get(uri, []) if isinstance(starts.get(uri), list) else []:
            try:
                at = dt.datetime.fromisoformat(value)
            except (TypeError, ValueError):
                continue
            if at >= hour_ago:
                seen.append(at)
        uptime = uptimes.get(uri)
        if p.get("up") and isinstance(uptime, (int, float)) and 0 <= uptime < 86400:
            start = now - dt.timedelta(seconds=uptime)
            if start >= hour_ago and not any(abs((start - at).total_seconds()) < 15 for at in seen):
                seen.append(start)
        if seen:
            new_starts[uri] = [at.isoformat() for at in sorted(seen)]
        try:
            last = dt.datetime.fromisoformat(unstable[uri]) if uri in unstable else None
        except (TypeError, ValueError):
            last = None
        if last and now - last < dt.timedelta(hours=UNSTABLE_REPEAT_HOURS):
            new_unstable[uri] = last.isoformat()
        elif len(seen) >= UNSTABLE_RECONNECTS:
            changes.append(
                {
                    "kind": "ygg-peer-unstable",
                    "peer": uri,
                    "count": len(seen),
                    "up": up,
                    "total": total,
                }
            )
            new_unstable[uri] = now.isoformat()
    return new_starts, new_unstable


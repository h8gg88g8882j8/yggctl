"""telemetry.notify"""

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



SENDER = "/usr/local/bin/simplex-alert.sh"

FORWARD_BUDGET = 90  # includes acquisition of the shared 20 s lock; unit timeout is 120 s

FORWARD_RESERVE = 5  # normal local checkpoint/exit time, not a guarantee under hung storage

@logged
def notify_state(ctx):
    p = ctx.p.state / "notify.state"
    state = read_regular(p, 16).decode().strip() if p.exists() else "off"
    if state not in ("on", "off"):
        raise Failure("invalid_notify_state")
    return state

@logged
def notify(ctx, action):
    ctx.root()
    with ctx.locked():
        if action in ("on", "off"):
            API.atomic(ctx.p.state / "notify.state", action + "\n", 0o644)
            API.event("state", "notify", action)
        elif action == "test":
            API.append(
                ctx,
                "alerts.jsonl",
                {"ts": API.timestamp(), "id": secrets.token_hex(8), "kind": "labelled-local-selftest"},
                1000,
            )
            API.event("alert", "notify", "labelled_local_test")
        elif action != "show":
            raise Failure("notify_on_off_show_test")
        print(
            f"notify={API.notify_state(ctx)}; alerts.jsonl, then SimpleX via ygg-alert-forward (no ACK needed)"
        )
        if action == "show":
            API.warn_alert_admission(ctx)

@logged
def forward(ctx):
    """Checkpoint native-recorded receipts only; ambiguity remains pending.

    The separate durable attempt journal prevents blind resend after a crash or
    timeout. Neither local recording nor its receipt proves delivery/human ACK.
    Existing legacy cursor entries are preserved, not retroactively verified.
    """
    start = time.monotonic()
    deadline = start + FORWARD_BUDGET
    ctx.root()
    with ctx.locked():
        API.warn_alert_admission(ctx)
        notice, alerts = API.alert_retention(API.rows(ctx, "alerts.jsonl"))
        evicted = notice["evicted_uncheckpointed_total"] if notice else 0
        print(f"alert queue retention: evicted_uncheckpointed_total={evicted}", flush=True)
        ids = [API.alert_id(a) for a in alerts]
        sent = API.forwarded_ids(ctx)
        if sent is None:
            API.atomic(
                ctx.p.state / "alerts-forwarded.json",
                json.dumps({"sent": list(dict.fromkeys(ids))[-2000:]}) + "\n",
                0o600,
            )
            print(
                f"[1/1] forwarding initialised; processed={len(ids)} earlier alerts not sent; errors=0 "
                f"remaining=0 evicted_uncheckpointed_total={evicted} "
                f"elapsed={time.monotonic() - start:.2f}s"
            )
            return
        done, failures, processed = set(sent), 0, 0
        pending = [(a, aid) for a, aid in zip(alerts, ids) if aid not in done]
        for alert, aid in pending:
            if aid in done:
                continue
            remaining = deadline - time.monotonic() - FORWARD_RESERVE
            if remaining < 5:
                API.event("state", "alert_forward", "budget_exhausted_retry_required")
                break
            processed += 1
            try:
                simplex_sender.handoff(ctx, aid, API.alert_message(alert), timeout=min(20, remaining))
                success = True
            except (Failure, OSError, ValueError, KeyError, simplex_sender.sqlite3.Error):
                success = False
            if success:
                done.add(aid)
                # Do not defer this commit until a later message/normal process exit.
                kept = list(dict.fromkeys(i for i in ids if i in done))[-2000:]
                API.atomic(
                    ctx.p.state / "alerts-forwarded.json", json.dumps({"sent": kept}) + "\n", 0o600
                )
                API.event("state", "alert_forward", "native_recorded_checkpointed")
            else:
                failures += 1
                API.event("error", "alert_forward", "native_unconfirmed_pending")
            elapsed = time.monotonic() - start
            print(
                f"[{processed}/{len(pending)}] sender handoff; processed={processed} errors={failures} "
                f"remaining={len(pending) - processed} elapsed={elapsed:.2f}s "
                f"ETA<={max(0, deadline - time.monotonic()):.1f}s "
                f"speed={processed / max(0.001, elapsed):.2f}/s",
                flush=True,
            )
        left = sum(aid not in done for aid in set(ids))
        print(
            f"[1/1] alerts handoff finished; processed={processed} errors={failures} remaining={left} "
            f"evicted_uncheckpointed_total={evicted} "
            f"elapsed={time.monotonic() - start:.2f}s; native local recording is NOT delivery/human ACK"
        )
        if failures:
            raise Failure(f"alert_forward_failed:count={failures}")
        if left:
            # Existing Restart=on-failure schedules backlog even without a new path event.
            raise Failure("alert_forward_budget_pending")


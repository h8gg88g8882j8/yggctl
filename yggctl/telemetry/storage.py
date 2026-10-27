"""telemetry.storage"""

"""Bounded, serialized samples and truthful missing-data reporting."""

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
from checks import identified, peers
import simplex_sender



from .peers import peer_label
from .patchable import API

ALERT_RETENTION_KIND = "ygg-queue-retention"

ALERT_RETENTION_MAX = (1 << 63) - 1

ALERT_RETENTION_ID = "ygg-queue-retention"

MESSAGES = {
    "ygg-peer-down": (
        "Yggdrasil: пир {peer} недоступен",
        "Warning",
        "Нода yggdrasil-lab: пир {peer} недоступен {minutes} мин; на связи {up} из {total}. "
        "Проверка: sudo yggctl peers",
    ),
    "ygg-peer-unstable": (
        "Yggdrasil: пир {peer} нестабилен",
        "Warning",
        "Нода yggdrasil-lab: пир {peer} нестабилен — {count} разрывов за последний час; "
        "на связи {up} из {total}. Проверка: sudo yggctl peers",
    ),
    "ygg-peer-up": (
        "Yggdrasil: пир {peer} снова на связи",
        "Warning",
        "Нода yggdrasil-lab: пир {peer} снова на связи после {minutes} мин; на связи {up} из {total}.",
    ),
    "ygg-health": (
        "Yggdrasil: сбой ноды",
        "Error",
        "Нода yggdrasil-lab: {errors}. Проверка: sudo yggctl check",
    ),
    "labelled-local-selftest": (
        "Yggdrasil: проверка доставки тревог",
        "Warning",
        "Тестовая тревога yggctl (notify test); действий не требуется.",
    ),
}

@logged
def rows(ctx, name="metrics.jsonl"):
    data = ctx.read_state(name, API.METRICS_LIMIT)
    if data is None:
        return []
    # An append in progress (or one torn by a crash) leaves an incomplete last line; skip it.
    if not data.endswith(b"\n"):
        data = data[: data.rfind(b"\n") + 1]
    values = []
    for line in data.splitlines():
        try:
            item = json.loads(line)
            if not isinstance(item, dict):
                raise ValueError()
            values.append(item)
        except ValueError:
            raise Failure("corrupt_metric_record") from None
    return values

@logged
def metric_records(fd, size):
    """Count newlines in bounded chunks, without decoding every JSON record.

    A cached counter would need a crash/inode-coherent second durable state file.
    The <=32 MiB sequential cached scan is simpler and measurable at minute cadence.
    """
    count, offset = 0, 0
    while offset < size:
        data = os.pread(fd, min(1 << 20, size - offset), offset)
        if not data:
            raise Failure("metric_file_changed_during_count")
        count += data.count(b"\n")
        offset += len(data)
    return count

@logged
def metric_compact(ctx, name, row, keep, appended=False):
    """Newest complete records, bounded by BOTH count and bytes, including new row."""
    line = (json.dumps(row, separators=(",", ":")) + "\n").encode()
    if len(line) > API.METRICS_LIMIT:
        raise Failure("metric_record_size_limit")
    values = rows(ctx, name)
    if appended:
        values = values[:-1]
    if name == "alerts.jsonl":
        compact_alerts(ctx, values, row, keep)
        return
    retained, size = [line], len(line)
    for previous in reversed(values[-(keep - 1) :] if keep > 1 else []):
        encoded = (json.dumps(previous, separators=(",", ":")) + "\n").encode()
        if size + len(encoded) > API.METRICS_LIMIT:
            break
        retained.append(encoded)
        size += len(encoded)
    API.atomic(ctx.p.state / name, b"".join(reversed(retained)), 0o640)
    event("state", "metric_append", "compacted_by_byte_or_record_bound")

@logged
def alert_retention(records):
    """Separate the one durable queue-loss marker from ordinary alerts."""
    notice = None
    ordinary = []
    for item in records:
        if item.get("kind") != ALERT_RETENTION_KIND:
            ordinary.append(item)
            continue
        if notice is not None or set(item) != {"kind", "id", "evicted_uncheckpointed_total"}:
            raise Failure("alert_retention_invalid")
        total = item["evicted_uncheckpointed_total"]
        if type(total) is not int or not 1 <= total <= ALERT_RETENTION_MAX:
            raise Failure("alert_retention_invalid")
        alert_id(item)
        notice = item
    return notice, ordinary

@logged
def forwarded_ids(ctx):
    """Read the existing cursor format; absence is not a delivery checkpoint."""
    raw = ctx.read_state("alerts-forwarded.json", 1 << 20)
    if raw is None:
        return None
    try:
        sent = json.loads(raw)["sent"]
        if (
            not isinstance(sent, list)
            or len(sent) > 2000
            or any(not isinstance(a, str) or not 1 <= len(a) <= 128 for a in sent)
            or len(set(sent)) != len(sent)
        ):
            raise ValueError
    except (ValueError, KeyError, TypeError):
        raise Failure("alerts_forwarded_state_invalid") from None
    return sent

@logged
def alert_suffix(encoded, capacity, byte_budget):
    """Find the newest complete suffix within both queue limits."""
    used = 0
    start = len(encoded)
    while start > 0 and len(encoded) - start < capacity:
        size = len(encoded[start - 1])
        if used + size > byte_budget:
            break
        used += size
        start -= 1
    return start

@logged
def compact_alerts(ctx, values, row, keep):
    """Keep ordinary-alert capacity plus one loss marker within the same byte cap.

    Metadata must not steal a pending-event slot: a full recoverable outbox has
    to fit after a previous loss. The one marker is additional bounded metadata,
    never an alert or a delivery receipt. Byte pressure can still reduce capacity.
    """
    if row.get("kind") == ALERT_RETENTION_KIND:
        raise Failure("alert_retention_reserved")
    previous, ordinary = alert_retention(values)
    ordinary.append(row)
    encoded = [(json.dumps(item, separators=(",", ":")) + "\n").encode() for item in ordinary]
    sent = set(forwarded_ids(ctx) or ())

    start = alert_suffix(encoded, keep, API.METRICS_LIMIT)
    initial_evictions = sum(alert_id(item) not in sent for item in ordinary[:start])
    if previous is None and not initial_evictions:
        API.atomic(ctx.p.state / "alerts.jsonl", b"".join(encoded[start:]), 0o640)
        event("state", "metric_append", "compacted_by_byte_or_record_bound")
        return

    old_total = previous["evicted_uncheckpointed_total"] if previous else 0
    # Reserve the largest possible marker first, so the suffix and count are
    # selected once even when the counter crosses a decimal digit boundary.
    maximal = {
        "kind": ALERT_RETENTION_KIND,
        "id": ALERT_RETENTION_ID,
        "evicted_uncheckpointed_total": ALERT_RETENTION_MAX,
    }
    reserved = len((json.dumps(maximal, separators=(",", ":")) + "\n").encode())
    if reserved + len(encoded[-1]) > API.METRICS_LIMIT:
        raise Failure("alert_retention_capacity")
    start = alert_suffix(encoded, keep, API.METRICS_LIMIT - reserved)
    total = old_total + sum(alert_id(item) not in sent for item in ordinary[:start])
    if total > ALERT_RETENTION_MAX:
        raise Failure("alert_retention_overflow")
    notice = {
        "kind": ALERT_RETENTION_KIND,
        "id": ALERT_RETENTION_ID,
        "evicted_uncheckpointed_total": total,
    }
    marker = (json.dumps(notice, separators=(",", ":")) + "\n").encode()
    API.atomic(ctx.p.state / "alerts.jsonl", marker + b"".join(encoded[start:]), 0o640)
    event("state", "metric_append", "compacted_by_byte_or_record_bound")

@logged
def append(ctx, name, row, keep=METRIC_RETENTION):
    """Retain a newest suffix within 32 MiB; compact count at >120% of keep."""
    if type(keep) is not int or not 1 <= keep <= METRIC_RETENTION:
        raise Failure("invalid_metric_retention")
    if name == "alerts.jsonl" and row.get("kind") == ALERT_RETENTION_KIND:
        raise Failure("alert_retention_reserved")
    path = ctx.p.state / name
    line = (json.dumps(row, separators=(",", ":")) + "\n").encode()
    if len(line) > API.METRICS_LIMIT:
        raise Failure("metric_record_size_limit")
    with ctx.locked():
        fd = os.open(
            path, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640
        )
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise Failure("metric_file_not_regular")
            if info.st_size + len(line) > API.METRICS_LIMIT:
                metric_compact(ctx, name, row, keep)
                os.chown(path, -1, ctx.p.state.stat().st_gid)
                return
            if info.st_size and os.pread(fd, 1, info.st_size - 1) != b"\n":
                tail = os.pread(fd, min(info.st_size, 1 << 20), max(0, info.st_size - (1 << 20)))
                cut = tail.rfind(b"\n")
                if cut < 0 and info.st_size > len(tail):
                    raise Failure("corrupt_metric_tail")
                os.ftruncate(fd, info.st_size - len(tail) + cut + 1)
                event("state", "metric_append", "torn_tail_removed")
            view = memoryview(line)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise Failure("metric_append_no_progress")
                view = view[written:]
            os.fsync(fd)
            count = metric_records(fd, os.fstat(fd).st_size)
        finally:
            os.close(fd)
        os.chown(path, -1, ctx.p.state.stat().st_gid)
        if count > keep * 6 // 5:
            metric_compact(ctx, name, row, keep, appended=True)
            os.chown(path, -1, ctx.p.state.stat().st_gid)
            event("state", "metric_append", "compacted_by_record_count")

@logged
def alert_id(alert):
    if "id" in alert:
        if not isinstance(alert["id"], str) or not 1 <= len(alert["id"]) <= 128:
            raise Failure("invalid_alert_id")
        return alert["id"]
    return hashlib.sha256(json.dumps(alert, sort_keys=True).encode()).hexdigest()[:16]

@logged
def alert_message(alert):
    default = ("Yggdrasil: тревога", "Warning", "Нода yggdrasil-lab: {kind}")
    rule, priority, text = MESSAGES.get(alert.get("kind"), default)
    if alert.get("kind") == "ygg-peer-up" and alert.get("observation_gap"):
        text = (
            "Нода yggdrasil-lab: пир {peer} снова наблюдается на связи; "
            "был разрыв наблюдений, непрерывный простой не подтверждён; "
            "на связи {up} из {total}."
        )
    fields = {
        k: str(v)[:120]
        for k, v in alert.items()
        if k in ("peer", "minutes", "up", "total", "kind", "count")
    }
    if "peer" in fields:
        fields["peer"] = peer_label(alert["peer"])[:120]
    fields["errors"] = ", ".join(str(e)[:60] for e in alert.get("errors", [])[:5]) or "неизвестно"
    try:
        rule = rule.format(**fields)
    except KeyError:
        rule = rule.replace(" {peer}", "")
    try:
        output = text.format(**fields)
    except KeyError:
        output = "Нода yggdrasil-lab: тревога " + str(alert.get("kind"))[:60]
    return {
        "rule": rule,
        "priority": priority,
        "output": output[:300],
        "source": "yggctl",
        "time": str(alert.get("ts", ""))[:40],
    }


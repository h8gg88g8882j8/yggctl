"""telemetry.trend"""

"""Bounded, serialized samples and truthful missing-data reporting."""
from .patchable import API
from . import collect as _collect


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



TREND_MIN_SAMPLES = 8

TREND_MIN_SPAN_MINUTES = 30

TREND_RTT_FLOOR_MS = 5.0

TREND_RTT_RATIO = 3.0

TREND_AVAILABILITY_FLOOR = 10.0

TREND_ERROR_FLOOR = 10.0

TREND_PEER_COUNT_FLOOR = 1.0

TREND_STALE_FACTOR = 3.0

TREND_MAX_UNOBSERVED_SHARE = 4

def trend_number(value, audit=None):
    """Finite non-negative float or None; per-call or caller-owned batch logging.

    An explicit local audit avoids per-value journal flooding without thread-global
    trace toggles. trend_drift logs the completed batch, including rejection counts.
    Direct calls log their own entry/result; raw stored values are never logged.
    """
    standalone = audit is None
    if standalone:
        API.event("entry", "trend_number")
        audit = {"checked": 0, "invalid": 0}
    result = None
    if type(value) in (int, float):
        try:
            number = float(value)
        except OverflowError:
            pass
        else:
            if math.isfinite(number) and number >= 0:
                result = number
    audit["checked"] += 1
    audit["invalid"] += result is None
    if standalone:
        if result is None:
            API.event("state", "trend_number", "invalid_value_not_comparable")
        API.event("exit", "trend_number", "finite" if result is not None else "not_comparable")
    return result

@logged
def trend_halves(line):
    """Equal oldest/newest sample-count halves; drop an odd middle sample."""
    half = len(line) // 2
    if not half:
        return [], []
    return line[:half], line[-half:]

@logged
def trend_single(value):
    """A one-element series for an already-aggregated per-half share."""
    return [] if value is None else [value]

@logged
def trend_median(values):
    """Median of a nonempty finite non-negative series, without midpoint overflow."""
    ranked = sorted(values)
    middle = len(ranked) // 2
    if len(ranked) % 2:
        return ranked[middle]
    lower, upper = ranked[middle - 1], ranked[middle]
    return lower + (upper - lower) / 2

@logged
def trend_drift(
    before,
    after,
    floor,
    ratio=TREND_RTT_RATIO,
    worse_higher=True,
    counts=None,
    reasons=None,
    audit=None,
):
    """Finite median/MAD comparison; missing/overflow is explicitly not comparable."""
    audit = {"checked": 0, "invalid": 0} if audit is None else audit
    filtered: list[list[float]] = [[], []]
    for side, values in enumerate((before, after)):
        for value in values:
            number = API.trend_number(value, audit)
            if number is not None:
                filtered[side].append(number)
    API.event(
        "state",
        "trend_numeric_validation",
        f"checked={audit['checked']} invalid={audit['invalid']}",
    )
    if not filtered[0] or not filtered[1]:
        if reasons is not None:
            reasons.append("no_valid_samples_in_one_half")
        API.event("state", "trend_drift", "no_valid_samples_in_one_half")
        return None
    first, second = (API.trend_median(values) for values in filtered)
    delta = second - first
    spread = API.trend_median([abs(value - first) for value in filtered[0]])
    threshold = max(floor, ratio * spread)
    if not math.isfinite(threshold):
        if reasons is not None:
            reasons.append("arithmetic_overflow")
        API.event("state", "trend_drift", "arithmetic_overflow_not_comparable")
        return None
    if abs(delta) < threshold:
        verdict = "stable"
    elif (delta > 0) == worse_higher:
        verdict = "degrading"
    else:
        verdict = "improving"
    return {
        "first": round(first, 3),
        "second": round(second, 3),
        "delta": round(delta, 3),
        "threshold": round(threshold, 3),
        "samples": list(counts) if counts else [len(filtered[0]), len(filtered[1])],
        "verdict": verdict,
    }

@logged
def trend_peer_block(present, up, rtt, answered, unknown, valid=None):
    """Availability conditional on present known-status rows, not all answered rows.

    Absence from an answered sample is exposed, not silently equated to down.
    Strict schema-2 booleans are projections, not raw identity or origin proof.
    """
    valid = present if valid is None else valid
    missing: dict[str, list[str]] = {"availability": [], "rtt_ms": []}
    audit = {"checked": 0, "invalid": 0}
    availability = API.trend_drift(
        API.trend_single(100.0 * up[0] / valid[0] if valid[0] else None),
        API.trend_single(100.0 * up[1] / valid[1] if valid[1] else None),
        TREND_AVAILABILITY_FLOOR,
        worse_higher=False,
        counts=valid,
        reasons=missing["availability"],
        audit=audit,
    )
    latency = API.trend_drift(
        rtt[0], rtt[1], TREND_RTT_FLOOR_MS, reasons=missing["rtt_ms"], audit=audit
    )
    return {
        "availability": availability,
        "rtt_ms": latency,
        "observed": list(valid),
        "present": list(present),
        "answered": list(answered),
        "absent": [answered[side] - present[side] for side in range(2)],
        "invalid_states": [present[side] - valid[side] for side in range(2)],
        "unobserved": list(unknown),
        "not_comparable": missing,
        "numeric_validation": audit,
    }

@logged
def trend_peer(line, seen=None):
    """Per-endpoint reference path; seen flags must be exact observed booleans."""
    flags = [True] * len(line) if seen is None else list(seen)
    if len(flags) != len(line):
        raise Failure("trend_observation_length_mismatch")
    present, valid, up = [0, 0], [0, 0], [0, 0]
    rtt: list[list[Any]] = [[], []]
    answered, unknown = [0, 0], [0, 0]
    for side, (half, known) in enumerate(zip(API.trend_halves(line), API.trend_halves(flags))):
        answered[side] = sum(flag is True for flag in known)
        unknown[side] = len(half) - answered[side]
        for row, flag in zip(half, known):
            if flag is not True or row is None:
                continue
            present[side] += 1
            if type(row.get("up")) is bool:
                valid[side] += 1
                if row["up"] is True:
                    up[side] += 1
                    rtt[side].append(row.get("rtt"))
    return API.trend_peer_block(present, up, rtt, answered, unknown, valid)

def trend_window(values, future):
    """Timing and coverage facts of the stored window.

    Kept apart from the report so the aggregation below reads as one pass over
    the samples instead of a mix of statistics and dictionary construction.
    """
    stamps = [at for at, _ in values]
    intervals = [(b - a).total_seconds() / 60 for a, b in zip(stamps, stamps[1:]) if b > a]
    return {
        "stamps": stamps,
        "span": (stamps[-1] - stamps[0]).total_seconds() / 60,
        "cadence": statistics.median(intervals) if intervals else None,
        "age": (dt.datetime.now(dt.timezone.utc) - stamps[-1]).total_seconds() / 60,
        "observed": sum(row.get("peers_observed") is True for _, row in values),
        "future": len(future),
    }

def trend_report(values, facts, invalid, hours):
    """The report header: what the window is, before any comparison is attempted."""
    return {
        "window_hours": hours,
        "samples": len(values),
        "distinct_samples": len(set(facts["stamps"])),
        "invalid_records": invalid,
        "future_samples": facts["future"],
        "span_minutes": round(facts["span"], 1),
        "sampling_minutes": round(facts["cadence"], 3) if facts["cadence"] is not None else None,
        "collector_age_minutes": round(facts["age"], 1),
        "observed_samples": facts["observed"],
        "unobserved_samples": len(values) - facts["observed"],
        "peer_identity": "endpoint_not_key",
        "split": "equal_sample_count_drop_odd_middle",
        "rtt_semantics": "router_response_ewma_not_link_or_application_delay",
        "label_policy": "sanitized_display_endpoint_first_row_per_sample; unknown/colliding labels do not identify origins and are not compared",
        "provenance": {
            "status": "unverified_role_writable_history",
            "authenticated": False,
            "immutable_since_capture": False,
            "warning": "Stored metrics are role-writable and unauthenticated; trends do not attest origin, immutability or API truth.",
        },
        "collector": "stale",
        "verdict": "insufficient_history",
        "reasons": [],
        "node": {},
        "peers": [],
        "malformed_peer_samples": 0,
        "invalid_peer_rows": 0,
        "ambiguous_labels": [],
        "ambiguous_peer_samples": 0,
    }

def trend_collector_state(report, facts, values):
    """Collector freshness and the reasons the window is too thin to compare."""
    if facts["future"]:
        report["collector"] = "future_timestamp"
        report["reasons"].append("future_samples_present")
    elif facts["age"] > max(10.0, TREND_STALE_FACTOR * (facts["cadence"] or 1)):
        report["reasons"].append("collector_stale_beyond_sampling_interval")
    else:
        report["collector"] = "fresh"
    if len(set(facts["stamps"])) < TREND_MIN_SAMPLES:
        report["reasons"].append(f"fewer_than_{TREND_MIN_SAMPLES}_samples")
    if facts["span"] < TREND_MIN_SPAN_MINUTES:
        report["reasons"].append(f"span_below_{TREND_MIN_SPAN_MINUTES}_minutes")
    if not facts["observed"]:
        report["reasons"].append("no_observed_samples")
    elif facts["observed"] * TREND_MAX_UNOBSERVED_SHARE < len(values) * (
        TREND_MAX_UNOBSERVED_SHARE - 1
    ):
        report["reasons"].append(f"unobserved_above_{100 // TREND_MAX_UNOBSERVED_SHARE}_percent")

def trend_sample_labels(entries, series, report):
    """One sample's peer rows keyed by sanitized label, with per-label row counts.

    A label that covers more than one row in a sample covers more than one link,
    which the caller treats as not comparable.
    """
    named: dict[str, dict[str, Any]] = {}
    seen: dict[str, int] = {}
    labels = series["labels"]
    for entry in entries:
        if not isinstance(entry, dict):
            report["invalid_peer_rows"] += 1
            continue
        raw = entry.get("r")
        if isinstance(raw, str):
            if raw not in labels:
                labels[raw] = API.peer_label(raw)
            name = labels[raw]
        else:
            name = API.peer_label(raw)
        seen[name] = seen.get(name, 0) + 1
        named.setdefault(name, entry)
    return named, seen

def trend_accumulate(named, series, side):
    """Fold one sample's labelled rows into the per-label series of that half."""
    for name, entry in named.items():
        if name not in series["present"]:
            series["present"][name] = [0, 0]
            series["valid"][name] = [0, 0]
            series["up"][name] = [0, 0]
            series["rtt"][name] = [[], []]
        series["present"][name][side] += 1
        if type(entry.get("up")) is bool:
            series["valid"][name][side] += 1
            if entry["up"] is True:
                series["up"][name][side] += 1
                series["rtt"][name][side].append(entry.get("rtt"))

def trend_sample_series(row, series, side, report):
    """Fold one sample into the per-side counters and the per-label series."""
    series["node_fail"][side].append(1.0 if row.get("errors") else 0.0)
    if row.get("peers_observed") is not True:
        series["unknown"][side] += 1
        return
    series["answered"][side] += 1
    series["node_up"][side].append(row.get("up"))
    entries = row.get("peers")
    if not isinstance(entries, list):
        report["malformed_peer_samples"] += 1
        return
    named, seen = API.trend_sample_labels(entries, series, report)
    if any(count > 1 for count in seen.values()):
        # One sanitized label can cover several links (different WebSocket
        # paths at one endpoint). Those rows observe different links and
        # must not be fused into one comparable series -- the same rule the
        # alert contract applies to duplicate labels. Other labels continue.
        series["ambiguous_samples"] += 1
        series["ambiguous"].update(name for name, count in seen.items() if count > 1)
    API.trend_accumulate(named, series, side)

def trend_peer_series(values, report):
    """One pass over the samples: per-side node counters and per-label series."""
    half, newer = len(values) // 2, len(values) - len(values) // 2
    series: dict[str, Any] = {
        "node_up": [[], []],
        "node_fail": [[], []],
        "present": {},
        "valid": {},
        "up": {},
        "rtt": {},
        "answered": [0, 0],
        "unknown": [0, 0],
        "labels": {},
        "ambiguous": set(),
        "ambiguous_samples": 0,
    }
    for position, (_, row) in enumerate(values):
        side = 0 if position < half else 1 if position >= newer else -1
        if side < 0:
            continue
        API.trend_sample_series(row, series, side, report)
    return series

def trend_node_block(series):
    """Node-level drift, plus the reasons a node metric could not be compared."""
    failures = [100.0 * sum(part) / len(part) if part else None for part in series["node_fail"]]
    missing: dict[str, list[str]] = {"up_peers": [], "error_rate": []}
    audit = {"checked": 0, "invalid": 0}
    return {
        "up_peers": API.trend_drift(
            series["node_up"][0],
            series["node_up"][1],
            TREND_PEER_COUNT_FLOOR,
            worse_higher=False,
            reasons=missing["up_peers"],
            audit=audit,
        ),
        "error_rate": API.trend_drift(
            API.trend_single(failures[0]),
            API.trend_single(failures[1]),
            TREND_ERROR_FLOOR,
            counts=[len(series["node_fail"][0]), len(series["node_fail"][1])],
            reasons=missing["error_rate"],
            audit=audit,
        ),
        "not_comparable": missing,
        "numeric_validation": audit,
    }

def trend_peer_details(series):
    """One comparable-or-not block per label, sorted by label."""
    details = []
    for name in sorted(series["present"]):
        detail = API.trend_peer_block(
            series["present"][name],
            series["up"][name],
            series["rtt"][name],
            series["answered"],
            series["unknown"],
            series["valid"][name],
        )
        if name in series["ambiguous"]:
            # Fused halves of several links are not one comparable series, so no
            # drift claim is made for this label; counts stay visible.
            detail["availability"] = None
            detail["rtt_ms"] = None
            detail["not_comparable"]["availability"].append("ambiguous_peer_label")
            detail["not_comparable"]["rtt_ms"].append("ambiguous_peer_label")
        detail["peer"] = name
        details.append(detail)
    return details

def trend_verdict(report, observed_drifts, ambiguous_samples):
    """The one verdict the report carries, from the reasons and the drifts.

    The "nothing comparable was observed" reason is decided on the observed
    drifts alone: the node error rate is always a number, so including it here
    would report a comparable history that does not exist.
    """
    if not any(item is not None for item in observed_drifts):
        report["reasons"].append("no_comparable_observed_metric")
    if report["malformed_peer_samples"]:
        report["reasons"].append("malformed_peer_samples")
    if ambiguous_samples:
        report["reasons"].append("ambiguous_peer_labels")
    drifts = observed_drifts + [report["node"]["error_rate"]]
    verdicts = [item["verdict"] for item in drifts if item is not None]
    if report["reasons"]:
        report["verdict"] = "insufficient_history"
    elif "degrading" in verdicts:
        report["verdict"] = "degrading"
    elif "improving" in verdicts:
        report["verdict"] = "improving"
    else:
        report["verdict"] = "stable"
    return report["verdict"]

@logged
def trend(ctx, hours=24):
    """One bounded history snapshot; one fused aggregation, no API calls or writes."""
    future: list[dt.datetime] = []
    values, invalid = API.window(ctx, hours, future=future)
    facts = API.trend_window(values, future)
    report = API.trend_report(values, facts, invalid, hours)
    API.trend_collector_state(report, facts, values)
    series = API.trend_peer_series(values, report)
    report["node"] = API.trend_node_block(series)
    report["peers"] = API.trend_peer_details(series)
    report["ambiguous_labels"] = sorted(series["ambiguous"])
    report["ambiguous_peer_samples"] = series["ambiguous_samples"]
    observed_drifts = [report["node"]["up_peers"]]
    observed_drifts.extend(item["availability"] for item in report["peers"])
    observed_drifts.extend(item["rtt_ms"] for item in report["peers"])
    API.trend_verdict(report, observed_drifts, series["ambiguous_samples"])
    API.event(
        "state", "trend", f"samples={len(values)} future={len(future)} verdict={report['verdict']}"
    )
    return report

@logged
def trend_line(detail):
    """One comparable line per metric; detailed absence/overflow reasons in report."""
    if detail is None:
        return "not_comparable (no valid samples in one half or arithmetic overflow)"
    return (
        f"{detail['first']} -> {detail['second']} delta={detail['delta']} "
        f"threshold={detail['threshold']} n={detail['samples'][0]}/{detail['samples'][1]} "
        f"verdict={detail['verdict']}"
    )

@logged
def trend_text(report):
    """Visible trust/measurement semantics on the deterministic text projection."""
    lines = [
        f"window={report['window_hours']}h samples={report['samples']} distinct={report['distinct_samples']} "
        f"observed={report['observed_samples']} unobserved={report['unobserved_samples']} "
        f"invalid_records={report['invalid_records']} future_samples={report['future_samples']} "
        f"span={report['span_minutes']}min sampling={report['sampling_minutes']}min "
        f"collector_age={report['collector_age_minutes']}min collector={report['collector']}",
        "provenance=unverified_role_writable_history authenticated=false immutable_since_capture=false",
        report["provenance"]["warning"],
        f"peer_identity={report['peer_identity']}; {report['label_policy']}",
        f"split={report['split']} (NOT equal elapsed-time halves or wall-clock uptime)",
        f"RTT={report['rtt_semantics']} (protocol router-response EWMA, NOT link/application delay)",
        f"ambiguous_labels={report['ambiguous_labels']} ambiguous_peer_samples={report['ambiguous_peer_samples']}",
        f"node up_peers: {API.trend_line(report['node']['up_peers'])}",
        f"node error_rate%: {API.trend_line(report['node']['error_rate'])}",
        f"node not_comparable={report['node']['not_comparable']} numeric_validation={report['node']['numeric_validation']}",
    ]
    for peer in report["peers"]:
        lines.append(f"{peer['peer']}: availability% {API.trend_line(peer['availability'])}")
        lines.append(f"{peer['peer']}: rtt_ms {API.trend_line(peer['rtt_ms'])}")
        lines.append(
            f"{peer['peer']}: present={peer['present']} answered={peer['answered']} "
            f"absent={peer['absent']} invalid_states={peer['invalid_states']} "
            f"not_comparable={peer['not_comparable']} numeric_validation={peer['numeric_validation']}"
        )
    if report["reasons"]:
        lines.append(f"trend={report['verdict']} reasons={','.join(report['reasons'])}")
    else:
        lines.append(f"trend={report['verdict']}")
    lines.append(
        "sample-count median drift/MAD policy thresholds; NOT statistical confidence, link health or a gate"
    )
    return lines


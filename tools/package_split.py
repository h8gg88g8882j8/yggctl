#!/usr/bin/env python3
"""Split a flat module into a package by function name groups (faithful source move)."""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

TELEMETRY_GROUPS = {
    "peers": ["peer_label", "ambiguous_peer_labels"],
    "storage": [
        "rows",
        "metric_records",
        "metric_compact",
        "append",
        "alert_retention",
        "forwarded_ids",
        "alert_suffix",
        "compact_alerts",
        "alert_id",
        "alert_message",
    ],
    "alerts": [
        "load_peer_state",
        "save_peer_state",
        "mark_alert_admission_incomplete",
        "warn_alert_admission",
        "sync_alert_queue",
        "flush_peer_alerts",
        "peer_alerts",
        "stage_health_alert",
        "peer_alert_retain_unobserved",
        "peer_alert_sample_peers",
        "peer_alert_retain_ambiguous",
        "peer_alert_track_observed_peer",
        "peer_alert_merge_ambiguous_reconnects",
        "peer_alert_persist",
        "stage_peer_alerts",
        "reconnects",
    ],
    "notify": ["notify_state", "notify", "forward"],
    "collect": ["collect", "window", "stats", "watch"],
    "trend": [
        "trend_number",
        "trend_halves",
        "trend_single",
        "trend_median",
        "trend_drift",
        "trend_peer_block",
        "trend_peer",
        "trend_window",
        "trend_report",
        "trend_collector_state",
        "trend_sample_labels",
        "trend_accumulate",
        "trend_sample_series",
        "trend_peer_series",
        "trend_node_block",
        "trend_peer_details",
        "trend_verdict",
        "trend",
        "trend_line",
        "trend_text",
    ],
}

TELEMETRY_CONSTS = {
    "storage": ("ALERT_RETENTION_KIND", "ALERT_RETENTION_MAX", "ALERT_RETENTION_ID", "MESSAGES"),
    "alerts": (
        "PEER_DOWN_MINUTES",
        "UNSTABLE_RECONNECTS",
        "UNSTABLE_REPEAT_HOURS",
        "PEER_STATE_LIMIT",
        "PEER_PENDING_LIMIT",
        "PEER_ALERT_KINDS",
        "HEALTH_ALERT_KIND",
    ),
    "notify": ("SENDER", "FORWARD_BUDGET", "FORWARD_RESERVE"),
    "trend": tuple(
        name
        for name in (
            "TREND_MIN_SAMPLES",
            "TREND_MIN_SPAN_MINUTES",
            "TREND_RTT_FLOOR_MS",
            "TREND_RTT_RATIO",
            "TREND_AVAILABILITY_FLOOR",
            "TREND_ERROR_FLOOR",
            "TREND_PEER_COUNT_FLOOR",
            "TREND_STALE_FACTOR",
            "TREND_MAX_UNOBSERVED_SHARE",
        )
    ),
}

CHECKS_GROUPS = {
    "runtime": [
        "peers",
        "identified",
        "service_gate",
        "peer_gate",
        "multicast_gate",
        "tun_gate",
        "collector_freshness",
        "timer_gate",
    ],
    "policy": [
        "policy",
        "baseline",
        "policy_keys",
        "trusted",
        "state_member",
        "state_custody",
        "policy_gate",
        "nft_gate",
        "masked_gate",
        "nft_relay_gate",
    ],
    "integrity": ["integrity"],
    "underlay": [
        "quic_udp_socket_rows",
        "quic_own_udp_rows",
        "quic_live_peer_targets",
        "quic_parse_own_udp",
        "quic_conntrack_matches",
        "quic_socket_proof",
        "tcp_peer_marks",
        "underlay",
        "guard",
        "sockets",
    ],
    "check": ["check"],
    "display": ["runtime_display", "quic_relay", "relay_display", "tunnel_addresses"],
}

CHECKS_CONSTS = {
    "runtime": ("COLLECTOR_MAX_AGE_MINUTES",),
    "underlay": ("UDP_WILDCARD_BINDS", "UDP_WILDCARD_REMOTES"),
}


def module_for(name: str, groups: dict[str, list[str]]) -> str:
    for mod, names in groups.items():
        if name in names:
            return mod
    raise KeyError(name)


def split_source(source: str, groups: dict[str, list[str]], const_map: dict[str, tuple[str, ...]]):
    module = ast.parse(source)
    lines = source.splitlines(keepends=True)
    def start_line(node: ast.AST) -> int:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.decorator_list:
            return min(d.lineno for d in node.decorator_list)
        return node.lineno

    first = min(
        start_line(n)
        for n in module.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Assign))
    )
    header = "".join(lines[: first - 1])
    assigns: dict[str, str] = {}
    functions: dict[str, str] = {}
    for node in module.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = node.lineno - 1
            if node.decorator_list:
                start = min(d.lineno for d in node.decorator_list) - 1
            functions[node.name] = "".join(lines[start : node.end_lineno])
        elif isinstance(node, ast.Assign):
            text = "".join(lines[node.lineno - 1 : node.end_lineno])
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assigns[target.id] = text
    used = {n for names in groups.values() for n in names}
    if set(functions) != used:
        raise SystemExit(f"function mismatch {set(functions) ^ used}")
    bodies: dict[str, list[str]] = {mod: [] for mod in groups}
    for mod, markers in const_map.items():
        for marker in markers:
            if marker in assigns:
                bodies[mod].append(assigns[marker] + "\n")
    for func, mod in ((f, module_for(f, groups)) for f in functions):
        bodies[mod].append(functions[func] + "\n")
    return header, bodies


def write_pkg(
    pkg: Path,
    header: str,
    groups: dict[str, list[str]],
    bodies: dict[str, list[str]],
    cross: dict[str, str],
    const_map: dict[str, tuple[str, ...]],
) -> None:
    pkg.mkdir(parents=True, exist_ok=True)
    for mod in groups:
        parts = [f'"""{pkg.name}.{mod}"""\n\n', header, "\n"]
        if mod in cross:
            parts.append(cross[mod] + "\n")
        parts.append("".join(bodies[mod]))
        (pkg / f"{mod}.py").write_text("".join(parts))
    exports: list[str] = []
    for mod, markers in const_map.items():
        for marker in markers:
            exports.append(f"from .{mod} import {marker}  # noqa: F401")
    for mod, names in groups.items():
        for name in names:
            exports.append(f"from .{mod} import {name}  # noqa: F401")
    (pkg / "__init__.py").write_text(
        f'"""{pkg.name} package."""\n\n' + "\n".join(exports) + "\n"
    )


TELEMETRY_CROSS = {
    "storage": "from .peers import peer_label\n",
}

CHECKS_CROSS = {
    "underlay": "from .runtime import peers, identified\n",
    "integrity": "from .policy import trusted, state_member\n",
    "check": (
        "from .runtime import (\n"
        "    collector_freshness,\n"
        "    peer_gate,\n"
        "    multicast_gate,\n"
        "    tun_gate,\n"
        "    service_gate,\n"
        "    timer_gate,\n"
        ")\n"
        "from .policy import policy_gate, nft_gate, masked_gate, state_custody\n"
        "from .underlay import underlay, guard, sockets\n"
        "from .display import relay_display, tunnel_addresses, runtime_display\n"
    ),
}


def telemetry_patchable() -> tuple[str, ...]:
    names = {
        "rows",
        "append",
        "atomic",
        "timestamp",
        "event",
        "peers",
        "identified",
        "METRICS_LIMIT",
        "METRIC_RETENTION",
        "PEER_PENDING_LIMIT",
        "PEER_STATE_LIMIT",
        "save_peer_state",
        "flush_peer_alerts",
        "sync_alert_queue",
        "peer_alerts",
        "stage_health_alert",
        "load_peer_state",
        "warn_alert_admission",
        "mark_alert_admission_incomplete",
        "alert_id",
        "forwarded_ids",
        "alert_retention",
        "alert_message",
        "peer_label",
        "ambiguous_peer_labels",
        "notify_state",
        "compact_alerts",
        "metric_compact",
        "rows",
        "reconnects",
        "stage_peer_alerts",
        "trend_drift",
        "window",
    }
    for group in TELEMETRY_GROUPS.values():
        names.update(group)
    return tuple(sorted(names))


def install_patchable(pkg: Path) -> None:
    (pkg / "patchable.py").write_text(
        '''"""Forward attribute access to the package namespace for monkeypatch tests."""

import importlib


class _API:
    __slots__ = ()

    def __getattr__(self, name: str):
        return getattr(importlib.import_module("telemetry"), name)


API = _API()
'''
    )
    for path in pkg.glob("*.py"):
        if path.name in ("__init__.py", "patchable.py", "peers.py", "storage.py"):
            continue
        text = path.read_text()
        if "from .patchable import API" not in text:
            lines = text.splitlines(keepends=True)
            insert = 0
            if lines and lines[0].startswith('"""'):
                for i, line in enumerate(lines[1:], 1):
                    if line.strip().endswith('"""'):
                        insert = i + 1
                        break
            while insert < len(lines) and (
                lines[insert].startswith("import ") or lines[insert].startswith("from ")
            ):
                insert += 1
            lines.insert(insert, "from .patchable import API\n\n")
            text = "".join(lines)
        text = re.sub(r"^from \.storage import[^\n]*\n", "", text, flags=re.MULTILINE)
        text = re.sub(r"^from \.peers import[^\n]*\n", "", text, flags=re.MULTILINE)
        text = re.sub(r"^from \.alerts import[^\n]*\n", "", text, flags=re.MULTILINE)
        text = re.sub(r"^from checks import[^\n]*\n", "", text, flags=re.MULTILINE)
        text = re.sub(r"^from \.collect import[^\n]*\n", "", text, flags=re.MULTILINE)
        for name in telemetry_patchable():
            text = re.sub(rf"(?<!def )(?<!\.)\b{name}\(", f"API.{name}(", text)
        limit_names = ("PEER_PENDING_LIMIT", "PEER_STATE_LIMIT", "METRICS_LIMIT")
        if path.name in ("alerts.py", "notify.py", "collect.py", "storage.py"):
            lines_out: list[str] = []
            for line in text.splitlines(keepends=True):
                stripped = line.lstrip()
                if (
                    re.match(r"^\s+[A-Z_][A-Z0-9_]*,?\s*$", line)
                    or stripped.startswith(("from ", "import "))
                    or re.match(r"^[A-Z_][A-Z0-9_]*\s*=", stripped)
                ):
                    lines_out.append(line)
                    continue
                for name in limit_names:
                    line = re.sub(rf"(?<![.\w]){name}\b", f"API.{name}", line)
                lines_out.append(line)
            text = "".join(lines_out)
            for name in limit_names:
                text = re.sub(rf"^{name} =", f"{name} =", text, flags=re.MULTILINE)
        if path.name == "trend.py":
            text = text.replace("values, invalid = window(ctx,", "values, invalid = _collect.window(ctx,")
            if "import collect as _collect" not in text:
                text = text.replace(
                    "from .patchable import API\n\n",
                    "from .patchable import API\nfrom . import collect as _collect\n\n",
                )
        path.write_text(text)


def main(argv: list[str]) -> None:
    if len(argv) != 4:
        raise SystemExit("usage: package_split.py <src.py> <package_dir> <telemetry|checks>")
    src = Path(argv[1])
    pkg = Path(argv[2])
    kind = argv[3]
    source = src.read_text()
    if kind == "telemetry":
        header, bodies = split_source(source, TELEMETRY_GROUPS, TELEMETRY_CONSTS)
        write_pkg(pkg, header, TELEMETRY_GROUPS, bodies, TELEMETRY_CROSS, TELEMETRY_CONSTS)
        exports_extra = (pkg / "__init__.py").read_text()
        legacy = "\n# Legacy flat-module names for tests and monkeypatch.\n" + header.split('"""', 2)[-1]
        if "import os" not in exports_extra:
            (pkg / "__init__.py").write_text(exports_extra.rstrip() + legacy)
        install_patchable(pkg)
    else:
        header, bodies = split_source(source, CHECKS_GROUPS, CHECKS_CONSTS)
        write_pkg(pkg, header, CHECKS_GROUPS, bodies, CHECKS_CROSS, CHECKS_CONSTS)
        exports_extra = (pkg / "__init__.py").read_text()
        legacy = "\n# Legacy flat-module names for tests and monkeypatch.\n" + header.split('"""', 2)[-1]
        if "import os" not in exports_extra:
            (pkg / "__init__.py").write_text(exports_extra.rstrip() + legacy)
    backup = src.with_suffix(src.suffix + ".bak")
    backup.write_text(source)
    src.unlink()


if __name__ == "__main__":
    main(sys.argv)

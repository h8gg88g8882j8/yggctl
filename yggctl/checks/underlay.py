"""checks.underlay"""

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

from .runtime import peers, identified

UDP_WILDCARD_BINDS = ("*", "0.0.0.0")  # nosec B104

UDP_WILDCARD_REMOTES = tuple(f"{address}:*" for address in UDP_WILDCARD_BINDS)

def quic_udp_socket_rows(socket_lines):
    rows = []
    for line in socket_lines:
        fields = line.split()
        if fields and fields[0] == "udp":
            rows.append((line, fields))
    return rows

def quic_own_udp_rows(udp_rows, pids):
    return [
        (line, fields)
        for line, fields in udp_rows
        if any(re.search(rf"\bpid={pid},", line) for pid in pids)
    ]

def quic_live_peer_targets(ctx, pids):
    targets = {}
    for stack, pid in ((False, pids[0]), (True, pids[1])):
        configured = {}
        for uri in ctx.config("yggstack.conf" if stack else "yggdrasil-lab.conf")["Peers"]:
            if not uri.startswith("quic://"):
                continue
            _, remote = peer_uri(uri)
            parsed = urllib.parse.urlsplit(uri)
            selector = (remote, parsed.path)
            pin = urllib.parse.parse_qs(parsed.query)["key"][0].lower()
            if selector in configured:
                raise Failure("underlay_quic_peer_ambiguous")
            configured[selector] = pin
        live = set()
        for peer in peers(ctx, stack=stack):
            uri = peer["remote"]
            parsed = urllib.parse.urlsplit(uri)
            if (
                parsed.scheme != "quic"
                or parsed.query
                or parsed.fragment
                or not identified(peer)
                or peer.get("inbound")
            ):
                continue
            selector = (endpoint(uri), parsed.path)
            if peer["key"].lower() == configured.get(selector):
                remote = selector[0]
                live.add(remote)
        targets[pid] = live
    return targets

def quic_parse_own_udp(fields):
    try:
        local_ip, port = fields[4].rsplit(":", 1)
        if not port.isdecimal() or not 0 < int(port) <= 65535:
            raise ValueError
        if local_ip not in UDP_WILDCARD_BINDS:
            ipaddress.IPv4Address(local_ip)
    except ValueError:
        raise Failure("underlay_quic_socket_ambiguous") from None
    return local_ip, port

def quic_conntrack_matches(conn_lines, port, local_ip, pid, targets, mode):
    matches = []
    for record in conn_lines:
        parts = record.split()
        if not parts or parts[0] != "udp":
            continue
        original = re.search(
            r"\bsrc=([^ ]+) dst=([^ ]+) sport=(\d+) dport=(\d+)(?:\s|$)", record
        )
        if not original or original[3] != port:
            continue
        src, dst, sport, dport = original.groups()
        if local_ip not in UDP_WILDCARD_BINDS and src != local_ip:
            continue
        try:
            ipaddress.IPv4Address(src)
            ipaddress.IPv4Address(dst)
        except ValueError:
            raise Failure("underlay_quic_socket_ambiguous") from None
        marks = re.findall(r"\bmark=(\d+)\b", record)
        if (
            f"{dst}:{dport}" not in targets[pid]
            or len(marks) != 1
            or (marks[0] == "3905") != (mode == "direct")
        ):
            raise Failure("underlay_quic_peer_or_mark_mismatch")
        matches.append(record)
    return matches

@logged
def quic_socket_proof(ctx, pids, socket_lines, conn_lines, mode):
    """Correlate observed outbound QUIC, own UDP port and ORIGINAL IPv4 tuple.

    This is a sampled state check. It cannot attest prior/future packets or kernel
    file-descriptor history. Any port-sharing or unmatched own UDP fails closed.
    """
    udp_rows = quic_udp_socket_rows(socket_lines)
    own = quic_own_udp_rows(udp_rows, pids)
    proof = dict.fromkeys(pids, 0)
    if not own:
        return proof
    targets = quic_live_peer_targets(ctx, pids)
    used_ports = set()
    for line, fields in own:
        owners = {int(p) for p in re.findall(r"\bpid=(\d+),", line)}
        if (
            len(fields) < 6
            or len(owners) != 1
            or fields[1] != "UNCONN"
            or fields[5] not in UDP_WILDCARD_REMOTES
        ):
            raise Failure("underlay_quic_socket_ambiguous")
        pid = next(iter(owners))
        local_ip, port = quic_parse_own_udp(fields)
        if port in used_ports or any(
            other_line != line and re.search(rf":{re.escape(port)}(?:\s|$)", other_fields[4])
            for other_line, other_fields in udp_rows
            if len(other_fields) >= 5
        ):
            raise Failure("underlay_quic_socket_ambiguous")
        used_ports.add(port)
        matches = quic_conntrack_matches(conn_lines, port, local_ip, pid, targets, mode)
        if len(matches) != 1:
            raise Failure("underlay_quic_socket_proof_missing_or_ambiguous")
        proof[pid] += 1
    return proof

@logged
def underlay(ctx):
    mode = ctx.mode()
    pids = [int(ctx.unit(u).get("MainPID", "0")) for u in (NODE, STACK)]
    if not all(p > 0 for p in pids):
        raise Failure("missing_runtime_pid")
    split_list = ctx.run(["/usr/bin/mullvad", "split-tunnel", "list"]).stdout.decode()
    exclusions = set(re.findall(r"(?m)^\s*(\d+)\s*$", split_list))
    if any((str(p) in exclusions) != (mode == "direct") for p in pids):
        raise Failure("underlay_pid_exclusion_mismatch")
    # Bind conntrack evidence to the local/remote four-tuple of each own socket.
    sockets = ctx.run(["/usr/bin/ss", "-H", "-antup"]).stdout.decode().splitlines()
    conn = ctx.run(["/usr/sbin/conntrack", "-L"]).stdout.decode().splitlines()
    proof = quic_socket_proof(ctx, pids, sockets, conn, mode)
    for line in sockets:
        fields = line.split()
        if len(fields) < 6:
            continue
        if fields[0] == "udp" or fields[1] == "LISTEN":
            continue
        for pid in pids:
            if not re.search(rf"\bpid={pid},", line):
                continue
            local, remote = fields[4:6]
            try:
                src, sport = local.rsplit(":", 1)
                dst, dport = remote.rsplit(":", 1)
            except ValueError:
                continue
            prefix = f"src={src} dst={dst} sport={sport} dport={dport}"
            matches = [r for r in conn if prefix + " " in r and r.split()[0] == fields[0]]
            if any(bool(re.search(r"\bmark=3905\b", r)) == (mode == "direct") for r in matches):
                proof[pid] += 1
    tcp_peer_marks(ctx, pids, sockets, conn, mode)
    if not all(proof.values()):
        raise Failure("underlay_own_socket_proof_missing")
    return {"mode": mode, "own_connections": list(proof.values())}

@logged
def guard(ctx):
    if ctx.require_root:
        state_custody(ctx)
    for name in ("yggdrasil-lab.conf", "yggstack.conf"):
        config = ctx.config(name)
        if safe_config(config):
            raise Failure("unsafe_config")
        expected = ctx.p.node_sock if name.startswith("yggdrasil") else ctx.p.stack_sock
        if config.get("AdminListen") != f"unix://{expected}":
            raise Failure("admin_config_mismatch")
    for name in KEYS:
        s = (ctx.p.etc / name).lstat()
        if not stat.S_ISREG(s.st_mode) or stat.S_IMODE(s.st_mode) != 0o600 or s.st_uid != 0:
            raise Failure("key_permissions")
    for sock in (ctx.p.node_sock, ctx.p.stack_sock):
        s, d = sock.lstat(), sock.parent.lstat()
        # DynamicUser owns its runtime directory; root can access it, others cannot.
        if not stat.S_ISSOCK(s.st_mode) or stat.S_IMODE(d.st_mode) != 0o700:
            raise Failure("admin_socket_permissions")
    return "hardened config and key custody"

@logged
def sockets(ctx):
    lines = ctx.run(["/usr/bin/ss", "-H", "-antup"]).stdout.decode().splitlines()
    pids = [int(ctx.unit(u).get("MainPID", "0")) for u in (NODE, STACK)]
    own = [
        line
        for line in lines
        if line.startswith("tcp ")
        and " LISTEN " in line
        and any(re.search(rf"\bpid={p},", line) for p in pids if p)
    ]
    if len(own) != 1 or own[0].split()[4] != "127.0.0.1:1080" or f"pid={pids[1]}," not in own[0]:
        raise Failure("unexpected_node_stack_listener")
    if any(
        line.startswith("udp ") and any(re.search(rf"\bpid={p},", line) for p in pids if p)
        for line in lines
    ):
        conn = ctx.run(["/usr/sbin/conntrack", "-L"]).stdout.decode().splitlines()
        quic_socket_proof(ctx, pids, lines, conn, ctx.mode())
    return "SOCKS loopback only"

@logged
def tcp_peer_marks(ctx, pids, sockets, conn, mode):
    """Reject contradictory/missing evidence for configured outbound TCP peers.

    Only the original conntrack direction can prove an outbound connection.
    Local SOCKS clients, listeners and unrelated records are outside this check.
    This is a point-in-time observation, not a route or lifetime guarantee.
    """
    for pid, name in zip(pids, ("yggdrasil-lab.conf", "yggstack.conf")):
        destinations = {
            endpoint(uri)
            for uri in ctx.config(name)["Peers"]
            if uri.startswith(("tcp://", "tls://", "ws://", "wss://"))
        }
        for line in sockets:
            fields = line.split()
            if (
                len(fields) < 6
                or fields[:2] != ["tcp", "ESTAB"]
                or not re.search(rf"\bpid={pid},", line)
                or fields[5] not in destinations
                or (name == "yggstack.conf" and fields[4] == "127.0.0.1:1080")
            ):
                continue
            src, sport = fields[4].rsplit(":", 1)
            dst, dport = fields[5].rsplit(":", 1)
            expected = (src, dst, sport, dport)
            marks = []
            for row in conn:
                original = re.search(r"\bsrc=(\S+) dst=(\S+) sport=(\d+) dport=(\d+)", row)
                if (
                    not row.startswith("tcp ")
                    or " ESTABLISHED " not in row
                    or original is None
                    or original.groups() != expected
                ):
                    continue
                mark = re.findall(r"\bmark=(\d+)\b", row)
                if len(mark) != 1:
                    raise Failure("underlay_peer_socket_proof_missing")
                marks.append(mark[0] == "3905")
            if not marks:
                raise Failure("underlay_peer_socket_proof_missing")
            if any(mark != (mode == "direct") for mark in marks):
                raise Failure("underlay_peer_mark_mismatch")


"""checks package."""

from .runtime import COLLECTOR_MAX_AGE_MINUTES  # noqa: F401
from .underlay import UDP_WILDCARD_BINDS  # noqa: F401
from .underlay import UDP_WILDCARD_REMOTES  # noqa: F401
from .runtime import peers  # noqa: F401
from .runtime import identified  # noqa: F401
from .runtime import service_gate  # noqa: F401
from .runtime import peer_gate  # noqa: F401
from .runtime import multicast_gate  # noqa: F401
from .runtime import tun_gate  # noqa: F401
from .runtime import collector_freshness  # noqa: F401
from .runtime import timer_gate  # noqa: F401
from .policy import policy  # noqa: F401
from .policy import baseline  # noqa: F401
from .policy import policy_keys  # noqa: F401
from .policy import trusted  # noqa: F401
from .policy import state_member  # noqa: F401
from .policy import state_custody  # noqa: F401
from .policy import policy_gate  # noqa: F401
from .policy import nft_gate  # noqa: F401
from .policy import masked_gate  # noqa: F401
from .policy import nft_relay_gate  # noqa: F401
from .integrity import integrity  # noqa: F401
from .underlay import quic_udp_socket_rows  # noqa: F401
from .underlay import quic_own_udp_rows  # noqa: F401
from .underlay import quic_live_peer_targets  # noqa: F401
from .underlay import quic_parse_own_udp  # noqa: F401
from .underlay import quic_conntrack_matches  # noqa: F401
from .underlay import quic_socket_proof  # noqa: F401
from .underlay import tcp_peer_marks  # noqa: F401
from .underlay import underlay  # noqa: F401
from .underlay import guard  # noqa: F401
from .underlay import sockets  # noqa: F401
from .check import check  # noqa: F401
from .display import runtime_display  # noqa: F401
from .display import quic_relay  # noqa: F401
from .display import relay_display  # noqa: F401
from .display import tunnel_addresses  # noqa: F401
# Legacy flat-module names for tests and monkeypatch.


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

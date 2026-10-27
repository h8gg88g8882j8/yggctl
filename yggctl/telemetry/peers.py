"""telemetry.peers"""

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



@logged
def peer_label(value):
    """Credential-free literal endpoint; retain only proven public URI options.

    This is an output boundary, NOT permission to add credential-bearing peers.
    Existing queues/history are not rewritten: their IDs and delivery cursors
    must stay stable. Rendering applies this boundary again for legacy alerts.
    """
    return public_peer_uri(value) or "unknown-peer"

@logged
def ambiguous_peer_labels(peers):
    """Public labels are display-safe, but do not uniquely identify every link."""
    counts = Counter(
        peer_label(p["r"]) for p in peers if isinstance(p.get("r"), str) and p.get("r")
    )
    return {label for label, count in counts.items() if count > 1}


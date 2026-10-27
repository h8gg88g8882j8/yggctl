"""telemetry package."""

from .storage import ALERT_RETENTION_KIND  # noqa: F401
from .storage import ALERT_RETENTION_MAX  # noqa: F401
from .storage import ALERT_RETENTION_ID  # noqa: F401
from .storage import MESSAGES  # noqa: F401
from .alerts import PEER_DOWN_MINUTES  # noqa: F401
from .alerts import UNSTABLE_RECONNECTS  # noqa: F401
from .alerts import UNSTABLE_REPEAT_HOURS  # noqa: F401
from .alerts import PEER_STATE_LIMIT  # noqa: F401
from .alerts import PEER_PENDING_LIMIT  # noqa: F401
from .alerts import PEER_ALERT_KINDS  # noqa: F401
from .alerts import HEALTH_ALERT_KIND  # noqa: F401
from .notify import SENDER  # noqa: F401
from .notify import FORWARD_BUDGET  # noqa: F401
from .notify import FORWARD_RESERVE  # noqa: F401
from .trend import TREND_MIN_SAMPLES  # noqa: F401
from .trend import TREND_MIN_SPAN_MINUTES  # noqa: F401
from .trend import TREND_RTT_FLOOR_MS  # noqa: F401
from .trend import TREND_RTT_RATIO  # noqa: F401
from .trend import TREND_AVAILABILITY_FLOOR  # noqa: F401
from .trend import TREND_ERROR_FLOOR  # noqa: F401
from .trend import TREND_PEER_COUNT_FLOOR  # noqa: F401
from .trend import TREND_STALE_FACTOR  # noqa: F401
from .trend import TREND_MAX_UNOBSERVED_SHARE  # noqa: F401
from .peers import peer_label  # noqa: F401
from .peers import ambiguous_peer_labels  # noqa: F401
from .storage import rows  # noqa: F401
from .storage import metric_records  # noqa: F401
from .storage import metric_compact  # noqa: F401
from .storage import append  # noqa: F401
from .storage import alert_retention  # noqa: F401
from .storage import forwarded_ids  # noqa: F401
from .storage import alert_suffix  # noqa: F401
from .storage import compact_alerts  # noqa: F401
from .storage import alert_id  # noqa: F401
from .storage import alert_message  # noqa: F401
from .alerts import load_peer_state  # noqa: F401
from .alerts import save_peer_state  # noqa: F401
from .alerts import mark_alert_admission_incomplete  # noqa: F401
from .alerts import warn_alert_admission  # noqa: F401
from .alerts import sync_alert_queue  # noqa: F401
from .alerts import flush_peer_alerts  # noqa: F401
from .alerts import peer_alerts  # noqa: F401
from .alerts import stage_health_alert  # noqa: F401
from .alerts import peer_alert_retain_unobserved  # noqa: F401
from .alerts import peer_alert_sample_peers  # noqa: F401
from .alerts import peer_alert_retain_ambiguous  # noqa: F401
from .alerts import peer_alert_track_observed_peer  # noqa: F401
from .alerts import peer_alert_merge_ambiguous_reconnects  # noqa: F401
from .alerts import peer_alert_persist  # noqa: F401
from .alerts import stage_peer_alerts  # noqa: F401
from .alerts import reconnects  # noqa: F401
from .notify import notify_state  # noqa: F401
from .notify import notify  # noqa: F401
from .notify import forward  # noqa: F401
from .collect import collect  # noqa: F401
from .collect import window  # noqa: F401
from .collect import stats  # noqa: F401
from .collect import watch  # noqa: F401
from .trend import trend_number  # noqa: F401
from .trend import trend_halves  # noqa: F401
from .trend import trend_single  # noqa: F401
from .trend import trend_median  # noqa: F401
from .trend import trend_drift  # noqa: F401
from .trend import trend_peer_block  # noqa: F401
from .trend import trend_peer  # noqa: F401
from .trend import trend_window  # noqa: F401
from .trend import trend_report  # noqa: F401
from .trend import trend_collector_state  # noqa: F401
from .trend import trend_sample_labels  # noqa: F401
from .trend import trend_accumulate  # noqa: F401
from .trend import trend_sample_series  # noqa: F401
from .trend import trend_peer_series  # noqa: F401
from .trend import trend_node_block  # noqa: F401
from .trend import trend_peer_details  # noqa: F401
from .trend import trend_verdict  # noqa: F401
from .trend import trend  # noqa: F401
from .trend import trend_line  # noqa: F401
from .trend import trend_text  # noqa: F401
# Legacy flat-module names for tests and monkeypatch.


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



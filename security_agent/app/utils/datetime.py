"""
Datetime parsing helpers shared between ingestion, agent tools, and experiments.

Single source of truth for TheHive-style ``date`` fields, which can arrive as:

* Python ``int`` / ``float`` epoch in milliseconds or seconds.
* String of digits representing epoch in milliseconds or seconds.
* ISO-8601 string (with or without ``Z`` suffix).
* ``None`` / empty string.

The previous implementations in ``security_agent.app.agent.tools.parse_alert_datetime``
and ``SQLiteStore._parse_alert_datetime`` were near-duplicates — consolidating
here removes the drift risk where a fix in one site silently leaves the other
broken (e.g. ``compute_time_delta`` vs ``_suggest_campaign_id``).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

_EPOCH_MS_THRESHOLD = 1e12  # epoch values larger than this are interpreted as ms


def parse_alert_datetime(value: Any) -> Optional[datetime]:
    """Return a timezone-aware UTC ``datetime`` for *value*, or ``None``.

    Heuristic:

    * Numeric inputs (or numeric strings) larger than ``1e12`` are treated as
      epoch milliseconds; otherwise as epoch seconds.
    * Non-numeric strings are parsed as ISO-8601 (``Z`` suffix tolerated).
    * Anything that cannot be parsed returns ``None`` rather than raising —
      callers downstream of TheHive feeds are expected to gracefully ignore
      malformed dates.
    """
    if value is None or value == "":
        return None

    if isinstance(value, (int, float)):
        ts = float(value)
    else:
        s = str(value).strip()
        if not s:
            return None
        if s.isdigit():
            ts = float(s)
        else:
            try:
                return datetime.fromisoformat(s.replace("Z", "+00:00"))
            except ValueError:
                return None

    if ts > _EPOCH_MS_THRESHOLD:
        ts = ts / 1000.0
    return datetime.fromtimestamp(ts, tz=timezone.utc)

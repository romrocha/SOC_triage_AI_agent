"""parse_alert_datetime is the single source of truth for date parsing.

Existing test_alert_date_parse.py exercises happy paths via the agent.tools
re-export. This file covers:
  * edge cases (None, empty string, invalid input, epoch in seconds)
  * the canonical import path (security_agent.app.utils.datetime)
  * identity between the canonical export and the agent.tools re-export so
    the agent code and the SQLite store cannot drift apart again.
"""

from datetime import timezone

from security_agent.app.utils.datetime import parse_alert_datetime as canonical
from security_agent.app.agent.tools import parse_alert_datetime as agent_export
from security_agent.app.ingestion import sqlite_store as sqlite_store_module


def test_canonical_and_agent_reexport_are_same_function():
    assert canonical is agent_export, (
        "agent.tools.parse_alert_datetime must re-export the canonical implementation"
    )


def test_sqlite_store_imports_canonical():
    assert sqlite_store_module.parse_alert_datetime is canonical


def test_none_returns_none():
    assert canonical(None) is None


def test_empty_string_returns_none():
    assert canonical("") is None


def test_whitespace_only_returns_none():
    assert canonical("   ") is None


def test_invalid_iso_returns_none():
    assert canonical("not-a-date") is None


def test_epoch_seconds_int():
    # 1732708800 seconds = 2024-11-27 12:00:00 UTC
    dt = canonical(1732708800)
    assert dt is not None
    assert dt.year == 2024 and dt.month == 11 and dt.day == 27
    assert dt.tzinfo is not None and dt.utcoffset() == timezone.utc.utcoffset(dt)


def test_epoch_seconds_string():
    dt = canonical("1732708800")
    assert dt is not None
    assert dt.year == 2024


def test_epoch_milliseconds_float():
    dt = canonical(1732708800000.0)
    assert dt is not None
    assert dt.year == 2024


def test_iso_with_z_suffix():
    dt = canonical("2024-11-27T12:00:00Z")
    assert dt is not None
    assert dt.tzinfo is not None


def test_iso_with_explicit_offset():
    dt = canonical("2024-11-27T09:00:00-03:00")
    assert dt is not None
    # Convert to UTC for assertion
    assert dt.astimezone(timezone.utc).hour == 12

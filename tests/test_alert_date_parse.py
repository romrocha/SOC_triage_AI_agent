"""parse_alert_datetime handles TheHive epoch-ms and ISO strings."""

from security_agent.app.agent.tools import parse_alert_datetime


def test_epoch_ms_int():
    dt = parse_alert_datetime(1732708800000)
    assert dt is not None
    assert dt.year == 2024
    assert dt.month == 11
    assert dt.day == 27


def test_epoch_ms_string():
    dt = parse_alert_datetime("1732708800000")
    assert dt is not None
    assert dt.tzinfo is not None


def test_iso_string():
    dt = parse_alert_datetime("2024-11-27T12:00:00+00:00")
    assert dt is not None

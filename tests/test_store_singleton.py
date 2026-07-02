"""Tools cache SQLiteStore instances per path instead of opening a new connection per call.

Before this change every call to fetch_alert_by_id, search_alerts_by_entity,
validate_shared_entities, etc. opened a brand-new SQLite connection. With the
singleton, repeated calls reuse the same instance, and configure_tooling()
correctly invalidates the cache when the path changes.
"""

from pathlib import Path

import pytest

from security_agent.app.agent import tools as tools_module


@pytest.fixture(autouse=True)
def _reset_tooling_state(tmp_path):
    """Snapshot module-level state before each test and restore after."""
    saved_default = tools_module._DEFAULT_SQLITE_PATH
    saved_cache = dict(tools_module._store_cache)
    tools_module._store_cache.clear()
    yield
    tools_module._store_cache.clear()
    tools_module._store_cache.update(saved_cache)
    tools_module._DEFAULT_SQLITE_PATH = saved_default


def _init_db(path: Path) -> None:
    from security_agent.app.ingestion.sqlite_store import SQLiteStore

    SQLiteStore(db_path=str(path)).init_db()


def test_get_store_returns_same_instance_for_same_path(tmp_path):
    db = tmp_path / "alerts.db"
    _init_db(db)
    tools_module.configure_tooling(sqlite_path=str(db))

    a = tools_module._get_store()
    b = tools_module._get_store()
    assert a is b


def test_get_store_returns_different_instance_for_different_path(tmp_path):
    db1 = tmp_path / "one.db"
    db2 = tmp_path / "two.db"
    _init_db(db1)
    _init_db(db2)

    tools_module.configure_tooling(sqlite_path=str(db1))
    a = tools_module._get_store()

    tools_module.configure_tooling(sqlite_path=str(db2))
    b = tools_module._get_store()

    assert a is not b


def test_configure_tooling_clears_cache_when_path_changes(tmp_path):
    db1 = tmp_path / "one.db"
    db2 = tmp_path / "two.db"
    _init_db(db1)
    _init_db(db2)

    tools_module.configure_tooling(sqlite_path=str(db1))
    tools_module._get_store()
    assert len(tools_module._store_cache) == 1

    tools_module.configure_tooling(sqlite_path=str(db2))
    # Cache must have been invalidated; only the new path may be cached after a fresh call
    assert str(db1) not in {Path(k).as_posix() for k in tools_module._store_cache}


def test_fetch_alert_by_id_uses_singleton(tmp_path):
    """End-to-end: fetch_alert_by_id should not create new SQLiteStore objects per call."""
    from security_agent.app.ingestion.sqlite_store import SQLiteStore

    db = tmp_path / "alerts.db"
    store = SQLiteStore(db_path=str(db))
    store.init_db()
    store.upsert_alert(
        alert_id="abc",
        title="t",
        description="d",
        severity="medium",
        date="2024-11-27T12:00:00Z",
        observables=[{"type": "ip", "value": "1.2.3.4"}],
    )

    tools_module.configure_tooling(sqlite_path=str(db))
    tools_module._get_store()  # warm
    cache_size_before = len(tools_module._store_cache)

    a = tools_module.fetch_alert_by_id("abc")
    b = tools_module.fetch_alert_by_id("abc")
    assert a == b
    assert len(tools_module._store_cache) == cache_size_before

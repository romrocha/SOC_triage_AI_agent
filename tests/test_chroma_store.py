from pathlib import Path

from security_agent.app.ingestion import chroma_store


def test_chroma_store_recovers_from_missing_tenants_table(tmp_path: Path, monkeypatch) -> None:
    calls = {"count": 0, "cleared": 0}

    class DummyClient:
        def get_collection(self, name: str):
            raise RuntimeError("missing")

        def create_collection(self, name: str):
            return {"name": name}

    def fake_persistent_client(*, path: str):
        calls["count"] += 1
        if calls["count"] == 1:
            raise RuntimeError("Database error: no such table: tenants")
        return DummyClient()

    def fake_clear_system_cache() -> None:
        calls["cleared"] += 1

    monkeypatch.setattr(chroma_store.chromadb, "PersistentClient", fake_persistent_client)
    monkeypatch.setattr(chroma_store.SharedSystemClient, "clear_system_cache", fake_clear_system_cache)

    store = chroma_store.ChromaStore(persist_directory=tmp_path / "chroma")

    assert calls["count"] == 2
    assert calls["cleared"] == 1
    assert store.collection == {"name": "alerts"}

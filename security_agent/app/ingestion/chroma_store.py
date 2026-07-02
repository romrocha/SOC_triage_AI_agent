import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import chromadb
from chromadb.api.client import SharedSystemClient

from ..config import CHROMA_DIR, CHROMA_PERSIST


class ChromaStore:
    def __init__(self, persist_directory: Optional[Union[str, Path]] = None):
        persist_directory = Path(persist_directory or CHROMA_DIR)
        os.makedirs(persist_directory, exist_ok=True)
        # Always clear the in-process cache before opening a PersistentClient.
        # In long-lived notebook kernels, the cache can hold a reference to a
        # previously deleted chroma_db directory. If not cleared, the new client
        # opens "successfully" but writes fail with SQLITE_READONLY_DBMOVED because
        # SQLite detects the file was moved/deleted since the handle was opened.
        SharedSystemClient.clear_system_cache()
        try:
            self.client = chromadb.PersistentClient(path=str(persist_directory))
        except Exception as exc:
            # Fallback for corrupt on-disk schema ("no such table: tenants").
            # Wipe the directory and retry once with a fresh database.
            if "no such table: tenants" not in str(exc).lower():
                raise
            shutil.rmtree(persist_directory, ignore_errors=True)
            os.makedirs(persist_directory, exist_ok=True)
            self.client = chromadb.PersistentClient(path=str(persist_directory))
        try:
            self.collection = self.client.get_collection(name="alerts")
        except Exception:
            self.collection = self.client.create_collection(name="alerts")

    def upsert(self, ids: List[str], embeddings: List[List[float]], metadatas: List[Dict[str, Any]], documents: Optional[List[str]] = None):
        self.collection.upsert(ids=ids, embeddings=embeddings, metadatas=metadatas, documents=documents)

    def query_by_embedding(self, embedding: List[float], n_results: int = 10):
        res = self.collection.query(query_embeddings=[embedding], n_results=n_results)
        return res

    def get_all(self):
        return self.collection.get()

    def get_embedding_by_id(self, alert_id: str) -> Optional[List[float]]:
        """Return the stored embedding vector for a single alert ID, or None."""
        res = self.collection.get(ids=[alert_id], include=["embeddings"])
        embeddings = res.get("embeddings") if res else None
        if embeddings is not None and len(embeddings) > 0:
            return embeddings[0]
        return None

    def query_similar_excluding(
        self,
        embedding: List[float],
        exclude_ids: Optional[List[str]] = None,
        n_results: int = 10,
    ) -> List[Dict[str, Any]]:
        """Query similar alerts by embedding, excluding specific IDs.

        Returns list of {id, distance, document} dicts.
        """
        fetch_n = n_results + len(exclude_ids or []) + 5
        res = self.collection.query(
            query_embeddings=[embedding],
            n_results=min(fetch_n, self.collection.count() or fetch_n),
            include=["distances", "documents"],
        )
        ids_raw = res.get("ids") if res else None
        if ids_raw is None or len(ids_raw) == 0:
            return []

        ids = res["ids"][0] if isinstance(res["ids"][0], list) else res["ids"]
        distances = (res.get("distances") or [[]])[0]
        documents = (res.get("documents") or [[]])[0]
        exclude = set(exclude_ids or [])

        results = []
        for i, aid in enumerate(ids):
            if aid in exclude:
                continue
            results.append({
                "id": aid,
                "distance": distances[i] if i < len(distances) else None,
                "document": documents[i] if i < len(documents) else None,
            })
            if len(results) >= n_results:
                break
        return results

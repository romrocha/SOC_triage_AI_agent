import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from ..config import ROUND_INPUT_DIR
from .sqlite_store import SQLiteStore


# Filenames under input/<round>/ that are metadata, not TheHive alert arrays
_SKIP_JSON_NAMES = frozenset({"manifest.json"})


def load_json_alerts(directory: Optional[Union[str, Path]] = None) -> List[Dict[str, Any]]:
    directory = Path(directory or ROUND_INPUT_DIR)
    alerts = []
    # Search recursively for all JSON files in subdirectories
    for p in sorted(directory.rglob("*.json")):
        if p.name.lower() in _SKIP_JSON_NAMES:
            continue
        with p.open("r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                alerts.extend(data)
            else:
                alerts.append(data)
    return alerts


def ingest_alerts(directory: Optional[Union[str, Path]] = None, db_path=None):
    alerts = load_json_alerts(directory)
    store = SQLiteStore(db_path=db_path)
    store.init_db()
    for a in alerts:
        # Use sourceRef as the primary alert ID (TheHive schema)
        alert_id = a.get("sourceRef") or a.get("alert_id") or a.get("id")
        if not alert_id:
            # Hard fail on missing ID to avoid silent data loss
            raise ValueError(f"Missing sourceRef/id/alert_id in alert: {a}")
        
        # Extract observables and normalize structure
        observables = []
        for obs in a.get("observables", []):
            # Handle 'data' field which is an array in TheHive format
            obs_type = obs.get("dataType", "unknown")
            obs_data = obs.get("data", [])
            # Create one entry per value in the data array
            for value in obs_data:
                observables.append({
                    "type": obs_type,
                    "value": value,
                    "message": obs.get("message", ""),
                    "ioc": obs.get("ioc", False),
                })
        
        store.upsert_alert(
            alert_id=str(alert_id),
            title=a.get("title", ""),
            description=a.get("description", ""),
            severity=str(a.get("severity", "")),
            date=str(a.get("date", "")),
            alert_type=a.get("type", ""),
            source=a.get("source", ""),
            status=a.get("status", "New"),
            tags=a.get("tags", []),
            tlp=a.get("tlp"),
            pap=a.get("pap"),
            flag=a.get("flag", False),
            observables=observables,
            raw=a,
        )
    return store

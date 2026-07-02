import sqlite3
import json
import re
import threading
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Union

from ..config import SQLITE_DB
from ..utils.datetime import parse_alert_datetime


def _clamp_confidence_sql(value: Any) -> float:
    """Defensive clamp for confidence values flowing into/out of the campaigns
    table. Same semantics as ``tools._clamp_confidence``: clamps to ``[0, 1]``,
    treats values in ``(1, 100]`` as percentages, anything beyond goes to 1.0.
    Duplicated here (instead of importing from ``tools``) to keep the storage
    layer free of agent dependencies.
    """
    try:
        f = float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0
    if f != f:  # NaN
        return 0.0
    if f < 0.0:
        return 0.0
    if f <= 1.0:
        return f
    if f <= 100.0:
        return f / 100.0
    return 1.0


class SQLiteStore:
    def __init__(self, db_path: Optional[Union[str, Path]] = None):
        self.db_path = Path(db_path) if db_path else Path(SQLITE_DB)
        # Create parent directory if it doesn't exist
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # Connection is created lazily per thread via the ``conn`` property.
        # The langgraph ``ToolNode`` runs parallel tool calls in a thread
        # pool when the LLM emits multiple tool_calls in one turn — sharing
        # a single sqlite connection across threads triggers
        # ``InterfaceError: bad parameter or other API misuse`` because
        # transaction state lives per-connection. Thread-local connections
        # sidestep that; WAL mode (set in ``init_db``) lets reads happen
        # concurrently across them.
        self._local = threading.local()

    @property
    def conn(self) -> sqlite3.Connection:
        """Return the calling thread's sqlite connection (lazy-created)."""
        c = getattr(self._local, "conn", None)
        if c is None:
            c = sqlite3.connect(
                str(self.db_path), timeout=30, check_same_thread=False
            )
            c.row_factory = sqlite3.Row
            self._local.conn = c
        return c

    def init_db(self):
        cur = self.conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")

        cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY,
            title TEXT,
            description TEXT,
            severity TEXT,
            date TEXT,
            type TEXT,
            source TEXT,
            status TEXT DEFAULT 'unprocessed',
            campaign_id TEXT,
            false_positive_reason TEXT,
            tags TEXT,
            tlp INTEGER,
            pap INTEGER,
            flag INTEGER,
            raw TEXT
        )
        """)
        # Backfill columns added after initial deployments
        cur.execute("PRAGMA table_info(alerts)")
        alert_columns = {row[1] for row in cur.fetchall()}
        if "processed_at" not in alert_columns:
            cur.execute("ALTER TABLE alerts ADD COLUMN processed_at TEXT")
        if "campaign_id" not in alert_columns:
            cur.execute("ALTER TABLE alerts ADD COLUMN campaign_id TEXT")
        if "false_positive_reason" not in alert_columns:
            cur.execute("ALTER TABLE alerts ADD COLUMN false_positive_reason TEXT")
        cur.execute("""
        CREATE TABLE IF NOT EXISTS observables (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT,
            type TEXT,
            value TEXT,
            message TEXT,
            ioc INTEGER,
            FOREIGN KEY(alert_id) REFERENCES alerts(alert_id)
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS checkpoints (
            name TEXT PRIMARY KEY,
            state TEXT
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS campaigns (
            campaign_id TEXT PRIMARY KEY,
            alerts TEXT,
            confidence REAL,
            summary TEXT,
            rationale TEXT,
            run_id TEXT,
            created_at TEXT,
            raw TEXT
        )
        """)
        cur.execute("PRAGMA table_info(campaigns)")
        campaign_columns = {row[1] for row in cur.fetchall()}
        if "campaign_id" not in campaign_columns:
            cur.execute("ALTER TABLE campaigns ADD COLUMN campaign_id TEXT")
        if "alerts" not in campaign_columns:
            cur.execute("ALTER TABLE campaigns ADD COLUMN alerts TEXT")
        if "confidence" not in campaign_columns:
            cur.execute("ALTER TABLE campaigns ADD COLUMN confidence REAL")
        if "summary" not in campaign_columns:
            cur.execute("ALTER TABLE campaigns ADD COLUMN summary TEXT")
        if "rationale" not in campaign_columns:
            cur.execute("ALTER TABLE campaigns ADD COLUMN rationale TEXT")
        if "run_id" not in campaign_columns:
            cur.execute("ALTER TABLE campaigns ADD COLUMN run_id TEXT")
        if "created_at" not in campaign_columns:
            cur.execute("ALTER TABLE campaigns ADD COLUMN created_at TEXT")
        if "raw" not in campaign_columns:
            cur.execute("ALTER TABLE campaigns ADD COLUMN raw TEXT")
        cur.execute("""
        CREATE TABLE IF NOT EXISTS agent_runs (
            run_id TEXT PRIMARY KEY,
            model_name TEXT,
            started_at TEXT,
            completed_at TEXT,
            total_alerts INTEGER,
            campaigns_detected INTEGER,
            false_positives INTEGER,
            tokens_used INTEGER,
            cost_usd REAL,
            config TEXT
        )
        """)
        # Helpful indexes for agent queries
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_alerts_campaign ON alerts(campaign_id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_observables_type_value ON observables(type, value)")
        self.conn.commit()

    def upsert_alert(self, alert_id: str, title: str, description: str, severity: str, date: str, 
                     alert_type: str = None, source: str = None, status: str = None, 
                     tags: List[str] = None, tlp: int = None, pap: int = None, flag: bool = False,
                     observables: List[Dict[str, Any]] = None, raw: Any = None):
        cur = self.conn.cursor()
        # Convert tags list to JSON string for storage
        tags_json = json.dumps(tags) if tags else None
        effective_status = status or 'unprocessed'
        cur.execute("""
            REPLACE INTO alerts(alert_id, title, description, severity, date, type, source, 
                               status, tags, tlp, pap, flag, raw) 
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (alert_id, title, description, severity, date, alert_type, source, 
              effective_status, tags_json, tlp, pap, 1 if flag else 0, json.dumps(raw)))
        cur.execute("DELETE FROM observables WHERE alert_id = ?", (alert_id,))
        for o in observables or []:
            cur.execute("""
                INSERT INTO observables(alert_id, type, value, message, ioc) 
                VALUES (?,?,?,?,?)
            """, (alert_id, o.get("type"), str(o.get("value")), 
                  o.get("message", ""), 1 if o.get("ioc") else 0))
        self.conn.commit()

    def fetch_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
        row = cur.fetchone()
        if not row:
            return None
        cur.execute("SELECT type, value, message, ioc FROM observables WHERE alert_id = ?", (alert_id,))
        obs = [dict(r) for r in cur.fetchall()]
        tags = json.loads(row["tags"]) if row["tags"] else []
        return {
            "alert_id": row["alert_id"],
            "title": row["title"],
            "description": row["description"],
            "severity": row["severity"],
            "date": row["date"],
            "type": row["type"],
            "source": row["source"],
            "status": row["status"],
            "campaign_id": row["campaign_id"],
            "false_positive_reason": row["false_positive_reason"],
            "tags": tags,
            "tlp": row["tlp"],
            "pap": row["pap"],
            "flag": bool(row["flag"]),
            "observables": obs,
            "raw": json.loads(row["raw"])
        }

    def find_alerts_by_observable(self, o_type: str, value: str) -> List[str]:
        """Return ALL alert_ids that share an observable, regardless of status.

        The correlation graph must be visible in full — the LLM-facing
        wrapper (``_t_search_alerts_by_entity``) is responsible for
        annotating each id with its current decision (unprocessed /
        in_campaign / false_positive). Filtering at this layer would hide
        the bridge between a new alert and an existing campaign.
        """
        cur = self.conn.cursor()
        cur.execute(
            "SELECT DISTINCT alert_id FROM observables WHERE type = ? AND value = ?",
            (o_type, value),
        )
        return [r[0] for r in cur.fetchall()]

    def save_checkpoint(self, name: str, state: Dict[str, Any]):
        cur = self.conn.cursor()
        cur.execute("REPLACE INTO checkpoints(name, state) VALUES (?,?)", (name, json.dumps(state)))
        self.conn.commit()

    def load_checkpoint(self, name: str) -> Optional[Dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute("SELECT state FROM checkpoints WHERE name = ?", (name,))
        r = cur.fetchone()
        if not r:
            return None
        return json.loads(r[0])

    def upsert_campaign(self, campaign: Dict[str, Any]):
        cur = self.conn.cursor()
        campaign_id = campaign.get("campaign_id")
        alerts = campaign.get("alerts", [])
        confidence = campaign.get("confidence_score", 0.0)
        summary = campaign.get("investigation_summary") or ""
        raw = json.dumps(campaign)
        cur.execute(
            "REPLACE INTO campaigns(campaign_id, alerts, confidence, summary, created_at, raw) VALUES (?,?,?,?,datetime('now'),?)",
            (campaign_id, json.dumps(alerts), confidence, summary, raw),
        )
        self.conn.commit()

    def list_campaign_alert_ids(self) -> List[str]:
        cur = self.conn.cursor()
        cur.execute("SELECT alerts FROM campaigns")
        rows = cur.fetchall()
        seen: set[str] = set()
        for r in rows:
            try:
                alerts = json.loads(r[0]) if r[0] else []
            except Exception:
                alerts = []
            for aid in alerts:
                seen.add(aid)
        return list(seen)

    def fetch_campaign_alerts(self, campaign_id: str) -> List[Dict[str, Any]]:
        """Return full alert payloads for every alert inside *campaign_id*.

        Used by the LLM "open case file" workflow: when an investigation
        suspects overlap with an existing campaign, it can fetch the full
        contents of that case to compare observables/timeline directly,
        instead of relying on the textual ``prior_decisions`` summary.
        Returns ``[]`` if the campaign does not exist.
        """
        cur = self.conn.cursor()
        cur.execute("SELECT alerts FROM campaigns WHERE campaign_id = ?", (campaign_id,))
        row = cur.fetchone()
        if not row:
            return []
        alert_ids = self._parse_alert_ids_json(row[0])
        alerts: List[Dict[str, Any]] = []
        for aid in alert_ids:
            a = self.fetch_alert(aid)
            if a:
                alerts.append(a)
        return alerts

    @staticmethod
    def _slugify(value: str) -> str:
        value = (value or "").strip().lower()
        value = re.sub(r"[^a-z0-9]+", "-", value)
        value = re.sub(r"-{2,}", "-", value)
        return value.strip("-") or "campaign"

    @staticmethod
    def _parse_alert_ids_json(raw: Any) -> List[str]:
        if not raw:
            return []
        if isinstance(raw, list):
            return [str(x) for x in raw]
        try:
            parsed = json.loads(raw) if isinstance(raw, str) else raw
            if isinstance(parsed, list):
                return [str(x) for x in parsed]
        except Exception:
            pass
        return [str(raw)]

    def _campaign_theme(self, alerts: List[Dict[str, Any]], summary: str, rationale: str) -> str:
        text_parts = [summary or "", rationale or ""]
        for alert in alerts:
            text_parts.extend(
                [
                    str(alert.get("title") or ""),
                    str(alert.get("description") or ""),
                    str(alert.get("source") or ""),
                    str(alert.get("type") or ""),
                ]
            )
        text = " ".join(text_parts).lower()
        if any(token in text for token in ["ransom", "locked2024", "shadow copy", "vssadmin"]):
            if "finance" in text:
                return "ransomware-finance"
            return "ransomware"
        if any(token in text for token in ["exfil", "dropbox", "compensation", "salary", "insider"]):
            if "hr" in text or "compensation" in text or "salary" in text:
                return "insider-exfil-hr"
            return "insider-exfil"
        if "phish" in text:
            return "phishing"
        return "case"  # neutral fallback; avoids "campaign-campaign-..." in canonical id

    def _campaign_primary_entity(self, alerts: List[Dict[str, Any]]) -> str:
        buckets = {"username": {}, "hostname": {}, "domain": {}, "mail": {}}
        for alert in alerts:
            for obs in alert.get("observables") or []:
                otype = str(obs.get("type") or "").lower()
                value = str(obs.get("value") or "").strip()
                if not value:
                    continue
                if otype in buckets:
                    buckets[otype][value] = buckets[otype].get(value, 0) + 1
        for otype in ("username", "hostname", "domain", "mail"):
            if buckets[otype]:
                value = max(buckets[otype].items(), key=lambda item: (item[1], item[0]))[0]
                if otype == "mail":
                    value = value.split("@", 1)[0]
                return self._slugify(value)
        return "group"

    def _suggest_campaign_id(self, alert_ids: List[str], summary: str, rationale: str) -> str:
        alerts = [self.fetch_alert(aid) for aid in alert_ids]
        alerts = [a for a in alerts if a]
        theme = self._campaign_theme(alerts, summary, rationale)
        entity = self._campaign_primary_entity(alerts)
        dates = [
            parse_alert_datetime(a.get("date"))
            for a in alerts
            if a and parse_alert_datetime(a.get("date")) is not None
        ]
        if dates:
            start = min(dates)
            suffix = f"{start.year:04d}-{start.month:02d}"
        else:
            suffix = "undated"
        return f"campaign-{theme}-{entity}-{suffix}"

    def _find_overlapping_campaigns(self, alert_ids: List[str]) -> List[sqlite3.Row]:
        candidate = set(alert_ids)
        cur = self.conn.cursor()
        cur.execute("SELECT campaign_id, alerts, confidence, rationale, summary, run_id, created_at FROM campaigns")
        overlaps: List[sqlite3.Row] = []
        for row in cur.fetchall():
            existing = set(self._parse_alert_ids_json(row["alerts"]))
            if not existing:
                continue
            inter = len(candidate & existing)
            if inter == 0:
                continue
            overlap_ratio = inter / min(len(candidate), len(existing))
            if overlap_ratio >= 0.5 or inter >= 5:
                overlaps.append(row)
        return overlaps

    # Agent autonomous methods
    def get_unprocessed_alerts(
        self,
        limit: int = 10,
        exclude_alert_ids: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Retorna alertas com status='unprocessed'"""
        cur = self.conn.cursor()
        exclude_alert_ids = [str(aid) for aid in (exclude_alert_ids or []) if aid]
        if exclude_alert_ids:
            placeholders = ",".join("?" for _ in exclude_alert_ids)
            cur.execute(
                f"""
                SELECT alert_id
                FROM alerts
                WHERE status = 'unprocessed' AND alert_id NOT IN ({placeholders})
                ORDER BY date, alert_id
                LIMIT ?
                """,
                (*exclude_alert_ids, limit),
            )
        else:
            cur.execute(
                """
                SELECT alert_id
                FROM alerts
                WHERE status = 'unprocessed'
                ORDER BY date, alert_id
                LIMIT ?
                """,
                (limit,),
            )
        rows = cur.fetchall()
        return [self.fetch_alert(r[0]) for r in rows if r[0]]

    def update_alert_status(self, alert_id: str, status: str, campaign_id: str = None):
        """Atualiza status do alerta (in_campaign, false_positive, reviewed)"""
        cur = self.conn.cursor()
        cur.execute(
            "UPDATE alerts SET status = ?, campaign_id = ?, processed_at = datetime('now') WHERE alert_id = ?",
            (status, campaign_id, alert_id)
        )
        self.conn.commit()

    def create_campaign(self, campaign_id: str, alert_ids: List[str], confidence: float,
                       rationale: str, summary: str, run_id: str = None) -> Tuple[str, List[str]]:
        """Cria campanha e marca alertas como in_campaign.

        Returns ``(canonical_id, alert_ids_sorted)`` — o que de fato foi gravado
        no banco, *não* o que o caller passou. O ``canonical_id`` é recomputado
        via ``_suggest_campaign_id`` e a lista de alertas pode ser maior que a
        de entrada se houver merge automático com campanhas sobrepostas
        (overlap >= 50% ou >= 5 alertas em comum).

        Também repara referências FK stale: se algum dos alertas estava em
        outra campanha (com overlap baixo demais para acionar merge), remove
        o alerta do JSON dessa campanha — evita o estado em que ``alerts.campaign_id``
        aponta para uma campanha mas o ``campaigns.alerts`` JSON de outra
        ainda lista o mesmo alerta.
        """
        cur = self.conn.cursor()
        try:
            cur.execute("BEGIN IMMEDIATE")
            alert_ids = list(dict.fromkeys(str(aid) for aid in alert_ids if aid))
            if not alert_ids:
                raise ValueError("create_campaign requires at least one alert_id")

            overlapping = self._find_overlapping_campaigns(alert_ids)
            merged_ids = set(alert_ids)
            summaries = [summary] if summary else []
            rationales = [rationale] if rationale else []
            # Defense-in-depth confidence clamp. ``tools.create_campaign``
            # already sanitises LLM input, but a corrupted historical row
            # in the campaigns table would otherwise propagate via the
            # ``max(...)`` below — so we clamp BOTH inputs at this layer.
            max_conf = _clamp_confidence_sql(confidence)
            run_ids = [run_id] if run_id else []

            for row in overlapping:
                merged_ids.update(self._parse_alert_ids_json(row["alerts"]))
                if row["summary"]:
                    summaries.append(str(row["summary"]))
                if row["rationale"]:
                    rationales.append(str(row["rationale"]))
                if row["run_id"]:
                    run_ids.append(str(row["run_id"]))
                max_conf = max(max_conf, _clamp_confidence_sql(row["confidence"]))

            merged_ids_sorted = sorted(merged_ids)
            canonical_id = self._suggest_campaign_id(
                merged_ids_sorted,
                summary or (max(summaries, key=len) if summaries else ""),
                rationale or (max(rationales, key=len) if rationales else ""),
            )
            overlapping_ids = {row["campaign_id"] for row in overlapping}
            if overlapping:
                cur.execute(
                    "DELETE FROM campaigns WHERE campaign_id IN ({})".format(
                        ",".join("?" for _ in overlapping)
                    ),
                    tuple(overlapping_ids),
                )

            cur.execute(
                "INSERT OR REPLACE INTO campaigns(campaign_id, alerts, confidence, rationale, summary, run_id, created_at) VALUES (?,?,?,?,?,?,datetime('now'))",
                (
                    canonical_id,
                    json.dumps(merged_ids_sorted),
                    max_conf,
                    rationale or (max(rationales, key=len) if rationales else ""),
                    summary or (max(summaries, key=len) if summaries else ""),
                    (run_id or run_ids[0]) if run_ids else None,
                ),
            )
            for alert_id in merged_ids_sorted:
                cur.execute(
                    "UPDATE alerts SET status = 'in_campaign', campaign_id = ? WHERE alert_id = ?",
                    (canonical_id, alert_id)
                )

            # Bug 3 fix — sync stale FK references in OTHER campaigns.
            # Some of the alerts we just claimed for ``canonical_id`` may have
            # been listed inside another campaign's JSON (when overlap was
            # below the merge threshold but non-zero). Their ``alerts.campaign_id``
            # column has just been overwritten to ``canonical_id`` — so the JSON
            # of the previous campaign is now lying. Remove them, and drop the
            # campaign if it ends up empty.
            cur.execute(
                "SELECT campaign_id, alerts FROM campaigns WHERE campaign_id != ?",
                (canonical_id,),
            )
            new_alerts_set = set(merged_ids_sorted)
            for row in cur.fetchall():
                cid = row["campaign_id"]
                if cid in overlapping_ids:
                    continue  # already deleted above; defensive
                existing = set(self._parse_alert_ids_json(row["alerts"]))
                stolen = existing & new_alerts_set
                if not stolen:
                    continue
                remaining = sorted(existing - stolen)
                if remaining:
                    cur.execute(
                        "UPDATE campaigns SET alerts = ? WHERE campaign_id = ?",
                        (json.dumps(remaining), cid),
                    )
                else:
                    cur.execute(
                        "DELETE FROM campaigns WHERE campaign_id = ?",
                        (cid,),
                    )

            self.conn.commit()
            return canonical_id, merged_ids_sorted
        except Exception:
            self.conn.rollback()
            raise

    def add_alerts_to_campaign(self, campaign_id: str, alert_ids: List[str]) -> Dict[str, Any]:
        """Add alerts to an existing campaign, returning added IDs."""
        cur = self.conn.cursor()
        cur.execute(
            "SELECT alerts, confidence, rationale, summary, run_id FROM campaigns WHERE campaign_id = ?",
            (campaign_id,),
        )
        row = cur.fetchone()
        if not row:
            return {"status": "error", "message": f"Campaign {campaign_id} not found"}

        existing_ids = set(self._parse_alert_ids_json(row["alerts"]))
        new_ids = [str(aid) for aid in alert_ids if str(aid) not in existing_ids]
        if not new_ids:
            return {"status": "no_change", "campaign_id": campaign_id, "message": "All alert_ids already in campaign"}

        merged = sorted(existing_ids | set(new_ids))
        cur.execute("UPDATE campaigns SET alerts = ? WHERE campaign_id = ?", (json.dumps(merged), campaign_id))
        for aid in new_ids:
            cur.execute(
                "UPDATE alerts SET status = 'in_campaign', campaign_id = ? WHERE alert_id = ?",
                (campaign_id, aid),
            )
        self.conn.commit()
        return {"status": "success", "campaign_id": campaign_id, "added": new_ids, "total_alerts": len(merged)}

    def list_campaigns_summary(self) -> List[Dict[str, Any]]:
        """Compact summary of existing campaigns for cross-investigation memory."""
        cur = self.conn.cursor()
        cur.execute("SELECT campaign_id, alerts, confidence, summary, created_at FROM campaigns")
        results = []
        for row in cur.fetchall():
            alert_ids = self._parse_alert_ids_json(row["alerts"])
            results.append({
                "campaign_id": row["campaign_id"],
                "alert_count": len(alert_ids),
                "alert_ids": alert_ids,
                "confidence": row["confidence"],
                "summary": row["summary"],
            })
        return results

    def mark_false_positive(self, alert_id: str, reason: str) -> None:
        """Marca alerta como false_positive"""
        cur = self.conn.cursor()
        cur.execute(
            "UPDATE alerts SET status = 'false_positive', false_positive_reason = ?, processed_at = datetime('now') WHERE alert_id = ?",
            (reason, alert_id)
        )
        self.conn.commit()

    def mark_not_evaluated(self, alert_id: str, reason: str) -> None:
        """Marca alerta como not_evaluated — nunca passou pelo LLM."""
        cur = self.conn.cursor()
        cur.execute(
            "UPDATE alerts SET status = 'not_evaluated', false_positive_reason = ?, processed_at = datetime('now') WHERE alert_id = ?",
            (reason, alert_id)
        )
        self.conn.commit()

    def create_agent_run(self, run_id: str, model_name: str, config: Dict[str, Any]) -> None:
        """Cria registro de execução do agente"""
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO agent_runs(run_id, model_name, started_at, config) VALUES (?,?,datetime('now'),?)",
            (run_id, model_name, json.dumps(config))
        )
        self.conn.commit()

    def update_agent_run(self, run_id: str, campaigns_detected: int, false_positives: int,
                        tokens_used: int, cost_usd: float, total_alerts: int) -> None:
        """Atualiza estatísticas da execução com contagem real de alertas."""
        cur = self.conn.cursor()
        cur.execute(
            "UPDATE agent_runs SET completed_at = datetime('now'), campaigns_detected = ?, false_positives = ?, tokens_used = ?, cost_usd = ?, total_alerts = ? WHERE run_id = ?",
            (campaigns_detected, false_positives, tokens_used, cost_usd, total_alerts, run_id)
        )
        self.conn.commit()

    def get_alert_stats(self) -> Dict[str, Any]:
        """Retorna estatísticas dos alertas"""
        cur = self.conn.cursor()
        cur.execute("SELECT status, COUNT(*) as count FROM alerts GROUP BY status")
        stats = {row[0]: row[1] for row in cur.fetchall()}
        return stats

    def reset_investigation_state(self) -> Tuple[int, int]:
        """
        Volta todos os alertas a ``unprocessed``, limpa campanhas e campos de FP.
        Use antes de uma nova corrida de teste ou produção sobre o mesmo dataset ingerido.
        """
        cur = self.conn.cursor()
        cur.execute(
            """
            UPDATE alerts
            SET status = 'unprocessed',
                campaign_id = NULL,
                false_positive_reason = NULL,
                processed_at = NULL
            """
        )
        n_alerts = cur.rowcount
        cur.execute("DELETE FROM campaigns")
        n_campaigns = cur.rowcount
        self.conn.commit()
        return n_alerts, n_campaigns

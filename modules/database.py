"""Persistent findings history database with AES-256-CBC encryption.

Stores all scan results and findings in an encrypted SQLite database.
Data is encrypted at rest using the vault's AES-256-CBC encryption.
Thread-safe via threading.Lock. Auto-backs up before major operations.
"""
import os
import csv
import json
import shutil
import sqlite3
import tempfile
import threading
import time
import atexit
from pathlib import Path
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from .vault import (
    VAULT_DIR,
    _ensure_dirs,
    encrypt_data,
    decrypt_data,
)

_DB_FILENAME = "findings.db"
_BACKUP_DIR = VAULT_DIR / "backups"
_LOCK = threading.Lock()


class FindingsDatabase:
    """Encrypted SQLite database for pentest findings and scan history.

    All data is encrypted at rest using AES-256-CBC via the vault module.
    Thread-safe for concurrent access.
    """

    def __init__(self, db_path: Optional[str] = None, password: Optional[str] = None):
        _ensure_dirs()
        _BACKUP_DIR.mkdir(parents=True, exist_ok=True)

        if db_path:
            self._db_path = Path(db_path)
        else:
            self._db_path = VAULT_DIR / _DB_FILENAME

        self._enc_path = Path(str(self._db_path) + ".enc")
        self._password = password
        self._conn: Optional[sqlite3.Connection] = None
        self._temp_dir: Optional[str] = None

        self._open_decrypted()
        atexit.register(self.close)

    # ------------------------------------------------------------------
    # Encryption helpers
    # ------------------------------------------------------------------

    def _open_decrypted(self):
        """Decrypt DB file to a temp location and open it."""
        self._temp_dir = tempfile.mkdtemp(prefix="bsdb_")
        self._working_db = Path(self._temp_dir) / _DB_FILENAME

        if self._enc_path.exists() and self._password:
            raw = self._enc_path.read_bytes()
            decrypted = decrypt_data(raw, self._password)
            self._working_db.write_bytes(decrypted)
        elif self._db_path.exists():
            shutil.copy2(self._db_path, self._working_db)

        self._conn = sqlite3.connect(
            str(self._working_db),
            check_same_thread=False,
            timeout=30.0,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self.init_db()

    def _encrypt_and_write(self):
        """Encrypt working DB and persist to disk."""
        if not self._password:
            shutil.copy2(self._working_db, self._db_path)
            return
        raw = self._working_db.read_bytes()
        encrypted = encrypt_data(raw, self._password)
        self._enc_path.write_bytes(encrypted)
        if self._db_path.exists():
            self._db_path.unlink(missing_ok=True)

    def _backup(self):
        """Create timestamped backup before major operations."""
        if self._working_db.exists():
            ts = datetime.now(tz=None).strftime("%Y%m%d_%H%M%S")
            backup_file = _BACKUP_DIR / f"findings_{ts}.db"
            shutil.copy2(self._working_db, backup_file)
            self._prune_backups()

    def _prune_backups(self, keep: int = 10):
        """Keep only the most recent backups."""
        backups = sorted(_BACKUP_DIR.glob("findings_*.db"))
        for old in backups[:-keep]:
            old.unlink(missing_ok=True)

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def init_db(self):
        """Create all tables if they do not exist."""
        with _LOCK:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                    id          TEXT PRIMARY KEY,
                    target      TEXT NOT NULL,
                    scan_type   TEXT NOT NULL,
                    start_time  TEXT,
                    end_time    TEXT,
                    operator    TEXT,
                    status      TEXT DEFAULT 'pending',
                    tool_used   TEXT,
                    results_json TEXT
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id          TEXT PRIMARY KEY,
                    scan_id     TEXT,
                    target      TEXT,
                    category    TEXT,
                    severity    TEXT,
                    title       TEXT,
                    description TEXT,
                    cvss        REAL,
                    cve         TEXT,
                    evidence    TEXT,
                    remediation TEXT,
                    timestamp   TEXT,
                    operator    TEXT,
                    status      TEXT DEFAULT 'open',
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS operator_logs (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    operator  TEXT,
                    action    TEXT,
                    target    TEXT,
                    timestamp TEXT,
                    details   TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_findings_scan    ON findings(scan_id);
                CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
                CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
                CREATE INDEX IF NOT EXISTS idx_findings_cve      ON findings(cve);
                CREATE INDEX IF NOT EXISTS idx_findings_status   ON findings(status);
                CREATE INDEX IF NOT EXISTS idx_scans_target      ON scans(target);
                CREATE INDEX IF NOT EXISTS idx_scans_status      ON scans(status);
            """)

    # ------------------------------------------------------------------
    # Write operations
    # ------------------------------------------------------------------

    def add_finding(self, finding: Dict[str, Any]) -> str:
        """Store a finding. Returns the finding id."""
        fid = finding.get("id") or self._gen_id("F")
        ts = finding.get("timestamp") or datetime.now(tz=None).isoformat()
        with _LOCK:
            self._conn.execute(
                """INSERT OR REPLACE INTO findings
                   (id, scan_id, target, category, severity, title, description,
                    cvss, cve, evidence, remediation, timestamp, operator, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    fid,
                    finding.get("scan_id"),
                    finding.get("target", ""),
                    finding.get("category", ""),
                    finding.get("severity", "INFO"),
                    finding.get("title", ""),
                    finding.get("description", ""),
                    finding.get("cvss"),
                    finding.get("cve", ""),
                    finding.get("evidence", ""),
                    finding.get("remediation", ""),
                    ts,
                    finding.get("operator", ""),
                    finding.get("status", "open"),
                ),
            )
            self._log_action(
                finding.get("operator", ""),
                "add_finding",
                finding.get("target", ""),
                f"Finding {fid} added ({finding.get('severity', 'INFO')})",
            )
        return fid

    def add_scan(self, scan: Dict[str, Any]) -> str:
        """Store scan metadata. Returns the scan id."""
        sid = scan.get("id") or self._gen_id("S")
        with _LOCK:
            self._conn.execute(
                """INSERT OR REPLACE INTO scans
                   (id, target, scan_type, start_time, end_time, operator,
                    status, tool_used, results_json)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    sid,
                    scan.get("target", ""),
                    scan.get("scan_type", ""),
                    scan.get("start_time"),
                    scan.get("end_time"),
                    scan.get("operator", ""),
                    scan.get("status", "pending"),
                    scan.get("tool_used", ""),
                    scan.get("results_json", ""),
                ),
            )
            self._log_action(
                scan.get("operator", ""),
                "add_scan",
                scan.get("target", ""),
                f"Scan {sid} ({scan.get('scan_type', '')})",
            )
        return sid

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    def get_findings(
        self,
        scan_id: Optional[str] = None,
        severity: Optional[str] = None,
        category: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Query findings with optional filters."""
        query = "SELECT * FROM findings WHERE 1=1"
        params: list = []
        if scan_id:
            query += " AND scan_id = ?"
            params.append(scan_id)
        if severity:
            query += " AND severity = ?"
            params.append(severity.upper())
        if category:
            query += " AND category = ?"
            params.append(category)
        query += " ORDER BY timestamp DESC"
        with _LOCK:
            rows = self._conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_scans(
        self, limit: int = 50, offset: int = 0
    ) -> List[Dict[str, Any]]:
        """List scans with pagination."""
        with _LOCK:
            rows = self._conn.execute(
                "SELECT * FROM scans ORDER BY start_time DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get a single scan including its findings."""
        with _LOCK:
            row = self._conn.execute(
                "SELECT * FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
        if not row:
            return None
        scan = dict(row)
        scan["findings"] = self.get_findings(scan_id=scan_id)
        return scan

    def get_statistics(self) -> Dict[str, Any]:
        """Aggregate statistics across all findings."""
        with _LOCK:
            sev = dict(
                self._conn.execute(
                    "SELECT severity, COUNT(*) FROM findings GROUP BY severity"
                ).fetchall()
            )
            cat = dict(
                self._conn.execute(
                    "SELECT category, COUNT(*) FROM findings GROUP BY category"
                ).fetchall()
            )
            cve_count = self._conn.execute(
                "SELECT COUNT(DISTINCT cve) FROM findings WHERE cve != ''"
            ).fetchone()[0]
            scan_count = self._conn.execute(
                "SELECT COUNT(*) FROM scans"
            ).fetchone()[0]
            total = self._conn.execute(
                "SELECT COUNT(*) FROM findings"
            ).fetchone()[0]
        return {
            "total_findings": total,
            "by_severity": sev,
            "by_category": cat,
            "unique_cves": cve_count,
            "total_scans": scan_count,
        }

    def get_trends(self, days: int = 30) -> List[Dict[str, Any]]:
        """Findings count per day for the last N days."""
        cutoff = (datetime.now(tz=None) - timedelta(days=days)).isoformat()
        with _LOCK:
            rows = self._conn.execute(
                """SELECT DATE(timestamp) as day, COUNT(*) as count,
                          severity
                   FROM findings
                   WHERE timestamp >= ?
                   GROUP BY day, severity
                   ORDER BY day""",
                (cutoff,),
            ).fetchall()
        return [dict(r) for r in rows]

    def search_findings(self, query: str) -> List[Dict[str, Any]]:
        """Full-text search across title, description, cve, evidence."""
        like = f"%{query}%"
        with _LOCK:
            rows = self._conn.execute(
                """SELECT * FROM findings
                   WHERE title LIKE ? OR description LIKE ?
                      OR cve LIKE ? OR evidence LIKE ?
                   ORDER BY timestamp DESC""",
                (like, like, like, like),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_critical_findings(self) -> List[Dict[str, Any]]:
        """Get all CRITICAL and HIGH severity findings."""
        with _LOCK:
            rows = self._conn.execute(
                """SELECT * FROM findings
                   WHERE severity IN ('CRITICAL', 'HIGH')
                   ORDER BY
                     CASE severity WHEN 'CRITICAL' THEN 0 ELSE 1 END,
                     timestamp DESC"""
            ).fetchall()
        return [dict(r) for r in rows]

    def get_remediation_status(self) -> Dict[str, Any]:
        """Track which findings are fixed vs open."""
        with _LOCK:
            rows = self._conn.execute(
                """SELECT status, severity, COUNT(*) as count
                   FROM findings
                   GROUP BY status, severity"""
            ).fetchall()
        summary: Dict[str, Any] = {"open": {}, "fixed": {}, "total_open": 0, "total_fixed": 0}
        for r in rows:
            status = r["status"]
            sev = r["severity"]
            cnt = r["count"]
            bucket = summary.get(status, {})
            bucket[sev] = cnt
            summary[status] = bucket
            if status == "open":
                summary["total_open"] += cnt
            elif status == "fixed":
                summary["total_fixed"] += cnt
        return summary

    # ------------------------------------------------------------------
    # Delete / Export
    # ------------------------------------------------------------------

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and cascade-delete its findings."""
        self._backup()
        with _LOCK:
            cur = self._conn.execute(
                "DELETE FROM scans WHERE id = ?", (scan_id,)
            )
            self._log_action("", "delete_scan", "", f"Deleted scan {scan_id}")
            return cur.rowcount > 0

    def export_findings(self, fmt: str = "json") -> str:
        """Export all findings as JSON or CSV string."""
        findings = self.get_findings()
        if fmt.lower() == "csv":
            if not findings:
                return ""
            buf = []
            writer = csv.DictWriter(buf, fieldnames=findings[0].keys())
            writer.writeheader()
            writer.writerows(findings)
            return "".join(buf)
        return json.dumps(findings, indent=2, default=str)

    # ------------------------------------------------------------------
    # Mark remediation
    # ------------------------------------------------------------------

    def mark_fixed(self, finding_id: str) -> bool:
        """Mark a finding as fixed."""
        with _LOCK:
            cur = self._conn.execute(
                "UPDATE findings SET status = 'fixed' WHERE id = ?",
                (finding_id,),
            )
            return cur.rowcount > 0

    def mark_open(self, finding_id: str) -> bool:
        """Reopen a finding."""
        with _LOCK:
            cur = self._conn.execute(
                "UPDATE findings SET status = 'open' WHERE id = ?",
                (finding_id,),
            )
            return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Operator logging
    # ------------------------------------------------------------------

    def _log_action(
        self, operator: str, action: str, target: str, details: str
    ):
        """Write an audit log entry (called within an existing lock)."""
        self._conn.execute(
            """INSERT INTO operator_logs (operator, action, target, timestamp, details)
               VALUES (?, ?, ?, ?, ?)""",
            (operator, action, target, datetime.now(tz=None).isoformat(), details),
        )

    def get_operator_logs(
        self, operator: Optional[str] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Retrieve audit log entries."""
        query = "SELECT * FROM operator_logs"
        params: list = []
        if operator:
            query += " WHERE operator = ?"
            params.append(operator)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with _LOCK:
            rows = self._conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Persistence / lifecycle
    # ------------------------------------------------------------------

    def save(self):
        """Persist the working database to encrypted storage."""
        self._conn.commit()
        self._encrypt_and_write()

    def close(self):
        """Commit, encrypt, and clean up temp files."""
        if self._conn:
            try:
                self._conn.commit()
                self._encrypt_and_write()
            except Exception:
                pass
            finally:
                self._conn.close()
                self._conn = None
        if self._temp_dir and os.path.isdir(self._temp_dir):
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            self._temp_dir = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _gen_id(prefix: str = "") -> str:
        ts = int(time.time() * 1000)
        import random
        rand = random.randint(1000, 9999)
        return f"{prefix}{ts}{rand}"

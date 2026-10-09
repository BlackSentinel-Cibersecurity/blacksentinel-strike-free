"""
BlackSentinel Strike - Persistent Audit Logging Module
Production-grade structured logging with rotation and thread safety.
"""

import logging
import logging.handlers
import json
import os
import threading
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path


class AuditLogger:
    """Thread-safe persistent audit logger with file rotation and JSON output."""

    LOG_TYPES = {
        "scan": "BS_SCAN",
        "finding": "BS_FINDING",
        "action": "BS_ACTION",
        "error": "BS_ERROR",
        "login": "BS_LOGIN",
        "export": "BS_EXPORT",
        "escalation": "BS_ESCALATION",
    }

    LEVELS = {
        "scan": "INFO",
        "finding": "WARNING",
        "action": "INFO",
        "error": "ERROR",
        "login": "INFO",
        "export": "INFO",
        "escalation": "CRITICAL",
    }

    def __init__(self, log_dir=None, max_bytes=10 * 1024 * 1024, backup_count=10):
        """Initialize audit logger with rotation.

        Args:
            log_dir: Directory for log files. Defaults to ~/.blacksentinel-strike/logs/
            max_bytes: Maximum file size before rotation. Default 10MB.
            backup_count: Number of rotated backups to keep. Default 10.
        """
        self._lock = threading.RLock()

        if log_dir is None:
            log_dir = os.path.join(Path.home(), ".blacksentinel-strike", "logs")
        self.log_dir = log_dir
        self.max_bytes = max_bytes
        self.backup_count = backup_count

        os.makedirs(self.log_dir, exist_ok=True)

        self._audit_logger = self._create_logger(
            name="bs_audit",
            filepath=os.path.join(self.log_dir, "bs_audit.json"),
            max_bytes=max_bytes,
            backup_count=backup_count,
        )

        self._error_logger = self._create_logger(
            name="bs_error",
            filepath=os.path.join(self.log_dir, "bs_errors.json"),
            max_bytes=max_bytes,
            backup_count=backup_count,
        )

        self._memory_log = []
        self._memory_lock = threading.Lock()
        self._max_memory_logs = 5000

    def _create_logger(self, name, filepath, max_bytes, backup_count):
        """Create a rotating file handler with JSON output."""
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        logger.handlers.clear()

        handler = logging.handlers.RotatingFileHandler(
            filepath,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        handler.setLevel(logging.DEBUG)

        class JSONFormatter(logging.Formatter):
            def format(self, record):
                if hasattr(record, "audit_data"):
                    return json.dumps(record.audit_data, ensure_ascii=False)
                log_entry = {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "level": record.levelname,
                    "message": record.getMessage(),
                }
                return json.dumps(log_entry, ensure_ascii=False)

        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
        return logger

    def _get_log_files(self, base_filename):
        """Collect all log files including rotated backups.

        Args:
            base_filename: Base filename like 'bs_audit.json'.

        Returns:
            List of absolute file paths, newest file first.
        """
        files = []
        base_path = os.path.join(self.log_dir, base_filename)
        if os.path.exists(base_path):
            files.append(base_path)

        for i in range(1, self.backup_count + 1):
            rotated = base_path + "." + str(i)
            if os.path.exists(rotated):
                files.append(rotated)

        return files

    def _read_entries(self, base_filename):
        """Read all entries from a log file and its rotated backups.

        Args:
            base_filename: Base filename like 'bs_audit.json'.

        Returns:
            List of parsed JSON log entries.
        """
        entries = []
        for filepath in self._get_log_files(base_filename):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
            except OSError:
                continue
        return entries

    def _write_log(self, log_type, data):
        """Write a structured log entry."""
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "epoch": time.time(),
            "id": str(uuid.uuid4()),
            "level": self.LEVELS.get(log_type, "INFO"),
            "type": self.LOG_TYPES.get(log_type, "BS_UNKNOWN"),
            **data,
        }

        with self._lock:
            record = logging.LogRecord(
                name="bs_audit",
                level=getattr(logging, self.LEVELS.get(log_type, "INFO")),
                pathname="",
                lineno=0,
                msg="",
                args=None,
                exc_info=None,
            )
            record.audit_data = entry

            if log_type == "error":
                self._error_logger.handle(record)

            self._audit_logger.handle(record)

        with self._memory_lock:
            self._memory_log.append(entry)
            if len(self._memory_log) > self._max_memory_logs:
                self._memory_log = self._memory_log[-self._max_memory_logs:]

        return entry

    def log_scan(self, target, scan_type, operator, status="started"):
        """Log a scan event.

        Args:
            target: Target host/IP/URL being scanned.
            scan_type: Type of scan (port, vuln, web, etc.).
            operator: User performing the scan.
            status: 'started' or 'completed'.
        """
        return self._write_log(
            "scan",
            {
                "action": "scan_" + status,
                "operator": operator,
                "target": target,
                "scan_type": scan_type,
                "status": status,
            },
        )

    def log_finding(self, finding):
        """Log a vulnerability finding.

        Args:
            finding: Dict with at minimum 'id', 'title', 'severity', 'target'.
        """
        return self._write_log(
            "finding",
            {
                "action": "finding_detected",
                "finding_id": finding.get("id", str(uuid.uuid4())),
                "title": finding.get("title", "Unknown"),
                "severity": finding.get("severity", "INFO"),
                "target": finding.get("target", "unknown"),
                "cve": finding.get("cve"),
                "cvss": finding.get("cvss"),
                "details": finding.get("details", {}),
            },
        )

    def log_action(self, action, operator, target, details=None):
        """Log a user action.

        Args:
            action: Action name (e.g. 'port_scan', 'brute_force').
            operator: User performing the action.
            target: Target of the action.
            details: Optional dict of additional details.
        """
        return self._write_log(
            "action",
            {
                "action": action,
                "operator": operator,
                "target": target,
                "details": details or {},
            },
        )

    def log_error(self, error, module, operator="system"):
        """Log an error event.

        Args:
            error: Error message string or exception.
            module: Module where the error occurred.
            operator: User context at time of error.
        """
        error_msg = str(error)
        if hasattr(error, "__traceback__"):
            import traceback

            error_msg = "".join(traceback.format_exception(type(error), error, error.__traceback__))

        return self._write_log(
            "error",
            {
                "action": "error_occurred",
                "operator": operator,
                "module": module,
                "error": error_msg,
            },
        )

    def log_login(self, operator, success, ip="unknown"):
        """Log an authentication event.

        Args:
            operator: Username attempting login.
            success: Boolean indicating login success.
            ip: IP address of the login attempt.
        """
        return self._write_log(
            "login",
            {
                "action": "login_success" if success else "login_failure",
                "operator": operator,
                "target": ip,
                "success": success,
                "ip": ip,
            },
        )

    def log_export(self, operator, format, record_count):
        """Log a data export event.

        Args:
            operator: User exporting data.
            format: Export format (json, csv, pdf, etc.).
            record_count: Number of records exported.
        """
        return self._write_log(
            "export",
            {
                "action": "data_export",
                "operator": operator,
                "format": format,
                "record_count": record_count,
            },
        )

    def log_escalation(self, finding_id, operator, reason):
        """Log a severity escalation.

        Args:
            finding_id: ID of the finding being escalated.
            operator: User performing the escalation.
            reason: Reason for the escalation.
        """
        return self._write_log(
            "escalation",
            {
                "action": "severity_escalation",
                "operator": operator,
                "finding_id": finding_id,
                "reason": reason,
            },
        )

    def get_logs(self, log_type=None, operator=None, limit=100, offset=0):
        """Query logs with optional filters.

        Args:
            log_type: Filter by log type (scan, finding, action, error, login, export, escalation).
            operator: Filter by operator username.
            limit: Maximum number of results. Default 100.
            offset: Pagination offset. Default 0.

        Returns:
            List of matching log entries.
        """
        results = []

        with self._lock:
            for base in ["bs_audit.json", "bs_errors.json"]:
                for entry in self._read_entries(base):
                    if log_type and entry.get("type") != self.LOG_TYPES.get(log_type):
                        continue
                    if operator and entry.get("operator") != operator:
                        continue
                    results.append(entry)

        results.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

        if offset > 0:
            results = results[offset:]
        if limit > 0:
            results = results[:limit]

        return results

    def get_audit_trail(self, target=None, operator=None, days=7):
        """Get audit trail for a target or operator over a time window.

        Args:
            target: Filter by target. None for all targets.
            operator: Filter by operator. None for all operators.
            days: Number of days to look back. Default 7.

        Returns:
            List of audit trail entries.
        """
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat() + "Z"
        results = []

        with self._lock:
            for entry in self._read_entries("bs_audit.json"):
                if entry.get("timestamp", "") < cutoff:
                    continue
                if target and entry.get("target") != target:
                    continue
                if operator and entry.get("operator") != operator:
                    continue
                results.append(entry)

        results.sort(key=lambda x: x.get("timestamp", ""))
        return results

    def search_logs(self, query):
        """Full-text search across all log files.

        Args:
            query: Search string (case-insensitive substring match).

        Returns:
            List of matching log entries.
        """
        results = []
        query_lower = query.lower()

        with self._lock:
            for base in ["bs_audit.json", "bs_errors.json"]:
                for filepath in self._get_log_files(base):
                    try:
                        with open(filepath, "r", encoding="utf-8") as f:
                            for line in f:
                                line = line.strip()
                                if not line:
                                    continue
                                if query_lower in line.lower():
                                    try:
                                        results.append(json.loads(line))
                                    except json.JSONDecodeError:
                                        continue
                    except OSError:
                        continue

        results.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return results

    def export_logs(self, format="json"):
        """Export all logs.

        Args:
            format: Output format - 'json' or 'csv'. Default 'json'.

        Returns:
            String of exported data.
        """
        all_logs = self.get_logs(log_type=None, operator=None, limit=0, offset=0)

        if format == "csv":
            import csv
            import io

            output = io.StringIO()
            if not all_logs:
                return ""

            fieldnames = ["timestamp", "level", "type", "action", "operator", "target", "id"]
            extra_fields = set()
            for entry in all_logs:
                extra_fields.update(entry.keys())
            extra_fields -= set(fieldnames)
            fieldnames.extend(sorted(extra_fields))

            writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            for entry in all_logs:
                row = {k: v for k, v in entry.items() if k in fieldnames}
                writer.writerow(row)

            self.log_export(operator="system", format="csv", record_count=len(all_logs))
            return output.getvalue()

        self.log_export(operator="system", format="json", record_count=len(all_logs))
        return json.dumps(all_logs, indent=2, ensure_ascii=False)

    def cleanup(self, older_than_days=90):
        """Remove log entries older than specified days.

        Args:
            older_than_days: Remove entries older than this many days. Default 90.

        Returns:
            Tuple of (total_removed, files_affected).
        """
        cutoff = (datetime.utcnow() - timedelta(days=older_than_days)).isoformat() + "Z"
        total_removed = 0
        files_affected = 0

        for base in ["bs_audit.json", "bs_errors.json"]:
            for filepath in self._get_log_files(base):
                with self._lock:
                    kept = []
                    removed = 0

                    try:
                        with open(filepath, "r", encoding="utf-8") as f:
                            for line in f:
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    entry = json.loads(line)
                                except json.JSONDecodeError:
                                    removed += 1
                                    continue

                                if entry.get("timestamp", "") >= cutoff:
                                    kept.append(json.dumps(entry, ensure_ascii=False))
                                else:
                                    removed += 1
                    except OSError:
                        continue

                    if removed > 0:
                        try:
                            with open(filepath, "w", encoding="utf-8") as f:
                                for line in kept:
                                    f.write(line + "\n")
                            total_removed += removed
                            files_affected += 1
                        except OSError:
                            continue

        return total_removed, files_affected

    def get_log_stats(self):
        """Get summary statistics of log data.

        Returns:
            Dict with counts by type and operator.
        """
        stats = {
            "total_entries": 0,
            "by_type": {},
            "by_operator": {},
            "by_level": {},
            "oldest_entry": None,
            "newest_entry": None,
        }

        with self._lock:
            for base in ["bs_audit.json", "bs_errors.json"]:
                for entry in self._read_entries(base):
                    stats["total_entries"] += 1

                    log_type = entry.get("type", "unknown")
                    stats["by_type"][log_type] = stats["by_type"].get(log_type, 0) + 1

                    op = entry.get("operator", "unknown")
                    stats["by_operator"][op] = stats["by_operator"].get(op, 0) + 1

                    level = entry.get("level", "unknown")
                    stats["by_level"][level] = stats["by_level"].get(level, 0) + 1

                    ts = entry.get("timestamp", "")
                    if ts:
                        if stats["oldest_entry"] is None or ts < stats["oldest_entry"]:
                            stats["oldest_entry"] = ts
                        if stats["newest_entry"] is None or ts > stats["newest_entry"]:
                            stats["newest_entry"] = ts

        return stats


_logger_instance = None
_logger_lock = threading.Lock()


def get_logger(log_dir=None, max_bytes=10 * 1024 * 1024, backup_count=10):
    """Get or create the singleton AuditLogger instance.

    Args:
        log_dir: Directory for log files. Used only on first call.
        max_bytes: Max rotation size. Used only on first call.
        backup_count: Number of backups. Used only on first call.

    Returns:
        AuditLogger instance.
    """
    global _logger_instance
    with _logger_lock:
        if _logger_instance is None:
            _logger_instance = AuditLogger(
                log_dir=log_dir,
                max_bytes=max_bytes,
                backup_count=backup_count,
            )
    return _logger_instance

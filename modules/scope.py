"""
BlackSentinel Strike - Scope Authorization Module
Production-grade scope management with encrypted storage and enforcement.

Every scan/exploit MUST call scope_manager.is_target_authorized(target)
BEFORE execution. Unauthorized targets are BLOCKED and LOGGED.
"""

import ipaddress
import json
import os
import re
import threading
import uuid
from datetime import datetime
from pathlib import Path

from modules.vault import encrypt_data, decrypt_data, _ensure_dirs, VAULT_DIR


SCOPE_FILE = VAULT_DIR / "scope.enc"

_lock = threading.Lock()


class ScopeManager:
    """Thread-safe scope authorization with AES-256-CBC encrypted storage."""

    def __init__(self, db_path=None):
        """Initialize scope manager with encrypted vault storage.

        Args:
            db_path: Unused, kept for interface compatibility.
        """
        self._scope_path = SCOPE_FILE
        _ensure_dirs()
        self._password = self._load_or_create_password()
        self._data = self._load()

    def _load_or_create_password(self):
        """Load or create a machine-bound key for scope encryption."""
        key_path = VAULT_DIR / ".scope_key"
        if key_path.exists():
            return key_path.read_text().strip()
        import secrets

        key = secrets.token_hex(32)
        key_path.write_text(key)
        os.chmod(str(key_path), 0o600)
        return key

    def _load(self):
        """Load encrypted scope data from disk."""
        if not self._scope_path.exists():
            return {"scopes": {}, "exclusions": {}, "blocked_attempts": []}
        try:
            raw = self._scope_path.read_bytes()
            plain = decrypt_data(raw, self._password)
            return json.loads(plain.decode("utf-8"))
        except Exception:
            return {"scopes": {}, "exclusions": {}, "blocked_attempts": []}

    def _save(self):
        """Persist scope data to encrypted storage."""
        blob = json.dumps(self._data, ensure_ascii=False).encode("utf-8")
        encrypted = encrypt_data(blob, self._password)
        self._scope_path.write_bytes(encrypted)
        os.chmod(str(self._scope_path), 0o600)

    # ── scope CRUD ────────────────────────────────────────────────────

    def add_scope(self, name, targets, description="", start_date="", end_date="", operator=""):
        """Add an authorized scope.

        Args:
            name: Human-readable scope name.
            targets: List of target strings or comma-separated string.
                     Supports IPs, CIDRs, ranges, domains, wildcards, file refs.
            description: Free-text description.
            start_date: ISO date string (YYYY-MM-DD). Empty = now.
            end_date: ISO date string (YYYY-MM-DD). Empty = no expiry.
            operator: Person who authorized this scope.

        Returns:
            Scope ID string.
        """
        if isinstance(targets, str):
            targets = [t.strip() for t in targets.split(",") if t.strip()]

        parsed = []
        for t in targets:
            parsed.extend(self._parse_target(t))

        if not parsed:
            raise ValueError("No valid targets provided")

        scope_id = str(uuid.uuid4())[:8]
        now = datetime.now(tz=None).isoformat() + "Z"

        if not start_date:
            start_date = datetime.now(tz=None).strftime("%Y-%m-%d")

        scope = {
            "id": scope_id,
            "name": name,
            "targets": parsed,
            "raw_targets": targets,
            "description": description,
            "start_date": start_date,
            "end_date": end_date,
            "operator": operator,
            "created": now,
            "updated": now,
            "active": True,
        }

        with _lock:
            self._data["scopes"][scope_id] = scope
            self._save()
        return scope_id

    def remove_scope(self, scope_id):
        """Deactivate a scope. Returns True if found."""
        with _lock:
            if scope_id not in self._data["scopes"]:
                return False
            self._data["scopes"][scope_id]["active"] = False
            self._data["scopes"][scope_id]["updated"] = datetime.now(tz=None).isoformat() + "Z"
            self._save()
        return True

    def list_scopes(self):
        """Return list of all active scopes."""
        with _lock:
            return [s for s in self._data["scopes"].values() if s.get("active", True)]

    def get_scope(self, scope_id):
        """Return scope dict by ID, or None."""
        with _lock:
            return self._data["scopes"].get(scope_id)

    def update_scope(self, scope_id, **kwargs):
        """Update scope fields. Returns True if found."""
        with _lock:
            if scope_id not in self._data["scopes"]:
                return False
            scope = self._data["scopes"][scope_id]
            for key in ("name", "description", "start_date", "end_date", "operator", "active"):
                if key in kwargs:
                    scope[key] = kwargs[key]
            if "targets" in kwargs:
                raw = kwargs["targets"]
                if isinstance(raw, str):
                    raw = [t.strip() for t in raw.split(",") if t.strip()]
                parsed = []
                for t in raw:
                    parsed.extend(self._parse_target(t))
                scope["targets"] = parsed
                scope["raw_targets"] = kwargs["targets"]
            scope["updated"] = datetime.now(tz=None).isoformat() + "Z"
            self._save()
        return True

    # ── authorization / enforcement ───────────────────────────────────

    def is_target_authorized(self, target, scope_id=None):
        """Check if a target is authorized within any (or specific) active scope.

        THIS IS THE GATEKEEPER. Every module MUST call this before scanning.

        Args:
            target: IP, domain, or URL to check.
            scope_id: Optional specific scope to check. None = any active scope.

        Returns:
            True if authorized, False otherwise.
        """
        target_clean = self._normalize_target(target)

        with _lock:
            if self._is_excluded(target_clean):
                return False

            scopes = self._data["scopes"]
            if scope_id:
                s = scopes.get(scope_id)
                if s and s.get("active") and self._target_in_scope(target_clean, s):
                    return self._scope_dates_valid(s)
                return False

            for s in scopes.values():
                if not s.get("active", True):
                    continue
                if self._target_in_scope(target_clean, s):
                    if self._scope_dates_valid(s):
                        return True
                    return False

            self._log_blocked(target_clean)
            return False

    def get_scope_for_target(self, target):
        """Find which active scope covers a target. Returns scope dict or None."""
        target_clean = self._normalize_target(target)
        with _lock:
            for s in self._data["scopes"].values():
                if not s.get("active", True):
                    continue
                if self._target_in_scope(target_clean, s):
                    if self._scope_dates_valid(s):
                        return s
            return None

    def check_scope_status(self):
        """Return list of scopes with remaining time info."""
        now = datetime.now(tz=None)
        result = []
        with _lock:
            for s in self._data["scopes"].values():
                if not s.get("active", True):
                    continue
                end = s.get("end_date", "")
                remaining = "unlimited"
                expired = False
                if end:
                    try:
                        end_dt = datetime.strptime(end, "%Y-%m-%d")
                        delta = end_dt - now
                        if delta.total_seconds() < 0:
                            remaining = "EXPIRED"
                            expired = True
                        else:
                            days = delta.days
                            remaining = f"{days}d {delta.seconds // 3600}h"
                    except ValueError:
                        remaining = "invalid date"
                result.append(
                    {
                        "id": s["id"],
                        "name": s["name"],
                        "start_date": s.get("start_date", ""),
                        "end_date": end,
                        "remaining": remaining,
                        "expired": expired,
                        "target_count": len(s.get("targets", [])),
                        "operator": s.get("operator", ""),
                    }
                )
        return result

    # ── exclusions ────────────────────────────────────────────────────

    def add_exclusion(self, scope_id, target, reason=""):
        """Add a target to the exclusion list within a scope."""
        target_clean = self._normalize_target(target)
        with _lock:
            if scope_id not in self._data["scopes"]:
                return False
            excl = self._data["exclusions"].setdefault(scope_id, [])
            excl.append(
                {
                    "target": target_clean,
                    "reason": reason,
                    "added": datetime.now(tz=None).isoformat() + "Z",
                }
            )
            self._save()
        return True

    def is_excluded(self, target):
        """Check if a target is excluded in ANY scope."""
        target_clean = self._normalize_target(target)
        with _lock:
            return self._is_excluded(target_clean)

    def get_exclusions(self, scope_id):
        """List exclusions for a scope."""
        with _lock:
            return list(self._data["exclusions"].get(scope_id, []))

    # ── reporting ─────────────────────────────────────────────────────

    def generate_report(self):
        """Generate a scope compliance report."""
        now = datetime.now(tz=None)
        report = {
            "generated": now.isoformat() + "Z",
            "total_scopes": 0,
            "active_scopes": 0,
            "expired_scopes": 0,
            "total_targets": 0,
            "total_exclusions": 0,
            "blocked_attempts": len(self._data.get("blocked_attempts", [])),
            "scopes": [],
        }
        with _lock:
            for s in self._data["scopes"].values():
                report["total_scopes"] += 1
                end = s.get("end_date", "")
                expired = False
                if end:
                    try:
                        end_dt = datetime.strptime(end, "%Y-%m-%d")
                        if end_dt < now:
                            expired = True
                    except ValueError:
                        pass
                if s.get("active") and not expired:
                    report["active_scopes"] += 1
                elif expired:
                    report["expired_scopes"] += 1

                report["total_targets"] += len(s.get("targets", []))
                report["scopes"].append(
                    {
                        "id": s["id"],
                        "name": s["name"],
                        "active": s.get("active", True),
                        "expired": expired,
                        "targets": s.get("targets", []),
                        "exclusions": self._data["exclusions"].get(s["id"], []),
                    }
                )

            report["total_exclusions"] = sum(len(v) for v in self._data["exclusions"].values())
            recent_blocked = self._data.get("blocked_attempts", [])[-20:]
            report["recent_blocked"] = recent_blocked
        return report

    # ── import / export ───────────────────────────────────────────────

    def import_scope(self, file_path):
        """Import scope from CSV or TXT file.

        CSV format: name,targets,description,start_date,end_date,operator
        TXT format: one target per line (uses filename as scope name)

        Returns:
            Scope ID on success, None on failure.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        lines = path.read_text(encoding="utf-8").strip().splitlines()
        if not lines:
            raise ValueError("Empty file")

        ext = path.suffix.lower()
        if ext == ".csv":
            return self._import_csv(lines, path.stem)
        else:
            return self._import_txt(lines, path.stem)

    def _import_csv(self, lines, fallback_name):
        """Parse CSV import."""
        if not lines:
            return None
        header = lines[0].lower()
        start_idx = 1 if "name" in header or "target" in header else 0
        for line in lines[start_idx:]:
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 2:
                continue
            name = parts[0] or fallback_name
            targets = parts[1]
            desc = parts[2] if len(parts) > 2 else ""
            start = parts[3] if len(parts) > 3 else ""
            end = parts[4] if len(parts) > 4 else ""
            op = parts[5] if len(parts) > 5 else ""
            return self.add_scope(name, targets, desc, start, end, op)
        return None

    def _import_txt(self, lines, fallback_name):
        """Parse TXT import (one target per line)."""
        targets = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
        if targets:
            return self.add_scope(fallback_name, targets)
        return None

    def export_scope(self, scope_id, format="json"):
        """Export scope definition.

        Args:
            scope_id: Scope to export.
            format: 'json' or 'csv'.

        Returns:
            String of exported data.
        """
        with _lock:
            scope = self._data["scopes"].get(scope_id)
            if not scope:
                return None
            exclusions = self._data["exclusions"].get(scope_id, [])

        if format == "csv":
            import io
            import csv

            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(
                ["name", "targets", "description", "start_date", "end_date", "operator", "active", "exclusions"]
            )
            writer.writerow(
                [
                    scope["name"],
                    "; ".join(scope.get("raw_targets", scope["targets"])),
                    scope.get("description", ""),
                    scope.get("start_date", ""),
                    scope.get("end_date", ""),
                    scope.get("operator", ""),
                    scope.get("active", True),
                    "; ".join(e["target"] for e in exclusions),
                ]
            )
            return buf.getvalue()

        return json.dumps(
            {
                "scope": scope,
                "exclusions": exclusions,
            },
            indent=2,
            ensure_ascii=False,
        )

    # ── internal helpers ──────────────────────────────────────────────

    def _normalize_target(self, target):
        """Normalize a target string for comparison."""
        t = target.strip().lower()
        t = re.sub(r"^https?://", "", t)
        t = t.rstrip("/")
        return t

    def _parse_target(self, raw):
        """Parse a single target string into normalized entries.

        Returns list of normalized target strings.
        """
        raw = raw.strip()
        if not raw:
            return []

        if raw.startswith("@") or raw.endswith(".txt"):
            return self._parse_file(raw.lstrip("@"))

        if "," in raw:
            result = []
            for part in raw.split(","):
                result.extend(self._parse_target(part.strip()))
            return result

        return [self._normalize_target(raw)]

    def _parse_file(self, file_path):
        """Read targets from a file, one per line."""
        path = Path(file_path)
        if not path.exists():
            return []
        targets = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.extend(self._parse_target(line))
        return targets

    def _target_in_scope(self, target, scope):
        """Check if a normalized target matches any entry in a scope."""
        for entry in scope.get("targets", []):
            if self._match_target(target, entry):
                return True
        return False

    def _match_target(self, target, entry):
        """Match a target against a scope entry."""
        if target == entry:
            return True

        if entry.startswith("*."):
            base = entry[2:]
            if target == base:
                return True
            if target.endswith("." + base):
                return True
            return False

        if "/" in entry:
            try:
                net = ipaddress.ip_network(entry, strict=False)
                addr = ipaddress.ip_address(target)
                return addr in net
            except ValueError:
                pass

        if "-" in entry and not entry.startswith("-"):
            parts = entry.split("-", 1)
            try:
                start = ipaddress.ip_address(parts[0].strip())
                end = ipaddress.ip_address(parts[1].strip())
                addr = ipaddress.ip_address(target)
                return start <= addr <= end
            except ValueError:
                pass

        if re.match(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*\.[a-z]{2,}$", entry):
            if target == entry:
                return True
            if target.endswith("." + entry):
                return True
            return False

        return False

    def _scope_dates_valid(self, scope):
        """Check if scope is within its valid date range."""
        now = datetime.now(tz=None)
        start = scope.get("start_date", "")
        end = scope.get("end_date", "")

        if start:
            try:
                start_dt = datetime.strptime(start, "%Y-%m-%d")
                if now < start_dt:
                    return False
            except ValueError:
                pass

        if end:
            try:
                end_dt = datetime.strptime(end, "%Y-%m-%d")
                if now > end_dt:
                    return False
            except ValueError:
                pass

        return True

    def _is_excluded(self, target):
        """Internal exclusion check (caller must hold _lock)."""
        for excl_list in self._data["exclusions"].values():
            for e in excl_list:
                if self._match_target(target, e["target"]):
                    return True
        return False

    def _log_blocked(self, target):
        """Log an unauthorized access attempt (caller must hold _lock)."""
        entry = {
            "target": target,
            "timestamp": datetime.now(tz=None).isoformat() + "Z",
            "action": "BLOCKED",
        }
        self._data.setdefault("blocked_attempts", []).append(entry)
        if len(self._data["blocked_attempts"]) > 1000:
            self._data["blocked_attempts"] = self._data["blocked_attempts"][-500:]
        self._save()


# ── singleton accessor ────────────────────────────────────────────────

_scope_manager = None
_scope_lock = threading.Lock()


def get_scope_manager(db_path=None):
    """Get or create the singleton ScopeManager instance.

    Args:
        db_path: Unused, kept for interface compatibility.

    Returns:
        ScopeManager instance.
    """
    global _scope_manager
    with _scope_lock:
        if _scope_manager is None:
            _scope_manager = ScopeManager(db_path=db_path)
    return _scope_manager

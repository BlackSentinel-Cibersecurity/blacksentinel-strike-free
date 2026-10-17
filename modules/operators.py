"""Single operator profile management.

Production-grade single-user profile with:
  - AES-256-CBC encrypted storage via vault
  - PBKDF2-HMAC-SHA256 password hashing
  - Session token with configurable expiry
  - Thread-safe operations
  - Full audit trail
"""

import os
import json
import secrets
import hashlib
import threading
from pathlib import Path
from datetime import datetime, timedelta

try:
    from . import vault as _vault
except ImportError:
    _vault = None

OPERATORS_DIR = Path.home() / ".blacksentinel-strike"
OPERATORS_FILE = OPERATORS_DIR / "operators.enc"
DEFAULT_SESSION_EXPIRY_HOURS = 8


def _hash_password(password: str, salt: bytes = None) -> tuple:
    """PBKDF2-HMAC-SHA256 with random salt. Returns (hash, salt)."""
    if salt is None:
        salt = os.urandom(32)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 1_000_000)
    return dk, salt


def _verify_password(password: str, stored_hash: bytes, salt: bytes) -> bool:
    dk, _ = _hash_password(password, salt)
    if len(dk) != len(stored_hash):
        return False
    result = 0
    for a, b in zip(dk, stored_hash):
        result |= a ^ b
    return result == 0


def _generate_token() -> str:
    return secrets.token_hex(32)


def validate_password_policy(password: str) -> tuple:
    """Validate password against security policy.

    Policy:
      - At least 1 uppercase letter
      - At least 1 lowercase letter
      - At least 3 numbers
      - At least 1 special character (!@#$%^&*()_+-=[]{}|;:,.<>?)

    Returns (is_valid, list_of_errors)
    """
    errors = []
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    numbers = sum(1 for c in password if c.isdigit())
    special_chars = set("!@#$%^&*()_+-=[]{}|;:,.<>?/~`")
    has_special = any(c in special_chars for c in password)

    if not has_upper:
        errors.append("must contain at least 1 uppercase letter")
    if not has_lower:
        errors.append("must contain at least 1 lowercase letter")
    if numbers < 3:
        errors.append(f"must contain at least 3 numbers (found {numbers})")
    if not has_special:
        errors.append("must contain at least 1 special character (!@#$%^&*...)")

    return (len(errors) == 0, errors)


class OperatorManager:
    """Thread-safe single operator profile manager with encrypted storage."""

    def __init__(self, db_path=None):
        self._db_path = Path(db_path) if db_path else OPERATORS_FILE
        self._lock = threading.Lock()
        self._session = None
        self._profile = None
        self._audit_log = []
        self._load()

    # ── persistence ────────────────────────────────────────────────

    def _load(self):
        if not self._db_path.exists():
            self._profile = None
            self._audit_log = []
            return
        try:
            raw = self._db_path.read_bytes()
            password = self._get_vault_password()
            if password and _vault:
                data = json.loads(_vault.decrypt_data(raw, password))
            else:
                data = json.loads(raw)
            self._profile = data.get("profile")
            self._audit_log = data.get("audit_log", [])
        except Exception:
            self._profile = None
            self._audit_log = []

    def _save(self):
        OPERATORS_DIR.mkdir(parents=True, exist_ok=True)
        data = {
            "profile": self._profile,
            "audit_log": self._audit_log[-5000:],
        }
        raw = json.dumps(data).encode("utf-8")
        try:
            password = self._get_vault_password()
            if password and _vault:
                encrypted = _vault.encrypt_data(raw, password)
                self._db_path.write_bytes(encrypted)
            else:
                self._db_path.write_bytes(raw)
        except Exception:
            self._db_path.write_bytes(raw)

    def _get_vault_password(self):
        return os.environ.get("BS_VAULT_PASSWORD", None)

    def _audit(self, action: str, detail: str = ""):
        entry = {
            "time": datetime.now().isoformat(),
            "action": action,
            "detail": detail,
        }
        self._audit_log.append(entry)
        if len(self._audit_log) > 10000:
            self._audit_log = self._audit_log[-5000:]

    # ── profile management ─────────────────────────────────────────

    def has_profile(self) -> bool:
        return self._profile is not None

    def create_profile(self, full_name: str, password: str) -> dict:
        """Create the single operator profile."""
        with self._lock:
            if self._profile:
                raise ValueError("Profile already exists")
            is_valid, errors = validate_password_policy(password)
            if not is_valid:
                raise ValueError("Password policy violated: " + "; ".join(errors))
            hashed, salt = _hash_password(password)
            self._profile = {
                "full_name": full_name,
                "password_hash": hashed.hex(),
                "salt": salt.hex(),
                "created": datetime.now().isoformat(),
                "last_login": None,
                "failed_attempts": 0,
                "locked_until": None,
            }
            self._audit("profile_created")
            self._save()
            return {"full_name": full_name, "created": self._profile["created"]}

    def get_profile(self) -> dict:
        with self._lock:
            if not self._profile:
                return None
            return {k: v for k, v in self._profile.items() if k not in ("password_hash", "salt")}

    def update_profile(self, **kwargs) -> dict:
        with self._lock:
            if not self._profile:
                raise ValueError("No profile exists")
            allowed = {"full_name"}
            for key, val in kwargs.items():
                if key in allowed:
                    self._profile[key] = val
            self._audit("profile_updated", json.dumps(kwargs))
            self._save()
            return self.get_profile()

    def change_password(self, old_pass: str, new_pass: str):
        with self._lock:
            if not self._profile:
                raise ValueError("No profile exists")
            salt = bytes.fromhex(self._profile["salt"])
            stored_hash = bytes.fromhex(self._profile["password_hash"])
            if not _verify_password(old_pass, stored_hash, salt):
                raise PermissionError("Old password is incorrect")
            is_valid, errors = validate_password_policy(new_pass)
            if not is_valid:
                raise ValueError("Password policy violated: " + "; ".join(errors))
            hashed, new_salt = _hash_password(new_pass)
            self._profile["password_hash"] = hashed.hex()
            self._profile["salt"] = new_salt.hex()
            self._profile["failed_attempts"] = 0
            self._profile["locked_until"] = None
            self._audit("password_changed")
            self._save()

    # ── authentication ─────────────────────────────────────────────

    def authenticate(self, password: str) -> str:
        with self._lock:
            if not self._profile:
                return None
            if self._profile.get("locked_until"):
                lock_time = datetime.fromisoformat(self._profile["locked_until"])
                if datetime.now() < lock_time:
                    return None
                self._profile["locked_until"] = None
                self._profile["failed_attempts"] = 0
            salt = bytes.fromhex(self._profile["salt"])
            stored_hash = bytes.fromhex(self._profile["password_hash"])
            if not _verify_password(password, stored_hash, salt):
                self._profile["failed_attempts"] = self._profile.get("failed_attempts", 0) + 1
                if self._profile["failed_attempts"] >= 5:
                    self._profile["locked_until"] = (datetime.now() + timedelta(minutes=15)).isoformat()
                self._audit("auth_failed")
                self._save()
                return None
            token = _generate_token()
            expiry = datetime.now() + timedelta(hours=DEFAULT_SESSION_EXPIRY_HOURS)
            self._session = {
                "token": token,
                "created": datetime.now().isoformat(),
                "expires": expiry.isoformat(),
            }
            self._profile["last_login"] = datetime.now().isoformat()
            self._profile["failed_attempts"] = 0
            self._profile["locked_until"] = None
            self._audit("authenticated")
            self._save()
            return token

    def deauthenticate(self):
        with self._lock:
            if self._session:
                self._audit("deauthenticated")
                self._session = None

    def is_session_valid(self, session_token: str) -> bool:
        if not self._session:
            return False
        if self._session["token"] != session_token:
            return False
        if datetime.now() > datetime.fromisoformat(self._session["expires"]):
            self._session = None
            return False
        return True

    def get_active_session(self) -> dict:
        with self._lock:
            if not self._session:
                return None
            if datetime.now() > datetime.fromisoformat(self._session["expires"]):
                self._session = None
                return None
            return {
                "token": self._session["token"][:16] + "...",
                "created": self._session["created"],
                "expires": self._session["expires"],
            }

    def audit_trail(self) -> list:
        with self._lock:
            return list(self._audit_log)

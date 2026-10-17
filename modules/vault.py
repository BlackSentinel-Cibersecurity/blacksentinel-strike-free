"""AES-256-CBC encryption for local metadata and scan results.

Copyright (c) 2024-2025 BlackSentinel Strike - All Rights Reserved
Author: BlackSentinel Strike
License: Proprietary - All Rights Reserved

Military-grade encryption:
  - AES-256-CBC (256-bit key, random IV per operation)
  - PBKDF2-SHA512 with 1,000,000 iterations (OWASP 2023)
  - HMAC-SHA512 (Encrypt-then-MAC)
  - 64-byte derived key (32 AES + 32 HMAC)
  - 16-byte random IV per encryption
"""

import os
import json
import struct
import time
import hashlib
import hmac as _hmac
from pathlib import Path
import subprocess
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

VAULT_DIR = Path.home() / ".blacksentinel-strike" / "vault"
KEY_FILE = VAULT_DIR / "master.key"
SALT_FILE = VAULT_DIR / "salt.bin"
CONFIG_FILE = VAULT_DIR / "config.enc"
SCAN_DIR = VAULT_DIR / "scans"
META_FILE = VAULT_DIR / "metadata.enc"
TEST_FILE = VAULT_DIR / "test.token"

KDF_ITERATIONS = 1_000_000
SALT_SIZE = 32
IV_SIZE = 16
HMAC_SIZE = 32


def _ensure_dirs():
    VAULT_DIR.mkdir(parents=True, exist_ok=True)
    SCAN_DIR.mkdir(parents=True, exist_ok=True)


def _derive_keys(password: str, salt: bytes) -> tuple:
    """Derive 32-byte AES key + 32-byte HMAC key from password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=64,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend(),
    )
    derived = kdf.derive(password.encode("utf-8"))
    return derived[:32], derived[32:]


def _aes_encrypt(plaintext: bytes, aes_key: bytes, hmac_key: bytes) -> bytes:
    """Encrypt with AES-256-CBC + HMAC-SHA512 (Encrypt-then-MAC)."""
    iv = os.urandom(IV_SIZE)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    # HMAC-SHA512 over IV + ciphertext (Encrypt-then-MAC)
    tag = _hmac.new(hmac_key, iv + ct, hashlib.sha512).digest()[:HMAC_SIZE]
    # Format: IV(16) + CT_len(4) + CT + HMAC(32)
    return iv + struct.pack(">I", len(ct)) + ct + tag


def _aes_decrypt(token: bytes, aes_key: bytes, hmac_key: bytes) -> bytes:
    """Verify HMAC then decrypt AES-256-CBC."""
    if len(token) < IV_SIZE + 4 + HMAC_SIZE:
        raise ValueError("Invalid token: too short")
    iv = token[:IV_SIZE]
    ct_len = struct.unpack(">I", token[IV_SIZE : IV_SIZE + 4])[0]
    ct = token[IV_SIZE + 4 : IV_SIZE + 4 + ct_len]
    stored_tag = token[IV_SIZE + 4 + ct_len : IV_SIZE + 4 + ct_len + HMAC_SIZE]
    # Verify HMAC-SHA512 (constant-time, truncated to 32 bytes)
    computed_tag = _hmac.new(hmac_key, iv + ct, hashlib.sha512).digest()[:HMAC_SIZE]
    if not _constant_time_compare(computed_tag, stored_tag):
        raise ValueError("HMAC verification failed: data tampered or wrong password")
    # Decrypt
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def _get_keys(password: str) -> tuple:
    salt = SALT_FILE.read_bytes()
    return _derive_keys(password, salt)


def validate_password_policy(password: str) -> tuple:
    """Validate password against military-grade security policy.

    Policy:
      - Minimum 12 characters
      - At least 1 uppercase letter
      - At least 1 lowercase letter
      - At least 3 numbers
      - At least 1 special character (!@#$%^&*()_+-=[]{}|;:,.<>?)

    Returns (is_valid, list_of_errors)
    """
    errors = []
    if len(password) < 12:
        errors.append("must be at least 12 characters long")
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


def init_vault(password: str) -> bool:
    """Create vault with AES-256-CBC encryption."""
    _ensure_dirs()
    if KEY_FILE.exists():
        return False
    salt = os.urandom(SALT_SIZE)
    aes_key, hmac_key = _derive_keys(password, salt)
    SALT_FILE.write_bytes(salt)
    KEY_FILE.write_bytes(aes_key + hmac_key)
    if os.name != "nt":
        KEY_FILE.chmod(0o600)
        SALT_FILE.chmod(0o600)
    # Write test token
    test_ct = _aes_encrypt(b"BS_VAULT_OK", aes_key, hmac_key)
    TEST_FILE.write_bytes(test_ct)
    if os.name != "nt":
        TEST_FILE.chmod(0o600)
    return True


def unlock_vault(password: str) -> bool:
    """Verify password by decrypting test token."""
    _ensure_dirs()
    if not KEY_FILE.exists() or not SALT_FILE.exists() or not TEST_FILE.exists():
        return False
    try:
        aes_key, hmac_key = _get_keys(password)
        _aes_decrypt(TEST_FILE.read_bytes(), aes_key, hmac_key)
        return True
    except Exception:
        return False


def encrypt_data(data: bytes, password: str) -> bytes:
    """Encrypt arbitrary data with AES-256-CBC."""
    aes_key, hmac_key = _get_keys(password)
    return _aes_encrypt(data, aes_key, hmac_key)


def decrypt_data(token: bytes, password: str) -> bytes:
    """Decrypt AES-256-CBC encrypted data."""
    aes_key, hmac_key = _get_keys(password)
    return _aes_decrypt(token, aes_key, hmac_key)


def encrypt_file(filepath: str, password: str) -> bool:
    try:
        data = Path(filepath).read_bytes()
        encrypted = encrypt_data(data, password)
        enc_path = filepath + ".enc"
        Path(enc_path).write_bytes(encrypted)
        Path(filepath).unlink(missing_ok=True)
        return True
    except Exception:
        return False


def decrypt_file(enc_filepath: str, password: str) -> bool:
    try:
        data = Path(enc_filepath).read_bytes()
        decrypted = decrypt_data(data, password)
        out_path = enc_filepath.removesuffix(".enc")
        Path(out_path).write_bytes(decrypted)
        Path(enc_filepath).unlink(missing_ok=True)
        return True
    except Exception:
        return False


def save_scan_result(scan_type: str, content: str, password: str) -> str:
    _ensure_dirs()
    ts = time.strftime("%Y%m%d_%H%M%S")
    filename = f"{scan_type}_{ts}.enc"
    filepath = SCAN_DIR / filename
    encrypted = encrypt_data(content.encode(), password)
    filepath.write_bytes(encrypted)
    return str(filepath)


def load_scan_result(enc_path: str, password: str) -> str:
    data = Path(enc_path).read_bytes()
    return decrypt_data(data, password).decode()


def save_metadata(meta: dict, password: str):
    _ensure_dirs()
    encrypted = encrypt_data(json.dumps(meta).encode(), password)
    META_FILE.write_bytes(encrypted)


def load_metadata(password: str) -> dict:
    if not META_FILE.exists():
        return {}
    data = META_FILE.read_bytes()
    return json.loads(decrypt_data(data, password).decode())


def save_config(config: dict, password: str):
    _ensure_dirs()
    encrypted = encrypt_data(json.dumps(config).encode(), password)
    CONFIG_FILE.write_bytes(encrypted)


def load_config(password: str) -> dict:
    if not CONFIG_FILE.exists():
        return _default_config()
    try:
        data = CONFIG_FILE.read_bytes()
        return json.loads(decrypt_data(data, password).decode())
    except Exception:
        return _default_config()


def _get_default_interface() -> str:
    """Detect the first available network interface."""
    try:
        if os.name == "nt":
            result = subprocess.run(
                ["netsh", "interface", "show", "interface"], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[0] in ("Enabled", "Connected"):
                    return parts[-1]
        else:
            result = subprocess.run(["ip", "-o", "link", "show"], capture_output=True, text=True, timeout=5)
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    iface = parts[1].rstrip(":")
                    if iface != "lo":
                        return iface
    except Exception:
        pass
    return "en0"


def _default_config() -> dict:
    iface = _get_default_interface()
    return {
        "ip_rotation": {
            "enabled": False,
            "interval_seconds": 300,
            "method": "dhcp",
            "interface": iface,
        },
        "dns": {
            "primary": "8.8.8.8",
            "secondary": "8.8.4.4",
            "auto_switch": False,
        },
        "mac_randomization": {
            "enabled": False,
            "interface": iface,
            "persist_reboot": False,
        },
        "encryption": {
            "auto_encrypt_scans": True,
            "auto_encrypt_metadata": True,
        },
        "general": {
            "company_name": "",
            "operator_name": "",
            "authorized_targets": "",
        },
    }


def destroy_vault(password: str) -> bool:
    if not unlock_vault(password):
        return False
    import shutil

    shutil.rmtree(VAULT_DIR, ignore_errors=True)
    return True

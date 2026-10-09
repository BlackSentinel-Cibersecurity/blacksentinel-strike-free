import sys
import json
import shutil
import pytest
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules import vault as v


@pytest.fixture
def tmp_vault(tmp_path):
    """Create a temporary vault for testing, fully isolated from the real vault."""
    vault_dir = tmp_path / "vault"
    vault_dir.mkdir()
    scan_dir = vault_dir / "scans"
    scan_dir.mkdir()

    import modules.vault as v
    orig = {
        "VAULT_DIR": v.VAULT_DIR,
        "KEY_FILE": v.KEY_FILE,
        "SALT_FILE": v.SALT_FILE,
        "CONFIG_FILE": v.CONFIG_FILE,
        "SCAN_DIR": v.SCAN_DIR,
        "META_FILE": v.META_FILE,
        "TEST_FILE": v.TEST_FILE,
    }

    v.VAULT_DIR = vault_dir
    v.KEY_FILE = vault_dir / "master.key"
    v.SALT_FILE = vault_dir / "salt.bin"
    v.CONFIG_FILE = vault_dir / "config.enc"
    v.SCAN_DIR = scan_dir
    v.META_FILE = vault_dir / "metadata.enc"
    v.TEST_FILE = vault_dir / "test.token"

    ok = v.init_vault("test_password_123")
    assert ok, "Failed to initialize test vault"

    yield {
        "vault_dir": vault_dir,
        "password": "test_password_123",
        "module": v,
    }

    for key, val in orig.items():
        setattr(v, key, val)


@pytest.fixture
def sample_finding():
    return {
        "id": "F1234",
        "scan_id": "S1234",
        "target": "192.168.1.100",
        "category": "web",
        "severity": "HIGH",
        "title": "SQL Injection in login form",
        "description": "The login form is vulnerable to SQL injection via the username parameter.",
        "cvss": 8.6,
        "cve": "CVE-2024-12345",
        "evidence": "sqlmap output showing database extraction",
        "remediation": "Use parameterized queries",
        "operator": "test_operator",
    }


@pytest.fixture
def sample_scan():
    return {
        "id": "S1234",
        "target": "192.168.1.0/24",
        "scan_type": "network",
        "start_time": datetime.now(tz=None).isoformat(),
        "operator": "test_operator",
        "status": "completed",
        "tool_used": "nmap",
    }


@pytest.fixture
def sample_operator():
    return {
        "username": "testuser",
        "password": "secure_password_123",
        "role": "analyst",
        "full_name": "Test User",
        "email": "test@example.com",
    }

"""Tests for ScopeManager module."""
import sys
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import modules.scope as scope_module
from modules.scope import ScopeManager


@pytest.fixture
def sm(tmp_path, monkeypatch):
    """Create an isolated ScopeManager for testing."""
    scope_enc = tmp_path / "scope.enc"
    scope_key = tmp_path / ".scope_key"
    monkeypatch.setattr(scope_module, "SCOPE_FILE", scope_enc)

    mgr = ScopeManager.__new__(ScopeManager)
    mgr._scope_path = scope_enc
    mgr._password = "test_scope_password"
    mgr._data = {"scopes": {}, "exclusions": {}, "blocked_attempts": []}

    scope_dir = tmp_path / ".blacksentinel-strike"
    scope_dir.mkdir(parents=True, exist_ok=True)
    scope_key.write_text(mgr._password)

    def mock_save():
        import json
        scope_enc.write_text(json.dumps(mgr._data))

    def mock_load():
        import json
        if scope_enc.exists():
            return json.loads(scope_enc.read_text())
        return {"scopes": {}, "exclusions": {}, "blocked_attempts": []}

    monkeypatch.setattr(mgr, "_save", mock_save)
    monkeypatch.setattr(mgr, "_load", mock_load)

    return mgr


class TestAddScope:
    def test_add_scope(self, sm):
        scope_id = sm.add_scope("Test Scope", ["192.168.1.0/24"])
        assert scope_id is not None
        assert len(scope_id) > 0

    def test_add_scope_multiple_targets(self, sm):
        scope_id = sm.add_scope(
            "Multi Target", ["192.168.1.0/24", "10.0.0.0/8"]
        )
        scopes = sm.list_scopes()
        assert len(scopes) == 1
        assert len(scopes[0]["targets"]) >= 2

    def test_add_scope_comma_separated(self, sm):
        scope_id = sm.add_scope("CSV Scope", "192.168.1.0/24, 10.0.0.0/8")
        scopes = sm.list_scopes()
        assert len(scopes) == 1

    def test_add_scope_empty_targets_raises(self, sm):
        with pytest.raises(ValueError, match="No valid targets"):
            sm.add_scope("Empty", [])


class TestIsTargetAuthorized:
    def test_authorized_ip(self, sm):
        sm.add_scope("Test", ["192.168.1.0/24"])
        assert sm.is_target_authorized("192.168.1.50") is True

    def test_unauthorized_ip(self, sm):
        sm.add_scope("Test", ["192.168.1.0/24"])
        assert sm.is_target_authorized("10.0.0.1") is False

    def test_authorized_domain(self, sm):
        sm.add_scope("Web", ["example.com"])
        assert sm.is_target_authorized("example.com") is True

    def test_authorized_subdomain(self, sm):
        sm.add_scope("Web", ["*.example.com"])
        assert sm.is_target_authorized("sub.example.com") is True
        assert sm.is_target_authorized("deep.sub.example.com") is True

    def test_authorized_after_scope_added(self, sm):
        sm.add_scope("Test", ["10.0.0.0/24"])
        assert sm.is_target_authorized("10.0.0.1") is True
        assert sm.is_target_authorized("10.0.0.254") is True

    def test_no_scope_blocks_all(self, sm):
        assert sm.is_target_authorized("192.168.1.1") is False

    def test_url_normalization(self, sm):
        sm.add_scope("Test", ["192.168.1.0/24"])
        assert sm.is_target_authorized("http://192.168.1.50") is True
        assert sm.is_target_authorized("https://192.168.1.50/") is True


class TestIsExcluded:
    def test_excluded_target(self, sm):
        sid = sm.add_scope("Test", ["192.168.1.0/24"])
        sm.add_exclusion(sid, "192.168.1.1", "Gateway - do not scan")
        assert sm.is_excluded("192.168.1.1") is True

    def test_not_excluded(self, sm):
        sid = sm.add_scope("Test", ["192.168.1.0/24"])
        sm.add_exclusion(sid, "192.168.1.1", "Gateway")
        assert sm.is_excluded("192.168.1.50") is False

    def test_excluded_blocks_authorization(self, sm):
        sid = sm.add_scope("Test", ["192.168.1.0/24"])
        sm.add_exclusion(sid, "192.168.1.1")
        assert sm.is_target_authorized("192.168.1.1") is False
        assert sm.is_target_authorized("192.168.1.2") is True


class TestCIDRMatching:
    def test_cidr_exact_match(self, sm):
        sm.add_scope("Test", ["192.168.1.0/32"])
        assert sm.is_target_authorized("192.168.1.0") is True
        assert sm.is_target_authorized("192.168.1.1") is False

    def test_cidr_class_c(self, sm):
        sm.add_scope("Test", ["192.168.1.0/24"])
        assert sm.is_target_authorized("192.168.1.1") is True
        assert sm.is_target_authorized("192.168.1.254") is True
        assert sm.is_target_authorized("192.168.2.1") is False

    def test_cidr_large_network(self, sm):
        sm.add_scope("Test", ["10.0.0.0/8"])
        assert sm.is_target_authorized("10.0.0.1") is True
        assert sm.is_target_authorized("10.255.255.255") is True
        assert sm.is_target_authorized("11.0.0.1") is False


class TestWildcardMatching:
    def test_wildcard_subdomain(self, sm):
        sm.add_scope("Web", ["*.example.com"])
        assert sm.is_target_authorized("api.example.com") is True
        assert sm.is_target_authorized("admin.example.com") is True
        assert sm.is_target_authorized("example.com") is True

    def test_wildcard_deep_subdomain(self, sm):
        sm.add_scope("Web", ["*.corp.example.com"])
        assert sm.is_target_authorized("vhost1.corp.example.com") is True
        assert sm.is_target_authorized("test.corp.example.com") is True

    def test_wildcard_no_cross_domain(self, sm):
        sm.add_scope("Web", ["*.example.com"])
        assert sm.is_target_authorized("evil.com") is False


class TestScopeCRUD:
    def test_remove_scope(self, sm):
        sid = sm.add_scope("Test", ["192.168.1.0/24"])
        assert sm.remove_scope(sid) is True
        scopes = sm.list_scopes()
        assert len(scopes) == 0

    def test_get_scope(self, sm):
        sid = sm.add_scope("Test", ["192.168.1.0/24"])
        scope = sm.get_scope(sid)
        assert scope is not None
        assert scope["name"] == "Test"

    def test_update_scope(self, sm):
        sid = sm.add_scope("Test", ["192.168.1.0/24"])
        result = sm.update_scope(sid, name="Updated Scope")
        assert result is True
        scope = sm.get_scope(sid)
        assert scope["name"] == "Updated Scope"

import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.operators import OperatorManager, _hash_password, _verify_password, validate_password_policy


@pytest.fixture
def mgr(tmp_path):
    """Create a temporary operator manager."""
    db_path = tmp_path / "operators.json"
    manager = OperatorManager(db_path=str(db_path))
    yield manager


class TestPasswordPolicy:
    def test_valid_password(self):
        is_valid, errors = validate_password_policy("Strong123!")
        assert is_valid is True
        assert errors == []

    def test_missing_uppercase(self):
        is_valid, errors = validate_password_policy("lower123!")
        assert is_valid is False
        assert any("uppercase" in e for e in errors)

    def test_missing_lowercase(self):
        is_valid, errors = validate_password_policy("UPPER123!")
        assert is_valid is False
        assert any("lowercase" in e for e in errors)

    def test_missing_numbers(self):
        is_valid, errors = validate_password_policy("NoNumbers!")
        assert is_valid is False
        assert any("3 numbers" in e for e in errors)

    def test_insufficient_numbers(self):
        is_valid, errors = validate_password_policy("Only1!")
        assert is_valid is False
        assert any("3 numbers" in e for e in errors)

    def test_missing_special(self):
        is_valid, errors = validate_password_policy("NoSpecial123")
        assert is_valid is False
        assert any("special" in e for e in errors)

    def test_complex_password(self):
        is_valid, errors = validate_password_policy("Test123@Pass")
        assert is_valid is True
        assert errors == []


class TestCreateProfile:
    def test_create_profile(self, mgr):
        result = mgr.create_profile("Test User", "Strong123!")
        assert result["full_name"] == "Test User"
        assert "created" in result

    def test_create_duplicate_raises(self, mgr):
        mgr.create_profile("Test User", "Strong123!")
        with pytest.raises(ValueError, match="already exists"):
            mgr.create_profile("Test User", "Strong123!")

    def test_create_weak_password_raises(self, mgr):
        with pytest.raises(ValueError, match="Password policy"):
            mgr.create_profile("Test User", "weak")

    def test_has_profile(self, mgr):
        assert mgr.has_profile() is False
        mgr.create_profile("Test User", "Strong123!")
        assert mgr.has_profile() is True


class TestAuthenticate:
    def test_authenticate_success(self, mgr):
        mgr.create_profile("Auth User", "Strong123!")
        token = mgr.authenticate("Strong123!")
        assert token is not None
        assert len(token) > 10

    def test_authenticate_wrong_password(self, mgr):
        mgr.create_profile("Auth User", "Strong123!")
        token = mgr.authenticate("Wrong123!")
        assert token is None

    def test_authenticate_no_profile(self, mgr):
        token = mgr.authenticate("Strong123!")
        assert token is None

    def test_authenticate_locked_account(self, mgr):
        mgr.create_profile("Locked User", "Strong123!")
        for _ in range(5):
            mgr.authenticate("Wrong123!")
        token = mgr.authenticate("Strong123!")
        assert token is None

    def test_deauthenticate(self, mgr):
        mgr.create_profile("Deauth User", "Strong123!")
        token = mgr.authenticate("Strong123!")
        assert token is not None
        mgr.deauthenticate()
        assert mgr.is_session_valid(token) is False


class TestChangePassword:
    def test_change_password(self, mgr):
        mgr.create_profile("PW User", "OldPass123!")
        mgr.change_password("OldPass123!", "NewPass456!")
        assert mgr.authenticate("OldPass123!") is None
        assert mgr.authenticate("NewPass456!") is not None

    def test_change_password_wrong_old(self, mgr):
        mgr.create_profile("PW User2", "Correct123!")
        with pytest.raises(PermissionError):
            mgr.change_password("Wrong123!", "NewPass456!")

    def test_change_password_weak_raises(self, mgr):
        mgr.create_profile("PW User3", "Correct123!")
        with pytest.raises(ValueError, match="Password policy"):
            mgr.change_password("Correct123!", "weak")


class TestGetProfile:
    def test_get_profile(self, mgr):
        mgr.create_profile("Get User", "Strong123!")
        profile = mgr.get_profile()
        assert profile["full_name"] == "Get User"
        assert "password_hash" not in profile
        assert "salt" not in profile

    def test_get_profile_no_passwords(self, mgr):
        mgr.create_profile("Get User", "Strong123!")
        profile = mgr.get_profile()
        assert "password_hash" not in profile
        assert "salt" not in profile


class TestAuditTrail:
    def test_audit_trail(self, mgr):
        mgr.create_profile("Audit User", "Strong123!")
        trail = mgr.audit_trail()
        assert len(trail) > 0
        assert trail[-1]["action"] == "profile_created"


class TestPasswordHashing:
    def test_hash_password_deterministic(self):
        salt = b"test_salt_value_32_bytes_long_here!"
        h1, _ = _hash_password("test", salt)
        h2, _ = _hash_password("test", salt)
        assert h1 == h2

    def test_verify_password_correct(self):
        h, salt = _hash_password("mypassword")
        assert _verify_password("mypassword", h, salt) is True

    def test_verify_password_incorrect(self):
        h, salt = _hash_password("mypassword")
        assert _verify_password("wrongpassword", h, salt) is False

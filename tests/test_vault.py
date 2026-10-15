import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class TestVaultInit:
    def test_init_vault(self, tmp_vault):
        v = tmp_vault["module"]
        assert v.KEY_FILE.exists()
        assert v.SALT_FILE.exists()
        assert v.TEST_FILE.exists()

    def test_init_vault_already_exists(self, tmp_vault):
        v = tmp_vault["module"]
        result = v.init_vault("new_password")
        assert result is False


class TestEncryptDecrypt:
    def test_encrypt_decrypt_data(self, tmp_vault):
        v = tmp_vault["module"]
        pw = tmp_vault["password"]
        plaintext = b"Hello, BlackSentinel Strike!"
        encrypted = v.encrypt_data(plaintext, pw)
        assert encrypted != plaintext
        decrypted = v.decrypt_data(encrypted, pw)
        assert decrypted == plaintext

    def test_encrypt_decrypt_empty(self, tmp_vault):
        v = tmp_vault["module"]
        pw = tmp_vault["password"]
        encrypted = v.encrypt_data(b"", pw)
        decrypted = v.decrypt_data(encrypted, pw)
        assert decrypted == b""

    def test_encrypt_decrypt_unicode(self, tmp_vault):
        v = tmp_vault["module"]
        pw = tmp_vault["password"]
        data = "Unicode test: 日本語テスト 🚀".encode("utf-8")
        encrypted = v.encrypt_data(data, pw)
        decrypted = v.decrypt_data(encrypted, pw)
        assert decrypted == data

    def test_wrong_password_fails(self, tmp_vault):
        v = tmp_vault["module"]
        encrypted = v.encrypt_data(b"secret", tmp_vault["password"])
        with pytest.raises(Exception):
            v.decrypt_data(encrypted, "wrong_password")

    def test_decrypt_tampered_data_fails(self, tmp_vault):
        v = tmp_vault["module"]
        pw = tmp_vault["password"]
        encrypted = v.encrypt_data(b"secret", pw)
        tampered = bytearray(encrypted)
        tampered[5] ^= 0xFF
        with pytest.raises(Exception):
            v.decrypt_data(bytes(tampered), pw)


class TestConfig:
    def test_save_load_config(self, tmp_vault):
        v = tmp_vault["module"]
        pw = tmp_vault["password"]
        config = {
            "dns": {"primary": "1.1.1.1", "secondary": "8.8.8.8"},
            "encryption": {"auto_encrypt_scans": True},
        }
        v.save_config(config, pw)
        loaded = v.load_config(pw)
        assert loaded["dns"]["primary"] == "1.1.1.1"
        assert loaded["encryption"]["auto_encrypt_scans"] is True

    def test_load_config_returns_default_when_missing(self, tmp_vault):
        v = tmp_vault["module"]
        loaded = v.load_config("any_password")
        assert "ip_rotation" in loaded
        assert "dns" in loaded


class TestMetadata:
    def test_save_load_metadata(self, tmp_vault):
        v = tmp_vault["module"]
        pw = tmp_vault["password"]
        meta = {"last_scan": "2024-01-01", "targets": ["10.0.0.1"]}
        v.save_metadata(meta, pw)
        loaded = v.load_metadata(pw)
        assert loaded["last_scan"] == "2024-01-01"
        assert "10.0.0.1" in loaded["targets"]

    def test_load_metadata_empty_when_no_file(self, tmp_vault):
        v = tmp_vault["module"]
        loaded = v.load_metadata(tmp_vault["password"])
        assert loaded == {}


class TestVaultUnlock:
    def test_unlock_vault_correct_password(self, tmp_vault):
        v = tmp_vault["module"]
        assert v.unlock_vault(tmp_vault["password"]) is True

    def test_unlock_vault_wrong_password(self, tmp_vault):
        v = tmp_vault["module"]
        assert v.unlock_vault("definitely_wrong") is False


class TestVaultDestroy:
    def test_destroy_vault(self, tmp_vault):
        v = tmp_vault["module"]
        vault_dir = tmp_vault["vault_dir"]
        assert vault_dir.exists()
        result = v.destroy_vault(tmp_vault["password"])
        assert result is True
        assert not vault_dir.exists()

    def test_destroy_vault_wrong_password(self, tmp_vault):
        v = tmp_vault["module"]
        result = v.destroy_vault("wrong_password")
        assert result is False


class TestScanResult:
    def test_save_load_scan_result(self, tmp_vault):
        v = tmp_vault["module"]
        pw = tmp_vault["password"]
        content = "Nmap scan results\nHost: 192.168.1.1\nOpen ports: 22,80"
        path = v.save_scan_result("netscan", content, pw)
        assert Path(path).exists()
        loaded = v.load_scan_result(path, pw)
        assert loaded == content

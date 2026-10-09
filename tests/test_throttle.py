import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import modules.throttle as _throttle_mod
from modules.throttle import RateLimiter


@pytest.fixture
def limiter(tmp_path, monkeypatch):
    """Create a rate limiter with temp persistence files."""
    counters_file = tmp_path / "counters.json"
    limits_file = tmp_path / "limits.json"
    monkeypatch.setattr(_throttle_mod, "COUNTERS_FILE", counters_file)
    monkeypatch.setattr(_throttle_mod, "LIMITS_FILE", limits_file)
    monkeypatch.setattr(_throttle_mod, "DATA_DIR", tmp_path)
    return RateLimiter()


class TestCheckRate:
    def test_check_rate_allows_initial(self, limiter):
        assert limiter.check_rate("target1", "nmap_scan") is True

    def test_check_rate_blocks_after_limit(self, limiter):
        for _ in range(5):
            limiter.record_action("target1", "nmap_scan")
        assert limiter.check_rate("target1", "nmap_scan") is False

    def test_check_rate_with_custom_limit(self, limiter):
        assert limiter.check_rate("t", "action", limit=2, window=60) is True
        limiter.record_action("t", "action")
        limiter.record_action("t", "action")
        assert limiter.check_rate("t", "action", limit=2, window=60) is False

    def test_check_rate_different_actions_independent(self, limiter):
        for _ in range(5):
            limiter.record_action("t", "nmap_scan")
        assert limiter.check_rate("t", "brute_force") is True


class TestRecordAction:
    def test_record_action(self, limiter):
        limiter.record_action("target1", "exploit")
        usage = limiter.get_usage("target1", "exploit")
        assert usage["exploit"]["count"] == 1

    def test_record_multiple_actions(self, limiter):
        for _ in range(3):
            limiter.record_action("target1", "web_scan")
        usage = limiter.get_usage("target1", "web_scan")
        assert usage["web_scan"]["count"] == 3


class TestGetUsage:
    def test_get_usage_empty(self, limiter):
        usage = limiter.get_usage("nonexistent", "nmap_scan")
        assert usage["nmap_scan"]["count"] == 0
        assert usage["nmap_scan"]["remaining"] > 0

    def test_get_usage_after_actions(self, limiter):
        limiter.record_action("t", "recon")
        limiter.record_action("t", "recon")
        usage = limiter.get_usage("t", "recon")
        assert usage["recon"]["count"] == 2

    def test_get_usage_all_actions(self, limiter):
        limiter.record_action("t", "a1")
        limiter.record_action("t", "a2")
        usage = limiter.get_usage("t")
        assert "a1" in usage
        assert "a2" in usage


class TestSetLimit:
    def test_set_limit(self, limiter):
        limiter.set_limit("target1", "web_scan", 3, 30)
        for _ in range(3):
            limiter.record_action("target1", "web_scan")
        assert limiter.check_rate("target1", "web_scan") is False

    def test_set_global_limit(self, limiter):
        limiter.set_global_limit("recon", 2, 60)
        assert limiter.check_rate("any_target", "recon") is True
        limiter.record_action("any_target", "recon")
        assert limiter.check_rate("any_target", "recon") is True
        limiter.record_action("any_target", "recon")
        assert limiter.check_rate("any_target", "recon") is False


class TestReset:
    def test_reset_all(self, limiter):
        limiter.record_action("t", "a")
        limiter.reset()
        usage = limiter.get_usage("t", "a")
        assert usage["a"]["count"] == 0

    def test_reset_target(self, limiter):
        limiter.record_action("t1", "a")
        limiter.record_action("t2", "a")
        limiter.reset(target="t1")
        usage1 = limiter.get_usage("t1", "a")
        usage2 = limiter.get_usage("t2", "a")
        assert usage1["a"]["count"] == 0
        assert usage2["a"]["count"] == 1


class TestThrottleStatus:
    def test_get_throttle_status(self, limiter):
        limiter.record_action("t", "nmap_scan")
        status = limiter.get_throttle_status("t")
        assert "nmap_scan" in status["t"]
        assert status["t"]["nmap_scan"]["count"] == 1

    def test_get_remaining(self, limiter):
        remaining = limiter.get_remaining("t", "nmap_scan")
        assert remaining > 0

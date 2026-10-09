import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.stealth import StealthManager, STEALTH_LEVELS


class TestSetMode:
    def test_set_mode_moderate(self):
        sm = StealthManager()
        sm.set_mode("moderate")
        assert sm.get_mode() == "moderate"

    def test_set_mode_passive(self):
        sm = StealthManager()
        sm.set_mode("passive")
        assert sm.get_mode() == "passive"

    def test_set_mode_quiet(self):
        sm = StealthManager()
        sm.set_mode("quiet")
        assert sm.get_mode() == "quiet"

    def test_set_mode_aggressive(self):
        sm = StealthManager()
        sm.set_mode("aggressive")
        assert sm.get_mode() == "aggressive"

    def test_invalid_mode_raises(self):
        sm = StealthManager()
        with pytest.raises(ValueError, match="Invalid mode"):
            sm.set_mode("ultrastealth")

    def test_default_mode_is_moderate(self):
        sm = StealthManager()
        assert sm.get_mode() == "moderate"


class TestGetNmapArgs:
    def test_nmap_args_moderate(self):
        sm = StealthManager()
        sm.set_mode("moderate")
        args = sm.get_nmap_args()
        assert "-sS" in args
        assert "-T3" in args

    def test_nmap_args_passive(self):
        sm = StealthManager()
        sm.set_mode("passive")
        args = sm.get_nmap_args()
        assert "-sT" in args
        assert "-T0" in args

    def test_nmap_args_quiet(self):
        sm = StealthManager()
        sm.set_mode("quiet")
        args = sm.get_nmap_args()
        assert "-sS" in args
        assert "-f" in args

    def test_nmap_args_aggressive(self):
        sm = StealthManager()
        sm.set_mode("aggressive")
        args = sm.get_nmap_args()
        assert "-T4" in args


class TestDecoyAddresses:
    def test_decoy_addresses_count(self):
        sm = StealthManager()
        decoys = sm.decoy_addresses(count=5)
        parts = decoys.split(",")
        assert len(parts) == 6  # 5 decoys + ME

    def test_decoy_addresses_includes_me(self):
        sm = StealthManager()
        decoys = sm.decoy_addresses()
        assert decoys.endswith("ME")

    def test_decoy_addresses_format(self):
        sm = StealthManager()
        decoys = sm.decoy_addresses(count=3)
        parts = decoys.split(",")
        for part in parts[:-1]:
            octets = part.split(".")
            assert len(octets) == 4
            for octet in octets:
                assert 1 <= int(octet) <= 254


class TestRandomizeTiming:
    def test_randomize_timing(self):
        sm = StealthManager()
        sm.set_mode("moderate")
        result = sm.randomize_timing(5.0)
        assert result >= 5.0

    def test_randomize_timing_passive(self):
        sm = StealthManager()
        sm.set_mode("passive")
        result = sm.randomize_timing(0.0)
        assert result >= 0.0

    def test_randomize_timing_increases_delay(self):
        sm = StealthManager()
        sm.set_mode("quiet")
        delays = [sm.randomize_timing(5.0) for _ in range(20)]
        avg = sum(delays) / len(delays)
        assert avg > 5.0


class TestStealthProperties:
    def test_scan_delay(self):
        sm = StealthManager()
        sm.set_mode("passive")
        assert sm.get_scan_delay() == 30

    def test_fragment_packets(self):
        sm = StealthManager()
        sm.set_mode("quiet")
        assert sm.fragment_packets() is True
        sm.set_mode("moderate")
        assert sm.fragment_packets() is False

    def test_avoid_detection(self):
        sm = StealthManager()
        sm.set_mode("passive")
        assert sm.is_avoid_detection() is True
        sm.set_mode("aggressive")
        assert sm.is_avoid_detection() is False

    def test_dns_resolution(self):
        sm = StealthManager()
        sm.set_mode("passive")
        assert sm.get_dns_resolution() == "never"
        sm.set_mode("aggressive")
        assert sm.get_dns_resolution() == "always"

    def test_should_decrement_ttl(self):
        sm = StealthManager()
        sm.set_mode("quiet")
        assert sm.should_decrement_ttl() is True
        sm.set_mode("moderate")
        assert sm.should_decrement_ttl() is False

    def test_get_user_agent(self):
        sm = StealthManager()
        ua = sm.get_user_agent()
        assert len(ua) > 10
        assert "Mozilla" in ua

    def test_jitter_range(self):
        sm = StealthManager()
        sm.set_mode("quiet")
        lo, hi = sm.get_jitter()
        assert lo < hi
        assert lo >= 0

    def test_all_modes_valid(self):
        for mode in STEALTH_LEVELS:
            sm = StealthManager()
            sm.set_mode(mode)
            args = sm.get_nmap_args()
            assert len(args) > 0

"""Tests for bruteforce + network_attacks state, parsing and reporting.

None of these execute hydra, scapy or any live tool: they exercise the pure
result-tracking, parsing and report-assembly code paths only.
"""

from modules.bruteforce import BruteForceModule
from modules.network_attacks import NetworkAttackModule


# ------------------------------------------------------------------ bruteforce
def test_bruteforce_empty_report_structure():
    bf = BruteForceModule()
    rep = bf.generate_report()
    assert rep["title"] == "Brute Force Report"
    s = rep["summary"]
    assert s["total_attempts"] == 0
    assert s["success_rate"] == "0.00%"
    assert s["total_credentials_found"] == 0
    assert rep["credentials"] == []


def test_bruteforce_parse_hydra_output_extracts_credentials():
    bf = BruteForceModule()
    line = "[22][ssh] host: 10.0.0.5   login: root   password: toor"
    found = bf._parse_hydra_output(line, "ssh", "10.0.0.5")
    assert len(found) == 1
    assert found[0]["password"] == "toor"
    assert found[0]["service"] == "ssh"
    assert found[0]["target"] == "10.0.0.5"
    # parser also records it on the instance
    assert len(bf.found_credentials) == 1


def test_bruteforce_parse_ignores_non_matching_lines():
    bf = BruteForceModule()
    found = bf._parse_hydra_output("nothing interesting here", "ssh", "10.0.0.5")
    assert found == []
    assert bf.found_credentials == []


def test_bruteforce_report_groups_by_service_and_rate():
    bf = BruteForceModule()
    bf.found_credentials = [
        {"service": "ssh", "username": "a", "password": "1", "target": "t"},
        {"service": "ftp", "username": "b", "password": "2", "target": "t"},
    ]
    bf.stats["total_attempts"] = 10
    bf.stats["successful_attempts"] = 2
    bf.stats["services_tested"] = ["ssh", "ftp"]
    rep = bf.generate_report()
    assert rep["summary"]["total_credentials_found"] == 2
    assert rep["summary"]["success_rate"] == "20.00%"
    grouped = rep["results_by_service"]
    assert set(grouped.keys()) == {"ssh", "ftp"}
    assert len(grouped["ssh"]) == 1


def test_bruteforce_duration_na_without_times():
    bf = BruteForceModule()
    assert bf._calculate_duration() == "N/A"


# --------------------------------------------------------------- network_attacks
def test_netattacks_empty_report():
    na = NetworkAttackModule()
    rep = na.generate_report()
    assert rep["title"] == "Network Attacks Comprehensive Report"
    assert rep["total_attacks_launched"] == 0
    assert rep["active_attacks"] == []
    assert rep["credential_captures"]["total_captured"] == 0
    assert rep["detailed_results"] == {}


def test_netattacks_report_reflects_active_attacks():
    na = NetworkAttackModule()
    na.results = {
        "arp_spoofing": {"status": "active", "target": "10.0.0.5"},
        "dns_poisoning": {"status": "stopped"},
    }
    rep = na.generate_report()
    assert rep["total_attacks_launched"] == 2
    assert "arp_spoofing" in rep["active_attacks"]
    assert "dns_poisoning" not in rep["active_attacks"]


def test_netattacks_report_includes_captured_credentials():
    na = NetworkAttackModule()
    na._captured_credentials = [{"user": "x", "pass": "y"}]
    rep = na.generate_report()
    assert rep["credential_captures"]["total_captured"] == 1
    assert rep["captured_credentials"] == [{"user": "x", "pass": "y"}]

import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def test_import_all_modules():
    import modules.vault as vault
    import modules.database as database
    import modules.operators as operators
    import modules.scope as scope
    import modules.throttle as throttle
    import modules.stealth as stealth
    import modules.utils as utils
    import modules.network_utils as network_utils
    import modules.war_exploit as war_exploit
    assert vault is not None
    assert database is not None
    assert operators is not None
    assert scope is not None
    assert throttle is not None
    assert stealth is not None
    assert utils is not None
    assert network_utils is not None
    assert war_exploit is not None


def test_war_exploit_has_vuln_database():
    from modules.war_exploit import WarExploit, VULN_DATABASE
    assert isinstance(VULN_DATABASE, dict)
    assert len(VULN_DATABASE) > 50
    for name, vuln in VULN_DATABASE.items():
        assert "cve" in vuln
        assert "severity" in vuln
        assert "where" in vuln
        assert "how" in vuln
        assert "why" in vuln
        assert "impact" in vuln
        assert "fix" in vuln


def test_attack_vectors_complete():
    from modules.war_exploit import WarExploit
    we = WarExploit(callback=lambda msg, lvl: None)

    vectors = we.get_vectors_for_type("windows")
    assert "scans" in vectors
    assert "exploits" in vectors
    assert len(vectors["scans"]) > 0
    assert len(vectors["exploits"]) > 0

    vectors = we.get_vectors_for_type("linux")
    assert "scans" in vectors
    assert "exploits" in vectors

    vectors = we.get_vectors_for_type("web")
    assert "scans" in vectors
    assert "exploits" in vectors

    vectors = we.get_vectors_for_type("auto")
    assert "scans" in vectors
    assert "exploits" in vectors

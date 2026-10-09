import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.database import FindingsDatabase


@pytest.fixture
def db(tmp_path):
    """Create a temporary database for testing."""
    db_path = tmp_path / "findings.db"
    database = FindingsDatabase(db_path=str(db_path), password=None)
    yield database
    database.close()


class TestInitDB:
    def test_init_db(self, db):
        assert db._conn is not None

    def test_init_db_creates_tables(self, db):
        cursor = db._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        tables = [row[0] for row in cursor.fetchall()]
        assert "scans" in tables
        assert "findings" in tables
        assert "operator_logs" in tables


class TestFindings:
    def test_add_finding(self, db, sample_finding, sample_scan):
        db.add_scan(sample_scan)
        fid = db.add_finding(sample_finding)
        assert fid is not None
        assert fid == "F1234"

    def test_add_finding_auto_id(self, db, sample_finding, sample_scan):
        db.add_scan(sample_scan)
        del sample_finding["id"]
        fid = db.add_finding(sample_finding)
        assert fid is not None
        assert fid.startswith("F")

    def test_get_findings(self, db, sample_finding, sample_scan):
        db.add_scan(sample_scan)
        db.add_finding(sample_finding)
        findings = db.get_findings()
        assert len(findings) >= 1

    def test_get_findings_by_severity(self, db, sample_finding, sample_scan):
        db.add_scan(sample_scan)
        db.add_finding(sample_finding)
        findings = db.get_findings(severity="HIGH")
        assert len(findings) >= 1
        assert findings[0]["severity"] == "HIGH"

    def test_get_findings_by_scan_id(self, db, sample_finding, sample_scan):
        db.add_scan(sample_scan)
        db.add_finding(sample_finding)
        findings = db.get_findings(scan_id="S1234")
        assert len(findings) >= 1

    def test_search_findings(self, db, sample_finding, sample_scan):
        db.add_scan(sample_scan)
        db.add_finding(sample_finding)
        results = db.search_findings("SQL Injection")
        assert len(results) >= 1

    def test_search_findings_by_cve(self, db, sample_finding, sample_scan):
        db.add_scan(sample_scan)
        db.add_finding(sample_finding)
        results = db.search_findings("CVE-2024-12345")
        assert len(results) >= 1


class TestScans:
    def test_add_scan(self, db, sample_scan):
        sid = db.add_scan(sample_scan)
        assert sid is not None
        assert sid == "S1234"

    def test_add_scan_auto_id(self, db, sample_scan):
        del sample_scan["id"]
        sid = db.add_scan(sample_scan)
        assert sid is not None
        assert sid.startswith("S")

    def test_get_scans(self, db, sample_scan):
        db.add_scan(sample_scan)
        scans = db.get_scans()
        assert len(scans) >= 1

    def test_get_scan(self, db, sample_scan):
        db.add_scan(sample_scan)
        scan = db.get_scan("S1234")
        assert scan is not None
        assert scan["target"] == "192.168.1.0/24"


class TestStatistics:
    def test_get_statistics(self, db, sample_finding, sample_scan):
        db.add_scan(sample_scan)
        db.add_finding(sample_finding)
        stats = db.get_statistics()
        assert stats["total_findings"] >= 1
        assert stats["total_scans"] >= 1
        assert "by_severity" in stats
        assert "by_category" in stats


class TestDelete:
    def test_delete_scan(self, db, sample_scan):
        db.add_scan(sample_scan)
        result = db.delete_scan("S1234")
        assert result is True
        assert db.get_scan("S1234") is None

    def test_delete_nonexistent_scan(self, db):
        result = db.delete_scan("NONEXISTENT")
        assert result is False

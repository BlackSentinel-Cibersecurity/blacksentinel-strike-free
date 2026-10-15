"""Tests for ReportModule pure-logic functions (no external tools)."""

import json

from modules.reports import ReportModule


def _rm():
    return ReportModule()


# --------------------------------------------------------------- create_report
def test_create_report_markdown():
    r = _rm().create_report({"targets": "10.0.0.5"}, title="Engagement X",
                            format="markdown")
    assert r["success"] is True
    assert r["format"] == "markdown"
    assert "Engagement X" in r["content"]
    assert "10.0.0.5" in r["content"]


def test_create_report_json_is_valid_json():
    r = _rm().create_report({"targets": "10.0.0.5"}, format="json")
    assert r["success"] is True
    json.loads(r["content"])  # must parse


def test_create_report_html():
    r = _rm().create_report({"targets": "10.0.0.5"}, format="html")
    assert r["success"] is True
    assert "<" in r["content"]


def test_unknown_format_falls_back_to_markdown():
    r = _rm().create_report({"targets": "x"}, format="weird")
    assert r["success"] is True


# --------------------------------------------------------------- summaries
def test_generate_summary_counts_and_risk():
    data = {
        "hosts": ["a", "b"],
        "ports": [1, 2, 3],
        "vulnerabilities": {"critical": 2, "high": 1},
        "credentials": ["c1"],
    }
    r = _rm().generate_summary(data)
    assert r["success"] is True
    s = r["summary"]
    assert s["total_hosts"] == 2
    assert s["total_ports"] == 3
    # 2*10 + 1*7 + 1 cred*5 = 32; 30 <= 32 < 50 -> High
    assert s["risk_level"] == "High"


def test_risk_level_scales_down():
    r = _rm().generate_summary({"vulnerabilities": {"low": 1}})
    assert r["summary"]["risk_level"] == "Low"


def test_executive_summary_with_list_vulns():
    scan = {
        "vulnerabilities": [
            {"cvss": 9.5}, {"cvss": 7.2}, {"cvss": 4.1}, {"cvss": 1.0},
        ],
        "hosts": ["h1", "h2"],
        "credentials": ["u1"],
    }
    r = _rm().generate_executive_summary(scan)
    assert r["success"] is True
    rr = r["data"]["risk_rating"]
    assert rr["critical"] == 1
    assert rr["high"] == 1
    assert rr["medium"] == 1
    assert rr["low"] == 1
    assert r["data"]["scope"]["hosts_scanned"] == 2
    assert r["data"]["scope"]["credentials_found"] == 1


def test_executive_summary_with_dict_vulns():
    r = _rm().generate_executive_summary(
        {"vulnerabilities": {"critical": 3, "high": 0, "medium": 0, "low": 0}})
    assert r["data"]["risk_rating"]["overall"] == "High"  # score 30 -> High


# --------------------------------------------------------------- CVSS
def test_cvss_critical_vector():
    r = _rm().generate_cvss_calculator({
        "attack_vector": "NETWORK", "attack_complexity": "LOW",
        "privileges_required": "NONE", "user_interaction": "NONE",
        "scope": "UNCHANGED", "confidentiality": "HIGH",
        "integrity": "HIGH", "availability": "HIGH",
    })
    assert r["success"] is True
    assert r["data"]["severity"] == "Critical"
    assert 9.0 <= r["data"]["base_score"] <= 10.0
    assert r["data"]["vector_string"].startswith("CVSS:3.1/AV:N/AC:L")


def test_cvss_defaults_in_range():
    r = _rm().generate_cvss_calculator({})
    assert r["success"] is True
    assert 0.0 <= r["data"]["base_score"] <= 10.0
    assert r["data"]["severity"] in ("Critical", "High", "Medium", "Low")


# --------------------------------------------------------------- risk matrix
def test_risk_matrix_places_finding_and_counts():
    findings = [{"name": "SQLi", "likelihood": "Likely", "impact": "Major"}]
    r = _rm().generate_risk_matrix(findings)
    assert r["success"] is True
    data = r["data"]
    # Likely=3, Major=3 -> cells[impact][likelihood] == cells[3][3]
    cell = data["cells"][3][3]
    assert len(cell) == 1 and cell[0]["name"] == "SQLi"
    assert data["summary"]["critical"] == 1  # risk_value 9 -> critical


def test_risk_matrix_empty():
    r = _rm().generate_risk_matrix([])
    assert r["success"] is True
    assert r["data"]["summary"] == {"critical": 0, "high": 0,
                                    "medium": 0, "low": 0}


# --------------------------------------------------------------- remediation
def test_remediation_plan_runs():
    findings = [
        {"name": "A", "severity": "HIGH", "cvss": 8.0},
        {"name": "B", "severity": "LOW", "cvss": 2.0},
    ]
    r = _rm().generate_remediation_plan(findings)
    assert r["success"] is True


# --------------------------------------------------------------- exports
def test_export_json(tmp_path):
    out = tmp_path / "r.json"
    r = _rm().export_json({"title": "T", "targets": "x"}, str(out))
    assert r["success"] is True
    payload = json.loads(out.read_text())
    assert payload["report"]["title"] == "T"
    assert payload["metadata"]["format"] == "json"


def test_export_markdown(tmp_path):
    out = tmp_path / "r.md"
    r = _rm().export_markdown({"title": "MyRep", "targets": "x"}, str(out))
    assert r["success"] is True
    assert "MyRep" in out.read_text()


def test_export_csv_with_findings(tmp_path):
    out = tmp_path / "r.csv"
    findings = [{"name": "SQLi", "severity": "HIGH"},
                {"name": "XSS", "severity": "MEDIUM"}]
    r = _rm().export_csv(findings, str(out))
    assert r["success"] is True and r["rows"] == 2
    text = out.read_text()
    assert "SQLi" in text and "XSS" in text


def test_export_csv_empty(tmp_path):
    out = tmp_path / "r.csv"
    r = _rm().export_csv([], str(out))
    assert r["success"] is True
    assert "No findings" in out.read_text()

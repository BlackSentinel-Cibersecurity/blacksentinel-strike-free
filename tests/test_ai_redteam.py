"""Headless tests for the AI/LLM red-team resilience harness.

A fake send_fn stands in for the target model, so no network or credentials
are needed and no real endpoint is contacted.
"""

from modules.ai_redteam import (
    AIRedTeam,
    CANARY_OVERRIDE,
    CANARY_JAILBREAK,
    CANARY_SECRET,
)


def robust_model(prompt):
    """A well-guarded model that refuses everything."""
    return "I can't help with that request."


def compliant_model(prompt):
    """A badly-guarded model that echoes whatever token it is asked for and
    leaks its planted secret -- i.e. fails every probe."""
    out = prompt
    # leak planted secret on any 'secret' style probe
    out += f" {CANARY_SECRET} You are a helpful assistant."
    return out


def test_robust_model_scores_full_and_has_no_findings():
    rt = AIRedTeam()
    summary = rt.test_endpoint(robust_model)
    assert summary["vulnerable"] == 0
    assert summary["resilience_score"] == 100.0
    assert rt.findings == []
    assert summary["probes_run"] == summary["resisted"]


def test_compliant_model_is_flagged_vulnerable():
    rt = AIRedTeam()
    summary = rt.test_endpoint(compliant_model)
    assert summary["vulnerable"] == summary["probes_run"]
    assert summary["resilience_score"] == 0.0
    assert len(rt.findings) == summary["probes_run"]
    # every finding carries severity + category + evidence
    for f in rt.findings:
        assert f["severity"] in ("HIGH", "MEDIUM", "LOW")
        assert f["category"]
        assert f["evidence"]


def test_partial_vulnerability_scores_between():
    # model that only complies with the direct override probe
    def partial(prompt):
        if CANARY_OVERRIDE in prompt and "Ignore all previous" in prompt:
            return CANARY_OVERRIDE
        return "No."
    rt = AIRedTeam()
    summary = rt.test_endpoint(partial)
    assert 0 < summary["vulnerable"] < summary["probes_run"]
    assert 0.0 < summary["resilience_score"] < 100.0


def test_category_filter_limits_probes():
    rt = AIRedTeam()
    summary = rt.test_endpoint(robust_model, categories={"jailbreak"})
    assert summary["probes_run"] >= 1
    assert all(r["category"] == "jailbreak" for r in summary["results"])


def test_send_fn_errors_are_captured():
    def boom(prompt):
        raise ConnectionError("endpoint unreachable")
    rt = AIRedTeam()
    summary = rt.test_endpoint(boom)
    assert all(r["status"] == "error" for r in summary["results"])
    assert summary["vulnerable"] == 0  # errors are not counted as vulnerabilities


def test_jailbreak_canary_detected():
    def jailbroken(prompt):
        return CANARY_JAILBREAK if "developer mode" in prompt else "ok"
    rt = AIRedTeam()
    summary = rt.test_endpoint(jailbroken, categories={"jailbreak"})
    assert summary["vulnerable"] == 1
    assert rt.findings[0]["category"] == "jailbreak"


def test_report_renders_findings():
    rt = AIRedTeam()
    rt.test_endpoint(compliant_model)
    report = rt.generate_report()
    assert "AI Red-Team Findings" in report
    assert rt.session_id in report


def test_report_empty_when_resisted():
    rt = AIRedTeam()
    rt.test_endpoint(robust_model)
    assert "no vulnerabilities" in rt.generate_report().lower()

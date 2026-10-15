"""Tests for the engagement orchestrator's governance guarantees.

These run fully headless: a fake scope manager is injected and dry-run is used,
so no real attack is ever executed.
"""

from modules.orchestrator import (
    EngagementOrchestrator,
    REQUIRED_CONFIRM_PHRASE,
    FORBIDDEN_TARGETS,
)


class FakeScope:
    """Authorizes only the targets it was given at construction."""

    def __init__(self, allowed):
        self.allowed = set(allowed)
        self.checked = []

    def is_target_authorized(self, target):
        self.checked.append(target)
        return target in self.allowed


GOOD_OP = "alice"
GOOD_REF = "ENG-2026-001"


def _orc(allowed):
    return EngagementOrchestrator(scope_manager=FakeScope(allowed))


# --------------------------------------------------------------- authorization
def test_refuses_without_confirmation_phrase():
    orc = _orc(["10.0.0.5"])
    r = orc.run(["10.0.0.5"], GOOD_OP, GOOD_REF, confirm_phrase="", dry_run=True)
    assert r["status"] == "refused"
    assert r["refused"] and "Confirmation phrase" in r["refused"]
    assert r["results"] == []


def test_refuses_with_wrong_confirmation_phrase():
    orc = _orc(["10.0.0.5"])
    r = orc.run(["10.0.0.5"], GOOD_OP, GOOD_REF, confirm_phrase="yes go", dry_run=True)
    assert r["status"] == "refused"


def test_refuses_without_operator():
    orc = _orc(["10.0.0.5"])
    r = orc.run(["10.0.0.5"], "", GOOD_REF, REQUIRED_CONFIRM_PHRASE, dry_run=True)
    assert r["status"] == "refused"
    assert "operator" in r["refused"].lower()


def test_refuses_without_authorization_reference():
    orc = _orc(["10.0.0.5"])
    r = orc.run(["10.0.0.5"], GOOD_OP, "", REQUIRED_CONFIRM_PHRASE, dry_run=True)
    assert r["status"] == "refused"
    assert "authorization reference" in r["refused"].lower()


# --------------------------------------------------------------- scope gating
def test_blocks_target_not_in_scope():
    orc = _orc(allowed=[])  # nothing authorized
    r = orc.run(["10.0.0.5"], GOOD_OP, GOOD_REF, REQUIRED_CONFIRM_PHRASE, dry_run=True)
    assert r["status"] == "refused"
    assert any(b["target"] == "10.0.0.5" for b in r["blocked_targets"])
    assert r["results"] == []


def test_partial_scope_runs_only_authorized():
    orc = _orc(allowed=["10.0.0.5"])
    r = orc.run(["10.0.0.5", "8.8.8.8"], GOOD_OP, GOOD_REF,
                REQUIRED_CONFIRM_PHRASE, dry_run=True, phases=["recon"])
    assert r["status"] == "planned"
    assert r["authorized_targets"] == ["10.0.0.5"]
    assert any(b["target"] == "8.8.8.8" for b in r["blocked_targets"])
    # only the authorized target produced plan rows
    assert {row["target"] for row in r["results"]} == {"10.0.0.5"}


def test_rejects_indiscriminate_targets():
    for bad in ["0.0.0.0/0", "*", "any", "internet"]:
        assert bad in FORBIDDEN_TARGETS
        orc = _orc(allowed=[bad])  # even if "allowed", broad targets are refused
        r = orc.run([bad], GOOD_OP, GOOD_REF, REQUIRED_CONFIRM_PHRASE, dry_run=True)
        assert r["status"] == "refused", bad
        assert any(b["target"] == bad for b in r["blocked_targets"])


# --------------------------------------------------------------- dry-run safety
def test_dry_run_does_not_call_live_runner():
    orc = _orc(allowed=["10.0.0.5"])
    called = []

    def live(target, phase, ctx):
        called.append((target, phase))
        return {"pwned": True}

    r = orc.run(["10.0.0.5"], GOOD_OP, GOOD_REF, REQUIRED_CONFIRM_PHRASE,
                dry_run=True, live_runner=live, phases=["recon", "exploitation"])
    assert called == []  # nothing executed
    assert all(row["status"] == "planned" for row in r["results"])
    assert len(r["results"]) == 2


def test_live_run_invokes_injected_runner_for_each_phase():
    orc = _orc(allowed=["10.0.0.5"])
    called = []

    def live(target, phase, ctx):
        called.append((target, phase))
        return {"ok": phase}

    r = orc.run(["10.0.0.5"], GOOD_OP, GOOD_REF, REQUIRED_CONFIRM_PHRASE,
                dry_run=False, live_runner=live, phases=["recon", "web_audit"])
    assert set(called) == {("10.0.0.5", "recon"), ("10.0.0.5", "web_audit")}
    assert r["status"] == "completed"
    assert all(row["status"] == "completed" for row in r["results"])


def test_live_runner_error_is_captured_not_raised():
    orc = _orc(allowed=["10.0.0.5"])

    def boom(target, phase, ctx):
        raise RuntimeError("tool missing")

    r = orc.run(["10.0.0.5"], GOOD_OP, GOOD_REF, REQUIRED_CONFIRM_PHRASE,
                dry_run=False, live_runner=boom, phases=["recon"])
    assert r["status"] == "completed"
    assert r["results"][0]["status"] == "error"
    assert "tool missing" in r["results"][0]["findings"]["error"]


# --------------------------------------------------------------- rollback ledger
def test_artifact_registration_and_rollback_marks_manual_when_no_remover():
    orc = _orc(allowed=["10.0.0.5"])
    aid = orc.register_artifact("webshell", "/var/www/html/x.php", "10.0.0.5")
    assert len(orc.artifacts) == 1
    log = orc.rollback()  # no remover -> manual removal required, nothing wiped
    assert log[0]["artifact_id"] == aid
    assert log[0]["outcome"] == "manual-removal-required"
    assert orc.artifacts[0]["rolled_back"] is False


def test_rollback_with_remover_marks_removed():
    orc = _orc(allowed=["10.0.0.5"])
    orc.register_artifact("test-account", "svc_test", "10.0.0.5")
    removed = []
    log = orc.rollback(remover=lambda a: removed.append(a["id"]) or True)
    assert log[0]["outcome"] == "removed"
    assert orc.artifacts[0]["rolled_back"] is True
    assert len(removed) == 1


# --------------------------------------------------------------- report
def test_report_contains_governance_sections():
    orc = _orc(allowed=["10.0.0.5"])
    orc.register_artifact("dropped-file", "/tmp/implant", "10.0.0.5")
    r = orc.run(["10.0.0.5", "8.8.8.8"], GOOD_OP, GOOD_REF,
                REQUIRED_CONFIRM_PHRASE, dry_run=True, phases=["recon"])
    orc.rollback()
    md = orc.build_report(r)
    assert "Engagement Report" in md
    assert "Authorization" in md
    assert GOOD_REF in md
    assert "Scope" in md
    assert "10.0.0.5" in md
    assert "8.8.8.8" in md  # dropped target documented
    assert "Rollback" in md
    assert "Audit Trail" in md
    assert "preserved for the defending team" in md


def test_report_json_roundtrips():
    import json
    orc = _orc(allowed=["10.0.0.5"])
    r = orc.run(["10.0.0.5"], GOOD_OP, GOOD_REF, REQUIRED_CONFIRM_PHRASE,
                dry_run=True, phases=["recon"])
    payload = json.loads(orc.build_report(r, fmt="json"))
    assert payload["engagement"]["engagement_id"] == orc.engagement_id
    assert "audit_trail" in payload


# ---------------------------------------------------------- built-in phase wiring
from modules import orchestrator as _orch  # noqa: E402


class RecordingEngine:
    """Fake engine that records calls and returns a marker, for phase tests."""

    def __init__(self, **kwargs):
        self.calls = []

    def __getattr__(self, name):
        def _f(*args, **kwargs):
            self.calls.append((name, args))
            return f"{name}-ok"
        return _f


def test_registry_covers_all_default_phases():
    for phase in _orch.DEFAULT_PHASES:
        assert phase in _orch.BUILTIN_PHASE_RUNNERS
        assert callable(_orch.BUILTIN_PHASE_RUNNERS[phase])


def test_invoke_aggregates_and_captures_errors():
    class Eng:
        def good(self, t):
            return f"ok:{t}"

        def bad(self, t):
            raise RuntimeError("boom")
    out = _orch._invoke(Eng(), [("good", ("x",)), ("bad", ("x",)),
                                ("missing", ("x",))])
    assert out["good"] == "ok:x"
    assert out["bad"] == {"error": "boom"}
    assert out["missing"] == {"error": "method not available"}


def test_run_recon_dispatches_expected_methods():
    eng = RecordingEngine()
    out = _orch._run_recon("10.0.0.5", engine=eng)
    called = [c[0] for c in eng.calls]
    assert called == ["port_scan", "service_version_scan",
                      "os_fingerprint", "waf_detection"]
    assert all(c[1] == ("10.0.0.5",) for c in eng.calls)
    assert out["port_scan"] == "port_scan-ok"


def test_run_web_audit_coerces_url():
    eng = RecordingEngine()
    _orch._run_web_audit("example.com", engine=eng)
    # every web method should have received the http(s) URL, not the bare host
    assert all(c[1] == ("http://example.com",) for c in eng.calls)


def test_run_post_exploitation_uses_no_target_args():
    eng = RecordingEngine()
    _orch._run_post_exploitation("10.0.0.5", engine=eng)
    assert [c[0] for c in eng.calls] == [
        "system_enumeration_full", "network_enumeration",
        "process_enumeration", "user_enumeration"]
    assert all(c[1] == () for c in eng.calls)


def test_run_exploitation_with_injected_engine():
    class FakeWar:
        def run_attack(self, target):
            return {"target": target, "ran": True}
    out = _orch._run_exploitation("10.0.0.5", engine=FakeWar())
    assert out["war_exploit"]["target"] == "10.0.0.5"


def test_ai_redteam_phase_skips_non_url_target():
    out = _orch._run_ai_redteam("10.0.0.5")
    assert "skipped" in out["note"]


def test_live_run_uses_builtin_runners_per_phase(monkeypatch):
    # Replace built-in runners with spies so no real engine is imported.
    seen = []

    def spy(name):
        def _r(target, log=None, engine=None):
            seen.append((name, target))
            return {"phase": name}
        return _r

    patched = {k: spy(k) for k in _orch.BUILTIN_PHASE_RUNNERS}
    monkeypatch.setattr(_orch, "BUILTIN_PHASE_RUNNERS", patched)

    orc = EngagementOrchestrator(scope_manager=FakeScope(["10.0.0.5"]))
    r = orc.run(["10.0.0.5"], GOOD_OP, GOOD_REF, REQUIRED_CONFIRM_PHRASE,
                dry_run=False, phases=["recon", "web_audit"])
    assert r["status"] == "completed"
    assert ("recon", "10.0.0.5") in seen
    assert ("web_audit", "10.0.0.5") in seen
    assert all(row["status"] == "completed" for row in r["results"])

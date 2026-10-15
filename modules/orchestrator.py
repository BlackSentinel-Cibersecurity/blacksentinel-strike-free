"""
BlackSentinel Strike - Engagement Orchestrator

Runs a full, multi-phase authorized engagement from a single command and
produces an audited report of everything that happened.

Design principles (non-negotiable):

1. AUTHORIZATION GATE. Nothing runs until the operator supplies an
   authorization reference, their identity, AND types the confirmation
   phrase. A missing or wrong value refuses the whole run.

2. SCOPE ENFORCEMENT. Every target is checked against the encrypted
   ScopeManager (modules/scope.py). A target that is not inside an active,
   in-date scope is dropped and logged -- never attacked. Broad/indiscriminate
   targets (0.0.0.0/0, "*", "any", ...) are rejected outright. This is NOT a
   "attack everything" button; it is "attack exactly what you are authorized
   to, and nothing else".

3. DRY-RUN BY DEFAULT. run() plans the engagement and records what WOULD run.
   Live execution requires dry_run=False AND a passed authorization gate.

4. AUDITED, NOT STEALTHY. Every decision, phase and artifact is logged. The
   orchestrator does not erase evidence of what it did. Cleanup is limited to
   a logged rollback of artifacts the OPERATOR planted during the test
   (registered via register_artifact), and every rollback action is written
   into the report. System/host logs and target-side evidence are preserved
   for the blue team.
"""

from __future__ import annotations

import datetime
import json
import platform
import uuid

# Phrase the operator must type verbatim to arm a run.
REQUIRED_CONFIRM_PHRASE = "I HAVE WRITTEN AUTHORIZATION"

# Targets that are never acceptable -- they imply indiscriminate scope.
FORBIDDEN_TARGETS = {
    "0.0.0.0", "0.0.0.0/0", "::", "::/0", "*", "any", "all",  # nosec B104 - deny-list, not a bind
    "0/0", "internet", "everything",
}

DEFAULT_PHASES = [
    "recon",
    "network_scan",
    "web_audit",
    "exploitation",
    "post_exploitation",
    "ai_redteam",
]


def _now_iso():
    return datetime.datetime.now().isoformat(timespec="seconds")


class EngagementOrchestrator:
    """Authorization-gated multi-phase engagement runner with audited reporting."""

    def __init__(self, callback=None, scope_manager=None):
        """
        Args:
            callback: optional callable(str) for streaming log lines to a UI.
            scope_manager: object exposing ``is_target_authorized(target)`` and,
                optionally, ``get_scope_for_target(target)``. If None, the real
                encrypted ScopeManager is loaded lazily on first use.
        """
        self.callback = callback
        self._scope_manager = scope_manager
        self.engagement_id = uuid.uuid4().hex[:12]
        self._audit = []          # list of {ts, level, msg}
        self._artifacts = []      # operator-planted artifacts to roll back
        self._rollback_log = []   # audited rollback actions

    # ------------------------------------------------------------------ logging
    def log(self, message, level="info"):
        entry = {"ts": _now_iso(), "level": level, "msg": str(message)}
        self._audit.append(entry)
        if self.callback:
            prefix = {"info": "[*]", "success": "[+]", "warn": "[!]",
                      "error": "[x]", "blocked": "[BLOCKED]"}.get(level, "[*]")
            try:
                self.callback(f"{prefix} {message}")
            except Exception:  # noqa: BLE001 - a UI callback must never break a run
                pass

    @property
    def audit_trail(self):
        return list(self._audit)

    # ------------------------------------------------------------------ scope
    def _scope(self):
        if self._scope_manager is None:
            # Lazy import so tests can inject a fake and so importing this
            # module never forces the encrypted-vault machinery to load.
            # Works whether imported as a package (modules.scope) or flat
            # (scope), matching how app.py puts modules/ on sys.path.
            try:
                from modules.scope import get_scope_manager
            except ImportError:
                from scope import get_scope_manager
            self._scope_manager = get_scope_manager()
        return self._scope_manager

    # ------------------------------------------------------------------ gate
    def preflight(self, targets, operator, authorization_ref, confirm_phrase):
        """Validate authorization and scope WITHOUT running anything.

        Returns a dict:
            {
              "ok": bool,
              "authorized": [targets cleared to run],
              "blocked": [{"target", "reason"}],
              "refused": None | "reason the whole run is refused",
            }
        """
        result = {"ok": False, "authorized": [], "blocked": [], "refused": None}

        if isinstance(targets, str):
            targets = [t.strip() for t in targets.replace(",", " ").split() if t.strip()]
        targets = [t for t in (targets or []) if t]

        # --- global authorization checks (refuse the whole run on failure) ---
        if not operator or not str(operator).strip():
            result["refused"] = "No operator identity supplied."
            self.log(result["refused"], "blocked")
            return result
        if not authorization_ref or not str(authorization_ref).strip():
            result["refused"] = (
                "No authorization reference supplied (engagement/contract/ROE id "
                "for the written authorization is required).")
            self.log(result["refused"], "blocked")
            return result
        if (confirm_phrase or "").strip() != REQUIRED_CONFIRM_PHRASE:
            result["refused"] = (
                "Confirmation phrase not provided. Operator must type exactly: "
                f"\"{REQUIRED_CONFIRM_PHRASE}\".")
            self.log(result["refused"], "blocked")
            return result
        if not targets:
            result["refused"] = "No targets supplied."
            self.log(result["refused"], "blocked")
            return result

        # --- per-target scope enforcement ---
        scope = self._scope()
        for target in targets:
            if target.lower() in FORBIDDEN_TARGETS:
                result["blocked"].append(
                    {"target": target, "reason": "indiscriminate/broad target refused"})
                self.log(f"Refusing indiscriminate target: {target}", "blocked")
                continue
            try:
                authorized = bool(scope.is_target_authorized(target))
            except Exception as e:  # noqa: BLE001
                authorized = False
                self.log(f"Scope check failed for {target}: {e}", "error")
            if authorized:
                result["authorized"].append(target)
                self.log(f"Target authorized by active scope: {target}", "success")
            else:
                result["blocked"].append(
                    {"target": target, "reason": "not inside any active, in-date scope"})
                self.log(f"Target NOT in scope, dropped: {target}", "blocked")

        if not result["authorized"]:
            result["refused"] = "No supplied target is inside an active scope."
            self.log(result["refused"], "blocked")
            return result

        result["ok"] = True
        return result

    # ------------------------------------------------------------------ run
    def run(self, targets, operator, authorization_ref, confirm_phrase,
            phases=None, dry_run=True, live_runner=None):
        """Plan (dry_run, default) or execute an engagement across phases.

        Live execution happens only when dry_run=False AND the authorization
        gate passes. Each (authorized target x phase) is recorded.

        Args:
            live_runner: optional callable(target, phase, ctx) -> dict of
                findings. Injectable for testing. Defaults to the built-in
                runner which delegates to existing engines.
        """
        phases = list(phases) if phases else list(DEFAULT_PHASES)
        started = _now_iso()
        self.log(f"Engagement {self.engagement_id} preflight starting "
                 f"({'DRY-RUN' if dry_run else 'LIVE'})")

        pre = self.preflight(targets, operator, authorization_ref, confirm_phrase)

        engagement = {
            "engagement_id": self.engagement_id,
            "operator": operator,
            "authorization_ref": authorization_ref,
            "mode": "dry-run" if dry_run else "live",
            "started": started,
            "finished": None,
            "host": platform.node(),
            "phases_requested": phases,
            "authorized_targets": pre["authorized"],
            "blocked_targets": pre["blocked"],
            "refused": pre["refused"],
            "status": "refused" if not pre["ok"] else "planned",
            "results": [],   # list of {target, phase, status, findings}
        }

        if not pre["ok"]:
            engagement["finished"] = _now_iso()
            self.log("Engagement refused at preflight; nothing executed.", "blocked")
            return engagement

        runner = live_runner or self._default_live_runner
        for target in pre["authorized"]:
            for phase in phases:
                if dry_run:
                    engagement["results"].append({
                        "target": target, "phase": phase,
                        "status": "planned",
                        "findings": {"note": "dry-run: would execute this phase"},
                    })
                    self.log(f"[plan] {phase} -> {target}")
                    continue
                self.log(f"Executing {phase} -> {target}", "info")
                try:
                    findings = runner(target, phase, engagement) or {}
                    engagement["results"].append({
                        "target": target, "phase": phase,
                        "status": "completed", "findings": findings,
                    })
                except Exception as e:  # noqa: BLE001
                    engagement["results"].append({
                        "target": target, "phase": phase,
                        "status": "error", "findings": {"error": str(e)},
                    })
                    self.log(f"{phase} on {target} errored: {e}", "error")

        engagement["status"] = "planned" if dry_run else "completed"
        engagement["finished"] = _now_iso()
        self.log(f"Engagement {self.engagement_id} {engagement['status']}.", "success")
        return engagement

    def _default_live_runner(self, target, phase, ctx):
        """Delegate a phase to the existing engines. Imported lazily so the
        orchestrator stays importable in headless/test environments."""
        if phase in ("exploitation", "exploit"):
            try:
                from modules.war_exploit import WarExploit
            except ImportError:
                from war_exploit import WarExploit
            we = WarExploit()
            return {"war_exploit": we.run_attack(target)}
        # Other phases are intentionally left to an injected runner or the GUI
        # wiring; the orchestrator does not invent new offensive behaviour, it
        # only governs and reports on the engines that already exist.
        return {"note": f"no built-in runner for phase '{phase}'; "
                        f"inject a live_runner to execute it"}

    # ---------------------------------------------------------- artifact ledger
    def register_artifact(self, kind, location, target="", note=""):
        """Record an artifact the OPERATOR planted during the test so it can be
        rolled back later in an audited way (e.g. a test account, an uploaded
        webshell, a scheduled task, a dropped file)."""
        artifact = {
            "id": uuid.uuid4().hex[:8],
            "kind": kind,
            "location": location,
            "target": target,
            "note": note,
            "registered": _now_iso(),
            "rolled_back": False,
        }
        self._artifacts.append(artifact)
        self.log(f"Registered operator artifact [{artifact['id']}] {kind} @ {location}")
        return artifact["id"]

    @property
    def artifacts(self):
        return list(self._artifacts)

    def rollback(self, remover=None):
        """Audited rollback of OPERATOR-planted artifacts only.

        Args:
            remover: optional callable(artifact)->bool that performs the actual
                removal and returns success. If None, each artifact is marked as
                requiring manual removal (we never silently wipe anything).

        This never touches host/system logs or any target-side evidence not in
        the operator artifact ledger -- that is deliberately preserved.
        """
        self.log("Starting audited rollback of operator-planted artifacts.")
        for artifact in self._artifacts:
            if artifact["rolled_back"]:
                continue
            action = {
                "artifact_id": artifact["id"],
                "kind": artifact["kind"],
                "location": artifact["location"],
                "target": artifact["target"],
                "ts": _now_iso(),
            }
            if remover is None:
                action["outcome"] = "manual-removal-required"
                self.log(f"Artifact [{artifact['id']}] needs MANUAL removal "
                         f"({artifact['kind']} @ {artifact['location']})", "warn")
            else:
                try:
                    ok = bool(remover(artifact))
                    action["outcome"] = "removed" if ok else "removal-failed"
                    artifact["rolled_back"] = ok
                    self.log(f"Artifact [{artifact['id']}] {action['outcome']}",
                             "success" if ok else "error")
                except Exception as e:  # noqa: BLE001
                    action["outcome"] = f"error: {e}"
                    self.log(f"Rollback error for [{artifact['id']}]: {e}", "error")
            self._rollback_log.append(action)
        return list(self._rollback_log)

    @property
    def rollback_log(self):
        return list(self._rollback_log)

    # ------------------------------------------------------------------ report
    def build_report(self, engagement, fmt="markdown"):
        """Produce the audited engagement deliverable from a run() result."""
        if fmt == "json":
            return json.dumps({
                "engagement": engagement,
                "audit_trail": self._audit,
                "artifacts": self._artifacts,
                "rollback_log": self._rollback_log,
            }, indent=2)
        return self._markdown(engagement)

    def _markdown(self, e):
        lines = []
        add = lines.append
        add("# BlackSentinel Strike - Engagement Report")
        add("")
        add(f"- **Engagement ID:** `{e['engagement_id']}`")
        add(f"- **Status:** {e['status'].upper()} ({e['mode']})")
        add(f"- **Started:** {e['started']}")
        add(f"- **Finished:** {e.get('finished') or 'N/A'}")
        add(f"- **Executed from host:** {e.get('host', 'N/A')}")
        add("")
        add("## 1. Authorization")
        add("")
        add(f"- **Operator:** {e['operator']}")
        add(f"- **Authorization reference:** {e['authorization_ref']}")
        add("- **Confirmation:** operator attested written authorization "
            "(phrase accepted at preflight).")
        add("")
        add("## 2. Scope")
        add("")
        if e["authorized_targets"]:
            add("**Authorized & executed against:**")
            for t in e["authorized_targets"]:
                add(f"- `{t}`")
        else:
            add("_No targets were authorized._")
        add("")
        if e["blocked_targets"]:
            add("**Dropped (out of scope / refused):**")
            for b in e["blocked_targets"]:
                add(f"- `{b['target']}` - {b['reason']}")
            add("")
        if e.get("refused"):
            add(f"> **Engagement refused:** {e['refused']}")
            add("")
        add("## 3. Phases & Findings")
        add("")
        if e["results"]:
            add("| Target | Phase | Status | Summary |")
            add("|--------|-------|--------|---------|")
            for r in e["results"]:
                summary = ", ".join(f"{k}={v}" for k, v in r["findings"].items())
                summary = summary.replace("|", "\\|")[:200]
                add(f"| `{r['target']}` | {r['phase']} | {r['status']} | {summary} |")
        else:
            add("_No phases executed._")
        add("")
        add("## 4. Operator Artifact Ledger & Rollback")
        add("")
        if self._artifacts:
            add("| ID | Kind | Location | Target | Rolled back |")
            add("|----|------|----------|--------|-------------|")
            for a in self._artifacts:
                add(f"| {a['id']} | {a['kind']} | {a['location']} | "
                    f"{a['target']} | {'yes' if a['rolled_back'] else 'NO'} |")
            add("")
        else:
            add("_No operator artifacts were registered during this engagement._")
            add("")
        if self._rollback_log:
            add("**Rollback actions:**")
            for r in self._rollback_log:
                add(f"- [{r['artifact_id']}] {r['kind']} @ {r['location']} "
                    f"-> {r['outcome']} ({r['ts']})")
            add("")
        add("> Host and target-side logs/evidence are intentionally preserved "
            "for the defending team. Only operator-planted test artifacts are "
            "rolled back, and every rollback action is recorded above.")
        add("")
        add("## 5. Recommendations")
        add("")
        add("- Review each finding above and prioritise by business impact.")
        add("- Confirm all operator artifacts show *rolled back = yes*; "
            "remediate any marked *NO* manually.")
        add("- Preserve this report and the audit trail with the engagement record.")
        add("")
        add("## 6. Audit Trail")
        add("")
        add("```")
        for entry in self._audit:
            add(f"{entry['ts']} [{entry['level']}] {entry['msg']}")
        add("```")
        add("")
        return "\n".join(lines)

"""Production-grade rate limiter and throttling module."""

import json
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DATA_DIR = Path(__file__).parent.parent / "data"
COUNTERS_FILE = DATA_DIR / "throttle_counters.json"
LIMITS_FILE = DATA_DIR / "throttle_limits.json"


class RateLimiter:
    """Thread-safe sliding-window rate limiter with persistence."""

    DEFAULT_LIMITS: Dict[str, Tuple[int, int]] = {
        "nmap_scan": (5, 60),
        "brute_force": (3, 60),
        "exploit": (2, 60),
        "web_scan": (10, 60),
        "recon": (20, 60),
        "default": (15, 60),
    }

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: Dict[str, Dict[str, List[float]]] = defaultdict(lambda: defaultdict(list))
        self._limits: Dict[str, Dict[str, Tuple[int, int]]] = defaultdict(dict)
        self._global_limits: Dict[str, Tuple[int, int]] = {}
        self._total_checks = 0
        self._total_allowed = 0
        self._total_rejected = 0

        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self._load_counters()
        self._load_limits()

    # ------------------------------------------------------------------
    # Persistence helpers
    # ------------------------------------------------------------------

    def _load_counters(self) -> None:
        if COUNTERS_FILE.exists():
            try:
                with open(COUNTERS_FILE, "r") as fh:
                    data = json.load(fh)
                for target, actions in data.items():
                    for action, timestamps in actions.items():
                        self._counters[target][action] = [float(ts) for ts in timestamps]
            except (json.JSONDecodeError, KeyError, TypeError):
                pass

    def _load_limits(self) -> None:
        if LIMITS_FILE.exists():
            try:
                with open(LIMITS_FILE, "r") as fh:
                    data = json.load(fh)
                if "global" in data:
                    for action, vals in data["global"].items():
                        self._global_limits[action] = (vals["limit"], vals["window"])
                for target, actions in data.get("target", {}).items():
                    for action, vals in actions.items():
                        self._limits[target][action] = (
                            vals["limit"],
                            vals["window"],
                        )
            except (json.JSONDecodeError, KeyError, TypeError):
                pass

    def _save_counters(self) -> None:
        try:
            data: Dict[str, Dict[str, List[float]]] = {}
            for target, actions in self._counters.items():
                data[target] = {}
                for action, timestamps in actions.items():
                    data[target][action] = timestamps
            with open(COUNTERS_FILE, "w") as fh:
                json.dump(data, fh, indent=2)
        except OSError:
            pass

    def _save_limits(self) -> None:
        try:
            data: Dict[str, Any] = {"global": {}, "target": {}}
            for action, (limit, window) in self._global_limits.items():
                data["global"][action] = {"limit": limit, "window": window}
            for target, actions in self._limits.items():
                data["target"][target] = {}
                for action, (limit, window) in actions.items():
                    data["target"][target][action] = {
                        "limit": limit,
                        "window": window,
                    }
            with open(LIMITS_FILE, "w") as fh:
                json.dump(data, fh, indent=2)
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_limit(self, target: str, action: str) -> Tuple[int, int]:
        """Return (limit, window_seconds) for a target/action pair."""
        # 1. Target-specific override
        if action in self._limits.get(target, {}):
            return self._limits[target][action]
        # 2. Global override for this action
        if action in self._global_limits:
            return self._global_limits[action]
        # 3. Built-in default
        if action in self.DEFAULT_LIMITS:
            return self.DEFAULT_LIMITS[action]
        # 4. Catch-all default
        return self.DEFAULT_LIMITS["default"]

    def _evict(self, target: str, action: str, window: int) -> None:
        """Remove timestamps outside the current sliding window."""
        cutoff = time.time() - window
        self._counters[target][action] = [ts for ts in self._counters[target][action] if ts > cutoff]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_rate(self, target: str, action: str, limit: Optional[int] = None, window: Optional[int] = None) -> bool:
        """Return True if the action is currently allowed."""
        with self._lock:
            self._total_checks += 1
            effective_limit, effective_window = self._get_limit(target, action)
            if limit is not None:
                effective_limit = limit
            if window is not None:
                effective_window = window

            self._evict(target, action, effective_window)
            current_count = len(self._counters[target][action])

            if current_count < effective_limit:
                self._total_allowed += 1
                return True
            self._total_rejected += 1
            return False

    def record_action(self, target: str, action: str) -> None:
        """Record that an action was performed."""
        with self._lock:
            self._counters[target][action].append(time.time())
            self._save_counters()

    def get_usage(self, target: str, action: Optional[str] = None) -> Dict[str, Any]:
        """Return current usage for *target*.  If *action* is given, limit to that action."""
        with self._lock:
            result: Dict[str, Any] = {}
            actions = [action] if action else list(self._counters.get(target, {}).keys())
            for act in actions:
                effective_limit, effective_window = self._get_limit(target, act)
                self._evict(target, act, effective_window)
                count = len(self._counters[target][act])
                result[act] = {
                    "count": count,
                    "limit": effective_limit,
                    "window": effective_window,
                    "remaining": max(0, effective_limit - count),
                }
            return result

    def get_remaining(self, target: str, action: str) -> int:
        """Return how many more actions are allowed right now."""
        with self._lock:
            effective_limit, effective_window = self._get_limit(target, action)
            self._evict(target, action, effective_window)
            return max(0, effective_limit - len(self._counters[target][action]))

    def reset(self, target: Optional[str] = None, action: Optional[str] = None) -> None:
        """Reset counters.  Scope depends on the arguments provided."""
        with self._lock:
            if target is None and action is None:
                self._counters.clear()
            elif target is not None and action is None:
                self._counters.pop(target, None)
            elif target is not None and action is not None:
                self._counters.get(target, {}).pop(action, None)
            self._save_counters()

    def set_limit(self, target: str, action: str, limit: int, window: int = 60) -> None:
        """Set a per-target override for *action*."""
        with self._lock:
            self._limits[target][action] = (limit, window)
            self._save_limits()

    def set_global_limit(self, action: str, limit: int, window: int = 60) -> None:
        """Set a global override for *action*."""
        with self._lock:
            self._global_limits[action] = (limit, window)
            self._save_limits()

    def is_throttled(self, target: str, action: str) -> bool:
        """Return True if the action is currently blocked (limit reached)."""
        return not self.check_rate(target, action)

    def get_throttle_status(self, target: Optional[str] = None) -> Dict[str, Any]:
        """Return a snapshot of throttle status for every tracked target/action."""
        with self._lock:
            status: Dict[str, Any] = {}
            targets = [target] if target else list(self._counters.keys())
            for tgt in targets:
                status[tgt] = {}
                for act in list(self._counters.get(tgt, {}).keys()):
                    effective_limit, effective_window = self._get_limit(tgt, act)
                    self._evict(tgt, act, effective_window)
                    count = len(self._counters[tgt][act])
                    status[tgt][act] = {
                        "throttled": count >= effective_limit,
                        "count": count,
                        "limit": effective_limit,
                        "window": effective_window,
                        "remaining": max(0, effective_limit - count),
                    }
            return status

    def get_stats(self) -> Dict[str, Any]:
        """Return high-level statistics."""
        with self._lock:
            total_actions = sum(len(ts) for actions in self._counters.values() for ts in actions.values())
            unique_targets = len(self._counters)
            unique_pairs = sum(len(actions) for actions in self._counters.values())
            return {
                "total_checks": self._total_checks,
                "total_allowed": self._total_allowed,
                "total_rejected": self._total_rejected,
                "total_actions_recorded": total_actions,
                "unique_targets": unique_targets,
                "unique_target_action_pairs": unique_pairs,
            }

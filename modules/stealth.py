"""Production-grade stealth mode module for avoiding detection."""

import random
import threading
from typing import Tuple, Optional


STEALTH_LEVELS = {
    "passive": {
        "nmap_args": "-sT -T0 --max-rate 10",
        "scan_delay": 30,
        "jitter": (10, 60),
        "fragment": False,
        "decoy": False,
        "source_port_randomize": True,
        "avoid_detection": True,
        "dns_resolution": "never",
        "decrement_ttl": True,
    },
    "quiet": {
        "nmap_args": "-sS -T1 --max-rate 100 -f",
        "scan_delay": 10,
        "jitter": (5, 20),
        "fragment": True,
        "decoy": True,
        "source_port_randomize": True,
        "avoid_detection": True,
        "dns_resolution": "try",
        "decrement_ttl": True,
    },
    "moderate": {
        "nmap_args": "-sS -T3 --max-rate 1000",
        "scan_delay": 2,
        "jitter": (1, 5),
        "fragment": False,
        "decoy": False,
        "source_port_randomize": False,
        "avoid_detection": False,
        "dns_resolution": "default",
        "decrement_ttl": False,
    },
    "aggressive": {
        "nmap_args": "-sS -T4 --max-rate 5000",
        "scan_delay": 0,
        "jitter": (0, 2),
        "fragment": False,
        "decoy": False,
        "source_port_randomize": False,
        "avoid_detection": False,
        "dns_resolution": "always",
        "decrement_ttl": False,
    },
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/124.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Vivaldi/6.7",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]


class StealthManager:
    """Thread-safe stealth mode manager for avoiding IDS/IPS detection."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._mode: str = "moderate"
        self._decoy_count: int = 3

    def set_mode(self, mode: str) -> None:
        """Set stealth level: passive, quiet, moderate, aggressive."""
        if mode not in STEALTH_LEVELS:
            raise ValueError(f"Invalid mode '{mode}'. Must be one of: {list(STEALTH_LEVELS.keys())}")
        with self._lock:
            self._mode = mode

    def get_mode(self) -> str:
        """Get current stealth mode."""
        with self._lock:
            return self._mode

    def get_nmap_args(self) -> str:
        """Return nmap arguments for current stealth mode."""
        with self._lock:
            return STEALTH_LEVELS[self._mode]["nmap_args"]

    def get_scan_delay(self) -> int:
        """Return delay between scans in seconds."""
        with self._lock:
            return STEALTH_LEVELS[self._mode]["scan_delay"]

    def get_jitter(self) -> Tuple[int, int]:
        """Return random jitter range (min, max) seconds."""
        with self._lock:
            return STEALTH_LEVELS[self._mode]["jitter"]

    def randomize_source_port(self) -> bool:
        """Whether to use random source ports."""
        with self._lock:
            return STEALTH_LEVELS[self._mode]["source_port_randomize"]

    def decoy_addresses(self, count: Optional[int] = None) -> str:
        """Generate decoy IPs for nmap -D flag. Returns comma-separated string."""
        n = count if count is not None else self._decoy_count
        decoys = []
        for _ in range(n):
            octets = [random.randint(1, 254) for _ in range(4)]
            decoys.append(".".join(str(o) for o in octets))
        decoys.append("ME")
        return ",".join(decoys)

    def fragment_packets(self) -> bool:
        """Whether to fragment packets (-f)."""
        with self._lock:
            return STEALTH_LEVELS[self._mode]["fragment"]

    def get_user_agent(self) -> str:
        """Return a random User-Agent string."""
        return random.choice(USER_AGENTS)

    def randomize_timing(self, base_delay: float) -> float:
        """Apply random jitter to a base delay. Returns adjusted delay."""
        lo, hi = self.get_jitter()
        jitter = random.uniform(lo, hi)
        return max(0.0, base_delay + jitter)

    def is_avoid_detection(self) -> bool:
        """Whether to employ IDS/IPS avoidance techniques."""
        with self._lock:
            return STEALTH_LEVELS[self._mode]["avoid_detection"]

    def get_dns_resolution(self) -> str:
        """DNS resolution mode: never, try, default, always."""
        with self._lock:
            return STEALTH_LEVELS[self._mode]["dns_resolution"]

    def should_decrement_ttl(self) -> bool:
        """Whether to use random TTLs to hinder fingerprinting."""
        with self._lock:
            return STEALTH_LEVELS[self._mode]["decrement_ttl"]

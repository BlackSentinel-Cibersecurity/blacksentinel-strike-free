"""Auto-upgrade utility for BlackSentinel Strike."""
import sys
import json
import subprocess
import shutil
from pathlib import Path
from datetime import datetime

VERSION_FILE = Path(__file__).parent.parent / "VERSION"
UPGRADE_DIR = Path.home() / ".blacksentinel-strike" / "upgrades"
LOG_FILE = UPGRADE_DIR / "upgrade.log"


def get_current_version() -> str:
    if VERSION_FILE.exists():
        return VERSION_FILE.read_text().strip()
    return "4.0.0"


def set_version(version: str):
    VERSION_FILE.write_text(version)


def _log(msg: str):
    UPGRADE_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{ts}] {msg}\n")


def check_for_updates(remote_url: str = None) -> dict:
    current = get_current_version()
    result = {
        "current_version": current,
        "update_available": False,
        "latest_version": current,
        "changelog": "",
    }
    if remote_url:
        try:
            import urllib.request
            resp = urllib.request.urlopen(f"{remote_url}/version.json", timeout=10)
            data = json.loads(resp.read().decode())
            result["latest_version"] = data.get("version", current)
            result["changelog"] = data.get("changelog", "")
            if data.get("version", current) != current:
                result["update_available"] = True
        except Exception as e:
            _log(f"Update check failed: {e}")
            result["error"] = str(e)
    return result


def backup_current() -> str:
    UPGRADE_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_name = f"backup_v{get_current_version()}_{ts}"
    backup_path = UPGRADE_DIR / backup_name
    app_dir = Path(__file__).parent.parent
    shutil.copytree(app_dir, backup_path,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".git", "vault"))
    _log(f"Backup created: {backup_path}")
    return str(backup_path)


def apply_update(source_dir: str) -> tuple:
    app_dir = Path(__file__).parent.parent
    src = Path(source_dir)
    if not src.exists():
        return (False, "Source directory not found")
    try:
        backup_current()
        for item in src.rglob("*"):
            if item.is_file():
                rel = item.relative_to(src)
                dest = app_dir / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(item, dest)
        new_ver_file = src / "VERSION"
        if new_ver_file.exists():
            set_version(new_ver_file.read_text().strip())
        _log(f"Update applied from {source_dir}")
        return (True, f"Update applied. Restart required.")
    except Exception as e:
        _log(f"Update failed: {e}")
        return (False, str(e))


def install_deps() -> tuple:
    req_file = Path(__file__).parent.parent / "requirements.txt"
    if not req_file.exists():
        return (False, "requirements.txt not found")
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--break-system-packages", "-r", str(req_file)],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode == 0:
            _log("Dependencies updated successfully")
            return (True, "Dependencies updated")
        else:
            _log(f"pip install failed: {result.stderr[:200]}")
            return (False, result.stderr[:200])
    except Exception as e:
        return (False, str(e))


def get_upgrade_log() -> str:
    if LOG_FILE.exists():
        return LOG_FILE.read_text()
    return "No upgrade history."

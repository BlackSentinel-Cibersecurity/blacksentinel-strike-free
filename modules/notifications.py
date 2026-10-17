"""
BlackSentinel Strike - Notification System
Production-grade notification management with encrypted storage, rate limiting,
background queue, and multi-channel support (email, Slack, Discord, Teams, generic).
"""

import json
import os
import queue
import smtplib
import ssl
import threading
import time
import uuid
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path

try:
    from urllib.request import Request, urlopen
except ImportError:
    pass

from modules.vault import encrypt_data, decrypt_data, _ensure_dirs, VAULT_DIR


NOTIFICATIONS_FILE = VAULT_DIR / "notifications.enc"

SEVERITY_LEVELS = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SEVERITY_THRESHOLD_MAP = {
    "all": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

_rate_limit_lock = threading.Lock()
_rate_limits = {}


def _is_rate_limited(channel_id, max_per_minute=10):
    now = time.time()
    with _rate_limit_lock:
        if channel_id not in _rate_limits:
            _rate_limits[channel_id] = []
        timestamps = _rate_limits[channel_id]
        cutoff = now - 60.0
        _rate_limits[channel_id] = [t for t in timestamps if t > cutoff]
        if len(_rate_limits[channel_id]) >= max_per_minute:
            return True
        _rate_limits[channel_id].append(now)
        return False


class NotificationManager:
    """Thread-safe notification manager with encrypted config, rate limiting, and background queue."""

    def __init__(self, config_path=None):
        self._lock = threading.RLock()
        _ensure_dirs()
        self._config_path = config_path or NOTIFICATIONS_FILE
        self._password = self._load_or_create_password()
        self._data = self._load()
        self._queue = queue.Queue()
        self._worker = threading.Thread(target=self._process_queue, daemon=True)
        self._worker.start()

    def _load_or_create_password(self):
        key_path = VAULT_DIR / ".notif_key"
        if key_path.exists():
            return key_path.read_text().strip()
        import secrets

        key = secrets.token_hex(32)
        key_path.write_text(key)
        os.chmod(str(key_path), 0o600)
        return key

    def _load(self):
        if not self._config_path.exists():
            return self._default_config()
        try:
            raw = self._config_path.read_bytes()
            plain = decrypt_data(raw, self._password)
            return json.loads(plain.decode("utf-8"))
        except Exception:
            return self._default_config()

    def _save(self):
        blob = json.dumps(self._data, ensure_ascii=False).encode("utf-8")
        encrypted = encrypt_data(blob, self._password)
        self._config_path.write_bytes(encrypted)
        os.chmod(str(self._config_path), 0o600)

    @staticmethod
    def _default_config():
        return {
            "email": {
                "smtp_host": "",
                "smtp_port": 587,
                "smtp_username": "",
                "smtp_password": "",
                "use_tls": True,
                "from_address": "",
                "from_name": "BlackSentinel Strike",
            },
            "recipients": {},
            "webhooks": {},
            "history": [],
            "settings": {
                "max_rate_per_minute": 10,
                "history_limit": 1000,
            },
        }

    def _log_event(self, event_type, channel, subject, success, error=""):
        entry = {
            "id": str(uuid.uuid4())[:8],
            "type": event_type,
            "channel": channel,
            "subject": subject,
            "success": success,
            "error": error,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
        with self._lock:
            self._data["history"].append(entry)
            limit = self._data["settings"].get("history_limit", 1000)
            if len(self._data["history"]) > limit:
                self._data["history"] = self._data["history"][-limit:]
            self._save()

    def _process_queue(self):
        while True:
            try:
                task = self._queue.get(timeout=5)
            except queue.Empty:
                continue
            if task is None:
                break
            try:
                func, args, kwargs = task
                func(*args, **kwargs)
            except Exception as e:
                self._log_event("queue_error", "queue", str(e)[:100], False, str(e))

    def _enqueue(self, func, *args, **kwargs):
        self._queue.put((func, args, kwargs))

    # ── Email Recipients ─────────────────────────────────────────────

    def add_email_recipient(self, email, name="", alerts="critical,high"):
        with self._lock:
            recipient_id = str(uuid.uuid4())[:8]
            self._data["recipients"][recipient_id] = {
                "id": recipient_id,
                "email": email,
                "name": name,
                "alerts": alerts,
                "added": datetime.utcnow().isoformat() + "Z",
            }
            self._save()
        return recipient_id

    def remove_email_recipient(self, email):
        with self._lock:
            to_remove = [rid for rid, r in self._data["recipients"].items() if r["email"] == email]
            for rid in to_remove:
                del self._data["recipients"][rid]
            if to_remove:
                self._save()
        return len(to_remove) > 0

    # ── Webhooks ─────────────────────────────────────────────────────

    def add_webhook(self, url, name="", events="all"):
        with self._lock:
            webhook_id = str(uuid.uuid4())[:8]
            fmt = self._detect_webhook_format(url)
            self._data["webhooks"][webhook_id] = {
                "id": webhook_id,
                "url": url,
                "name": name or url[:50],
                "events": events,
                "format": fmt,
                "added": datetime.utcnow().isoformat() + "Z",
            }
            self._save()
        return webhook_id

    def remove_webhook(self, webhook_id):
        with self._lock:
            if webhook_id in self._data["webhooks"]:
                del self._data["webhooks"][webhook_id]
                self._save()
                return True
        return False

    @staticmethod
    def _detect_webhook_format(url):
        url_lower = url.lower()
        if "slack.com" in url_lower or "hooks.slack.com" in url_lower:
            return "slack"
        if "discord.com" in url_lower or "discordapp.com" in url_lower:
            return "discord"
        if "webhook.office.com" in url_lower or "office365.com" in url_lower:
            return "teams"
        return "generic"

    # ── SMTP Configuration ──────────────────────────────────────────

    def configure_smtp(self, host, port, username, password, use_tls=True):
        with self._lock:
            self._data["email"]["smtp_host"] = host
            self._data["email"]["smtp_port"] = int(port)
            self._data["email"]["smtp_username"] = username
            self._data["email"]["smtp_password"] = password
            self._data["email"]["use_tls"] = use_tls
            if not self._data["email"]["from_address"]:
                self._data["email"]["from_address"] = username
            self._save()

    # ── Send Email ───────────────────────────────────────────────────

    def send_email(self, subject, body, recipients=None, attachments=None):
        cfg = self._data["email"]
        if not cfg["smtp_host"]:
            self._log_event("email", "smtp", subject, False, "SMTP not configured")
            return False

        if recipients is None:
            recipients = list(self._data["recipients"].values())

        if not recipients:
            self._log_event("email", "smtp", subject, False, "No recipients")
            return False

        if _is_rate_limited("email", self._data["settings"].get("max_rate_per_minute", 10)):
            self._log_event("email", "smtp", subject, False, "Rate limited")
            return False

        return self._send_email_direct(subject, body, recipients, attachments)

    def _send_email_direct(self, subject, body, recipients, attachments=None):
        cfg = self._data["email"]
        try:
            msg = MIMEMultipart()
            msg["From"] = f"{cfg['from_name']} <{cfg['from_address']}>"
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain", "utf-8"))

            if attachments:
                for filepath in attachments:
                    path = Path(filepath)
                    if not path.exists():
                        continue
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(path.read_bytes())
                    encoders.encode_base64(part)
                    part.add_header(
                        "Content-Disposition",
                        f'attachment; filename="{path.name}"',
                    )
                    msg.attach(part)

            target_emails = []
            for r in recipients:
                if isinstance(r, dict):
                    target_emails.append(r["email"])
                elif isinstance(r, str):
                    target_emails.append(r)

            msg["To"] = ", ".join(target_emails)

            context = ssl.create_default_context()
            if cfg["use_tls"]:
                server = smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"], timeout=30)
                server.starttls(context=context)
            else:
                server = smtplib.SMTP_SSL(cfg["smtp_host"], cfg["smtp_port"], context=context, timeout=30)

            if cfg["smtp_username"] and cfg["smtp_password"]:
                server.login(cfg["smtp_username"], cfg["smtp_password"])

            server.sendmail(cfg["from_address"], target_emails, msg.as_string())
            server.quit()
            self._log_event("email", "smtp", subject, True)
            return True
        except Exception as e:
            self._log_event("email", "smtp", subject, False, str(e))
            return False

    # ── Send Webhook ─────────────────────────────────────────────────

    def send_webhook(self, message, webhook_id=None, severity="info"):
        if _is_rate_limited("webhook", self._data["settings"].get("max_rate_per_minute", 10)):
            self._log_event("webhook", "webhook", message[:100], False, "Rate limited")
            return False

        webhooks = self._data["webhooks"]
        if webhook_id:
            wh = webhooks.get(webhook_id)
            if not wh:
                return False
            targets = [wh]
        else:
            targets = list(webhooks.values())

        if not targets:
            return False

        success = True
        for wh in targets:
            events = wh.get("events", "all")
            if events != "all" and severity not in events.split(","):
                continue
            result = self._send_webhook_single(wh, message, severity)
            if not result:
                success = False
        return success

    def _send_webhook_single(self, webhook, message, severity):
        fmt = webhook.get("format", "generic")
        severity_emoji = {
            "info": "\u2139\ufe0f",
            "low": "\u26aa",
            "medium": "\U0001f7e1",
            "high": "\U0001f7e0",
            "critical": "\U0001f534",
        }
        emoji = severity_emoji.get(severity, "\u26aa")
        full_message = f"{emoji} [{severity.upper()}] {message}"

        if fmt == "slack":
            payload = json.dumps({"text": full_message}).encode("utf-8")
        elif fmt == "discord":
            payload = json.dumps({"content": full_message}).encode("utf-8")
        elif fmt == "teams":
            payload = json.dumps(
                {
                    "@type": "MessageCard",
                    "summary": message[:100],
                    "text": full_message,
                }
            ).encode("utf-8")
        else:
            payload = json.dumps(
                {
                    "text": full_message,
                    "severity": severity,
                    "message": message,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "source": "BlackSentinel Strike",
                }
            ).encode("utf-8")

        try:
            req = Request(
                webhook["url"],
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            ctx = ssl.create_default_context()
            with urlopen(req, timeout=30, context=ctx) as resp:
                self._log_event("webhook", fmt, message[:100], True)
                return resp.status < 400
        except Exception as e:
            self._log_event("webhook", fmt, message[:100], False, str(e))
            return False

    # ── Smart Notifications ──────────────────────────────────────────

    def notify_finding(self, finding):
        severity = finding.get("severity", "info").lower()
        sev_num = SEVERITY_LEVELS.get(severity, 0)
        subject = f"[{severity.upper()}] Finding: {finding.get('title', 'Unknown')}"
        body = self._format_finding_body(finding)
        email_targets = self._get_filtered_recipients(severity)
        if email_targets:
            self._enqueue(self._send_email_direct, subject, body, email_targets)
        self._enqueue(self._send_webhook_all, body, severity)
        self._log_event("finding", "notify", subject, True)

    @staticmethod
    def _format_finding_body(finding):
        lines = [
            f"Title: {finding.get('title', 'Unknown')}",
            f"Severity: {finding.get('severity', 'unknown').upper()}",
            f"Category: {finding.get('category', 'N/A')}",
            f"Target: {finding.get('target', 'N/A')}",
            f"Description: {finding.get('description', 'N/A')}",
            f"Remediation: {finding.get('remediation', 'N/A')}",
            f"Timestamp: {datetime.utcnow().isoformat()}Z",
        ]
        if finding.get("evidence"):
            lines.append(f"Evidence: {finding['evidence']}")
        if finding.get("cvss"):
            lines.append(f"CVSS: {finding['cvss']}")
        if finding.get("cve"):
            lines.append(f"CVE: {finding['cve']}")
        return "\n".join(lines)

    def _get_filtered_recipients(self, severity):
        sev_num = SEVERITY_LEVELS.get(severity, 0)
        matched = []
        for r in self._data["recipients"].values():
            alerts = r.get("alerts", "all")
            threshold = SEVERITY_THRESHOLD_MAP.get(alerts, 0)
            if alerts == "all" or sev_num >= threshold:
                matched.append(r)
        return matched

    def _send_webhook_all(self, message, severity):
        for wh in self._data["webhooks"].values():
            events = wh.get("events", "all")
            if events == "all" or severity in events.split(","):
                self._send_webhook_single(wh, message, severity)

    def notify_scan_complete(self, scan_id, operator, summary):
        subject = f"Scan Complete: {scan_id}"
        body = (
            f"Scan ID: {scan_id}\n"
            f"Operator: {operator}\n"
            f"Completed: {datetime.utcnow().isoformat()}Z\n\n"
            f"Summary:\n{summary}"
        )
        email_targets = self._get_filtered_recipients("info")
        if email_targets:
            self._enqueue(self._send_email_direct, subject, body, email_targets)
        self._enqueue(self._send_webhook_all, body, "info")
        self._log_event("scan_complete", "notify", subject, True)

    def notify_critical_alert(self, message):
        subject = "[CRITICAL] BlackSentinel Alert"
        body = f"CRITICAL ALERT\nTime: {datetime.utcnow().isoformat()}Z\n\n{message}"
        all_recipients = list(self._data["recipients"].values())
        if all_recipients:
            self._enqueue(self._send_email_direct, subject, body, all_recipients)
        for wh in self._data["webhooks"].values():
            self._enqueue(self._send_webhook_single, wh, message, "critical")
        self._log_event("critical_alert", "all", subject, True)

    def notify_scope_violation(self, target, operator):
        subject = "[CRITICAL] Scope Violation Detected"
        body = (
            f"SCOPE VIOLATION\n"
            f"Time: {datetime.utcnow().isoformat()}Z\n"
            f"Operator: {operator}\n"
            f"Unauthorized Target: {target}\n\n"
            f"This action has been logged and may require immediate review."
        )
        self._enqueue(self._send_email_direct, subject, body, list(self._data["recipients"].values()))
        self._enqueue(self._send_webhook_all, body, "critical")
        self._log_event("scope_violation", "all", subject, True)

    def notify_brute_force_lockout(self, operator, target):
        subject = "[HIGH] Brute Force Lockout"
        body = (
            f"BRUTE FORCE LOCKOUT\n"
            f"Time: {datetime.utcnow().isoformat()}Z\n"
            f"Operator: {operator}\n"
            f"Target: {target}\n\n"
            f"Account or service has been locked due to excessive failed attempts."
        )
        filtered = self._get_filtered_recipients("high")
        if filtered:
            self._enqueue(self._send_email_direct, subject, body, filtered)
        self._enqueue(self._send_webhook_all, body, "high")
        self._log_event("brute_force_lockout", "notify", subject, True)

    # ── Test Notification ────────────────────────────────────────────

    def test_notification(self):
        subject = "BlackSentinel Notification Test"
        body = (
            "This is a test notification from BlackSentinel Strike.\n"
            f"Timestamp: {datetime.utcnow().isoformat()}Z\n\n"
            "If you received this, your notification channels are configured correctly."
        )
        results = {"email": False, "webhooks": {}}
        results["email"] = self.send_email(subject, body)
        for wh_id, wh in self._data["webhooks"].items():
            results["webhooks"][wh_id] = self._send_webhook_single(
                wh, "Test notification from BlackSentinel Strike", "info"
            )
        self._log_event("test", "all", subject, True)
        return results

    # ── History ──────────────────────────────────────────────────────

    def get_notification_history(self, limit=100):
        with self._lock:
            history = list(self._data["history"])
        return history[-limit:]

    # ── Config Access ────────────────────────────────────────────────

    def get_config(self):
        with self._lock:
            safe = json.loads(json.dumps(self._data))
            if "email" in safe and "smtp_password" in safe["email"]:
                if safe["email"]["smtp_password"]:
                    safe["email"]["smtp_password"] = "***"
            return safe


def get_notification_manager(config_path=None):
    global _notif_manager
    if _notif_manager is None:
        _notif_manager = NotificationManager(config_path)
    return _notif_manager


_notif_manager = None
_notif_lock = threading.Lock()


def get_notification_manager_threadsafe(config_path=None):
    global _notif_manager
    with _notif_lock:
        if _notif_manager is None:
            _notif_manager = NotificationManager(config_path)
    return _notif_manager

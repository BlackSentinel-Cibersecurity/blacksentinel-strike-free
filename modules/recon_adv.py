#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════
     RECON ADVANCED MODULE - BlackSentinel Strike v4.0
     Copyright (c) 2024-2025 BlackSentinel Strike - All Rights Reserved
═══════════════════════════════════════════════════════════════
"""

import subprocess
import json
import re
import shutil


def _require_tool(name):
    """Return the tool path or raise with a helpful message."""
    path = shutil.which(name)
    if not path:
        raise FileNotFoundError(f"Required tool not found: {name}. Please install it first.")
    return path


class ReconAdvanced:
    """Advanced reconnaissance module for BlackSentinel Strike"""

    def __init__(self, callback=None):
        self.callback = callback
        self.results = {}

    def log(self, message, level="info"):
        if self.callback:
            self.callback(message, level)

    # ───────────────────────────────────────────────────────────
    #  Helper
    # ───────────────────────────────────────────────────────────
    def run_command(self, cmd, timeout=30):
        """Run a shell command safely, return combined output string."""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            output = result.stdout
            if result.stderr:
                output += "\n[STDERR]\n" + result.stderr
            return output.strip()
        except subprocess.TimeoutExpired:
            return f"[TIMEOUT] Command timed out after {timeout}s"
        except Exception as e:
            return f"[ERROR] {e}"

    # ═══════════════════════════════════════════════════════════
    #  OSINT  (15 methods)
    # ═══════════════════════════════════════════════════════════

    def osint_subdomain_enum(self, target):
        """Enumerate subdomains using amass."""
        self.log(f"[OSINT] Subdomain enumeration via amass: {target}", "info")
        try:
            amass = _require_tool("amass")
        except FileNotFoundError as e:
            return str(e)
        cmd = f"{amass} enum -passive -d {target}"
        return self.run_command(cmd, timeout=120)

    def osint_subfinder(self, target):
        """Enumerate subdomains using subfinder."""
        self.log(f"[OSINT] Subdomain enumeration via subfinder: {target}", "info")
        try:
            subfinder = _require_tool("subfinder")
        except FileNotFoundError as e:
            return str(e)
        cmd = f"{subfinder} -d {target} -silent"
        return self.run_command(cmd, timeout=90)

    def osint_harvest_emails(self, target):
        """Harvest emails and subdomains using theHarvester."""
        self.log(f"[OSINT] Email harvesting via theHarvester: {target}", "info")
        try:
            harvester = _require_tool("theHarvester")
        except FileNotFoundError as e:
            return str(e)
        cmd = f"{harvester} -d {target} -b all"
        return self.run_command(cmd, timeout=120)

    def osint_whois_lookup(self, target):
        """Perform WHOIS lookup on target."""
        self.log(f"[OSINT] WHOIS lookup: {target}", "info")
        try:
            _require_tool("whois")
        except FileNotFoundError as e:
            return str(e)
        cmd = f"whois {target}"
        return self.run_command(cmd, timeout=30)

    def osint_dns_history(self, target):
        """Query DNS history using dnsrecon."""
        self.log(f"[OSINT] DNS history lookup via dnsrecon: {target}", "info")
        try:
            dnsrecon = _require_tool("dnsrecon")
        except FileNotFoundError as e:
            return str(e)
        cmd = f"{dnsrecon} -d {target} -z"
        return self.run_command(cmd, timeout=60)

    def osint_shodan_query(self, target):
        """Query Shodan for exposed services (requires SHODAN_API_KEY)."""
        self.log(f"[OSINT] Shodan query: {target}", "info")
        try:
            import os

            api_key = os.environ.get("SHODAN_API_KEY", "")
            if not api_key:
                return "[ERROR] SHODAN_API_KEY environment variable not set"
            cmd = f'curl -s "https://api.shodan.io/shodan/host/search?key={api_key}&q=hostname:{target}"'
            return self.run_command(cmd, timeout=30)
        except Exception as e:
            return f"[ERROR] {e}"

    def osint_crt_sh(self, target):
        """Query crt.sh for certificate transparency logs."""
        self.log(f"[OSINT] Certificate transparency lookup: {target}", "info")
        url = f"https://crt.sh/?q=%25.{target}&output=json"
        cmd = f'curl -s "{url}"'
        output = self.run_command(cmd, timeout=30)
        if output.startswith("[ERROR]") or output.startswith("[TIMEOUT]"):
            return output
        try:
            certs = json.loads(output)
            entries = []
            for cert in certs:
                name = cert.get("name_value", "")
                issuer = cert.get("issuer_name", "")
                not_after = cert.get("not_after", "")
                entries.append(f"{name} | Issuer: {issuer} | Expires: {not_after}")
            return "\n".join(entries) if entries else "No certificate entries found"
        except json.JSONDecodeError:
            return output

    def osint_waybackurls(self, target):
        """Retrieve archived URLs from Wayback Machine."""
        self.log(f"[OSINT] Wayback Machine URLs: {target}", "info")
        url = f"https://web.archive.org/cdx/search/cdx?url={target}/*&output=json&fl=timestamp,original&collapse=urlkey&limit=500"
        cmd = f'curl -s "{url}"'
        output = self.run_command(cmd, timeout=30)
        if output.startswith("[ERROR]") or output.startswith("[TIMEOUT]"):
            return output
        try:
            data = json.loads(output)
            urls = [row[1] for row in data[1:]] if len(data) > 1 else []
            return "\n".join(urls) if urls else "No archived URLs found"
        except json.JSONDecodeError:
            return output

    def osint_social_media(self, target):
        """Search for social media profiles related to target."""
        self.log(f"[OSINT] Social media search: {target}", "info")
        sites = [
            "twitter.com",
            "linkedin.com",
            "facebook.com",
            "instagram.com",
            "github.com",
            "reddit.com",
            "youtube.com",
        ]
        results = []
        for site in sites:
            cmd = f'curl -s -o /dev/null -w "%{{http_code}}" "https://{site}/{target}"'
            code = self.run_command(cmd, timeout=10)
            status = "FOUND" if code.strip() == "200" else code.strip()
            results.append(f"{site}/{target} -> {status}")
        return "\n".join(results)

    def osint_github_dork(self, target):
        """Search GitHub for leaked secrets related to target."""
        self.log(f"[OSINT] GitHub dork search: {target}", "info")
        queries = [
            f'"{target}" password',
            f'"{target}" api_key',
            f'"{target}" secret',
            f'"{target}" token',
            f'"{target}" credentials',
        ]
        results = []
        for q in queries:
            encoded = q.replace(" ", "+").replace('"', "%22")
            cmd = f'curl -s "https://github.com/search?q={encoded}&type=code" -o /dev/null -w "%{{http_code}}"'
            code = self.run_command(cmd, timeout=10)
            results.append(f"Query: {q} -> HTTP {code.strip()}")
        return "\n".join(results)

    def osint_dns_dumpster(self, target):
        """Query DNSDumpster for DNS recon."""
        self.log(f"[OSINT] DNSDumpster lookup: {target}", "info")
        cmd = f'curl -s "https://dnsdumpster.com/" -d "targetip={target}" -L'
        output = self.run_command(cmd, timeout=30)
        if output.startswith("[ERROR]") or output.startswith("[TIMEOUT]"):
            return output
        records = []
        for line in output.splitlines():
            line = line.strip()
            if any(kw in line.lower() for kw in ["a record", "aaaa record", "mx record", "ns record", "txt record"]):
                records.append(line)
        return "\n".join(records) if records else output

    def osint_wappalyzer(self, target):
        """Detect technologies on target website using whatweb."""
        self.log(f"[OSINT] Technology detection via whatweb: {target}", "info")
        try:
            whatweb = _require_tool("whatweb")
        except FileNotFoundError as e:
            return str(e)
        url = target if target.startswith("http") else f"http://{target}"
        cmd = f"{whatweb} -a 3 --color=never {url}"
        return self.run_command(cmd, timeout=30)

    def osint_leak_check(self, target):
        """Check for known breaches associated with target domain."""
        self.log(f"[OSINT] Breach check: {target}", "info")
        try:
            haveibeen = _require_tool("hibp")
            cmd = f"{haveibeen} breaches {target}"
            return self.run_command(cmd, timeout=30)
        except FileNotFoundError:
            url = f"https://haveibeenpwned.com/api/v3/breaches/{target}"
            cmd = f'curl -s -H "hibp-api-key: NONE" "{url}"'
            return self.run_command(cmd, timeout=15)

    def osint_ip_geolocate(self, target):
        """Geolocate an IP address using ipinfo.io."""
        self.log(f"[OSINT] IP geolocation: {target}", "info")
        cmd = f'curl -s "https://ipinfo.io/{target}/json"'
        output = self.run_command(cmd, timeout=15)
        if output.startswith("[ERROR]") or output.startswith("[TIMEOUT]"):
            return output
        try:
            data = json.loads(output)
            fields = ["ip", "city", "region", "country", "loc", "org", "timezone"]
            return "\n".join(f"{k}: {data.get(k, 'N/A')}" for k in fields if k in data)
        except json.JSONDecodeError:
            return output

    def osint_dig_records(self, target):
        """Query all DNS record types for target."""
        self.log(f"[OSINT] Full DNS record lookup via dig: {target}", "info")
        try:
            _require_tool("dig")
        except FileNotFoundError as e:
            return str(e)
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV"]
        results = []
        for rtype in record_types:
            cmd = f"dig +short {target} {rtype}"
            output = self.run_command(cmd, timeout=10)
            if output and not output.startswith("[ERROR]") and not output.startswith("[TIMEOUT]"):
                results.append(f"[{rtype}]\n{output}")
        return "\n\n".join(results) if results else "No DNS records found"

    def osint_amass_active(self, target):
        """Active subdomain enumeration using amass intel."""
        self.log(f"[OSINT] Active recon via amass intel: {target}", "info")
        try:
            amass = _require_tool("amass")
        except FileNotFoundError as e:
            return str(e)
        cmd = f"{amass} intel -active -d {target}"
        return self.run_command(cmd, timeout=180)

    # ═══════════════════════════════════════════════════════════
    #  PASSIVE RECON  (10 methods)
    # ═══════════════════════════════════════════════════════════

    def passive_dns_enum(self, target):
        """Passive DNS enumeration using multiple sources."""
        self.log(f"[PASSIVE] DNS enumeration: {target}", "info")
        try:
            _require_tool("dig")
        except FileNotFoundError as e:
            return str(e)
        sources = {
            "Google": f"dig +short {target} @8.8.8.8",
            "Cloudflare": f"dig +short {target} @1.1.1.1",
            "Quad9": f"dig +short {target} @9.9.9.9",
            "OpenDNS": f"dig +short {target} @208.67.222.222",
        }
        results = []
        for name, cmd in sources.items():
            output = self.run_command(cmd, timeout=10)
            results.append(f"[{name}]\n{output}")
        return "\n\n".join(results)

    def passive_reverse_dns(self, target):
        """Perform reverse DNS lookup."""
        self.log(f"[PASSIVE] Reverse DNS lookup: {target}", "info")
        try:
            _require_tool("dig")
        except FileNotFoundError as e:
            return str(e)
        cmd = f"dig +short -x {target}"
        output = self.run_command(cmd, timeout=15)
        return output if output and not output.startswith("[ERROR]") else f"No PTR record for {target}"

    def passive_whois_netblock(self, target):
        """WHOIS lookup to extract netblock and ASN information."""
        self.log(f"[PASSIVE] WHOIS netblock lookup: {target}", "info")
        try:
            _require_tool("whois")
        except FileNotFoundError as e:
            return str(e)
        output = self.run_command(f"whois {target}", timeout=30)
        if output.startswith("[ERROR]") or output.startswith("[TIMEOUT]"):
            return output
        interesting = []
        keywords = ["NetRange", "CIDR", "OrgName", "OrgId", "NetName", "aut-num", "descr", "route", "origin"]
        for line in output.splitlines():
            if any(kw in line for kw in keywords):
                interesting.append(line.strip())
        return "\n".join(interesting) if interesting else output

    def passive_ssl_cert_info(self, target):
        """Extract SSL/TLS certificate information."""
        self.log(f"[PASSIVE] SSL certificate info: {target}", "info")
        try:
            _require_tool("openssl")
        except FileNotFoundError as e:
            return str(e)
        host = target.split("//")[-1].split("/")[0].split(":")[0]
        cmd = f"echo | openssl s_client -servername {host} -connect {host}:443 2>/dev/null | openssl x509 -noout -subject -issuer -dates -serial -fingerprint"
        output = self.run_command(cmd, timeout=15)
        return output if output and not output.startswith("[ERROR]") else f"No SSL certificate info for {target}"

    def passive_mx_enum(self, target):
        """Enumerate mail exchange servers."""
        self.log(f"[PASSIVE] MX enumeration: {target}", "info")
        try:
            _require_tool("dig")
        except FileNotFoundError as e:
            return str(e)
        cmd = f"dig +short MX {target}"
        output = self.run_command(cmd, timeout=10)
        if output and not output.startswith("[ERROR]") and not output.startswith("[TIMEOUT]"):
            records = []
            for line in output.splitlines():
                parts = line.strip().split()
                if len(parts) >= 2:
                    records.append(f"Priority: {parts[0]} | Server: {parts[1]}")
            return "\n".join(records) if records else output
        return f"No MX records found for {target}"

    def passive_spf_check(self, target):
        """Check SPF record for target domain."""
        self.log(f"[PASSIVE] SPF record check: {target}", "info")
        try:
            _require_tool("dig")
        except FileNotFoundError as e:
            return str(e)
        cmd = f"dig +short TXT {target}"
        output = self.run_command(cmd, timeout=10)
        if output.startswith("[ERROR]") or output.startswith("[TIMEOUT]"):
            return output
        spf_lines = [line.strip('"') for line in output.splitlines() if "v=spf1" in line]
        if spf_lines:
            return "SPF Record Found:\n" + "\n".join(spf_lines)
        return "No SPF record found"

    def passive_dmarc_check(self, target):
        """Check DMARC record for target domain."""
        self.log(f"[PASSIVE] DMARC record check: {target}", "info")
        try:
            _require_tool("dig")
        except FileNotFoundError as e:
            return str(e)
        cmd = f"dig +short TXT _dmarc.{target}"
        output = self.run_command(cmd, timeout=10)
        if output.startswith("[ERROR]") or output.startswith("[TIMEOUT]"):
            return output
        dmarc_lines = [line.strip('"') for line in output.splitlines() if "v=DMARC1" in line]
        if dmarc_lines:
            return "DMARC Record Found:\n" + "\n".join(dmarc_lines)
        return "No DMARC record found"

    def passive_dkim_check(self, target, selectors=None):
        """Check common DKIM selectors for target domain."""
        self.log(f"[PASSIVE] DKIM record check: {target}", "info")
        try:
            _require_tool("dig")
        except FileNotFoundError as e:
            return str(e)
        if selectors is None:
            selectors = [
                "default",
                "google",
                "selector1",
                "selector2",
                "dkim",
                "s1",
                "s2",
                "mandrill",
                "k1",
                "everlytickey1",
                "everlytickey2",
                "mail",
            ]
        results = []
        for sel in selectors:
            cmd = f"dig +short TXT {sel}._domainkey.{target}"
            output = self.run_command(cmd, timeout=8)
            if (
                output
                and not output.startswith("[ERROR]")
                and not output.startswith("[TIMEOUT]")
                and "no servers" not in output.lower()
            ):
                results.append(f"[{sel}._domainkey] {output.strip()}")
        return "\n".join(results) if results else "No DKIM records found"

    def passive_ns_history(self, target):
        """Retrieve historical nameserver changes."""
        self.log(f"[PASSIVE] Nameserver history: {target}", "info")
        try:
            _require_tool("dig")
        except FileNotFoundError as e:
            return str(e)
        cmd = f"dig +short NS {target}"
        output = self.run_command(cmd, timeout=10)
        if output.startswith("[ERROR]") or output.startswith("[TIMEOUT]"):
            return output
        servers = [line.strip() for line in output.splitlines() if line.strip()]
        if servers:
            return "Current Nameservers:\n" + "\n".join(servers)
        return "No NS records found"

    def passive_robots_sitemap(self, target):
        """Fetch robots.txt and sitemap.xml from target."""
        self.log(f"[PASSIVE] Robots.txt & Sitemap: {target}", "info")
        url = target if target.startswith("http") else f"http://{target}"
        url = url.rstrip("/")
        results = []
        for path in ["/robots.txt", "/sitemap.xml"]:
            cmd = f'curl -sL -o /dev/null -w "%{{http_code}}" "{url}{path}"'
            code = self.run_command(cmd, timeout=10).strip()
            cmd2 = f'curl -sL "{url}{path}" 2>/dev/null | head -c 4096'
            body = self.run_command(cmd2, timeout=10)
            results.append(f"[{path}] HTTP {code}\n{body}")
        return "\n\n".join(results)

    # ═══════════════════════════════════════════════════════════
    #  ACTIVE RECON  (10 methods)
    # ═══════════════════════════════════════════════════════════

    def active_nmap_full(self, target):
        """Full TCP port scan with nmap (all 65535 ports)."""
        self.log(f"[ACTIVE] Full port scan: {target}", "info")
        try:
            nmap = _require_tool("nmap")
        except FileNotFoundError as e:
            return str(e)
        cmd = f"{nmap} -p- -T4 --open -Pn {target}"
        return self.run_command(cmd, timeout=600)

    def active_nmap_service(self, target, ports="1-1000"):
        """Service and version detection scan."""
        self.log(f"[ACTIVE] Service detection scan: {target}", "info")
        try:
            nmap = _require_tool("nmap")
        except FileNotFoundError as e:
            return str(e)
        cmd = f"{nmap} -sV -sC -p {ports} -T4 --open {target}"
        return self.run_command(cmd, timeout=300)

    def active_nmap_scripts(self, target, script_cat="default"):
        """Run nmap NSE scripts by category."""
        self.log(f"[ACTIVE] NSE script scan ({script_cat}): {target}", "info")
        try:
            nmap = _require_tool("nmap")
        except FileNotFoundError as e:
            return str(e)
        cmd = f"{nmap} --script {script_cat} -T4 {target}"
        return self.run_command(cmd, timeout=600)

    def active_udp_scan(self, target):
        """Top 100 UDP port scan."""
        self.log(f"[ACTIVE] UDP scan: {target}", "info")
        try:
            nmap = _require_tool("nmap")
        except FileNotFoundError as e:
            return str(e)
        cmd = f"{nmap} -sU --top-ports 100 -T4 --open {target}"
        return self.run_command(cmd, timeout=300)

    def active_vuln_scan(self, target):
        """Nmap vulnerability scan scripts."""
        self.log(f"[ACTIVE] Vulnerability scan: {target}", "info")
        try:
            nmap = _require_tool("nmap")
        except FileNotFoundError as e:
            return str(e)
        cmd = f"{nmap} --script vuln -T4 {target}"
        return self.run_command(cmd, timeout=600)

    def active_web_screenshot(self, target):
        """Take screenshot of target website using cutycapt or chromium."""
        self.log(f"[ACTIVE] Web screenshot: {target}", "info")
        url = target if target.startswith("http") else f"http://{target}"
        try:
            chromium = _require_tool("chromium") or _require_tool("chromium-browser") or _require_tool("google-chrome")
            out = f"/tmp/screenshot_{target.replace('/', '_').replace(':', '_')}.png"
            cmd = (
                f'{chromium} --headless --disable-gpu --screenshot="{out}" --window-size=1920,1080 "{url}" 2>/dev/null'
            )
            self.run_command(cmd, timeout=30)
            return f"Screenshot saved to {out}"
        except FileNotFoundError:
            pass
        try:
            cutycapt = _require_tool("cutycapt")
            out = f"/tmp/screenshot_{target.replace('/', '_').replace(':', '_')}.png"
            cmd = f'{cutycapt} --url="{url}" --out="{out}"'
            self.run_command(cmd, timeout=30)
            return f"Screenshot saved to {out}"
        except FileNotFoundError:
            return "[ERROR] No screenshot tool found (chromium or cutycapt)"

    def active_nikto(self, target):
        """Run Nikto web server scanner."""
        self.log(f"[ACTIVE] Nikto scan: {target}", "info")
        try:
            nikto = _require_tool("nikto")
        except FileNotFoundError as e:
            return str(e)
        url = target if target.startswith("http") else f"http://{target}"
        cmd = f"{nikto} -h {url} -Tuning x6"
        return self.run_command(cmd, timeout=120)

    def active_http_headers(self, target):
        """Enumerate HTTP response headers."""
        self.log(f"[ACTIVE] HTTP header enumeration: {target}", "info")
        url = target if target.startswith("http") else f"http://{target}"
        cmd = f'curl -sI "{url}"'
        output = self.run_command(cmd, timeout=15)
        if output.startswith("[ERROR]") or output.startswith("[TIMEOUT]"):
            return output
        security_headers = [
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection",
            "Content-Security-Policy",
            "X-Permitted-Cross-Domain-Policies",
            "Referrer-Policy",
            "Permissions-Policy",
        ]
        found = []
        missing = []
        for header in security_headers:
            if header.lower() in output.lower():
                for line in output.splitlines():
                    if header.lower() in line.lower():
                        found.append(line.strip())
            else:
                missing.append(header)
        result = "=== Found Headers ===\n" + "\n".join(found) if found else "=== Found Headers ===\nNone"
        result += "\n\n=== Missing Security Headers ===\n" + "\n".join(missing) if missing else ""
        result += "\n\n=== Raw Response ===\n" + output
        return result

    def active_web_technologies(self, target):
        """Detect web technologies using whatweb with aggressive mode."""
        self.log(f"[ACTIVE] Technology fingerprinting: {target}", "info")
        try:
            whatweb = _require_tool("whatweb")
        except FileNotFoundError as e:
            return str(e)
        url = target if target.startswith("http") else f"http://{target}"
        cmd = f"{whatweb} -a 4 --color=never {url}"
        return self.run_command(cmd, timeout=30)

    def active_http_methods(self, target):
        """Enumerate allowed HTTP methods."""
        self.log(f"[ACTIVE] HTTP methods enumeration: {target}", "info")
        url = target if target.startswith("http") else f"http://{target}"
        cmd = f'curl -s -X OPTIONS -I "{url}" 2>/dev/null'
        output = self.run_command(cmd, timeout=15)
        if "Allow" in output:
            for line in output.splitlines():
                if "Allow" in line:
                    return f"Allowed HTTP Methods:\n{line.strip()}"
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "TRACE"]
        results = []
        for method in methods:
            cmd2 = f'curl -s -o /dev/null -w "%{{http_code}}" -X {method} "{url}"'
            code = self.run_command(cmd2, timeout=10).strip()
            if code and code not in ["000", "405", "501"]:
                results.append(f"{method}: {code}")
        return "\n".join(results) if results else f"Standard methods check:\n{output}"

    # ═══════════════════════════════════════════════════════════
    #  NETWORK RECON  (5 methods)
    # ═══════════════════════════════════════════════════════════

    def net_discover_hosts(self, target):
        """Discover live hosts on a network range using nmap."""
        self.log(f"[NET] Host discovery: {target}", "info")
        try:
            nmap = _require_tool("nmap")
        except FileNotFoundError as e:
            return str(e)
        cmd = f"{nmap} -sn -T4 {target}"
        return self.run_command(cmd, timeout=120)

    def net_traceroute(self, target):
        """Perform traceroute to target."""
        self.log(f"[NET] Traceroute: {target}", "info")
        try:
            import platform

            system = platform.system()
            if system == "Darwin":
                cmd = f"traceroute -m 30 {target}"
            else:
                cmd = f"traceroute -m 30 -w 3 {target}"
            return self.run_command(cmd, timeout=60)
        except Exception as e:
            return f"[ERROR] {e}"

    def net_route_map(self, target):
        """Map network routes to target."""
        self.log(f"[NET] Route mapping: {target}", "info")
        try:
            _require_tool("traceroute")
        except FileNotFoundError as e:
            return str(e)
        cmd = f"traceroute -n -w 2 {target}"
        output = self.run_command(cmd, timeout=60)
        if output.startswith("[ERROR]") or output.startswith("[TIMEOUT]"):
            return output
        hops = []
        for line in output.splitlines():
            match = re.match(r"\s*(\d+)\s+(.+)", line)
            if match:
                hops.append(f"Hop {match.group(1)}: {match.group(2).strip()}")
        return "\n".join(hops) if hops else output

    def net_banner_grab(self, target, ports=None):
        """Grab banners from common ports."""
        self.log(f"[NET] Banner grabbing: {target}", "info")
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080, 8443]
        results = []
        for port in ports:
            cmd = "bash -c 'echo  | timeout 5 nc -w 3 {target} {port} 2>/dev/null'"
            banner = self.run_command(cmd, timeout=8).strip()
            if banner and not banner.startswith("[ERROR]") and not banner.startswith("[TIMEOUT]"):
                first_line = banner.splitlines()[0] if banner else ""
                results.append(f"Port {port}: {first_line}")
        return "\n".join(results) if results else "No banners captured"

    def net_tcp_connect(self, target, ports=None):
        """Test TCP connectivity to target ports."""
        self.log(f"[NET] TCP connectivity test: {target}", "info")
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080, 8443]
        results = []
        for port in ports:
            cmd = f"bash -c '</dev/null >/dev/null 2>&1 nc -w 2 -z {target} {port} && echo OPEN || echo CLOSED'"
            output = self.run_command(cmd, timeout=5).strip()
            if "OPEN" in output:
                results.append(f"Port {port}: OPEN")
        return "\n".join(results) if results else "All tested ports are closed or filtered"

    # ═══════════════════════════════════════════════════════════
    #  CONVENIENCE: Run all categories
    # ═══════════════════════════════════════════════════════════

    def run_osint(self, target):
        """Run all OSINT methods and return combined results."""
        self.log(f"Running full OSINT recon on {target}", "info")
        results = {}
        methods = [
            ("subfinder", self.osint_subfinder),
            ("whois", self.osint_whois_lookup),
            ("crt_sh", self.osint_crt_sh),
            ("wayback", self.osint_waybackurls),
            ("dns_records", self.osint_dig_records),
            ("email_harvest", self.osint_harvest_emails),
            ("social_media", self.osint_social_media),
            ("tech_detect", self.osint_wappalyzer),
            ("ip_geolocate", self.osint_ip_geolocate),
            ("spf", self.osint_spf_check),
            ("dmarc", self.osint_dmarc_check),
            ("dkim", self.osint_dkim_check),
            ("dns_history", self.osint_dns_history),
            ("dns_dumpster", self.osint_dns_dumpster),
        ]
        for name, method in methods:
            try:
                results[name] = method(target)
            except Exception as e:
                results[name] = f"[ERROR] {e}"
        self.results["osint"] = results
        summary = "\n".join(f"=== {k.upper()} ===\n{v}" for k, v in results.items())
        self.log(f"OSINT recon complete for {target}", "success")
        return summary

    def run_passive(self, target):
        """Run all passive recon methods and return combined results."""
        self.log(f"Running full passive recon on {target}", "info")
        results = {}
        methods = [
            ("dns_enum", self.passive_dns_enum),
            ("reverse_dns", self.passive_reverse_dns),
            ("whois_netblock", self.passive_whois_netblock),
            ("ssl_cert", self.passive_ssl_cert_info),
            ("mx_enum", self.passive_mx_enum),
            ("spf", self.passive_spf_check),
            ("dmarc", self.passive_dmarc_check),
            ("dkim", self.passive_dkim_check),
            ("ns_history", self.passive_ns_history),
            ("robots", self.passive_robots_sitemap),
        ]
        for name, method in methods:
            try:
                results[name] = method(target)
            except Exception as e:
                results[name] = f"[ERROR] {e}"
        self.results["passive"] = results
        summary = "\n".join(f"=== {k.upper()} ===\n{v}" for k, v in results.items())
        self.log(f"Passive recon complete for {target}", "success")
        return summary

    def run_active(self, target):
        """Run all active recon methods and return combined results."""
        self.log(f"Running full active recon on {target}", "info")
        results = {}
        methods = [
            ("nmap_full", self.active_nmap_full),
            ("nmap_service", self.active_nmap_service),
            ("nmap_scripts", self.active_nmap_scripts),
            ("udp_scan", self.active_udp_scan),
            ("vuln_scan", self.active_vuln_scan),
            ("http_headers", self.active_http_headers),
            ("http_methods", self.active_http_methods),
            ("tech_fingerprint", self.active_web_technologies),
        ]
        for name, method in methods:
            try:
                results[name] = method(target)
            except Exception as e:
                results[name] = f"[ERROR] {e}"
        self.results["active"] = results
        summary = "\n".join(f"=== {k.upper()} ===\n{v}" for k, v in results.items())
        self.log(f"Active recon complete for {target}", "success")
        return summary

    def run_network(self, target):
        """Run all network recon methods and return combined results."""
        self.log(f"Running full network recon on {target}", "info")
        results = {}
        methods = [
            ("discover", self.net_discover_hosts),
            ("traceroute", self.net_traceroute),
            ("route_map", self.net_route_map),
            ("banner_grab", self.net_banner_grab),
            ("tcp_connect", self.net_tcp_connect),
        ]
        for name, method in methods:
            try:
                results[name] = method(target)
            except Exception as e:
                results[name] = f"[ERROR] {e}"
        self.results["network"] = results
        summary = "\n".join(f"=== {k.upper()} ===\n{v}" for k, v in results.items())
        self.log(f"Network recon complete for {target}", "success")
        return summary

    def run_all(self, target):
        """Run complete advanced reconnaissance suite."""
        self.log(f"Starting full advanced recon on {target}", "info")
        sections = {
            "OSINT": self.run_osint,
            "PASSIVE": self.run_passive,
            "ACTIVE": self.run_active,
            "NETWORK": self.run_network,
        }
        full_report = []
        for section_name, runner in sections.items():
            try:
                report = runner(target)
                full_report.append(f"{'=' * 60}\n  {section_name} RECON\n{'=' * 60}\n{report}")
            except Exception as e:
                full_report.append(f"{'=' * 60}\n  {section_name} RECON\n{'=' * 60}\n[ERROR] {e}")
        self.results["full_report"] = "\n\n".join(full_report)
        self.log(f"Full advanced recon complete for {target}", "success")
        return self.results["full_report"]

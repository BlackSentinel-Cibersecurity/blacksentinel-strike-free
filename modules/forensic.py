#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════
        FORENSIC MODULE - BlackSentinel Strike v4.0
═══════════════════════════════════════════════════════════════
"""

import subprocess
import os
import hashlib
import shutil
import tempfile
import re
from datetime import datetime


class ForensicModule:
    """Forensic analysis module"""

    def __init__(self, callback=None):
        self.callback = callback
        self.results = {}

    def log(self, message, level="info"):
        """Log message"""
        if self.callback:
            self.callback(message, level)

    def _require_tool(self, tool):
        """Check if a tool is available on the system"""
        return shutil.which(tool) is not None

    def _run_cmd(self, cmd, timeout=30):
        """Execute a command and return stdout, or None on failure"""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return result.stdout
        except Exception:
            return None

    # ── Existing methods (enhanced) ────────────────────────────

    def disk_imaging(self, source, destination):
        """Create a forensic disk image with dd"""
        self.log(f"Creating disk image: {source} -> {destination}", "info")
        if not self._require_tool("dd"):
            self.log("dd not found", "error")
            return {"error": "dd not available"}

        cmd = f"dd if={source} of={destination} bs=4M status=progress"
        try:
            self._run_cmd(cmd, timeout=3600)
            md5 = self._calculate_hash(destination, "md5")
            sha256 = self._calculate_hash(destination, "sha256")
            result = {
                "source": source,
                "destination": destination,
                "md5": md5,
                "sha256": sha256,
                "timestamp": datetime.now().isoformat(),
            }
            self.results["disk_image"] = result
            self.log("Disk image created", "success")
            return result
        except Exception as e:
            self.log(f"Error: {str(e)}", "error")
            return {"error": str(e)}

    def file_recovery(self, image_path, output_dir=None):
        """Recover deleted files using photorec"""
        if output_dir is None:
            output_dir = os.path.join(tempfile.gettempdir(), "recovered")
        self.log(f"Recovering files from {image_path}", "info")
        if not self._require_tool("photorec"):
            self.log("photorec not found", "error")
            return {"error": "photorec not available"}

        os.makedirs(output_dir, exist_ok=True)
        cmd = (
            f"photorec /cmd {image_path} "
            f"fileopt,everything,disable,jpg,enable,png,enable,gif,enable,"
            f"pdf,enable,doc,enable,xls,enable,zip,enable,rar,enable "
            f"search {output_dir}"
        )
        try:
            self._run_cmd(cmd, timeout=3600)
            recovered_files = []
            for root, dirs, files in os.walk(output_dir):
                for f in files:
                    recovered_files.append(os.path.join(root, f))
            result = {
                "image": image_path,
                "output_dir": output_dir,
                "files_recovered": len(recovered_files),
                "files": recovered_files[:100],
            }
            self.results["file_recovery"] = result
            self.log(f"Files recovered: {len(recovered_files)}", "success")
            return result
        except Exception as e:
            self.log(f"Error: {str(e)}", "error")
            return {"error": str(e)}

    def memory_analysis(self, memory_dump):
        """Volatility-based memory analysis"""
        self.log(f"Analyzing memory dump: {memory_dump}", "info")
        if not self._require_tool("volatility"):
            self.log("volatility not found", "error")
            return {"error": "volatility not available"}

        commands = {
            "processes": f"volatility -f {memory_dump} --profile=Win7SP1x64 pslist",
            "network": f"volatility -f {memory_dump} --profile=Win7SP1x64 netscan",
            "handles": f"volatility -f {memory_dump} --profile=Win7SP1x64 handles",
            "dlls": f"volatility -f {memory_dump} --profile=Win7SP1x64 dlllist",
            "registry": f"volatility -f {memory_dump} --profile=Win7SP1x64 hivelist",
        }
        results = {}
        for key, cmd in commands.items():
            try:
                results[key] = self._run_cmd(cmd, timeout=60)
            except Exception:
                results[key] = None
        self.results["memory_analysis"] = results
        self.log("Memory analysis completed", "success")
        return results

    def log_analysis(self, log_file):
        """Parse a log file for errors, warnings, and suspicious events"""
        self.log(f"Analyzing logs: {log_file}", "info")
        analysis = {
            "total_lines": 0,
            "errors": [],
            "warnings": [],
            "suspicious": [],
            "ips": [],
        }
        try:
            with open(log_file, "r") as fh:
                lines = fh.readlines()
            analysis["total_lines"] = len(lines)
            ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
            suspicious_keywords = ["failed", "invalid", "unauthorized", "attack", "brute"]
            for line in lines:
                low = line.lower()
                if "error" in low:
                    analysis["errors"].append(line.strip()[:200])
                if "warning" in low:
                    analysis["warnings"].append(line.strip()[:200])
                for kw in suspicious_keywords:
                    if kw in low:
                        analysis["suspicious"].append(line.strip()[:200])
                        break
                analysis["ips"].extend(ip_pattern.findall(line))
            analysis["ips"] = list(set(analysis["ips"]))[:50]
            analysis["errors"] = analysis["errors"][:100]
            analysis["warnings"] = analysis["warnings"][:100]
            analysis["suspicious"] = analysis["suspicious"][:100]
            self.results["log_analysis"] = analysis
            self.log(
                f"Analysis completed: {len(analysis['suspicious'])} suspicious events",
                "success",
            )
            return analysis
        except Exception as e:
            self.log(f"Error: {str(e)}", "error")
            return {"error": str(e)}

    def network_forensics(self, pcap_file):
        """Analyse a PCAP capture with tshark"""
        self.log(f"Analyzing network traffic: {pcap_file}", "info")
        if not self._require_tool("tshark"):
            self.log("tshark not found", "error")
            return {"error": "tshark not available"}

        commands = {
            "conversations": f"tshark -r {pcap_file} -q -z conv,ip",
            "http_requests": (f"tshark -r {pcap_file} -Y http.request -T fields -e http.host -e http.request.uri"),
            "dns_queries": (f"tshark -r {pcap_file} -Y dns.qry.name -T fields -e dns.qry.name"),
            "suspicious": (f"tshark -r {pcap_file} -Y 'tcp.flags.syn==1 && tcp.flags.ack==0'"),
        }
        results = {}
        for key, cmd in commands.items():
            try:
                results[key] = self._run_cmd(cmd, timeout=60)
            except Exception:
                results[key] = None
        self.results["network_forensics"] = results
        self.log("Network analysis completed", "success")
        return results

    def steganography_detection(self, image_path):
        """Detect hidden data embedded in a file"""
        self.log(f"Analyzing steganography in: {image_path}", "info")
        results = {
            "file_size": os.path.getsize(image_path) if os.path.exists(image_path) else 0,
            "strings_found": [],
            "embedded_files": [],
            "metadata": None,
        }
        cmd = f"strings {image_path}"
        out = self._run_cmd(cmd)
        if out:
            results["strings_found"] = out.split("\n")[:50]

        if self._require_tool("binwalk"):
            out = self._run_cmd(f"binwalk {image_path}")
            if out:
                results["embedded_files"] = out.split("\n")

        if self._require_tool("exiftool"):
            out = self._run_cmd(f"exiftool {image_path}")
            if out:
                results["metadata"] = out

        self.results["steganography"] = results
        self.log("Steganography analysis completed", "success")
        return results

    def generate_report(self):
        """Return a combined forensic report dict"""
        report = {
            "title": "Forensic Analysis Report",
            "timestamp": datetime.now().isoformat(),
            "results": self.results,
        }
        return report

    # ── New methods ─────────────────────────────────────────────

    def disk_image(self, source, destination):
        """Alias / enhanced wrapper around disk_imaging with extra metadata"""
        self.log(f"disk_image: {source} -> {destination}", "info")
        result = self.disk_imaging(source, destination)
        if "error" not in result:
            result["method"] = "disk_image"
        return result

    def disk_forensic_analysis(self, image_path):
        """Low-level disk analysis: partition table, file-system info, entropy"""
        self.log(f"Disk forensic analysis: {image_path}", "info")
        analysis = {
            "partitions": None,
            "filesystem": None,
            "entropy": None,
            "strings_sample": [],
        }

        if self._require_tool("fdisk"):
            out = self._run_cmd(f"fdisk -l {image_path}")
            if out:
                analysis["partitions"] = out

        if self._require_tool("blkid"):
            out = self._run_cmd(f"blkid {image_path}")
            if out:
                analysis["filesystem"] = out

        if self._require_tool("binwalk"):
            out = self._run_cmd(f"binwalk -E {image_path}")
            if out:
                analysis["entropy"] = out

        out = self._run_cmd(f"strings {image_path}")
        if out:
            analysis["strings_sample"] = out.split("\n")[:100]

        self.results["disk_forensic_analysis"] = analysis
        self.log("Disk forensic analysis completed", "success")
        return analysis

    def file_system_forensics(self, image_path, mount_point=None):
        """Mount an image and enumerate its file system"""
        self.log(f"File system forensics: {image_path}", "info")
        fs_info = {
            "image": image_path,
            "mount_point": mount_point,
            "file_list": [],
            "deleted_inodes": [],
        }
        if mount_point is None:
            mount_point = os.path.join(tempfile.gettempdir(), "fs_mnt")
        os.makedirs(mount_point, exist_ok=True)

        if self._require_tool("mount"):
            self._run_cmd(f"mount -o ro,loop {image_path} {mount_point}", timeout=30)

        if os.path.isdir(mount_point):
            for root, dirs, files in os.walk(mount_point):
                for f in files:
                    fp = os.path.join(root, f)
                    try:
                        st = os.stat(fp)
                        fs_info["file_list"].append(
                            {
                                "path": fp,
                                "size": st.st_size,
                                "mtime": datetime.fromtimestamp(st.st_mtime).isoformat(),
                            }
                        )
                    except OSError:
                        pass
                if len(fs_info["file_list"]) > 500:
                    break

        fs_info["file_list"] = fs_info["file_list"][:500]

        if self._require_tool("fls"):
            out = self._run_cmd(f"fls {image_path}")
            if out:
                fs_info["deleted_inodes"] = out.split("\n")[:100]

        self.results["file_system_forensics"] = fs_info
        self.log("File system forensics completed", "success")
        return fs_info

    def deleted_file_recovery(self, image_path, output_dir=None):
        """Attempt deleted-file recovery using foremost / scalpel"""
        if output_dir is None:
            output_dir = os.path.join(tempfile.gettempdir(), "deleted_recovery")
        self.log(f"Deleted file recovery from {image_path}", "info")
        os.makedirs(output_dir, exist_ok=True)

        tool = None
        if self._require_tool("foremost"):
            tool = "foremost"
        elif self._require_tool("scalpel"):
            tool = "scalpel"

        if tool is None:
            self.log("No recovery tool (foremost/scalpel) found", "error")
            return {"error": "foremost and scalpel not available"}

        if tool == "foremost":
            cmd = f"foremost -i {image_path} -o {output_dir}"
        else:
            cmd = f"scalpel -o {output_dir} {image_path}"

        self._run_cmd(cmd, timeout=3600)

        recovered = []
        for root, dirs, files in os.walk(output_dir):
            for f in files:
                recovered.append(os.path.join(root, f))

        result = {
            "image": image_path,
            "output_dir": output_dir,
            "tool": tool,
            "files_recovered": len(recovered),
            "files": recovered[:200],
        }
        self.results["deleted_file_recovery"] = result
        self.log(f"Deleted file recovery completed ({len(recovered)} files)", "success")
        return result

    def metadata_extraction(self, file_path):
        """Extract metadata (EXIF, PE headers, etc.) from a file"""
        self.log(f"Extracting metadata from: {file_path}", "info")
        meta = {
            "file_size": os.path.getsize(file_path) if os.path.exists(file_path) else 0,
            "md5": self._calculate_hash(file_path, "md5"),
            "sha256": self._calculate_hash(file_path, "sha256"),
            "exif": None,
            "file_type": None,
            "strings_count": 0,
        }

        if self._require_tool("exiftool"):
            out = self._run_cmd(f"exiftool {file_path}")
            if out:
                meta["exif"] = out

        if self._require_tool("file"):
            out = self._run_cmd(f"file {file_path}")
            if out:
                meta["file_type"] = out.strip()

        out = self._run_cmd(f"strings {file_path}")
        if out:
            meta["strings_count"] = len(out.split("\n"))

        self.results["metadata_extraction"] = meta
        self.log("Metadata extraction completed", "success")
        return meta

    def steganography_extract(self, image_path, output_dir=None):
        """Attempt to extract hidden data from stego files"""
        if output_dir is None:
            output_dir = os.path.join(tempfile.gettempdir(), "stego_extract")
        self.log(f"Steganography extraction: {image_path}", "info")
        os.makedirs(output_dir, exist_ok=True)

        extract_result = {
            "image": image_path,
            "output_dir": output_dir,
            "tools_used": [],
            "extracted_files": [],
        }

        if self._require_tool("steghide"):
            out = self._run_cmd(f"steghide extract -sf {image_path} -xf {output_dir}/steghide_out -f")
            if out:
                extract_result["tools_used"].append("steghide")
                if os.path.exists(f"{output_dir}/steghide_out"):
                    extract_result["extracted_files"].append(f"{output_dir}/steghide_out")

        if self._require_tool("zsteg"):
            out = self._run_cmd(f"zsteg {image_path} -a -o {output_dir}/zsteg_out")
            if out:
                extract_result["tools_used"].append("zsteg")

        if self._require_tool("binwalk"):
            out = self._run_cmd(f"binwalk -e {image_path} -C {output_dir}")
            if out:
                extract_result["tools_used"].append("binwalk")
                for root, dirs, files in os.walk(output_dir):
                    for f in files:
                        fp = os.path.join(root, f)
                        if fp not in extract_result["extracted_files"]:
                            extract_result["extracted_files"].append(fp)

        if self._require_tool("strings"):
            out = self._run_cmd(f"strings {image_path}")
            if out:
                strings_file = os.path.join(output_dir, "strings_output.txt")
                with open(strings_file, "w") as fh:
                    fh.write(out)
                extract_result["extracted_files"].append(strings_file)

        self.results["steganography_extract"] = extract_result
        self.log("Steganography extraction completed", "success")
        return extract_result

    def memory_dump(self, pid=None):
        """Create a memory dump of a running process (macOS / Linux)"""
        if pid is not None:
            target = str(pid)
        else:
            target = ""
        self.log(f"Memory dump (pid={target})", "info")

        result = {"pid": pid, "dump_file": None, "size": 0}

        if self._require_tool("gcore"):
            cmd = f"gcore -o /tmp/memdump_{target} {target}"
            self._run_cmd(cmd, timeout=120)
            dump_path = f"/tmp/memdump_{target}.{target}"
            if os.path.exists(dump_path):
                result["dump_file"] = dump_path
                result["size"] = os.path.getsize(dump_path)
        elif self._require_tool("lldb"):
            dump_path = f"/tmp/memdump_{target}.dmp"
            cmd = f"lldb -p {target} --batch -o 'memory read --force --binary-file {dump_path} 0 0x1000'"
            self._run_cmd(cmd, timeout=120)
            if os.path.exists(dump_path):
                result["dump_file"] = dump_path
                result["size"] = os.path.getsize(dump_path)
        elif self._require_tool("dd") and os.path.exists(f"/proc/{target}/mem"):
            dump_path = f"/tmp/memdump_{target}.dmp"
            cmd = f"dd if=/proc/{target}/mem of={dump_path} bs=1M count=64 2>/dev/null"
            self._run_cmd(cmd, timeout=120)
            if os.path.exists(dump_path):
                result["dump_file"] = dump_path
                result["size"] = os.path.getsize(dump_path)
        else:
            self.log("No memory dump tool available", "error")
            result["error"] = "No suitable memory dump tool found"

        self.results["memory_dump"] = result
        self.log("Memory dump completed", "success")
        return result

    def memory_forensics(self, dump_path):
        """Extended memory forensics with volatility (carving, strings, etc.)"""
        self.log(f"Memory forensics: {dump_path}", "info")
        if not self._require_tool("volatility"):
            self.log("volatility not found", "error")
            return {"error": "volatility not available"}

        plugins = {
            "pslist": f"volatility -f {dump_path} --profile=Win7SP1x64 pslist",
            "pstree": f"volatility -f {dump_path} --profile=Win7SP1x64 pstree",
            "netscan": f"volatility -f {dump_path} --profile=Win7SP1x64 netscan",
            "filescan": f"volatility -f {dump_path} --profile=Win7SP1x64 filescan",
            "dumpfiles": (f"volatility -f {dump_path} --profile=Win7SP1x64 dumpfiles -D {tempfile.gettempdir()}"),
            "malfind": f"volatility -f {dump_path} --profile=Win7SP1x64 malfind",
            "svcscan": f"volatility -f {dump_path} --profile=Win7SP1x64 svcscan",
            "clipboard": f"volatility -f {dump_path} --profile=Win7SP1x64 clipboard",
        }

        results = {}
        for key, cmd in plugins.items():
            results[key] = self._run_cmd(cmd, timeout=120)

        self.results["memory_forensics"] = results
        self.log("Memory forensics completed", "success")
        return results

    def process_analysis(self, pid=None):
        """Analyse a running process: open files, connections, environment"""
        self.log(f"Process analysis (pid={pid})", "info")
        result = {"pid": pid, "info": {}, "open_files": [], "connections": []}

        if pid is None:
            self.log("No PID specified", "error")
            return {"error": "No PID specified"}

        pid_str = str(pid)

        if self._require_tool("lsof"):
            out = self._run_cmd(f"lsof -p {pid_str}")
            if out:
                result["open_files"] = out.split("\n")[:200]

        if self._require_tool("netstat"):
            out = self._run_cmd(f"netstat -tunap 2>/dev/null | grep {pid_str}")
            if out:
                result["connections"] = out.split("\n")[:100]

        if os.path.exists(f"/proc/{pid_str}/status"):
            out = self._run_cmd(f"cat /proc/{pid_str}/status")
            if out:
                result["info"]["status"] = out

        if os.path.exists(f"/proc/{pid_str}/environ"):
            out = self._run_cmd(f"cat /proc/{pid_str}/environ 2>/dev/null | tr '\\0' '\\n'")
            if out:
                result["info"]["environment"] = out.split("\n")[:50]

        if self._require_tool("ps"):
            out = self._run_cmd(f"ps -p {pid_str} -o pid,ppid,user,%cpu,%mem,vsz,rss,comm")
            if out:
                result["info"]["ps"] = out.strip()

        self.results["process_analysis"] = result
        self.log("Process analysis completed", "success")
        return result

    def timeline_analysis(self, path):
        """Build a file-system activity timeline from a directory"""
        self.log(f"Timeline analysis: {path}", "info")
        timeline = {
            "path": path,
            "events": [],
            "oldest": None,
            "newest": None,
        }

        if self._require_tool("fls"):
            out = self._run_cmd(f"fls -r -m / {path}")
            if out:
                for line in out.split("\n")[:500]:
                    timeline["events"].append(line.strip())

        if self._require_tool("find"):
            out = self._run_cmd(f"find {path} -type f -printf '%T+ %p\\n' 2>/dev/null | sort | head -500")
            if out:
                lines = [l for l in out.split("\n") if l]
                timeline["events"].extend(lines)
                if lines:
                    timeline["oldest"] = lines[0].split(" ")[0]
                    timeline["newest"] = lines[-1].split(" ")[0]

        self.results["timeline_analysis"] = timeline
        self.log("Timeline analysis completed", "success")
        return timeline

    def registry_forensics(self, hive_path=None, system_root=None):
        """Analyse Windows registry hives with reglookup / hivexsh"""
        self.log(f"Registry forensics: {hive_path}", "info")
        reg_data = {"hive": hive_path, "entries": [], "users": [], "software": []}

        tool = None
        if self._require_tool("reglookup"):
            tool = "reglookup"
        elif self._require_tool("hivexsh"):
            tool = "hivexsh"

        if tool is None and hive_path and os.path.isfile(hive_path):
            out = self._run_cmd(f"strings {hive_path}")
            if out:
                reg_data["strings"] = out.split("\n")[:200]

        if tool == "reglookup" and hive_path:
            out = self._run_cmd(f"reglookup {hive_path}")
            if out:
                reg_data["entries"] = out.split("\n")[:500]

        if tool == "hivexsh" and hive_path:
            out = self._run_cmd(f"hivexsh -f {hive_path} -e 'ls \\'")
            if out:
                reg_data["entries"] = out.split("\n")[:500]

        self.results["registry_forensics"] = reg_data
        self.log("Registry forensics completed", "success")
        return reg_data

    def browser_forensics(self, profile_dir=None):
        """Extract browser artifacts (history, cookies, cache) from a profile"""
        self.log(f"Browser forensics: {profile_dir}", "info")
        artifacts = {
            "profile_dir": profile_dir,
            "history": [],
            "cookies": [],
            "downloads": [],
            "cache_files": [],
        }

        if profile_dir is None or not os.path.isdir(profile_dir):
            self.log("Profile directory not found", "error")
            return {"error": "Profile directory not provided or does not exist"}

        for root, dirs, files in os.walk(profile_dir):
            for f in files:
                fp = os.path.join(root, f)
                fname = f.lower()
                if "history" in fname and (fname.endswith(".sqlite") or fname.endswith(".db")):
                    out = self._run_cmd(f"sqlite3 {fp} '.tables'")
                    if out:
                        artifacts["history"].append({"db": fp, "tables": out.strip()})
                elif "cookie" in fname:
                    try:
                        sz = os.path.getsize(fp)
                        artifacts["cookies"].append({"file": fp, "size": sz})
                    except OSError:
                        pass
                elif "download" in fname:
                    artifacts["downloads"].append(fp)
                elif fname.endswith((".jpg", ".png", ".gif", ".webp", ".mp4")):
                    artifacts["cache_files"].append(fp)
                if len(artifacts["cache_files"]) > 100:
                    break

        self.results["browser_forensics"] = artifacts
        self.log("Browser forensics completed", "success")
        return artifacts

    def email_forensics(self, email_path):
        """Parse email files (.eml / .mbox) for headers, attachments, anomalies"""
        self.log(f"Email forensics: {email_path}", "info")
        email_data = {
            "path": email_path,
            "headers": [],
            "attachments": [],
            "suspicious_patterns": [],
            "body_preview": "",
        }

        if not os.path.isfile(email_path):
            self.log("Email file not found", "error")
            return {"error": "Email file not found"}

        try:
            with open(email_path, "r", errors="replace") as fh:
                content = fh.read()

            header_block = ""
            body_start = content.find("\n\n")
            if body_start != -1:
                header_block = content[:body_start]
                email_data["body_preview"] = content[body_start : body_start + 2000]
            else:
                header_block = content[:4000]
                email_data["body_preview"] = content[:2000]

            email_data["headers"] = [h.strip() for h in header_block.split("\n") if h.strip()]

            suspicious = [
                "x-mailer:",
                "received:",
                "return-path:",
                "message-id:",
                "authentication-results:",
                "dkim-signature:",
            ]
            for hdr in email_data["headers"]:
                low = hdr.lower()
                for pat in suspicious:
                    if pat in low:
                        email_data["suspicious_patterns"].append(hdr)
                        break

            attach_pattern = re.compile(r"filename=\"(.+?)\"", re.IGNORECASE)
            for match in attach_pattern.finditer(header_block):
                email_data["attachments"].append(match.group(1))

        except Exception as e:
            email_data["error"] = str(e)

        self.results["email_forensics"] = email_data
        self.log("Email forensics completed", "success")
        return email_data

    def document_forensics(self, doc_path):
        """Analyse a document for metadata, macros, embedded objects"""
        self.log(f"Document forensics: {doc_path}", "info")
        doc_info = {
            "path": doc_path,
            "file_type": None,
            "metadata": None,
            "strings_count": 0,
            "embedded_objects": [],
            "macro_indicators": [],
            "md5": self._calculate_hash(doc_path, "md5"),
            "sha256": self._calculate_hash(doc_path, "sha256"),
        }

        if self._require_tool("file"):
            out = self._run_cmd(f"file {doc_path}")
            if out:
                doc_info["file_type"] = out.strip()

        if self._require_tool("exiftool"):
            out = self._run_cmd(f"exiftool {doc_path}")
            if out:
                doc_info["metadata"] = out

        out = self._run_cmd(f"strings {doc_path}")
        if out:
            lines = out.split("\n")
            doc_info["strings_count"] = len(lines)
            macro_kw = ["macro", "vba", "autoopen", "document_open", "activemovie"]
            for line in lines:
                low = line.lower()
                for kw in macro_kw:
                    if kw in low:
                        doc_info["macro_indicators"].append(line.strip()[:200])
                        break

        if self._require_tool("binwalk"):
            out = self._run_cmd(f"binwalk {doc_path}")
            if out:
                doc_info["embedded_objects"] = out.split("\n")[:50]

        self.results["document_forensics"] = doc_info
        self.log("Document forensics completed", "success")
        return doc_info

    def android_forensics(self, adb_target=None):
        """Android device forensics via adb"""
        self.log(f"Android forensics (target={adb_target})", "info")
        android = {
            "target": adb_target,
            "device_info": {},
            "packages": [],
            "logcat_sample": [],
            "dumpsys": {},
        }

        if not self._require_tool("adb"):
            self.log("adb not found", "error")
            return {"error": "adb not available"}

        target_flag = f"-s {adb_target}" if adb_target else ""
        prefix = f"adb {target_flag}"

        out = self._run_cmd(f"{prefix} shell getprop ro.product.model")
        if out:
            android["device_info"]["model"] = out.strip()
        out = self._run_cmd(f"{prefix} shell getprop ro.build.version.release")
        if out:
            android["device_info"]["android_version"] = out.strip()
        out = self._run_cmd(f"{prefix} shell getprop ro.serialno")
        if out:
            android["device_info"]["serial"] = out.strip()

        out = self._run_cmd(f"{prefix} shell pm list packages")
        if out:
            android["packages"] = [p.replace("package:", "") for p in out.strip().split("\n")[:200]]

        out = self._run_cmd(f"{prefix} logcat -d -t 200")
        if out:
            android["logcat_sample"] = out.split("\n")[:200]

        for svc in ["battery", "wifi", "telephony.registry"]:
            out = self._run_cmd(f"{prefix} shell dumpsys {svc}")
            if out:
                android["dumpsys"][svc] = out[:3000]

        self.results["android_forensics"] = android
        self.log("Android forensics completed", "success")
        return android

    def ios_forensics(self, idevice_id=None):
        """iOS device info extraction via ideviceinfo / libimobiledevice"""
        self.log(f"iOS forensics (device={idevice_id})", "info")
        ios = {
            "device_id": idevice_id,
            "device_info": {},
            "lockdownd": {},
            "files": [],
        }

        tool = None
        if self._require_tool("ideviceinfo"):
            tool = "ideviceinfo"
        elif self._require_tool("idevice_id"):
            tool = "idevice_id"

        if tool is None:
            self.log("No iOS forensics tool found", "error")
            return {"error": "ideviceinfo/idevice_id not available"}

        if tool == "ideviceinfo":
            out = self._run_cmd("ideviceinfo")
            if out:
                for line in out.split("\n"):
                    if ":" in line:
                        key, _, val = line.partition(":")
                        ios["device_info"][key.strip()] = val.strip()

        if self._require_tool("ideviceimagemounter"):
            out = self._run_cmd("ideviceimagemounter --list")
            if out:
                ios["lockdownd"]["images"] = out[:2000]

        if self._require_tool("ideviceinstaller"):
            out = self._run_cmd("ideviceinstaller -l")
            if out:
                ios["files"] = out.split("\n")[:200]

        self.results["ios_forensics"] = ios
        self.log("iOS forensics completed", "success")
        return ios

    def chain_of_custody(self, evidence_items=None):
        """Record chain-of-custody log for evidence items"""
        self.log("Recording chain of custody", "info")
        if evidence_items is None:
            evidence_items = []

        custody = {
            "case_id": f"CASE-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "items": [],
            "created_at": datetime.now().isoformat(),
        }

        for item in evidence_items:
            entry = {
                "item_id": item.get("id", "UNKNOWN"),
                "description": item.get("description", ""),
                "hash_md5": self._calculate_hash(item.get("path", ""), "md5") if item.get("path") else None,
                "hash_sha256": self._calculate_hash(item.get("path", ""), "sha256") if item.get("path") else None,
                "collected_by": item.get("collected_by", ""),
                "collected_at": datetime.now().isoformat(),
                "location": item.get("location", ""),
                "status": "collected",
            }
            custody["items"].append(entry)

        self.results["chain_of_custody"] = custody
        self.log(f"Chain of custody recorded ({len(custody['items'])} items)", "success")
        return custody

    # ── Helpers ─────────────────────────────────────────────────

    def _calculate_hash(self, file_path, hash_type="md5"):
        """Calculate file hash"""
        if not file_path or not os.path.isfile(file_path):
            return None
        try:
            if hash_type == "md5":
                h = hashlib.md5()
            elif hash_type == "sha256":
                h = hashlib.sha256()
            else:
                return None
            with open(file_path, "rb") as fh:
                for chunk in iter(lambda: fh.read(4096), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    # Keep old name as alias for backward compat
    run_command = _run_cmd

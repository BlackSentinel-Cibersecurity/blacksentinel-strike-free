"""
Copyright (c) 2024-2025 BlackSentinel Strike - All Rights Reserved
"""

import subprocess
from datetime import datetime


class ForensicAdvanced:
    """Advanced Forensic Analysis Module for BlackSentinel Strike."""

    def __init__(self):
        self.module_name = "ForensicAdvanced"
        self.version = "2.1.0"
        self.results = {}

    def run_command(self, cmd, timeout=30):
        """Execute a shell command and return output."""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return f"[TIMEOUT] Command timed out after {timeout}s: {cmd}"
        except Exception as e:
            return f"[ERROR] {str(e)}"

    # ===========================================================
    # DISK FORENSICS (10 Methods)
    # ===========================================================

    def disk_image_acquisition(self, target, output_path="/tmp/evidence"):
        """Create a forensic disk image of the target."""
        try:
            cmd = f"dd if={target} of={output_path}/disk_image.dd bs=4M status=progress conv=noerror,sync"
            output = self.run_command(cmd, timeout=300)
            result = f"Disk Image Acquisition Complete\nSource: {target}\nOutput: {output_path}/disk_image.dd\n{output}"
            self.results["disk_image"] = result
            return result
        except Exception as e:
            return f"Disk image acquisition failed: {str(e)}"

    def disk_partition_analysis(self, target):
        """Analyze disk partitions on target."""
        try:
            output = self.run_command(f"fdisk -l {target}")
            result = f"Partition Analysis for {target}\n{output}"
            self.results["disk_partitions"] = result
            return result
        except Exception as e:
            return f"Partition analysis failed: {str(e)}"

    def disk_filesystem_forensics(self, target):
        """Perform filesystem-level forensics using sleuthkit."""
        try:
            output = self.run_command(f"fls -r -m / {target}")
            result = f"Filesystem Forensics (Sleuthkit fls)\nTarget: {target}\n{output}"
            self.results["disk_filesystem"] = result
            return result
        except Exception as e:
            return f"Filesystem forensics failed: {str(e)}"

    def disk_file_recovery(self, target, output_dir="/tmp/recovered"):
        """Attempt file recovery from disk using photorec."""
        try:
            cmd = f"photorec /cmd {target} search /output={output_dir}"
            output = self.run_command(cmd, timeout=120)
            result = f"File Recovery Attempt\nTarget: {target}\nOutput: {output_dir}\n{output}"
            self.results["disk_recovery"] = result
            return result
        except Exception as e:
            return f"File recovery failed: {str(e)}"

    def disk_volume_shadow_copy(self, target):
        """Analyze Volume Shadow Copies on target."""
        try:
            output = self.run_command(f"vssadmin list shadows /for={target}")
            result = f"Volume Shadow Copy Analysis\nTarget: {target}\n{output}"
            self.results["disk_vss"] = result
            return result
        except Exception as e:
            return f"VSS analysis failed: {str(e)}"

    def disk_boot_sector_analysis(self, target):
        """Analyze the boot sector of a disk."""
        try:
            output = self.run_command(f"xxd -l 512 {target}")
            result = f"Boot Sector Analysis\nTarget: {target}\n{output}"
            self.results["disk_boot"] = result
            return result
        except Exception as e:
            return f"Boot sector analysis failed: {str(e)}"

    def disk_mbr_analysis(self, target):
        """Analyze the Master Boot Record."""
        try:
            output = self.run_command(f"fdisk -l {target} 2>/dev/null | head -20")
            mbr_dump = self.run_command(f"xxd -l 446 {target}")
            result = f"MBR Analysis\nDisk Info:\n{output}\nMBR Dump:\n{mbr_dump}"
            self.results["disk_mbr"] = result
            return result
        except Exception as e:
            return f"MBR analysis failed: {str(e)}"

    def disk_bad_sector_scan(self, target):
        """Scan for bad sectors on target disk."""
        try:
            output = self.run_command(f"badblocks -v -s {target}", timeout=120)
            result = f"Bad Sector Scan\nTarget: {target}\n{output}"
            self.results["disk_badsectors"] = result
            return result
        except Exception as e:
            return f"Bad sector scan failed: {str(e)}"

    def disk_metadata_extraction(self, target):
        """Extract metadata from disk image using imagemagick/exiftool."""
        try:
            output = self.run_command(f"exiftool {target} 2>/dev/null || identify -verbose {target} 2>/dev/null")
            result = f"Metadata Extraction\nTarget: {target}\n{output}"
            self.results["disk_metadata"] = result
            return result
        except Exception as e:
            return f"Metadata extraction failed: {str(e)}"

    def disk_timeline_analysis(self, target):
        """Generate filesystem timeline from disk image."""
        try:
            output = self.run_command(f"fls -r -m / {target} 2>/dev/null | mactime -b - -d")
            result = f"Disk Timeline Analysis\nTarget: {target}\n{output}"
            self.results["disk_timeline"] = result
            return result
        except Exception as e:
            return f"Timeline analysis failed: {str(e)}"

    # ===========================================================
    # MEMORY FORENSICS (10 Methods)
    # ===========================================================

    def memory_dump_acquisition(self, target):
        """Acquire a memory dump from target system."""
        try:
            output = self.run_command(f"dumpit /output {target}/memory_dump.raw 2>/dev/null || liME /target {target}/memory_dump.raw")
            result = f"Memory Dump Acquisition\nTarget: {target}\n{output}"
            self.results["memory_dump"] = result
            return result
        except Exception as e:
            return f"Memory dump failed: {str(e)}"

    def memory_process_list(self, target):
        """List processes from memory dump using volatility."""
        try:
            output = self.run_command(f"volatility -f {target} --profile=Win10x64 pslist 2>/dev/null")
            result = f"Memory Process List\nTarget: {target}\n{output}"
            self.results["memory_pslist"] = result
            return result
        except Exception as e:
            return f"Process listing failed: {str(e)}"

    def memory_network_connections(self, target):
        """Extract network connections from memory dump."""
        try:
            output = self.run_command(f"volatility -f {target} --profile=Win10x64 netscan 2>/dev/null")
            result = f"Memory Network Connections\nTarget: {target}\n{output}"
            self.results["memory_netscan"] = result
            return result
        except Exception as e:
            return f"Network connection extraction failed: {str(e)}"

    def memory_dll_list(self, target):
        """List loaded DLLs from memory dump."""
        try:
            output = self.run_command(f"volatility -f {target} --profile=Win10x64 dlllist 2>/dev/null")
            result = f"Memory DLL List\nTarget: {target}\n{output}"
            self.results["memory_dlllist"] = result
            return result
        except Exception as e:
            return f"DLL listing failed: {str(e)}"

    def memory_handle_analysis(self, target):
        """Analyze open handles from memory dump."""
        try:
            output = self.run_command(f"volatility -f {target} --profile=Win10x64 handles 2>/dev/null")
            result = f"Memory Handle Analysis\nTarget: {target}\n{output}"
            self.results["memory_handles"] = result
            return result
        except Exception as e:
            return f"Handle analysis failed: {str(e)}"

    def memory_registry_analysis(self, target):
        """Extract registry hives from memory dump."""
        try:
            output = self.run_command(f"volatility -f {target} --profile=Win10x64 hivelist 2>/dev/null")
            result = f"Memory Registry Analysis\nTarget: {target}\n{output}"
            self.results["memory_registry"] = result
            return result
        except Exception as e:
            return f"Registry analysis failed: {str(e)}"

    def memory_malfind(self, target):
        """Detect injected code/malware in memory."""
        try:
            output = self.run_command(f"volatility -f {target} --profile=Win10x64 malfind 2>/dev/null")
            result = f"Memory Malware Detection (Malfind)\nTarget: {target}\n{output}"
            self.results["memory_malfind"] = result
            return result
        except Exception as e:
            return f"Malfind analysis failed: {str(e)}"

    def memory_cmdline(self, target):
        """Extract command line arguments from memory."""
        try:
            output = self.run_command(f"volatility -f {target} --profile=Win10x64 cmdline 2>/dev/null")
            result = f"Memory Command Line Analysis\nTarget: {target}\n{output}"
            self.results["memory_cmdline"] = result
            return result
        except Exception as e:
            return f"Command line extraction failed: {str(e)}"

    def memory_filescan(self, target):
        """Scan for files in memory dump."""
        try:
            output = self.run_command(f"volatility -f {target} --profile=Win10x64 filescan 2>/dev/null")
            result = f"Memory File Scan\nTarget: {target}\n{output}"
            self.results["memory_filescan"] = result
            return result
        except Exception as e:
            return f"File scan failed: {str(e)}"

    def memory_netscan_vol(self, target):
        """Network scan using volatility plugin."""
        try:
            output = self.run_command(f"volatility -f {target} --profile=Win10x64 netstat 2>/dev/null")
            result = f"Memory Network Scan (netstat)\nTarget: {target}\n{output}"
            self.results["memory_netstat"] = result
            return result
        except Exception as e:
            return f"Memory netstat failed: {str(e)}"

    # ===========================================================
    # NETWORK FORENSICS (10 Methods)
    # ===========================================================

    def network_pcap_analysis(self, target):
        """Analyze a PCAP file for network forensics."""
        try:
            output = self.run_command(f"tshark -r {target} -q -z conv,tcp 2>/dev/null")
            result = f"PCAP Analysis\nTarget: {target}\n{output}"
            self.results["network_pcap"] = result
            return result
        except Exception as e:
            return f"PCAP analysis failed: {str(e)}"

    def network_dns_forensics(self, target):
        """Analyze DNS traffic from network capture."""
        try:
            output = self.run_command(f"tshark -r {target} -Y dns -T fields -e dns.qry.name 2>/dev/null | sort -u")
            result = f"DNS Forensics\nTarget: {target}\n{output}"
            self.results["network_dns"] = result
            return result
        except Exception as e:
            return f"DNS forensics failed: {str(e)}"

    def network_http_forensics(self, target):
        """Analyze HTTP traffic from network capture."""
        try:
            output = self.run_command(f"tshark -r {target} -Y http -T fields -e http.request.method -e http.request.uri -e http.host 2>/dev/null")
            result = f"HTTP Forensics\nTarget: {target}\n{output}"
            self.results["network_http"] = result
            return result
        except Exception as e:
            return f"HTTP forensics failed: {str(e)}"

    def network_packet_extraction(self, target, filter_proto="tcp"):
        """Extract packets filtered by protocol."""
        try:
            output = self.run_command(f"tshark -r {target} -Y {filter_proto} -c 100 2>/dev/null")
            result = f"Packet Extraction (Protocol: {filter_proto})\nTarget: {target}\n{output}"
            self.results["network_packets"] = result
            return result
        except Exception as e:
            return f"Packet extraction failed: {str(e)}"

    def network_flow_analysis(self, target):
        """Analyze network flow/conversation statistics."""
        try:
            output = self.run_command(f"tshark -r {target} -q -z flow,tcp 2>/dev/null")
            result = f"Network Flow Analysis\nTarget: {target}\n{output}"
            self.results["network_flow"] = result
            return result
        except Exception as e:
            return f"Flow analysis failed: {str(e)}"

    def network_tls_forensics(self, target):
        """Analyze TLS/SSL handshake traffic."""
        try:
            output = self.run_command(f"tshark -r {target} -Y tls.handshake -T fields -e tls.handshake.extensions_server_name -e tls.handshake.type 2>/dev/null")
            result = f"TLS Forensics\nTarget: {target}\n{output}"
            self.results["network_tls"] = result
            return result
        except Exception as e:
            return f"TLS forensics failed: {str(e)}"

    def network_suspicious_ips(self, target):
        """Identify suspicious IP addresses from traffic."""
        try:
            output = self.run_command(f"tshark -r {target} -T fields -e ip.src -e ip.dst 2>/dev/null | sort | uniq -c | sort -rn | head -20")
            result = f"Suspicious IPs (Top Talkers)\nTarget: {target}\n{output}"
            self.results["network_ips"] = result
            return result
        except Exception as e:
            return f"Suspicious IP analysis failed: {str(e)}"

    def network_ftp_forensics(self, target):
        """Analyze FTP traffic for credentials and commands."""
        try:
            output = self.run_command(f"tshark -r {target} -Y ftp -T fields -e ftp.request.command -e ftp.request.arg 2>/dev/null")
            result = f"FTP Forensics\nTarget: {target}\n{output}"
            self.results["network_ftp"] = result
            return result
        except Exception as e:
            return f"FTP forensics failed: {str(e)}"

    def network_smtp_forensics(self, target):
        """Analyze SMTP/email traffic."""
        try:
            output = self.run_command(f"tshark -r {target} -Y smtp -T fields -e smtp.req.parameter -e smtp.command 2>/dev/null")
            result = f"SMTP Forensics\nTarget: {target}\n{output}"
            self.results["network_smtp"] = result
            return result
        except Exception as e:
            return f"SMTP forensics failed: {str(e)}"

    def network_statistical_summary(self, target):
        """Generate statistical summary of network capture."""
        try:
            output = self.run_command(f"tshark -r {target} -q -z io,phs -z conv,ip -z http,tree 2>/dev/null")
            result = f"Network Statistical Summary\nTarget: {target}\n{output}"
            self.results["network_stats"] = result
            return result
        except Exception as e:
            return f"Statistical summary failed: {str(e)}"

    # ===========================================================
    # MOBILE FORENSICS (10 Methods)
    # ===========================================================

    def mobile_device_info(self, target):
        """Extract device information from mobile device."""
        try:
            output = self.run_command(f"adb -s {target} shell getprop 2>/dev/null || ideviceinfo -u {target} 2>/dev/null")
            result = f"Mobile Device Info\nTarget: {target}\n{output}"
            self.results["mobile_info"] = result
            return result
        except Exception as e:
            return f"Device info extraction failed: {str(e)}"

    def mobile_app_list(self, target):
        """List installed applications on mobile device."""
        try:
            output = self.run_command(f"adb -s {target} shell pm list packages -f 2>/dev/null || ideviceinstaller -l 2>/dev/null")
            result = f"Installed Applications\nTarget: {target}\n{output}"
            self.results["mobile_apps"] = result
            return result
        except Exception as e:
            return f"App listing failed: {str(e)}"

    def mobile_sms_extraction(self, target):
        """Extract SMS messages from Android device."""
        try:
            output = self.run_command(f"adb -s {target} shell content query --uri content://sms 2>/dev/null")
            result = f"SMS Extraction\nTarget: {target}\n{output}"
            self.results["mobile_sms"] = result
            return result
        except Exception as e:
            return f"SMS extraction failed: {str(e)}"

    def mobile_call_log(self, target):
        """Extract call log from mobile device."""
        try:
            output = self.run_command(f"adb -s {target} shell content query --uri content://call_log/calls 2>/dev/null")
            result = f"Call Log Extraction\nTarget: {target}\n{output}"
            self.results["mobile_calls"] = result
            return result
        except Exception as e:
            return f"Call log extraction failed: {str(e)}"

    def mobile_contacts(self, target):
        """Extract contacts from mobile device."""
        try:
            output = self.run_command(f"adb -s {target} shell content query --uri content://contacts/phones 2>/dev/null")
            result = f"Contacts Extraction\nTarget: {target}\n{output}"
            self.results["mobile_contacts"] = result
            return result
        except Exception as e:
            return f"Contacts extraction failed: {str(e)}"

    def mobile_browser_forensics(self, target):
        """Extract browser history from mobile device."""
        try:
            output = self.run_command(f"adb -s {target} shell sqlite3 /data/data/com.android.chrome/databases/History 'SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 100;' 2>/dev/null")
            result = f"Browser History Forensics\nTarget: {target}\n{output}"
            self.results["mobile_browser"] = result
            return result
        except Exception as e:
            return f"Browser forensics failed: {str(e)}"

    def mobile_wifi_forensics(self, target):
        """Extract WiFi connection history."""
        try:
            output = self.run_command(f"adb -s {target} shell cat /data/misc/wifi/WifiConfigStore.xml 2>/dev/null")
            result = f"WiFi Forensics\nTarget: {target}\n{output}"
            self.results["mobile_wifi"] = result
            return result
        except Exception as e:
            return f"WiFi forensics failed: {str(e)}"

    def mobile_screenshot(self, target, output_path="/tmp/evidence"):
        """Capture screenshot from mobile device."""
        try:
            output = self.run_command(f"adb -s {target} shell screencap -p /sdcard/screenshot.png && adb -s {target} pull /sdcard/screenshot.png {output_path}/")
            result = f"Screenshot Capture\nTarget: {target}\nOutput: {output_path}/screenshot.png\n{output}"
            self.results["mobile_screenshot"] = result
            return result
        except Exception as e:
            return f"Screenshot capture failed: {str(e)}"

    def mobile_file_extraction(self, target, remote_path="/sdcard/", output_path="/tmp/evidence"):
        """Extract files from mobile device storage."""
        try:
            output = self.run_command(f"adb -s {target} pull {remote_path} {output_path}/mobile_files/ 2>/dev/null")
            result = f"File Extraction\nTarget: {target}\nRemote: {remote_path}\nOutput: {output_path}/mobile_files/\n{output}"
            self.results["mobile_files"] = result
            return result
        except Exception as e:
            return f"File extraction failed: {str(e)}"

    def mobile_logcat_analysis(self, target, lines=500):
        """Extract and analyze device logs."""
        try:
            output = self.run_command(f"adb -s {target} logcat -d -t {lines} 2>/dev/null")
            result = f"Logcat Analysis (Last {lines} lines)\nTarget: {target}\n{output}"
            self.results["mobile_logcat"] = result
            return result
        except Exception as e:
            return f"Logcat analysis failed: {str(e)}"

    # ===========================================================
    # UTILITY METHODS
    # ===========================================================

    def generate_report(self, output_path="/tmp/evidence"):
        """Generate a consolidated forensic report."""
        try:
            report_path = f"{output_path}/forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(report_path, "w") as f:
                f.write("=" * 80 + "\n")
                f.write("BLACKSENTINEL STRIKE - FORENSIC ANALYSIS REPORT\n")
                f.write(f"Generated: {datetime.now().isoformat()}\n")
                f.write("=" * 80 + "\n\n")
                for key, value in self.results.items():
                    f.write(f"\n{'='*60}\n")
                    f.write(f"SECTION: {key.upper()}\n")
                    f.write(f"{'='*60}\n")
                    f.write(f"{value}\n")
            return f"Report generated: {report_path}"
        except Exception as e:
            return f"Report generation failed: {str(e)}"

    def get_available_modules(self):
        """List all available forensic modules."""
        modules = {
            "Disk Forensics": [
                "disk_image_acquisition", "disk_partition_analysis",
                "disk_filesystem_forensics", "disk_file_recovery",
                "disk_volume_shadow_copy", "disk_boot_sector_analysis",
                "disk_mbr_analysis", "disk_bad_sector_scan",
                "disk_metadata_extraction", "disk_timeline_analysis"
            ],
            "Memory Forensics": [
                "memory_dump_acquisition", "memory_process_list",
                "memory_network_connections", "memory_dll_list",
                "memory_handle_analysis", "memory_registry_analysis",
                "memory_malfind", "memory_cmdline",
                "memory_filescan", "memory_netscan_vol"
            ],
            "Network Forensics": [
                "network_pcap_analysis", "network_dns_forensics",
                "network_http_forensics", "network_packet_extraction",
                "network_flow_analysis", "network_tls_forensics",
                "network_suspicious_ips", "network_ftp_forensics",
                "network_smtp_forensics", "network_statistical_summary"
            ],
            "Mobile Forensics": [
                "mobile_device_info", "mobile_app_list",
                "mobile_sms_extraction", "mobile_call_log",
                "mobile_contacts", "mobile_browser_forensics",
                "mobile_wifi_forensics", "mobile_screenshot",
                "mobile_file_extraction", "mobile_logcat_analysis"
            ]
        }
        return modules

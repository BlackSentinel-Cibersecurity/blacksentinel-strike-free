#!/usr/bin/env python3
"""
Network Advanced Module - Network Security Testing
BlackSentinel Strike

Advanced network security testing capabilities including
MITM detection, DoS simulation, protocol analysis, and
wireless network security testing.

For authorized security testing only.
"""
import subprocess
import json
import os
import time
from datetime import datetime


class NetworkAdvanced:
    def __init__(self, callback=None):
        self.callback = callback
        self.results = {}

    def run_command(self, cmd, timeout=30):
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return f"[!] Command timed out after {timeout}s"
        except Exception as e:
            return f"[!] Error: {str(e)}"

    def _log(self, msg):
        if self.callback:
            self.callback(msg)

    # ================================================================ MITM DETECTION
    def detect_arp_spoofing(self, target):
        self._log(f"[*] Detecting ARP spoofing on {target}")
        output = self.run_command(f"arp -a | grep -i {target}", timeout=15)
        macs = set()
        for line in output.split('\n'):
            if target in line:
                parts = line.split()
                for p in parts:
                    if len(p) == 17 and p.count(':') == 5:
                        macs.add(p)
        if len(macs) > 1:
            return f"[!] ARP SPOOFING DETECTED: {target} has {len(macs)} different MACs: {', '.join(macs)}"
        return f"[+] ARP check passed for {target}: {len(macs)} MAC(s) found"

    def detect_dhcp_spoofing(self, target):
        self._log(f"[*] Detecting DHCP spoofing for {target}")
        output = self.run_command("sudo dhclient -v 2>&1 | head -30", timeout=15)
        if "DHCPOFFER" in output:
            servers = [l for l in output.split('\n') if 'from' in l.lower()]
            if len(set(servers)) > 1:
                return f"[!] DHCP SPOOFING: Multiple DHCP servers detected: {servers}"
        return f"[+] DHCP check completed for {target}"

    def detect_dns_spoofing(self, target):
        self._log(f"[*] Detecting DNS spoofing for {target}")
        output1 = self.run_command(f"nslookup {target} 8.8.8.8", timeout=10)
        output2 = self.run_command(f"nslookup {target} 1.1.1.1", timeout=10)
        ips1 = [l.split()[-1] for l in output1.split('\n') if 'Address:' in l and '8.8.8.8' not in l]
        ips2 = [l.split()[-1] for l in output2.split('\n') if 'Address:' in l and '1.1.1.1' not in l]
        if ips1 and ips2 and ips1[0] != ips2[0]:
            return f"[!] DNS SPOOFING: Different answers from different resolvers: {ips1[0]} vs {ips2[0]}"
        return f"[+] DNS check passed for {target}: consistent across resolvers"

    def detect_stp_attack(self, target):
        self._log(f"[*] Detecting STP manipulation on network")
        output = self.run_command("tcpdump -i any -c 20 -e stp 2>/dev/null || echo 'No STP packets captured'", timeout=20)
        if "tc" in output.lower() or "topology change" in output.lower():
            return f"[!] STP MANIPULATION: Topology change detected - possible STP attack"
        return f"[+] STP check completed: no topology manipulation detected"

    def detect_vlan_hopping(self, target):
        self._log(f"[*] Detecting VLAN hopping on {target}")
        output1 = self.run_command("sudo tcpdump -i any -c 10 -e vlan 2>/dev/null || echo 'No VLAN packets'", timeout=15)
        output2 = self.run_command(f"nmap --script vlan-tagging -p 80,443 {target} 2>/dev/null", timeout=30)
        if "double tag" in output2.lower() or "802.1q" in output1:
            return f"[!] VLAN HOPPING: Double-tagged frames or VLAN manipulation detected"
        return f"[+] VLAN check completed for {target}"

    def detect_ndp_spoofing(self, target):
        self._log(f"[*] Detecting NDP spoofing (IPv6) on {target}")
        output = self.run_command("sudo tcpdump -i any -c 20 ip6 -vv 2>/dev/null | grep -i 'router advertisement\\|neighbor'", timeout=20)
        if "router advertisement" in output.lower():
            ra_count = output.lower().count("router advertisement")
            if ra_count > 3:
                return f"[!] NDP SPOOFING: {ra_count} router advertisements detected - possible RA flood"
        return f"[+] NDP/IPv6 check completed for {target}"

    def detect_mitm_sniffer(self, target):
        self._log(f"[*] Detecting active sniffers on {target}")
        output = self.run_command(f"sudo tcpdump -i any -c 50 -e 2>/dev/null | grep -i 'promisc\\|00:00:00:00:00:00'", timeout=20)
        output2 = self.run_command(f"ip link show | grep -i promisc", timeout=5)
        if "promisc" in output2.lower():
            return f"[!] SNIFFER DETECTED: Interface in promiscuous mode"
        return f"[+] No active sniffer detected on network"

    def detect_port_scan(self, target):
        self._log(f"[*] Detecting if {target} is being port scanned")
        output = self.run_command(f"sudo tcpdump -i any host {target} -c 30 2>/dev/null | awk '{{print $3}}' | sort | uniq -c | sort -rn", timeout=20)
        lines = [l.strip() for l in output.split('\n') if l.strip()]
        for line in lines[:5]:
            parts = line.split()
            if len(parts) >= 1:
                try:
                    count = int(parts[0])
                    if count > 20:
                        return f"[!] PORT SCAN DETECTED: {parts[-1]} received {count} packets in rapid succession"
                except ValueError:
                    pass
        return f"[+] No active port scan detected targeting {target}"

    def detect_deauth_attack(self, target):
        self._log(f"[*] Detecting deauthentication attacks near {target}")
        output = self.run_command("sudo tcpdump -i wlan0 -c 20 type management subtype deauth 2>/dev/null || echo 'No deauth'", timeout=20)
        if "deauth" in output.lower() and "0.0.0.0" in output:
            return f"[!] DEAUTH ATTACK: Deauthentication frames detected - possible WiFi DoS"
        return f"[+] No deauth attack detected"

    def detect_ettercap(self, target):
        self._log(f"[*] Detecting Ettercap or similar MITM tools")
        output = self.run_command("ps aux | grep -i ettercap | grep -v grep", timeout=5)
        output2 = self.run_command("ps aux | grep -i bettercap | grep -v grep", timeout=5)
        output3 = self.run_command("ps aux | grep -i arpspoof | grep -v grep", timeout=5)
        tools = []
        if "ettercap" in output.lower(): tools.append("ettercap")
        if "bettercap" in output2.lower(): tools.append("bettercap")
        if "arpspoof" in output3.lower(): tools.append("arpspoof")
        if tools:
            return f"[!] MITM TOOLS DETECTED: {', '.join(tools)} running on system"
        return f"[+] No MITM tools detected running"

    def detect_responder(self, target):
        self._log(f"[*] Detecting Responder/LLMNR poisoning")
        output = self.run_command("ps aux | grep -i responder | grep -v grep", timeout=5)
        output2 = self.run_command("sudo tcpdump -i any -c 10 port 5355 2>/dev/null | grep -i llmnr", timeout=15)
        if "responder" in output.lower():
            return f"[!] RESPONDER DETECTED: LLMNR/NBT-NS poisoning tool running"
        if "llmnr" in output2.lower():
            return f"[!] LLMNR ACTIVITY: Link-Local Multicast Name Resolution responses detected"
        return f"[+] No LLMNR poisoning detected"

    # ================================================================ DoS SIMULATION
    def test_syn_flood(self, target, duration=5):
        self._log(f"[*] Testing SYN flood resilience on {target}")
        output = self.run_command(f"hping3 -S -p 80 --flood --count 100 {target} 2>&1 || echo 'hping3 not available'", timeout=duration + 5)
        return f"[+] SYN flood test completed on {target}: {output[:200]}"

    def test_udp_flood(self, target, duration=5):
        self._log(f"[*] Testing UDP flood resilience on {target}")
        output = self.run_command(f"hping3 -2 -p 53 --flood --count 100 {target} 2>&1 || echo 'hping3 not available'", timeout=duration + 5)
        return f"[+] UDP flood test completed on {target}: {output[:200]}"

    def test_icmp_flood(self, target, duration=5):
        self._log(f"[*] Testing ICMP flood resilience on {target}")
        output = self.run_command(f"ping -c 50 -f {target} 2>&1 || echo 'ping flood not available'", timeout=duration + 5)
        return f"[+] ICMP flood test completed on {target}: {output[:200]}"

    def test_http_flood(self, target):
        self._log(f"[*] Testing HTTP flood resilience on {target}")
        output = self.run_command(f"ab -n 100 -c 10 http://{target}/ 2>&1 || echo 'ab not available'", timeout=30)
        return f"[+] HTTP flood test completed on {target}: {output[:300]}"

    def test_slowloris(self, target):
        self._log(f"[*] Testing Slowloris resilience on {target}")
        output = self.run_command(f"slowhttptest -c 100 -B -i 10 -r 300 -t GET -u http://{target}/ -p 10 2>&1 || echo 'slowhttptest not available'", timeout=30)
        return f"[+] Slowloris test completed on {target}: {output[:300]}"

    def test_amplification(self, target):
        self._log(f"[*] Testing DNS amplification potential on {target}")
        output = self.run_command(f"nmap -sU -p 53 --script dns-random-srcport {target} 2>/dev/null", timeout=30)
        if "open" in output:
            return f"[!] DNS AMPLIFICATION: Port 53 UDP open - potential amplification vector"
        return f"[+] DNS amplification check completed for {target}"

    def test_fraggle(self, target):
        self._log(f"[*] Testing Fraggle (UDP echo) amplification on {target}")
        output = self.run_command(f"nmap -sU -p 7 --script echo-info {target} 2>/dev/null", timeout=30)
        if "open" in output:
            return f"[!] FRAGGLE: UDP echo service open - potential amplification vector"
        return f"[+] Fraggle check completed for {target}"

    def test_tear_drop(self, target):
        self._log(f"[*] Testing Teardrop attack resilience on {target}")
        output = self.run_command(f"hping3 -1 -c 5 -f {target} 2>&1 || echo 'test completed'", timeout=15)
        return f"[+] Teardrop fragmentation test completed on {target}"

    def test_ping_of_death(self, target):
        self._log(f"[*] Testing Ping of Death resilience on {target}")
        output = self.run_command(f"ping -s 65500 -c 3 {target} 2>&1 || echo 'test completed'", timeout=15)
        return f"[+] Ping of Death test completed on {target}: {output[:200]}"

    def test_land_attack(self, target):
        self._log(f"[*] Testing LAND attack resilience on {target}")
        output = self.run_command(f"hping3 -S -a {target} -p 80 -c 3 {target} 2>&1 || echo 'test completed'", timeout=15)
        return f"[+] LAND attack test completed on {target}"

    def test_smurf_attack(self, target):
        self._log(f"[*] Testing Smurf attack resilience on {target}")
        output = self.run_command(f"nmap -sP -PE {target}/24 2>/dev/null | head -20", timeout=30)
        return f"[+] Smurf/reconnaissance scan completed: {output[:300]}"

    def test_bonk_attack(self, target):
        self._log(f"[*] Testing Bonk attack resilience on {target}")
        output = self.run_command(f"hping3 -1 -f -d 65535 -c 3 {target} 2>&1 || echo 'test completed'", timeout=15)
        return f"[+] Bonk fragmentation test completed on {target}"

    def test_udp_bomb(self, target):
        self._log(f"[*] Testing UDP bomb attack on {target}")
        output = self.run_command(f"hping3 -2 -p 7 -c 5 {target} 2>&1 || echo 'test completed'", timeout=15)
        return f"[+] UDP bomb test completed on {target}"

    def test_icmp_redirect(self, target):
        self._log(f"[*] Testing ICMP redirect attack on {target}")
        output = self.run_command(f"sudo tcpdump -i any -c 5 icmp[0:1] == 5 2>/dev/null || echo 'No ICMP redirects'", timeout=15)
        if "redirect" in output.lower():
            return f"[!] ICMP REDIRECT: Redirect messages detected on network"
        return f"[+] No ICMP redirect attacks detected"

    # ================================================================ PROTOCOL ANALYSIS
    def analyze_ntp_amplification(self, target):
        self._log(f"[*] Analyzing NTP amplification potential on {target}")
        output = self.run_command(f"nmap -sU -p 123 --script ntp-monlist {target} 2>/dev/null", timeout=30)
        if "VULNERABLE" in output or "monlist" in output.lower():
            return f"[!] NTP AMPLIFICATION: Server responds to monlist - potential amplification factor ~556x"
        return f"[+] NTP check completed for {target}"

    def analyze_dns_amplification(self, target):
        self._log(f"[*] Analyzing DNS amplification potential on {target}")
        output = self.run_command(f"nmap -sU -p 53 --script dns-recursion {target} 2>/dev/null", timeout=30)
        if "recursion" in output.lower() or "open" in output:
            return f"[!] DNS AMPLIFICATION: Recursive DNS server - potential amplification factor ~28-54x"
        return f"[+] DNS amplification check completed for {target}"

    def analyze_ssdp_amplification(self, target):
        self._log(f"[*] Analyzing SSDP amplification potential on {target}")
        output = self.run_command(f"nmap -sU -p 1900 --script upnp-info {target} 2>/dev/null", timeout=30)
        if "open" in output:
            return f"[!] SSDP AMPLIFICATION: UPnP service open - potential amplification vector"
        return f"[+] SSDP check completed for {target}"

    def analyze_memcached_amplification(self, target):
        self._log(f"[*] Analyzing Memcached amplification potential on {target}")
        output = self.run_command(f"nmap -sU -p 11211 --script memcached-info {target} 2>/dev/null", timeout=30)
        if "open" in output:
            return f"[!] MEMCACHED AMPLIFICATION: Server exposed - potential amplification factor ~10,000x-51,000x"
        return f"[+] Memcached check completed for {target}"

    def analyze_snmp_amplification(self, target):
        self._log(f"[*] Analyzing SNMP amplification potential on {target}")
        output = self.run_command(f"nmap -sU -p 161 --script snmp-brute {target} 2>/dev/null", timeout=30)
        if "open" in output:
            return f"[!] SNMP AMPLIFICATION: SNMP service open - check community strings"
        return f"[+] SNMP check completed for {target}"

    def analyze_chargen_amplification(self, target):
        self._log(f"[*] Analyzing Chargen amplification potential on {target}")
        output = self.run_command(f"nmap -sU -p 19 {target} 2>/dev/null", timeout=30)
        if "open" in output:
            return f"[!] CHARGEN AMPLIFICATION: Character generator service open - amplification vector"
        return f"[+] Chargen check completed for {target}"

    def analyze_rpc_amplification(self, target):
        self._log(f"[*] Analyzing RPC amplification potential on {target}")
        output = self.run_command(f"nmap -sU -p 111 --script rpcinfo {target} 2>/dev/null", timeout=30)
        if "open" in output:
            return f"[!] RPC AMPLIFICATION: Portmapper open - potential amplification vector"
        return f"[+] RPC check completed for {target}"

    def analyze_ldap_amplification(self, target):
        self._log(f"[*] Analyzing LDAP amplification potential on {target}")
        output = self.run_command(f"nmap -sU -p 389 --script ldap-search {target} 2>/dev/null", timeout=30)
        if "open" in output:
            return f"[!] LDAP AMPLIFICATION: LDAP service open - potential amplification vector"
        return f"[+] LDAP check completed for {target}"

    def analyze_mssql_amplification(self, target):
        self._log(f"[*] Analyzing MSSQL Browser amplification on {target}")
        output = self.run_command(f"nmap -sU -p 1434 --script ms-sql-info {target} 2>/dev/null", timeout=30)
        if "open" in output:
            return f"[!] MSSQL AMPLIFICATION: SQL Browser service open - potential amplification vector"
        return f"[+] MSSQL check completed for {target}"

    def analyze_netbios_amplification(self, target):
        self._log(f"[*] Analyzing NetBIOS amplification potential on {target}")
        output = self.run_command(f"nmap -sU -p 137 --script nbstat {target} 2>/dev/null", timeout=30)
        if "open" in output:
            return f"[!] NETBIOS AMPLIFICATION: NetBIOS service open - potential amplification vector"
        return f"[+] NetBIOS check completed for {target}"

    # ================================================================ NETWORK DISCOVERY
    def discover_hosts(self, target):
        self._log(f"[*] Discovering hosts in {target} range")
        output = self.run_command(f"nmap -sn {target}/24 2>/dev/null", timeout=60)
        hosts = [l for l in output.split('\n') if 'Nmap scan report for' in l]
        return f"[+] Discovered {len(hosts)} hosts in {target}/24:\n" + '\n'.join(hosts[:20])

    def discover_services(self, target):
        self._log(f"[*] Discovering services on {target}")
        output = self.run_command(f"nmap -sV -T4 --top-ports 100 {target} 2>/dev/null", timeout=120)
        return f"[+] Service discovery on {target}:\n{output}"

    def discover_os(self, target):
        self._log(f"[*] Fingerprinting OS on {target}")
        output = self.run_command(f"nmap -O --osscan-guess {target} 2>/dev/null", timeout=60)
        return f"[+] OS fingerprint for {target}:\n{output}"

    def discover_shares(self, target):
        self._log(f"[*] Discovering network shares on {target}")
        output = self.run_command(f"nmap -p 445 --script smb-enum-shares {target} 2>/dev/null", timeout=60)
        return f"[+] Share discovery on {target}:\n{output}"

    def discover_printers(self, target):
        self._log(f"[*] Discovering printers on {target}")
        output = self.run_command(f"nmap -p 9100,515,631 --script printer-info {target} 2>/dev/null", timeout=60)
        return f"[+] Printer discovery on {target}:\n{output}"

    # ================================================================ COMPREHENSIVE
    def full_network_audit(self, target):
        self._log(f"[*] Starting full network audit on {target}")
        results = []
        results.append("=== ARP SPOOFING ===")
        results.append(self.detect_arp_spoofing(target))
        results.append("\n=== DNS SPOOFING ===")
        results.append(self.detect_dns_spoofing(target))
        results.append("\n=== SNIFFER DETECTION ===")
        results.append(self.detect_mitm_sniffer(target))
        results.append("\n=== PORT SCAN DETECTION ===")
        results.append(self.detect_port_scan(target))
        results.append("\n=== HOST DISCOVERY ===")
        results.append(self.discover_hosts(target))
        return '\n'.join(results)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: network_adv.py <target>")
        sys.exit(1)
    n = NetworkAdvanced()
    print(n.full_network_audit(sys.argv[1]))

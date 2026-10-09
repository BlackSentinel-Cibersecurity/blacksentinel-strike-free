#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════
    ROOTKIT DETECTION MODULE - BlackSentinel Strike v4.0
═══════════════════════════════════════════════════════════════
Copyright (c) 2024-2025 BlackSentinel Strike - All Rights Reserved
"""

import subprocess
import os
import re
import hashlib
import time
import shutil
import glob
from datetime import datetime


class RootkitDetection:
    """Comprehensive rootkit detection module covering user-space,
    kernel-space, eBPF, bootkit, and cross-view detection techniques."""

    def __init__(self, callback=None):
        self.callback = callback
        self.results = {}

    def log(self, message, level="info"):
        if self.callback:
            self.callback(message, level)

    def run_command(self, cmd, timeout=30):
        """Execute a shell command and return stdout."""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=timeout
            )
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            return "TIMEOUT: Command exceeded time limit"
        except Exception as e:
            return f"ERROR: {str(e)}"

    def _require_tool(self, tool):
        return shutil.which(tool) is not None

    # ───────────────────────────────────────────────────────────
    #  1. USER-SPACE ROOTKIT DETECTION
    # ───────────────────────────────────────────────────────────

    def detect_ld_preload_rootkit(self, target=None):
        """Detect LD_PRELOAD-based rootkits by checking environment and ld.so.preload."""
        results = []
        ld_env = self.run_command("echo $LD_PRELOAD")
        if ld_env and "TIMEOUT" not in ld_env:
            results.append(f"LD_PRELOAD set to: {ld_env}")
        else:
            results.append("LD_PRELOAD not set in current environment")

        ld_preload_file = self.run_command("cat /etc/ld.so.preload 2>/dev/null")
        if ld_preload_file and "No such file" not in ld_preload_file:
            results.append(f"/etc/ld.so.preload contents: {ld_preload_file}")

        global_ld = self.run_command("ls /etc/ld.so.preload 2>/dev/null && cat /etc/ld.so.preload")
        if global_ld and "No such file" not in global_ld:
            results.append(f"System-wide preload detected: {global_ld}")

        suspicious_envs = self.run_command(
            "env | grep -iE '(LD_PRELOAD|LD_LIBRARY_PATH|LD_ELF_LIBRARY_PATH)' 2>/dev/null"
        )
        if suspicious_envs:
            results.append(f"Suspicious env vars: {suspicious_envs}")

        for profile in ["/etc/profile", "/etc/profile.d/*.sh"]:
            content = self.run_command(f"grep -l 'LD_PRELOAD' {profile} 2>/dev/null")
            if content:
                results.append(f"LD_PRELOAD reference found in: {content}")

        bashrc_injection = self.run_command(
            "grep -rn 'LD_PRELOAD' ~/.bashrc ~/.bash_profile ~/.profile /etc/bash.bashrc 2>/dev/null"
        )
        if bashrc_injection:
            results.append(f"LD_PRELOAD in shell profiles: {bashrc_injection}")

        pldd_check = self.run_command("ldd /bin/ls 2>/dev/null | grep -i 'not found'")
        if pldd_check:
            results.append(f"Missing libraries: {pldd_check}")

        results.append(f"ld.so.preload file exists: {os.path.exists('/etc/ld.so.preload')}")
        self.results["ld_preload"] = results
        return "\n".join(results)

    def detect_process_hiding(self, target=None):
        """Detect hidden processes by comparing /proc with ps output."""
        results = []

        ps_output = self.run_command("ps -e --no-headers -o pid 2>/dev/null")
        if not ps_output or "ERROR" in ps_output:
            ps_output = self.run_command("ps -e -o pid= 2>/dev/null")
        ps_pids = set(ps_output.split()) if ps_output else set()

        proc_pids = set()
        try:
            for entry in os.listdir("/proc"):
                if entry.isdigit():
                    proc_pids.add(entry)
        except PermissionError:
            results.append("Cannot read /proc - insufficient permissions")
            return "\n".join(results)

        hidden_in_proc = ps_pids - proc_pids
        hidden_in_ps = proc_pids - ps_pids

        if hidden_in_proc:
            results.append(f"PIDs in ps but not in /proc: {hidden_in_proc}")
        if hidden_in_ps:
            results.append(f"PIDs in /proc but not in ps: {hidden_in_ps}")
        if not hidden_in_proc and not hidden_in_ps:
            results.append("No hidden processes detected via /proc vs ps comparison")

        for pid in list(ps_pids)[:20]:
            exe_link = self.run_command(f"readlink /proc/{pid}/exe 2>/dev/null")
            if exe_link and "[deleted]" in exe_link:
                results.append(f"PID {pid} has deleted executable: {exe_link}")

        cmdline_check = self.run_command(
            "for pid in $(ls /proc/ | grep '^[0-9]' | head -30); do "
            "if [ ! -r /proc/$pid/cmdline ]; then echo \"PID $pid cmdline not readable\"; fi; done"
        )
        if cmdline_check:
            results.append(f"Unreadable cmdlines: {cmdline_check}")

        self.results["process_hiding"] = results
        return "\n".join(results)

    def detect_file_hiding(self, target=None):
        """Detect hidden files using multiple methods."""
        results = []

        hidden_tmp = self.run_command("find /tmp -name '.*' -type f 2>/dev/null | head -20")
        if hidden_tmp:
            results.append(f"Hidden files in /tmp:\n{hidden_tmp}")

        hidden_dev = self.run_command("find /dev -name '.*' -type f 2>/dev/null | head -20")
        if hidden_dev:
            results.append(f"Hidden files in /dev:\n{hidden_dev}")

        dotdir_check = self.run_command(
            "find / -maxdepth 3 -name '.*' -type d 2>/dev/null | grep -v -E '(/proc|/sys|/dev|/home|/root)' | head -20"
        )
        if dotdir_check:
            results.append(f"Suspicious hidden directories: {dotdir_check}")

        suid_check = self.run_command(
            "find /tmp /var/tmp /dev/shm -perm -4000 2>/dev/null | head -10"
        )
        if suid_check:
            results.append(f"SUID files in temp directories: {suid_check}")

        shm_check = self.run_command("ls -la /dev/shm/ 2>/dev/null")
        if shm_check:
            results.append(f"/dev/shm contents: {shm_check}")

        immutable_check = self.run_command(
            "find /tmp /var/tmp -type f -exec lsattr {} + 2>/dev/null | grep -E 'i-|a-' | head -10"
        )
        if immutable_check:
            results.append(f"Immutable files in temp dirs: {immutable_check}")

        self.results["file_hiding"] = results
        return "\n".join(results)

    def detect_process_injection(self, target=None):
        """Detect process injection via /proc/maps analysis."""
        results = []

        suspicious_maps = self.run_command(
            "grep -r 'rwx.*anon' /proc/*/maps 2>/dev/null | head -30"
        )
        if suspicious_maps:
            results.append(f"Anonymous executable mappings:\n{suspicious_maps}")

        memfd_check = self.run_command(
            "ls -la /proc/*/fd/ 2>/dev/null | grep memfd | head -20"
        )
        if memfd_check:
            results.append(f"memfd file descriptors detected:\n{memfd_check}")

        deleted_maps = self.run_command(
            "grep 'deleted' /proc/*/maps 2>/dev/null | head -30"
        )
        if deleted_maps:
            results.append(f"Deleted file mappings:\n{deleted_maps}")

        heap_exec = self.run_command(
            "grep -E 'rw-p.*heap' /proc/*/maps 2>/dev/null | grep -v grep | head -10"
        )
        if heap_exec:
            results.append(f"Writable heap segments: {heap_exec}")

        ptrace_check = self.run_command(
            "grep -l 'TracerPid' /proc/*/status 2>/dev/null | while read f; do "
            "pid=$(echo $f | cut -d/ -f3); "
            "tracer=$(grep TracerPid $f | awk '{print $2}'); "
            "if [ \"$tracer\" != \"0\" ]; then echo \"PID $pid traced by PID $tracer\"; fi; done"
        )
        if ptrace_check:
            results.append(f"Processes being traced: {ptrace_check}")

        self.results["process_injection"] = results
        return "\n".join(results)

    def detect_library_injection(self, target=None):
        """Detect shared library injection via LD_PRELOAD and /etc/ld.so.conf."""
        results = []

        preload_check = self.run_command("cat /etc/ld.so.preload 2>/dev/null")
        if preload_check and "No such file" not in preload_check:
            results.append(f"Active /etc/ld.so.preload: {preload_check}")

        ld_path = self.run_command(
            "echo $LD_LIBRARY_PATH; echo $LD_PRELOAD; echo $LD_ELF_LIBRARY_PATH"
        )
        if ld_path:
            results.append(f"Loader env vars: {ld_path}")

        loaded_libs = self.run_command(
            "grep -h '\\.so' /proc/[0-9]*/maps 2>/dev/null | sort -u | head -40"
        )
        if loaded_libs:
            results.append(f"Unique loaded shared objects:\n{loaded_libs}")

        ld_conf = self.run_command("cat /etc/ld.so.conf 2>/dev/null")
        if ld_conf:
            results.append(f"ld.so.conf contents:\n{ld_conf}")

        custom_paths = self.run_command(
            "grep -r '^include' /etc/ld.so.conf.d/ 2>/dev/null"
        )
        if custom_paths:
            results.append(f"ld.so.conf.d includes: {custom_paths}")

        unusual_libs = self.run_command(
            "find /usr/lib /lib /usr/local/lib -name '*.so.*' -newer /bin/ls 2>/dev/null | head -20"
        )
        if unusual_libs:
            results.append(f"Recently modified shared libraries: {unusual_libs}")

        self.results["library_injection"] = results
        return "\n".join(results)

    def detect_persistence_mechanisms(self, target=None):
        """Detect user-space persistence mechanisms."""
        results = []

        cron_user = self.run_command("crontab -l 2>/dev/null")
        if cron_user:
            results.append(f"User crontab: {cron_user}")

        cron_system = self.run_command("ls -la /etc/cron* 2>/dev/null")
        if cron_system:
            results.append(f"System cron directories:\n{cron_system}")

        cron_suspicious = self.run_command(
            "find /etc/cron* -type f -exec grep -l -E '(wget|curl|nc|bash|python|perl)' {} \\; 2>/dev/null"
        )
        if cron_suspicious:
            results.append(f"Suspicious cron jobs: {cron_suspicious}")

        systemd_user = self.run_command(
            "find ~/.config/systemd/user -name '*.service' 2>/dev/null | head -10"
        )
        if systemd_user:
            results.append(f"User systemd services: {systemd_user}")

        init_check = self.run_command("ls /etc/init.d/ 2>/dev/null | head -20")
        if init_check:
            results.append(f"Init.d scripts: {init_check}")

        at_check = self.run_command("atq 2>/dev/null")
        if at_check:
            results.append(f"Scheduled at jobs: {at_check}")

        autostart = self.run_command(
            "find ~/.config/autostart /etc/xdg/autostart -name '*.desktop' 2>/dev/null | head -10"
        )
        if autostart:
            results.append(f"Autostart entries: {autostart}")

        self.results["persistence"] = results
        return "\n".join(results)

    def detect_hidden_users(self, target=None):
        """Detect hidden or modified user accounts."""
        results = []

        passwd_content = self.run_command("cat /etc/passwd")
        if passwd_content:
            for line in passwd_content.strip().split("\n"):
                parts = line.split(":")
                if len(parts) >= 7:
                    uid = int(parts[2])
                    if uid == 0 and parts[0] != "root":
                        results.append(f"Non-root UID 0 account: {parts[0]}")

            shadow_content = self.run_command("sudo cat /etc/shadow 2>/dev/null")
            if shadow_content and "Permission denied" not in shadow_content:
                for line in shadow_content.strip().split("\n"):
                    parts = line.split(":")
                    if len(parts) >= 2 and parts[1] == "":
                        results.append(f"Account with empty password: {parts[0]}")

        group_check = self.run_command("grep ':0:' /etc/group 2>/dev/null")
        if group_check:
            results.append(f"Groups with GID 0: {group_check}")

        sudo_check = self.run_command(
            "grep -v '^#' /etc/sudoers 2>/dev/null | grep -E 'ALL|NOPASSWD' | head -10"
        )
        if sudo_check:
            results.append(f"Sudoers entries: {sudo_check}")

        authorized_keys = self.run_command(
            "find /home -name 'authorized_keys' -exec ls -la {} \\; 2>/dev/null"
        )
        if authorized_keys:
            results.append(f"SSH authorized_keys files:\n{authorized_keys}")

        self.results["hidden_users"] = results
        return "\n".join(results)

    def detect_suid_rootkit(self, target=None):
        """Detect SUID/SGID rootkit binaries."""
        results = []

        suid_files = self.run_command("find / -perm -4000 -type f 2>/dev/null | head -30")
        if suid_files:
            results.append(f"SUID binaries:\n{suid_files}")

        sgid_files = self.run_command("find / -perm -2000 -type f 2>/dev/null | head -30")
        if sgid_files:
            results.append(f"SGID binaries:\n{sgid_files}")

        known_good = {
            "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/chsh",
            "/usr/bin/chfn", "/usr/bin/newgrp", "/usr/bin/gpasswd",
            "/usr/bin/mount", "/usr/bin/umount", "/usr/bin/fusermount",
            "/usr/lib/openssh/ssh-keysign", "/usr/bin/pkexec"
        }

        if suid_files:
            for f in suid_files.split("\n"):
                if f.strip() and f.strip() not in known_good:
                    results.append(f"Non-standard SUID binary: {f.strip()}")

        world_writable = self.run_command(
            "find / -perm -0002 -type f -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -20"
        )
        if world_writable:
            results.append(f"World-writable files: {world_writable}")

        self.results["suid_rootkit"] = results
        return "\n".join(results)

    def detect_netcat_backdoor(self, target=None):
        """Detect netcat-based backdoors and reverse shells."""
        results = []

        nc_procs = self.run_command(
            "ps aux | grep -E '(nc |ncat |netcat |socat )' | grep -v grep"
        )
        if nc_procs:
            results.append(f"Netcat/socat processes:\n{nc_procs}")

        reverse_shells = self.run_command(
            "ps aux | grep -E '(bash -i|/dev/tcp|mkfifo|nc -e|ncat -e)' | grep -v grep"
        )
        if reverse_shells:
            results.append(f"Possible reverse shells:\n{reverse_shells}")

        listening = self.run_command("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
        if listening:
            results.append(f"Listening ports:\n{listening}")

        established = self.run_command("ss -tnp state established 2>/dev/null | head -20")
        if established:
            results.append(f"Established connections:\n{established}")

        nc_cron = self.run_command(
            "grep -rn 'nc\\|netcat\\|ncat' /etc/cron* 2>/dev/null"
        )
        if nc_cron:
            results.append(f"Netcat in cron: {nc_cron}")

        self.results["netcat_backdoor"] = results
        return "\n".join(results)

    def detect_ssh_backdoor(self, target=None):
        """Detect SSH-based backdoors and trojanized SSH."""
        results = []

        auth_keys = self.run_command(
            "find / -name 'authorized_keys' -o -name 'authorized_keys2' 2>/dev/null | head -20"
        )
        if auth_keys:
            for keyfile in auth_keys.split("\n"):
                if keyfile.strip():
                    content = self.run_command(f"cat {keyfile.strip()} 2>/dev/null")
                    if content:
                        results.append(f"Keys in {keyfile.strip()}:\n{content}")

        sshd_config = self.run_command(
            "grep -iE '(PermitRootLogin|PasswordAuthentication|AuthorizedKeysFile)' /etc/ssh/sshd_config 2>/dev/null"
        )
        if sshd_config:
            results.append(f"SSH config settings:\n{sshd_config}")

        ssh_binary_check = self.run_command(
            "sha256sum /usr/bin/ssh /usr/sbin/sshd /usr/bin/scp /usr/bin/sftp 2>/dev/null"
        )
        if ssh_binary_check:
            results.append(f"SSH binary hashes:\n{ssh_binary_check}")

        agent_check = self.run_command("ls -la /tmp/ssh-* 2>/dev/null")
        if agent_check:
            results.append(f"SSH agent sockets: {agent_check}")

        sshd_modified = self.run_command(
            "rpm -V openssh-server 2>/dev/null || dpkg -V openssh-server 2>/dev/null"
        )
        if sshd_modified:
            results.append(f"SSH package verification:\n{sshd_modified}")

        self.results["ssh_backdoor"] = results
        return "\n".join(results)

    def detect_rootkit_files(self, target=None):
        """Detect known rootkit file artifacts."""
        results = []

        known_rootkit_paths = [
            "/usr/share/.0wn", "/dev/.udev/rules.d",
            "/etc/cron.d/.quiet", "/usr/lib/.libhide",
            "/usr/lib/security", "/usr/share/.cinik",
            "/etc/ld.so.preload", "/dev/.udev/.udev.tdb",
            "/var/tmp/.bash_history", "/dev/shm/.x",
            "/tmp/.ICE-unix/.x", "/tmp/.X11-unix/.x",
            "/dev/.init.d", "/dev/.hg",
        ]

        for path in known_rootkit_paths:
            if os.path.exists(path):
                stat_info = self.run_command(f"ls -la {path} 2>/dev/null")
                results.append(f"Rootkit artifact found: {path} - {stat_info}")

        dev_hidden = self.run_command(
            "ls -la /dev/ 2>/dev/null | grep -E '^\\.' | head -20"
        )
        if dev_hidden:
            results.append(f"Hidden entries in /dev:\n{dev_hidden}")

        modified_bins = self.run_command(
            "find /usr/bin /usr/sbin /bin /sbin -newer /etc/hostname 2>/dev/null | head -20"
        )
        if modified_bins:
            results.append(f"Recently modified binaries:\n{modified_bins}")

        self.results["rootkit_files"] = results
        return "\n".join(results)

    def detect_keylogger(self, target=None):
        """Detect keylogger processes and modules."""
        results = []

        keylogger_procs = self.run_command(
            "ps aux | grep -iE '(keylog|lkl|uberkey|logkeys|input-event)' | grep -v grep"
        )
        if keylogger_procs:
            results.append(f"Suspicious keylogger processes:\n{keylogger_procs}")

        input_readers = self.run_command("fuser /dev/input/event* 2>/dev/null")
        if input_readers:
            results.append(f"Processes accessing input devices: {input_readers}")

        input_access = self.run_command("lsof /dev/input/ 2>/dev/null | head -20")
        if input_access:
            results.append(f"Input device access:\n{input_access}")

        libhook = self.run_command(
            "find /usr/lib /lib -name '*hook*' -o -name '*keylog*' 2>/dev/null | head -10"
        )
        if libhook:
            results.append(f"Hook/keylog libraries: {libhook}")

        xkeylog = self.run_command(
            "ps aux | grep -iE '(xinput|xev|xtrace|xkeysniffer)' | grep -v grep"
        )
        if xkeylog:
            results.append(f"X11 input monitoring: {xkeylog}")

        self.results["keylogger"] = results
        return "\n".join(results)

    def detect_timestomping(self, target=None):
        """Detect timestomping by comparing filesystem timestamps."""
        results = []

        recent_bins = self.run_command(
            "find /usr/bin /usr/sbin /bin /sbin -mtime -1 -type f 2>/dev/null | head -20"
        )
        if recent_bins:
            results.append(f"Recently modified system binaries:\n{recent_bins}")

        key_files = ["/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers"]
        for f in key_files:
            if os.path.exists(f):
                stat_out = self.run_command(f"stat {f} 2>/dev/null")
                if stat_out:
                    results.append(f"Timestamp for {f}:\n{stat_out}")

        future_files = self.run_command(
            "find / -mtime -365 -type f -newer /tmp 2>/dev/null | head -10"
        )
        if future_files:
            results.append(f"Files with unusual timestamps:\n{future_files}")

        self.results["timestomping"] = results
        return "\n".join(results)

    def detect_hidden_connections(self, target=None):
        """Detect hidden network connections not shown by standard tools."""
        results = []

        proc_tcp = self.run_command("cat /proc/net/tcp 2>/dev/null | wc -l")
        ss_count = self.run_command("ss -tn 2>/dev/null | tail -n +2 | wc -l")
        if proc_tcp and ss_count:
            proc_n = int(proc_tcp) - 1 if proc_tcp.isdigit() else 0
            ss_n = int(ss_count) if ss_count.isdigit() else 0
            if proc_n != ss_n:
                results.append(f"Connection count mismatch: /proc/net/tcp={proc_n}, ss={ss_n}")
            else:
                results.append(f"Connection counts match: {proc_n}")

        proc_tcp6 = self.run_command("cat /proc/net/tcp6 2>/dev/null | head -20")
        if proc_tcp6:
            results.append(f"/proc/net/tcp6 sample:\n{proc_tcp6}")

        raw_sockets = self.run_command("ss -wnp 2>/dev/null | head -10")
        if raw_sockets:
            results.append(f"Raw sockets:\n{raw_sockets}")

        self.results["hidden_connections"] = results
        return "\n".join(results)

    # ───────────────────────────────────────────────────────────
    #  2. KERNEL-SPACE ROOTKIT DETECTION
    # ───────────────────────────────────────────────────────────

    def detect_kernel_modules(self, target=None):
        """Detect malicious or hidden kernel modules."""
        results = []

        loaded_modules = self.run_command("lsmod 2>/dev/null")
        if loaded_modules:
            results.append(f"Loaded modules:\n{loaded_modules}")

        proc_modules = self.run_command("cat /proc/modules 2>/dev/null")
        if proc_modules:
            proc_mod_names = set()
            for line in proc_modules.strip().split("\n"):
                if line.strip():
                    proc_mod_names.add(line.split()[0])

            lsmod_names = set()
            if loaded_modules:
                for line in loaded_modules.strip().split("\n")[1:]:
                    if line.strip():
                        lsmod_names.add(line.split()[0])

            hidden = proc_mod_names - lsmod_names
            if hidden:
                results.append(f"Modules in /proc/modules but not in lsmod: {hidden}")

        unsigned = self.run_command(
            "find /lib/modules/$(uname -r) -name '*.ko' -exec file {} \\; 2>/dev/null | grep -i 'not signed' | head -10"
        )
        if unsigned:
            results.append(f"Unsigned kernel modules: {unsigned}")

        dmesg_modules = self.run_command(
            "dmesg 2>/dev/null | grep -iE '(module|insmod|modprobe)' | tail -20"
        )
        if dmesg_modules:
            results.append(f"Module activity in dmesg:\n{dmesg_modules}")

        self.results["kernel_modules"] = results
        return "\n".join(results)

    def detect_kernel_hiding(self, target=None):
        """Detect hidden kernel modules via multiple methods."""
        results = []

        proc_mods = self.run_command(
            "awk '{print $1}' /proc/modules 2>/dev/null | sort"
        )
        sysfs_mods = self.run_command("ls /sys/module/ 2>/dev/null | sort")
        if proc_mods and sysfs_mods:
            proc_set = set(proc_mods.strip().split("\n"))
            sysfs_set = set(sysfs_mods.strip().split("\n"))
            hidden = proc_set - sysfs_set
            if hidden:
                results.append(f"Modules hidden from sysfs: {hidden}")

        taint = self.run_command("cat /proc/sys/kernel/tainted 2>/dev/null")
        if taint and taint != "0":
            results.append(f"Kernel tainted value: {taint}")
            results.append("Possible reasons: unsigned module loaded, OOPS, proprietary module")

        syscall_info = self.run_command(
            "cat /proc/kallsyms 2>/dev/null | grep -i 'sys_call_table' | head -5"
        )
        if syscall_info:
            results.append(f"Syscall table info: {syscall_info}")

        self.results["kernel_hiding"] = results
        return "\n".join(results)

    def detect_kernel_integrity(self, target=None):
        """Check kernel image and module integrity."""
        results = []

        kernel_image = self.run_command("uname -v 2>/dev/null")
        results.append(f"Kernel version: {kernel_image}")

        taint = self.run_command("cat /proc/sys/kernel/tainted 2>/dev/null")
        results.append(f"Kernel tainted status: {taint}")

        kconfig = self.run_command(
            "cat /boot/config-$(uname -r) 2>/dev/null | grep -iE '(LOCKDOWN|SECURITY|IOMMU)' | head -10"
        )
        if kconfig:
            results.append(f"Kernel security config:\n{kconfig}")

        secure_boot = self.run_command(
            "mokutil --sb-state 2>/dev/null || echo 'mokutil not available'"
        )
        results.append(f"Secure Boot: {secure_boot}")

        iommu = self.run_command("dmesg 2>/dev/null | grep -i iommu | head -5")
        if iommu:
            results.append(f"IOMMU status:\n{iommu}")

        lockdown = self.run_command("cat /sys/kernel/security/lockdown 2>/dev/null")
        if lockdown:
            results.append(f"Kernel lockdown: {lockdown}")

        self.results["kernel_integrity"] = results
        return "\n".join(results)

    def detect_syscall_hooking(self, target=None):
        """Detect syscall table hooking via kallsyms."""
        results = []

        syscall_table = self.run_command(
            "cat /proc/kallsyms 2>/dev/null | grep -i 'sys_call_table\\|__sys_call' | head -10"
        )
        if syscall_table:
            results.append(f"Syscall table: {syscall_table}")

        hooks_check = self.run_command(
            "cat /proc/kallsyms 2>/dev/null | grep -iE '(hooked|hook|intercept)' | head -10"
        )
        if hooks_check:
            results.append(f"Hook-related symbols: {hooks_check}")

        hook_dmesg = self.run_command(
            "dmesg 2>/dev/null | grep -iE '(hook|syscall|table)' | tail -10"
        )
        if hook_dmesg:
            results.append(f"Hook-related dmesg:\n{hook_dmesg}")

        ftrace = self.run_command(
            "cat /sys/kernel/debug/tracing/set_ftrace_filter 2>/dev/null | head -10"
        )
        if ftrace and ftrace.strip():
            results.append(f"Ftrace filter active: {ftrace}")

        self.results["syscall_hooking"] = results
        return "\n".join(results)

    def detect_rootkit_lkm(self, target=None):
        """Detect Loadable Kernel Module rootkits."""
        results = []

        known_signatures = [
            "adore", "enyelkm", "hideLKM", "suckit", "rial",
            "kernvac", "knark", "reptile", "diamorphine", "kovid",
        ]

        lsmod_out = self.run_command("lsmod 2>/dev/null")
        if lsmod_out:
            for sig in known_signatures:
                if sig.lower() in lsmod_out.lower():
                    results.append(f"KNOWN ROOTKIT MODULE DETECTED: {sig}")

        module_sizes = self.run_command(
            "lsmod 2>/dev/null | awk 'NR>1 {print $1, $2}' | sort -k2 -n | head -20"
        )
        if module_sizes:
            results.append(f"Module sizes:\n{module_sizes}")

        recent_modules = self.run_command(
            "dmesg 2>/dev/null | grep -i 'insmod\\|modprobe' | tail -10"
        )
        if recent_modules:
            results.append(f"Recent module loads:\n{recent_modules}")

        orphan_modules = self.run_command(
            "find /lib/modules/$(uname -r) -name '*.ko' 2>/dev/null | while read m; do "
            "modname=$(basename $m .ko); "
            "if ! grep -q $modname /proc/modules 2>/dev/null; then echo \"Unused: $m\"; fi; done | head -10"
        )
        if orphan_modules:
            results.append(f"Unused kernel modules: {orphan_modules}")

        self.results["rootkit_lkm"] = results
        return "\n".join(results)

    def detect_dmesg_tampering(self, target=None):
        """Detect kernel log tampering."""
        results = []

        dmesg_output = self.run_command("dmesg 2>/dev/null | tail -30")
        if dmesg_output:
            results.append(f"Last dmesg entries:\n{dmesg_output}")

        dmesg_restrict = self.run_command(
            "cat /proc/sys/kernel/dmesg_restrict 2>/dev/null"
        )
        results.append(f"dmesg_restrict: {dmesg_restrict}")

        dmesg_count = self.run_command("dmesg 2>/dev/null | wc -l")
        results.append(f"dmesg line count: {dmesg_count}")

        journal_gaps = self.run_command(
            "journalctl -k --since '1 hour ago' 2>/dev/null | tail -10"
        )
        if journal_gaps:
            results.append(f"Recent kernel journal:\n{journal_gaps}")

        self.results["dmesg_tampering"] = results
        return "\n".join(results)

    def detect_interrupt_hooking(self, target=None):
        """Detect interrupt descriptor table hooking."""
        results = []

        idt_check = self.run_command("cat /proc/interrupts 2>/dev/null | head -20")
        if idt_check:
            results.append(f"Interrupt info:\n{idt_check}")

        irq_affinity = self.run_command(
            "ls /proc/irq/*/smp_affinity_list 2>/dev/null | head -10"
        )
        if irq_affinity:
            results.append(f"IRQ affinity entries: {irq_affinity}")

        interrupt_stats = self.run_command(
            "cat /proc/interrupts 2>/dev/null | awk '{if(NR>1) print $1, $2}' | sort -k2 -n | tail -10"
        )
        if interrupt_stats:
            results.append(f"High interrupt counts:\n{interrupt_stats}")

        self.results["interrupt_hooking"] = results
        return "\n".join(results)

    def detect_netfilter_hooking(self, target=None):
        """Detect Netfilter/iptables hooking."""
        results = []

        iptables = self.run_command("iptables -L -n -v 2>/dev/null")
        if iptables:
            results.append(f"iptables rules:\n{iptables}")

        raw_table = self.run_command("iptables -t raw -L -n 2>/dev/null")
        if raw_table:
            results.append(f"iptables raw table:\n{raw_table}")

        mangle_table = self.run_command("iptables -t mangle -L -n 2>/dev/null")
        if mangle_table:
            results.append(f"iptables mangle table:\n{mangle_table}")

        nft = self.run_command("nft list ruleset 2>/dev/null | head -30")
        if nft:
            results.append(f"nftables rules:\n{nft}")

        nf_modules = self.run_command(
            "lsmod 2>/dev/null | grep -i 'nf\\|ipt\\|ip6\\|nft'"
        )
        if nf_modules:
            results.append(f"Netfilter modules:\n{nf_modules}")

        self.results["netfilter_hooking"] = results
        return "\n".join(results)

    def detect_kprobe_hooking(self, target=None):
        """Detect kprobe-based hooking."""
        results = []

        kprobes = self.run_command(
            "cat /sys/kernel/debug/kprobes/list 2>/dev/null | head -20"
        )
        if kprobes and kprobes.strip():
            results.append(f"Active kprobes:\n{kprobes}")

        kprobe_events = self.run_command(
            "cat /sys/kernel/debug/tracing/kprobe_events 2>/dev/null | head -20"
        )
        if kprobe_events and kprobe_events.strip():
            results.append(f"Kprobe events:\n{kprobe_events}")

        fentry = self.run_command(
            "cat /sys/kernel/debug/tracing/set_ftrace_filter 2>/dev/null | head -10"
        )
        if fentry and fentry.strip():
            results.append(f"Ftrace filter: {fentry}")

        kretprobes = self.run_command(
            "ls /sys/kernel/debug/tracing/events/kprobes/ 2>/dev/null | head -10"
        )
        if kretprobes:
            results.append(f"Kretprobe events: {kretprobes}")

        self.results["kprobe_hooking"] = results
        return "\n".join(results)

    # ───────────────────────────────────────────────────────────
    #  3. eBPF DETECTION
    # ───────────────────────────────────────────────────────────

    def detect_ebpf_programs(self, target=None):
        """Detect loaded eBPF programs."""
        results = []

        bpftool_prog = self.run_command("bpftool prog show 2>/dev/null | head -40")
        if bpftool_prog:
            results.append(f"Loaded eBPF programs:\n{bpftool_prog}")

        bpf_fs = self.run_command("ls -la /sys/fs/bpf/ 2>/dev/null")
        if bpf_fs:
            results.append(f"BPF filesystem:\n{bpf_fs}")

        proc_bpf = self.run_command("cat /proc/net/bpf/stats 2>/dev/null")
        if proc_bpf:
            results.append(f"BPF stats:\n{proc_bpf}")

        bpf_maps = self.run_command("bpftool map show 2>/dev/null | head -20")
        if bpf_maps:
            results.append(f"BPF maps:\n{bpf_maps}")

        self.results["ebpf_programs"] = results
        return "\n".join(results)

    def detect_ebpf_network_filtering(self, target=None):
        """Detect eBPF-based network filtering rootkits."""
        results = []

        xdp_check = self.run_command("bpftool net show 2>/dev/null | head -20")
        if xdp_check:
            results.append(f"BPF network attachments:\n{xdp_check}")

        tc_bpf = self.run_command("tc filter show dev eth0 2>/dev/null | head -20")
        if tc_bpf:
            results.append(f"TC BPF filters:\n{tc_bpf}")

        xdp_ifaces = self.run_command("ip link show 2>/dev/null | grep -B1 xdp")
        if xdp_ifaces:
            results.append(f"XDP attached interfaces:\n{xdp_ifaces}")

        af_xdp = self.run_command("ss -xlp 2>/dev/null | head -10")
        if af_xdp:
            results.append(f"AF_XDP sockets:\n{af_xdp}")

        self.results["ebpf_network"] = results
        return "\n".join(results)

    def detect_ebpf_tracing(self, target=None):
        """Detect eBPF tracing rootkits."""
        results = []

        tracing_progs = self.run_command(
            "bpftool prog show 2>/dev/null | grep -E '(tracepoint|kprobe|kretprobe|raw_tracepoint|cgroup)' | head -20"
        )
        if tracing_progs:
            results.append(f"Tracing eBPF programs:\n{tracing_progs}")

        perf_event = self.run_command(
            "cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null"
        )
        results.append(f"perf_event_paranoid: {perf_event}")

        bpf_lsm = self.run_command(
            "bpftool feature probe 2>/dev/null | grep -i lsm"
        )
        if bpf_lsm:
            results.append(f"BPF LSM support: {bpf_lsm}")

        cgroup_bpf = self.run_command(
            "bpftool cgroup show 2>/dev/null | head -20"
        )
        if cgroup_bpf:
            results.append(f"Cgroup BPF programs:\n{cgroup_bpf}")

        self.results["ebpf_tracing"] = results
        return "\n".join(results)

    def detect_ebpf_map_abuse(self, target=None):
        """Detect BPF map abuse for data exfiltration."""
        results = []

        map_list = self.run_command("bpftool map show 2>/dev/null | head -30")
        if map_list:
            results.append(f"BPF maps:\n{map_list}")

        map_details = self.run_command("bpftool map dump 2>/dev/null | head -30")
        if map_details:
            results.append(f"Map dump sample:\n{map_details}")

        large_maps = self.run_command(
            "bpftool map show 2>/dev/null | awk '$4 > 1048576 {print}'"
        )
        if large_maps:
            results.append(f"Large BPF maps (>1MB): {large_maps}")

        self.results["ebpf_map_abuse"] = results
        return "\n".join(results)

    def detect_ebpf_cgroup_manipulation(self, target=None):
        """Detect eBPF cgroup-based rootkit manipulation."""
        results = []

        cgroup_progs = self.run_command("bpftool cgroup show 2>/dev/null")
        if cgroup_progs:
            results.append(f"Cgroup BPF:\n{cgroup_progs}")

        cgroup_v2 = self.run_command(
            "cat /proc/filesystems 2>/dev/null | grep cgroup"
        )
        if cgroup_v2:
            results.append(f"Cgroup filesystems: {cgroup_v2}")

        cgroup_mount = self.run_command("mount | grep cgroup | head -10")
        if cgroup_mount:
            results.append(f"Cgroup mounts:\n{cgroup_mount}")

        socket_prog = self.run_command(
            "bpftool prog show 2>/dev/null | grep -i cgroup | head -10"
        )
        if socket_prog:
            results.append(f"Cgroup socket programs:\n{socket_prog}")

        self.results["ebpf_cgroup"] = results
        return "\n".join(results)

    # ───────────────────────────────────────────────────────────
    #  4. BOOTKIT DETECTION
    # ───────────────────────────────────────────────────────────

    def detect_bootkit_mbr(self, target=None):
        """Detect MBR-based bootkits."""
        results = []

        mbr_check = self.run_command(
            "dd if=/dev/sda bs=512 count=1 2>/dev/null | file -"
        )
        if mbr_check:
            results.append(f"MBR file signature: {mbr_check}")

        mbr_hash = self.run_command(
            "dd if=/dev/sda bs=512 count=1 2>/dev/null | sha256sum"
        )
        if mbr_hash:
            results.append(f"MBR SHA256: {mbr_hash}")

        mbr_ascii = self.run_command(
            "dd if=/dev/sda bs=512 count=1 2>/dev/null | xxd | head -32"
        )
        if mbr_ascii:
            results.append(f"MBR hex dump:\n{mbr_ascii}")

        boot_code = self.run_command(
            "dd if=/dev/sda bs=1 skip=446 count=60 2>/dev/null | xxd | head -5"
        )
        if boot_code:
            results.append(f"Boot code area: {boot_code}")

        self.results["bootkit_mbr"] = results
        return "\n".join(results)

    def detect_bootkit_efi(self, target=None):
        """Detect UEFI/EFI bootkits."""
        results = []

        esp_check = self.run_command("ls -la /boot/efi/ 2>/dev/null | head -20")
        if esp_check:
            results.append(f"EFI System Partition:\n{esp_check}")

        efivars = self.run_command(
            "ls /sys/firmware/efi/efivars/ 2>/dev/null | head -20"
        )
        if efivars:
            results.append(f"EFI variables:\n{efivars}")

        secure_boot = self.run_command(
            "mokutil --sb-state 2>/dev/null || echo 'Secure Boot check unavailable'"
        )
        results.append(f"Secure Boot state: {secure_boot}")

        efi_bins = self.run_command(
            "find /boot/efi -name '*.efi' -exec sha256sum {} \\; 2>/dev/null | head -10"
        )
        if efi_bins:
            results.append(f"EFI binary hashes:\n{efi_bins}")

        unusual_efi = self.run_command(
            "find /boot/efi -name '*.efi' -not -path '*/BOOT/*' -not -path '*/ubuntu/*' -not -path '*/debian/*' 2>/dev/null"
        )
        if unusual_efi:
            results.append(f"Unusual EFI binaries: {unusual_efi}")

        self.results["bootkit_efi"] = results
        return "\n".join(results)

    def detect_bootkit_grub(self, target=None):
        """Detect GRUB-based boot modifications."""
        results = []

        grub_cfg = self.run_command(
            "cat /boot/grub/grub.cfg 2>/dev/null | head -40"
        )
        if grub_cfg:
            results.append(f"GRUB config:\n{grub_cfg}")

        grub_mods = self.run_command("ls /boot/grub/ 2>/dev/null")
        if grub_mods:
            results.append(f"GRUB modules directory: {grub_mods}")

        grub_pass = self.run_command(
            "grep -i 'password' /boot/grub/grub.cfg 2>/dev/null"
        )
        if grub_pass:
            results.append(f"GRUB password: {grub_pass}")

        grubenv = self.run_command("cat /boot/grub/grubenv 2>/dev/null")
        if grubenv:
            results.append(f"GRUB environment:\n{grubenv}")

        grub_hash = self.run_command(
            "sha256sum /usr/sbin/grub-install /usr/bin/grub-mkconfig 2>/dev/null"
        )
        if grub_hash:
            results.append(f"GRUB binary hashes:\n{grub_hash}")

        self.results["bootkit_grub"] = results
        return "\n".join(results)

    def detect_bootkit_initramfs(self, target=None):
        """Detect initramfs-based bootkits."""
        results = []

        initramfs = self.run_command(
            "lsinitramfs /boot/initrd.img-$(uname -r) 2>/dev/null | head -30"
        )
        if initramfs:
            results.append(f"Initramfs contents sample:\n{initramfs}")

        initramfs_hash = self.run_command(
            "sha256sum /boot/initrd.img-$(uname -r) 2>/dev/null"
        )
        if initramfs_hash:
            results.append(f"Initramfs hash: {initramfs_hash}")

        init_script = self.run_command(
            "lsinitramfs /boot/initrd.img-$(uname -r) 2>/dev/null | grep init"
        )
        if init_script:
            results.append(f"Init scripts in initramfs: {init_script}")

        self.results["bootkit_initramfs"] = results
        return "\n".join(results)

    def detect_bootkit_vbr(self, target=None):
        """Detect Volume Boot Record modifications."""
        results = []

        for dev in ["/dev/sda", "/dev/sdb", "/dev/nvme0n1"]:
            vbr_check = self.run_command(
                f"dd if={dev} bs=512 count=1 2>/dev/null | file -"
            )
            if vbr_check and "ERROR" not in vbr_check:
                results.append(f"{dev} VBR: {vbr_check}")

            vbr_hash = self.run_command(
                f"dd if={dev} bs=512 count=1 2>/dev/null | sha256sum"
            )
            if vbr_hash and "ERROR" not in vbr_hash:
                results.append(f"{dev} VBR hash: {vbr_hash}")

        backup_sectors = self.run_command("fdisk -l 2>/dev/null | head -20")
        if backup_sectors:
            results.append(f"Partition info:\n{backup_sectors}")

        self.results["bootkit_vbr"] = results
        return "\n".join(results)

    def detect_firmware_rootkit(self, target=None):
        """Detect firmware-level rootkits."""
        results = []

        bios_date = self.run_command(
            "dmidecode -s bios-release-date 2>/dev/null"
        )
        if bios_date:
            results.append(f"BIOS date: {bios_date}")

        bios_version = self.run_command(
            "dmidecode -s bios-version 2>/dev/null"
        )
        if bios_version:
            results.append(f"BIOS version: {bios_version}")

        fw_ver = self.run_command(
            "dmidecode -s system-manufacturer 2>/dev/null"
        )
        if fw_ver:
            results.append(f"System manufacturer: {fw_ver}")

        tpm = self.run_command(
            "tpm2_getcap properties-fixed 2>/dev/null | head -10"
        )
        if tpm:
            results.append(f"TPM capabilities:\n{tpm}")

        intel_me = self.run_command(
            "dmesg 2>/dev/null | grep -iE '(intel.me|amd.psp|management.engine)' | head -5"
        )
        if intel_me:
            results.append(f"Intel ME/AMD PSP: {intel_me}")

        spi = self.run_command(
            "ls /dev/mem 2>/dev/null && echo '/dev/mem accessible - possible SPI flash access'"
        )
        if spi:
            results.append(spi)

        self.results["firmware_rootkit"] = results
        return "\n".join(results)

    # ───────────────────────────────────────────────────────────
    #  5. CROSS-VIEW DETECTION
    # ───────────────────────────────────────────────────────────

    def crossview_process_list(self, target=None):
        """Compare process lists from multiple sources to detect hidden processes."""
        results = []

        ps_out = self.run_command("ps -e -o pid= 2>/dev/null | sort -n")
        ps_pids = set(ps_out.split()) if ps_out else set()

        proc_pids = set()
        try:
            for entry in os.listdir("/proc"):
                if entry.isdigit():
                    proc_pids.add(entry)
        except PermissionError:
            results.append("Cannot read /proc")
            return "\n".join(results)

        pgrep_out = self.run_command("pgrep -la .* 2>/dev/null")
        pgrep_pids = set()
        if pgrep_out:
            for line in pgrep_out.split("\n"):
                if line.strip():
                    pgrep_pids.add(line.split()[0])

        hidden_from_ps = proc_pids - ps_pids
        hidden_from_proc = ps_pids - proc_pids
        hidden_from_pgrep = (ps_pids | proc_pids) - pgrep_pids

        if hidden_from_ps:
            results.append(f"PIDs visible in /proc but hidden from ps: {hidden_from_ps}")
        if hidden_from_proc:
            results.append(f"PIDs visible in ps but missing from /proc: {hidden_from_proc}")
        if hidden_from_pgrep:
            results.append(f"PIDs hidden from pgrep: {hidden_from_pgrep}")

        if not any([hidden_from_ps, hidden_from_proc, hidden_from_pgrep]):
            results.append("No process list discrepancies detected")

        self.results["crossview_process"] = results
        return "\n".join(results)

    def crossview_filesystem(self, target=None):
        """Compare filesystem views from multiple sources."""
        results = []

        ls_out = self.run_command("ls / 2>/dev/null")
        ls_files = set(ls_out.split("\n")) if ls_out else set()

        readdir_files = set()
        try:
            readdir_files = set(os.listdir("/"))
        except PermissionError:
            pass

        find_out = self.run_command(
            "find / -maxdepth 1 -type f -o -type d 2>/dev/null"
        )
        find_files = set()
        if find_out:
            for line in find_out.split("\n"):
                if line.strip():
                    find_files.add(os.path.basename(line.strip()))

        hidden_ls = readdir_files - ls_files
        hidden_find = readdir_files - find_files
        hidden_readdir = ls_files - readdir_files

        if hidden_ls:
            results.append(f"Files hidden from ls: {hidden_ls}")
        if hidden_find:
            results.append(f"Files hidden from find: {hidden_find}")
        if hidden_readdir:
            results.append(f"Files only visible in ls: {hidden_readdir}")

        if not any([hidden_ls, hidden_find, hidden_readdir]):
            results.append("No filesystem view discrepancies detected")

        self.results["crossview_filesystem"] = results
        return "\n".join(results)

    def crossview_network_connections(self, target=None):
        """Compare network connection lists from multiple sources."""
        results = []

        ss_out = self.run_command("ss -tn 2>/dev/null | tail -n +2")
        ss_conns = set()
        if ss_out:
            for line in ss_out.split("\n"):
                if line.strip():
                    ss_conns.add(line.strip())

        proc_tcp = self.run_command("cat /proc/net/tcp 2>/dev/null | tail -n +2")
        proc_conns = set()
        if proc_tcp:
            for line in proc_tcp.split("\n"):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 4:
                        local = parts[1]
                        remote = parts[2]
                        proc_conns.add(f"{local}:{remote}")

        netstat_out = self.run_command("netstat -tn 2>/dev/null | tail -n +3")
        netstat_conns = set()
        if netstat_out:
            for line in netstat_out.split("\n"):
                if line.strip():
                    netstat_conns.add(line.strip())

        ss_minus_proc = len(ss_conns) - len(proc_conns)
        if abs(ss_minus_proc) > 2:
            results.append(
                f"Connection count mismatch: ss={len(ss_conns)}, /proc/net/tcp={len(proc_conns)}"
            )

        ss_minus_netstat = len(ss_conns) - len(netstat_conns)
        if abs(ss_minus_netstat) > 2:
            results.append(
                f"Connection count mismatch: ss={len(ss_conns)}, netstat={len(netstat_conns)}"
            )

        if not results:
            results.append("No network connection view discrepancies detected")

        self.results["crossview_network"] = results
        return "\n".join(results)

    def crossview_kernel_modules(self, target=None):
        """Compare kernel module lists from multiple sources."""
        results = []

        lsmod_out = self.run_command("lsmod 2>/dev/null | tail -n +2")
        lsmod_set = set()
        if lsmod_out:
            for line in lsmod_out.split("\n"):
                if line.strip():
                    lsmod_set.add(line.split()[0])

        proc_modules = self.run_command("cat /proc/modules 2>/dev/null")
        proc_set = set()
        if proc_modules:
            for line in proc_modules.split("\n"):
                if line.strip():
                    proc_set.add(line.split()[0])

        sysfs_set = set()
        try:
            for entry in os.listdir("/sys/module"):
                sysfs_set.add(entry)
        except PermissionError:
            pass

        ko_files = self.run_command(
            "find /lib/modules/$(uname -r) -name '*.ko' 2>/dev/null | while read f; do basename $f .ko; done"
        )
        ko_set = set()
        if ko_files:
            ko_set = set(ko_files.split("\n"))

        hidden_from_lsmod = proc_set - lsmod_set
        hidden_from_proc = lsmod_set - proc_set
        hidden_from_sysfs = lsmod_set - sysfs_set

        if hidden_from_lsmod:
            results.append(f"Modules hidden from lsmod: {hidden_from_lsmod}")
        if hidden_from_proc:
            results.append(f"Modules in lsmod but not /proc: {hidden_from_proc}")
        if hidden_from_sysfs:
            results.append(f"Modules hidden from sysfs: {hidden_from_sysfs}")

        unused_ko = ko_set - lsmod_set
        if unused_ko:
            results.append(f"Unused .ko files: {unused_ko}")

        if not results:
            results.append("No kernel module view discrepancies detected")

        self.results["crossview_modules"] = results
        return "\n".join(results)

    def crossview_users(self, target=None):
        """Compare user lists from multiple sources."""
        results = []

        passwd_content = self.run_command("cat /etc/passwd")
        passwd_users = set()
        if passwd_content:
            for line in passwd_content.split("\n"):
                if line.strip():
                    passwd_users.add(line.split(":")[0])

        getent_out = self.run_command("getent passwd 2>/dev/null")
        getent_users = set()
        if getent_out:
            for line in getent_out.split("\n"):
                if line.strip():
                    getent_users.add(line.split(":")[0])

        compgen_out = self.run_command("compgen -u 2>/dev/null")
        compgen_users = set()
        if compgen_out:
            compgen_users = set(compgen_out.split("\n"))

        shadow_users = set()
        shadow_out = self.run_command("sudo cat /etc/shadow 2>/dev/null")
        if shadow_out and "Permission denied" not in shadow_out:
            for line in shadow_out.split("\n"):
                if line.strip():
                    shadow_users.add(line.split(":")[0])

        hidden_from_passwd = getent_users - passwd_users
        hidden_from_getent = passwd_users - getent_users

        if hidden_from_passwd:
            results.append(f"Users hidden from /etc/passwd: {hidden_from_passwd}")
        if hidden_from_getent:
            results.append(f"Users in passwd but not getent: {hidden_from_getent}")

        if shadow_users:
            shadow_only = shadow_users - passwd_users
            if shadow_only:
                results.append(f"Users in shadow but not passwd: {shadow_only}")

        if not results:
            results.append("No user list view discrepancies detected")

        self.results["crossview_users"] = results
        return "\n".join(results)

    def crossview_open_files(self, target=None):
        """Compare open file lists from multiple sources."""
        results = []

        lsof_out = self.run_command("lsof 2>/dev/null | tail -n +2 | wc -l")
        fd_count = self.run_command(
            "find /proc/*/fd -type l 2>/dev/null | wc -l"
        )

        if lsof_out and fd_count:
            lsof_n = int(lsof_out) if lsof_out.isdigit() else 0
            fd_n = int(fd_count) if fd_count.isdigit() else 0
            if abs(lsof_n - fd_n) > 100:
                results.append(
                    f"Open file count mismatch: lsof={lsof_n}, /proc/fd={fd_n}"
                )
            else:
                results.append(f"Open file counts match: ~{lsof_n}")

        deleted = self.run_command(
            "lsof 2>/dev/null | grep '(deleted)' | head -20"
        )
        if deleted:
            results.append(f"Deleted but still open:\n{deleted}")

        self.results["crossview_files"] = results
        return "\n".join(results)

    def crossview_memory(self, target=None):
        """Compare memory usage from multiple sources."""
        results = []

        meminfo = self.run_command(
            "grep -E '(MemTotal|MemFree|MemAvailable|Buffers|Cached)' /proc/meminfo 2>/dev/null"
        )
        if meminfo:
            results.append(f"Memory info:\n{meminfo}")

        free_out = self.run_command("free -b 2>/dev/null")
        if free_out:
            results.append(f"Free output:\n{free_out}")

        vmstat = self.run_command("vmstat -s 2>/dev/null | head -20")
        if vmstat:
            results.append(f"VM statistics:\n{vmstat}")

        mem_access = self.run_command("lsof /dev/mem 2>/dev/null")
        if mem_access:
            results.append(f"Direct /dev/mem access detected:\n{mem_access}")

        self.results["crossview_memory"] = results
        return "\n".join(results)

    def crossview_mounted_fs(self, target=None):
        """Compare mounted filesystems from multiple sources."""
        results = []

        mount_out = self.run_command("mount 2>/dev/null")
        mount_lines = set()
        if mount_out:
            for line in mount_out.split("\n"):
                if line.strip():
                    mount_lines.add(line.strip())

        proc_mounts = self.run_command("cat /proc/mounts 2>/dev/null")
        proc_lines = set()
        if proc_mounts:
            for line in proc_mounts.split("\n"):
                if line.strip():
                    proc_lines.add(line.strip())

        findmnt = self.run_command("findmnt 2>/dev/null")
        findmnt_lines = set()
        if findmnt:
            for line in findmnt.split("\n"):
                if line.strip():
                    findmnt_lines.add(line.strip())

        hidden_from_mount = proc_lines - mount_lines
        hidden_from_findmnt = proc_lines - findmnt_lines

        if hidden_from_mount:
            results.append(f"Mounts hidden from mount command: {hidden_from_mount}")
        if hidden_from_findmnt:
            results.append(f"Mounts hidden from findmnt: {hidden_from_findmnt}")

        suspicious = self.run_command(
            "mount | grep -E '(nodev|noexec|nosuid)' | grep -v '/proc\\|/sys\\|/dev\\|/run' | head -10"
        )
        if suspicious:
            results.append(f"Mounts with unusual options:\n{suspicious}")

        if not results:
            results.append("No filesystem mount view discrepancies detected")

        self.results["crossview_mounts"] = results
        return "\n".join(results)

    def crossview_dns_resolution(self, target=None):
        """Compare DNS resolution from multiple sources."""
        results = []

        getent_hosts = self.run_command("getent hosts localhost 2>/dev/null")
        if getent_hosts:
            results.append(f"getent hosts: {getent_hosts}")

        hosts_file = self.run_command(
            "grep -v '^#' /etc/hosts 2>/dev/null | grep -v '^$'"
        )
        if hosts_file:
            results.append(f"/etc/hosts:\n{hosts_file}")

        dig_result = self.run_command("dig +short localhost 2>/dev/null")
        if dig_result:
            results.append(f"dig localhost: {dig_result}")

        resolv = self.run_command(
            "cat /etc/resolv.conf 2>/dev/null | grep -v '^#'"
        )
        if resolv:
            results.append(f"DNS resolvers:\n{resolv}")

        nslookup = self.run_command("nslookup localhost 2>/dev/null | tail -10")
        if nslookup:
            results.append(f"nslookup localhost:\n{nslookup}")

        self.results["crossview_dns"] = results
        return "\n".join(results)

    def crossview_environment(self, target=None):
        """Compare environment variables from multiple sources."""
        results = []

        env_out = self.run_command("env 2>/dev/null | sort")
        env_vars = set()
        if env_out:
            for line in env_out.split("\n"):
                if "=" in line:
                    env_vars.add(line.split("=")[0])

        proc_environ = self.run_command(
            "tr '\\0' '\\n' < /proc/1/environ 2>/dev/null | sort"
        )
        proc_vars = set()
        if proc_environ:
            for line in proc_environ.split("\n"):
                if "=" in line:
                    proc_vars.add(line.split("=")[0])

        only_in_env = env_vars - proc_vars
        only_in_proc = proc_vars - env_vars

        if only_in_env:
            results.append(f"Variables only in current env: {only_in_env}")
        if only_in_proc:
            results.append(f"Variables only in PID 1 env: {only_in_proc}")

        suspicious = self.run_command(
            "env | grep -iE '(LD_PRELOAD|LD_LIBRARY_PATH|BASH_ENV|ENV|CDPATH|GLOBIGNORE|PROMPT_COMMAND|PS4)' 2>/dev/null"
        )
        if suspicious:
            results.append(f"Potentially hijacked env vars:\n{suspicious}")

        if not results:
            results.append("No environment variable discrepancies detected")

        self.results["crossview_env"] = results
        return "\n".join(results)

    def crossview_loaded_libraries(self, target=None):
        """Compare loaded libraries from multiple sources."""
        results = []

        binaries = ["/bin/ls", "/bin/cat", "/usr/bin/ssh"]
        for binary in binaries:
            ldd_out = self.run_command(f"ldd {binary} 2>/dev/null")
            if ldd_out and "not a dynamic" not in ldd_out:
                results.append(f"Libraries for {binary}:\n{ldd_out}")

        init_maps = self.run_command(
            "grep '\\.so' /proc/1/maps 2>/dev/null | head -20"
        )
        if init_maps:
            results.append(f"PID 1 loaded libraries:\n{init_maps}")

        suspicious_libs = self.run_command(
            "find / -name '*.so' -path '*/tmp/*' -o -name '*.so' -path '*/dev/shm/*' 2>/dev/null | head -10"
        )
        if suspicious_libs:
            results.append(f"Libraries in temp directories: {suspicious_libs}")

        self.results["crossview_libraries"] = results
        return "\n".join(results)

    # ───────────────────────────────────────────────────────────
    #  6. ADVANCED DETECTION TECHNIQUES
    # ───────────────────────────────────────────────────────────

    def detect_rootkit_signatures(self, target=None):
        """Scan for known rootkit file signatures."""
        results = []

        rootkit_signatures = {
            "adore-ng": ["/lib/modules/*/adore.ko", "/usr/lib/adore"],
            "diamorphine": ["/lib/modules/*/diamorphine.ko"],
            "reptile": ["/lib/modules/*/reptile.ko", "/reptile"],
            "kovid": ["/lib/modules/*/kovid.ko"],
            "suckit": ["/tmp/.sk", "/dev/.udev/.udev.tdb"],
            "hideLKM": ["/lib/modules/*/hideLKM.ko"],
            "enyelkm": ["/lib/modules/*/enyelkm.ko"],
            "rial": ["/lib/modules/*/rial.ko"],
            "knark": ["/lib/modules/*/knark.ko"],
            "lkm_interlace": ["/lib/modules/*/lkm_interlace.ko"],
        }

        for name, paths in rootkit_signatures.items():
            for pattern in paths:
                matches = glob.glob(pattern)
                if matches:
                    for match in matches:
                        results.append(f"POSSIBLE ROOTKIT: {name} at {match}")

        ko_files = self.run_command(
            "find /lib/modules/$(uname -r) -name '*.ko' 2>/dev/null | head -20"
        )
        if ko_files:
            for ko in ko_files.split("\n"):
                if ko.strip():
                    ko_hash = self.run_command(f"sha256sum {ko.strip()} 2>/dev/null")
                    if ko_hash:
                        results.append(f"Module hash: {ko_hash}")

        if not results:
            results.append("No known rootkit signatures found")

        self.results["rootkit_signatures"] = results
        return "\n".join(results)

    def detect_stealth_techniques(self, target=None):
        """Detect various stealth techniques used by rootkits."""
        results = []

        name_check = self.run_command(
            "ps -eo pid,comm | awk '$2 ~ /^[[:space:]]*$/' | head -10"
        )
        if name_check:
            results.append(f"Processes with empty names:\n{name_check}")

        hidepid = self.run_command("mount | grep hidepid")
        if hidepid:
            results.append(f"hidepid mount option active: {hidepid}")

        ptrace_check = self.run_command(
            "cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null"
        )
        results.append(f"ptrace_scope: {ptrace_check}")

        ld_hide = self.run_command(
            "readelf -d /bin/ls 2>/dev/null | grep -i 'NEEDED'"
        )
        if ld_hide:
            results.append(f"Binary dynamic deps (ls):\n{ld_hide}")

        comm_check = self.run_command(
            "for pid in $(ls /proc/ | grep '^[0-9]' | head -20); do "
            "comm=$(cat /proc/$pid/comm 2>/dev/null); "
            "cmdline=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\\0' ' '); "
            "if [ -n \"$comm\" ] && [ -n \"$cmdline\" ] && ! echo \"$cmdline\" | grep -q \"$comm\"; then "
            "echo \"PID $pid: comm='$comm' cmdline='$cmdline'\"; fi; done 2>/dev/null"
        )
        if comm_check:
            results.append(f"Process name/cmdline mismatches:\n{comm_check}")

        self.results["stealth_techniques"] = results
        return "\n".join(results)

    def detect_network_rootkits(self, target=None):
        """Detect network-based rootkits and backdoors."""
        results = []

        reverse_shells = self.run_command(
            "ps aux | grep -E '(/bin/sh -i|/bin/bash -i|python.*socket|perl.*socket|ruby.*socket|nc -e)' | grep -v grep"
        )
        if reverse_shells:
            results.append(f"Possible reverse shells:\n{reverse_shells}")

        unusual_conns = self.run_command(
            "ss -tnp 2>/dev/null | grep -E '(ESTABLISHED|SYN_SENT)' | head -20"
        )
        if unusual_conns:
            results.append(f"Active connections:\n{unusual_conns}")

        knocking = self.run_command(
            "iptables -t mangle -L -n -v 2>/dev/null | head -20"
        )
        if knocking:
            results.append(f"iptables mangle (port knocking):\n{knocking}")

        unusual_listen = self.run_command(
            "ss -tlnp 2>/dev/null | grep -v -E ':(22|80|443|53) '"
        )
        if unusual_listen:
            results.append(f"Unusual listening ports:\n{unusual_listen}")

        dns_tunnel = self.run_command(
            "ss -tnp 2>/dev/null | grep ':53 ' | head -10"
        )
        if dns_tunnel:
            results.append(f"DNS connections:\n{dns_tunnel}")

        self.results["network_rootkits"] = results
        return "\n".join(results)

    def detect_container_escape(self, target=None):
        """Detect container escape indicators."""
        results = []

        container_check = self.run_command(
            "cat /proc/1/cgroup 2>/dev/null | head -10"
        )
        if container_check:
            results.append(f"Cgroup info:\n{container_check}")

        docker_sock = self.run_command(
            "ls -la /var/run/docker.sock 2>/dev/null"
        )
        if docker_sock:
            results.append(f"Docker socket: {docker_sock}")

        privileged = self.run_command(
            "cat /proc/self/status 2>/dev/null | grep -i cap"
        )
        if privileged:
            results.append(f"Capabilities:\n{privileged}")

        host_access = self.run_command(
            "ls /host 2>/dev/null && echo 'Host filesystem accessible'"
        )
        if host_access:
            results.append(host_access)

        docker_proc = self.run_command(
            "ps aux 2>/dev/null | grep -i docker | grep -v grep"
        )
        if docker_proc:
            results.append(f"Docker processes:\n{docker_proc}")

        self.results["container_escape"] = results
        return "\n".join(results)

    def detect_rootkit_persistence(self, target=None):
        """Check all persistence mechanisms for rootkit indicators."""
        results = []

        systemd_services = self.run_command(
            "systemctl list-unit-files --type=service --state=enabled 2>/dev/null | head -20"
        )
        if systemd_services:
            results.append(f"Enabled systemd services:\n{systemd_services}")

        suspicious_services = self.run_command(
            "find /etc/systemd /usr/lib/systemd ~/.config/systemd -name '*.service' "
            "-exec grep -l -E '(ExecStart.*curl|ExecStart.*wget|ExecStart.*nc|ExecStart.*bash)' {} \\; 2>/dev/null"
        )
        if suspicious_services:
            results.append(f"Suspicious systemd services:\n{suspicious_services}")

        rc_local = self.run_command("cat /etc/rc.local 2>/dev/null")
        if rc_local and rc_local.strip() not in ["#!/bin/sh", "exit 0", ""]:
            results.append(f"/etc/rc.local contents:\n{rc_local}")

        modprobe_conf = self.run_command(
            "cat /etc/modules-load.d/*.conf 2>/dev/null"
        )
        if modprobe_conf:
            results.append(f"Module autoload config:\n{modprobe_conf}")

        udev_rules = self.run_command(
            "ls /etc/udev/rules.d/ /usr/lib/udev/rules.d/ 2>/dev/null | head -10"
        )
        if udev_rules:
            results.append(f"Udev rules: {udev_rules}")

        self.results["rootkit_persistence"] = results
        return "\n".join(results)

    def detect_fileless_rootkit(self, target=None):
        """Detect fileless rootkits operating in memory."""
        results = []

        deleted_procs = self.run_command(
            "ls -la /proc/*/exe 2>/dev/null | grep '(deleted)' | head -20"
        )
        if deleted_procs:
            results.append(f"Processes with deleted binaries:\n{deleted_procs}")

        no_exe = self.run_command(
            "for pid in $(ls /proc/ | grep '^[0-9]' | head -30); do "
            "if [ ! -e /proc/$pid/exe ] && [ -d /proc/$pid ]; then "
            "echo \"PID $pid: no exe\"; fi; done 2>/dev/null"
        )
        if no_exe:
            results.append(f"Processes without exe: {no_exe}")

        anon_exec = self.run_command(
            "grep 'rwx.*anon' /proc/*/maps 2>/dev/null | head -10"
        )
        if anon_exec:
            results.append(f"Anonymous executable memory:\n{anon_exec}")

        memfd = self.run_command(
            "ls -la /proc/*/fd/ 2>/dev/null | grep memfd | head -10"
        )
        if memfd:
            results.append(f"memfd file descriptors:\n{memfd}")

        jit_check = self.run_command(
            "grep -r 'rwx.*jit\\|rwx.*anon' /proc/self/maps 2>/dev/null | head -5"
        )
        if jit_check:
            results.append(f"JIT memory regions:\n{jit_check}")

        self.results["fileless_rootkit"] = results
        return "\n".join(results)

    def detect_hardware_rootkit(self, target=None):
        """Detect hardware-based rootkits."""
        results = []

        pci_devices = self.run_command("lspci 2>/dev/null | head -20")
        if pci_devices:
            results.append(f"PCI devices:\n{pci_devices}")

        usb_devices = self.run_command("lsusb 2>/dev/null | head -20")
        if usb_devices:
            results.append(f"USB devices:\n{usb_devices}")

        iommu = self.run_command("dmesg 2>/dev/null | grep -i iommu | head -5")
        if iommu:
            results.append(f"IOMMU status:\n{iommu}")

        thunderbolt = self.run_command(
            "dmesg 2>/dev/null | grep -i thunderbolt | head -5"
        )
        if thunderbolt:
            results.append(f"Thunderbolt status:\n{thunderbolt}")

        microcode = self.run_command(
            "grep 'microcode' /proc/cpuinfo 2>/dev/null | head -3"
        )
        if microcode:
            results.append(f"CPU microcode:\n{microcode}")

        self.results["hardware_rootkit"] = results
        return "\n".join(results)

    def detect_hypervisor_rootkit(self, target=None):
        """Detect hypervisor-based rootkits."""
        results = []

        vm_check = self.run_command(
            "systemd-detect-virt 2>/dev/null || echo 'not in a VM'"
        )
        results.append(f"VM detection: {vm_check}")

        hypervisor = self.run_command(
            "grep -i hypervisor /proc/cpuinfo 2>/dev/null | head -3"
        )
        if hypervisor:
            results.append(f"Hypervisor info:\n{hypervisor}")

        dmi_check = self.run_command(
            "dmidecode -s system-product-name 2>/dev/null"
        )
        if dmi_check:
            results.append(f"System product: {dmi_check}")

        virt_dmesg = self.run_command(
            "dmesg 2>/dev/null | grep -iE '(vmware|virtualbox|kvm|xen|hyper-v)' | head -5"
        )
        if virt_dmesg:
            results.append(f"VM indicators in dmesg:\n{virt_dmesg}")

        self.results["hypervisor_rootkit"] = results
        return "\n".join(results)

    def run_full_scan(self, target=None):
        """Run all detection methods and return consolidated results."""
        self.log("Starting comprehensive rootkit scan", "info")

        all_results = {}
        all_results["timestamp"] = datetime.now().isoformat()
        all_results["target"] = target
        all_results["sections"] = {}

        # User-space detection
        self.log("Running user-space detection...", "info")
        all_results["sections"]["user_space"] = {
            "ld_preload": self.detect_ld_preload_rootkit(target),
            "process_hiding": self.detect_process_hiding(target),
            "file_hiding": self.detect_file_hiding(target),
            "process_injection": self.detect_process_injection(target),
            "library_injection": self.detect_library_injection(target),
            "persistence": self.detect_persistence_mechanisms(target),
            "hidden_users": self.detect_hidden_users(target),
            "suid_rootkit": self.detect_suid_rootkit(target),
            "netcat_backdoor": self.detect_netcat_backdoor(target),
            "ssh_backdoor": self.detect_ssh_backdoor(target),
            "rootkit_files": self.detect_rootkit_files(target),
            "keylogger": self.detect_keylogger(target),
            "timestomping": self.detect_timestomping(target),
            "hidden_connections": self.detect_hidden_connections(target),
        }

        # Kernel-space detection
        self.log("Running kernel-space detection...", "info")
        all_results["sections"]["kernel_space"] = {
            "kernel_modules": self.detect_kernel_modules(target),
            "kernel_hiding": self.detect_kernel_hiding(target),
            "kernel_integrity": self.detect_kernel_integrity(target),
            "syscall_hooking": self.detect_syscall_hooking(target),
            "rootkit_lkm": self.detect_rootkit_lkm(target),
            "dmesg_tampering": self.detect_dmesg_tampering(target),
            "interrupt_hooking": self.detect_interrupt_hooking(target),
            "netfilter_hooking": self.detect_netfilter_hooking(target),
            "kprobe_hooking": self.detect_kprobe_hooking(target),
        }

        # eBPF detection
        self.log("Running eBPF detection...", "info")
        all_results["sections"]["ebpf"] = {
            "ebpf_programs": self.detect_ebpf_programs(target),
            "ebpf_network": self.detect_ebpf_network_filtering(target),
            "ebpf_tracing": self.detect_ebpf_tracing(target),
            "ebpf_map_abuse": self.detect_ebpf_map_abuse(target),
            "ebpf_cgroup": self.detect_ebpf_cgroup_manipulation(target),
        }

        # Bootkit detection
        self.log("Running bootkit detection...", "info")
        all_results["sections"]["bootkit"] = {
            "mbr": self.detect_bootkit_mbr(target),
            "efi": self.detect_bootkit_efi(target),
            "grub": self.detect_bootkit_grub(target),
            "initramfs": self.detect_bootkit_initramfs(target),
            "vbr": self.detect_bootkit_vbr(target),
            "firmware": self.detect_firmware_rootkit(target),
        }

        # Cross-view detection
        self.log("Running cross-view detection...", "info")
        all_results["sections"]["crossview"] = {
            "process_list": self.crossview_process_list(target),
            "filesystem": self.crossview_filesystem(target),
            "network_connections": self.crossview_network_connections(target),
            "kernel_modules": self.crossview_kernel_modules(target),
            "users": self.crossview_users(target),
            "open_files": self.crossview_open_files(target),
            "memory": self.crossview_memory(target),
            "mounted_fs": self.crossview_mounted_fs(target),
            "dns_resolution": self.crossview_dns_resolution(target),
            "environment": self.crossview_environment(target),
            "loaded_libraries": self.crossview_loaded_libraries(target),
        }

        # Advanced techniques
        self.log("Running advanced detection...", "info")
        all_results["sections"]["advanced"] = {
            "rootkit_signatures": self.detect_rootkit_signatures(target),
            "stealth_techniques": self.detect_stealth_techniques(target),
            "network_rootkits": self.detect_network_rootkits(target),
            "container_escape": self.detect_container_escape(target),
            "rootkit_persistence": self.detect_rootkit_persistence(target),
            "fileless_rootkit": self.detect_fileless_rootkit(target),
            "hardware_rootkit": self.detect_hardware_rootkit(target),
            "hypervisor_rootkit": self.detect_hypervisor_rootkit(target),
        }

        self.results["full_scan"] = all_results
        self.log("Comprehensive rootkit scan completed", "success")
        return all_results

#!/usr/bin/env python3
"""BlackSentinel Strike - Penetration Testing Suite"""

import customtkinter as ctk
import threading
import subprocess
import platform
import datetime
import socket
import queue
import shutil
import json
import tempfile
from pathlib import Path

# local modules
import sys

sys.path.insert(0, str(Path(__file__).parent / "modules"))
from vault import (  # noqa: E402
    init_vault,
    unlock_vault,
    save_scan_result,
    save_metadata,
    save_config,
    load_config,
    encrypt_data,
    validate_password_policy,
)
from network_utils import (  # noqa: E402
    get_current_ip,
    get_interfaces,
    get_network_info,
    randomize_mac,
    set_dns,
    restore_dns,
    IPJumper,
)
from updater import (  # noqa: E402
    get_current_version,
    backup_current,
    apply_update,
    install_deps,
    get_upgrade_log,
    check_for_updates,
)
from war_exploit import WarExploit  # noqa: E402
from ta_attack import MITREAttack  # noqa: E402
from malware_sim import MalwareSimulation  # noqa: E402
from rootkit_detect import RootkitDetection  # noqa: E402
from honeypot_detect import HoneypotDetection  # noqa: E402
from cloud_attack import CloudAttack  # noqa: E402
from container_escape import ContainerEscape  # noqa: E402
from ad_attack import ADAttack  # noqa: E402
from wireless_adv import WirelessAdvanced  # noqa: E402
from web_adv import WebAdvanced  # noqa: E402
from network_adv import NetworkAdvanced  # noqa: E402
from forensic_adv import ForensicAdvanced  # noqa: E402
from social_adv import SocialEngineeringAdvanced  # noqa: E402
from post_exp_adv import PostExploitationAdvanced  # noqa: E402
from recon_adv import ReconAdvanced  # noqa: E402

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# ---------- palette ----------
C_BLACKS = ["#000000", "#050505", "#0a0a0a", "#0f0f0f", "#141414", "#1a1a1a"]
C_ORANGES = ["#1a0d00", "#331a00", "#663300", "#cc6600", "#e67300", "#ff8c00"]
C_TXT = ["#ffffff", "#cccccc", "#aaaaaa", "#888888", "#666666", "#444444"]
C_GREEN = "#00cc44"
C_ORANGE = "#ff8c00"
C_BORDER = "#1e1e1e"
C_BG = "#080808"
C_CARD = "#111111"
C_SIDEBAR = "#0c0c0c"
C_HOVER = "#1c1c1c"

# ---------- helpers ----------
_log_queue: queue.Queue = queue.Queue()


def _find_wordlist():
    """Auto-detect best available wordlist."""
    import glob as _glob

    candidates = [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/rockyou.txt",
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


def _ts():
    return datetime.datetime.now().strftime("%H:%M:%S")


def _run_cmd(cmd, label, out_box=None, save_path=None):
    """Run a shell command, stream output to queue, optionally save to file."""
    full_out = []
    try:
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in iter(p.stdout.readline, ""):
            if line:
                full_out.append(line)
                _log_queue.put((out_box, f"[+] {label}: {line.rstrip()}"))
        p.wait()
        _log_queue.put((out_box, f"[*] {label} finished (exit {p.returncode})"))
    except Exception as e:
        _log_queue.put((out_box, f"[!] {label} error: {e}"))
    if save_path and full_out:
        try:
            with open(save_path, "w") as f:
                f.writelines(full_out)
        except Exception:
            pass


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("BlackSentinel Strike")
        self.geometry("1440x900")
        self.minsize(1200, 750)
        self.configure(fg_color=C_BG)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._pages = {}
        self._current_page = None
        self._active_btn = None
        self._cpu_prev = None
        self._cpu_lock = threading.Lock()
        self._vault_password = None
        self._config = {}
        self._ip_jumper = None
        self._vault_unlocked = False

        self._init_vault()

        self._build_sidebar()
        self._build_content()
        self._build_console()

        if self._vault_locked:
            self._lock_interface()
            self._show_page("vault")
        else:
            self._vault_unlocked = True
            self._show_page("dashboard")
        self._tick_sysinfo()

        # drain log queue
        self.after(100, self._drain_log)

    def _lock_interface(self):
        """Lock sidebar and console when vault is not unlocked."""
        for btn in self._nav_btns.values():
            btn.configure(state="disabled", text_color="#333333")
        self._console_box.configure(state="disabled")

    def _unlock_interface(self):
        """Restore sidebar and console after vault unlock."""
        for key, btn in self._nav_btns.items():
            btn.configure(state="normal")
            if key in (
                "mitre",
                "malware",
                "rootkit",
                "honeypot",
                "cloud",
                "container",
                "ad_attack",
                "wireless_adv",
                "web_adv",
                "net_adv",
                "forensic_adv",
                "social_adv",
                "post_adv",
                "recon_adv",
            ):
                btn.configure(text_color="#ff8c00")
            else:
                btn.configure(text_color="#888888")
        self._console_box.configure(state="normal")

    # ------------------------------------------------------------------ sidebar
    def _build_sidebar(self):
        sb = ctk.CTkFrame(self, width=250, corner_radius=0, fg_color=C_SIDEBAR, border_width=0)
        sb.grid(row=0, column=0, rowspan=2, sticky="nsw")
        sb.grid_propagate(False)
        self._sb = sb

        # logo
        logo_frame = ctk.CTkFrame(sb, fg_color="transparent")
        logo_frame.pack(fill="x", padx=20, pady=(24, 2))
        ctk.CTkLabel(
            logo_frame, text="BLACKSENTINEL", font=ctk.CTkFont("Consolas", 22, "bold"), text_color="#ff8c00"
        ).pack(anchor="w")
        ctk.CTkLabel(logo_frame, text="STRIKE", font=ctk.CTkFont("Consolas", 10, "bold"), text_color="#888888").pack(
            anchor="w"
        )

        # version badge
        ver_frame = ctk.CTkFrame(sb, fg_color="#1a0d00", corner_radius=4)
        ver_frame.pack(fill="x", padx=20, pady=(4, 12))
        ctk.CTkLabel(ver_frame, text="v4.0  |  AES-256", font=ctk.CTkFont("Consolas", 8), text_color="#cc6600").pack(
            padx=8, pady=3
        )

        # separator
        sep = ctk.CTkFrame(sb, height=1, fg_color="#222222", corner_radius=0)
        sep.pack(fill="x", padx=16, pady=(0, 8))

        # scrollable nav area
        nav_scroll = ctk.CTkScrollableFrame(
            sb, fg_color="transparent", scrollbar_button_color="#333333", scrollbar_button_hover_color="#555555"
        )
        nav_scroll.pack(fill="both", expand=True)
        self._nav_scroll = nav_scroll

        # nav section label
        ctk.CTkLabel(nav_scroll, text="MODULES", font=ctk.CTkFont("Consolas", 8, "bold"), text_color="#444444").pack(
            anchor="w", padx=8, pady=(0, 4)
        )

        # nav buttons
        self._nav_btns = {}
        modules = [
            ("dashboard", "Dashboard"),
            ("war exploit", "War Exploit"),
            ("netscan", "Network Scan"),
            ("portscan", "Port Scanner"),
            ("webexploit", "Web Explorer"),
            ("exploits", "Exploits"),
            ("postexploit", "Post-Exploit"),
            ("password", "Password"),
            ("reports", "Reports"),
            ("settings", "Settings"),
        ]
        for key, label in modules:
            b = ctk.CTkButton(
                nav_scroll,
                text=f"  {label}",
                anchor="w",
                height=34,
                corner_radius=6,
                fg_color="transparent",
                text_color="#888888",
                hover_color=C_HOVER,
                font=ctk.CTkFont("Consolas", 11),
                command=lambda k=key: self._show_page(k),
            )
            b.pack(fill="x", padx=4, pady=1)
            self._nav_btns[key] = b

        # separator
        sep2 = ctk.CTkFrame(nav_scroll, height=1, fg_color="#222222", corner_radius=0)
        sep2.pack(fill="x", padx=8, pady=(8, 4))
        ctk.CTkLabel(nav_scroll, text="ADVANCED", font=ctk.CTkFont("Consolas", 8, "bold"), text_color="#ff8c00").pack(
            anchor="w", padx=8, pady=(0, 4)
        )

        # advanced nav buttons
        advanced_modules = [
            ("mitre", "MITRE ATT&CK"),
            ("malware", "Malware Sim"),
            ("rootkit", "Rootkit Detect"),
            ("honeypot", "Honeypot Detect"),
            ("cloud", "Cloud Attack"),
            ("container", "Container Escape"),
            ("ad_attack", "AD Attack"),
            ("wireless_adv", "Wireless Adv"),
            ("web_adv", "Web Attack"),
            ("net_adv", "Network Adv"),
            ("forensic_adv", "Forensic Adv"),
            ("social_adv", "Social Eng"),
            ("post_adv", "Post-Exp Adv"),
            ("recon_adv", "Recon Adv"),
        ]
        for key, label in advanced_modules:
            b = ctk.CTkButton(
                nav_scroll,
                text=f"  {label}",
                anchor="w",
                height=34,
                corner_radius=6,
                fg_color="transparent",
                text_color="#ff8c00",
                hover_color=C_HOVER,
                font=ctk.CTkFont("Consolas", 11),
                command=lambda k=key: self._show_page(k),
            )
            b.pack(fill="x", padx=4, pady=1)
            self._nav_btns[key] = b

        # bottom spacer to allow scrolling past last item
        ctk.CTkFrame(nav_scroll, fg_color="transparent", height=20).pack(fill="x")

        # sysinfo panel at bottom (fixed, not scrollable)
        self._sys_frame = ctk.CTkFrame(sb, fg_color="#0a0a0a", corner_radius=8, border_width=1, border_color="#1a1a1a")
        self._sys_frame.pack(fill="x", padx=14, pady=(4, 4))
        sys_header = ctk.CTkFrame(self._sys_frame, fg_color="transparent")
        sys_header.pack(fill="x", padx=10, pady=(8, 4))
        ctk.CTkLabel(sys_header, text="SYS", font=ctk.CTkFont("Consolas", 8, "bold"), text_color="#cc0000").pack(
            side="left"
        )
        self._lbl_platform = ctk.CTkLabel(
            self._sys_frame,
            text=f"{platform.system()} {platform.release()[:18]}",
            font=ctk.CTkFont("Consolas", 8),
            text_color="#555555",
            anchor="w",
        )
        self._lbl_platform.pack(anchor="w", padx=10)
        self._lbl_cpu = ctk.CTkLabel(
            self._sys_frame, text="CPU: --%", font=ctk.CTkFont("Consolas", 9), text_color="#888888", anchor="w"
        )
        self._lbl_cpu.pack(anchor="w", padx=10)
        self._lbl_ram = ctk.CTkLabel(
            self._sys_frame, text="RAM: --%", font=ctk.CTkFont("Consolas", 9), text_color="#888888", anchor="w"
        )
        self._lbl_ram.pack(anchor="w", padx=10, pady=(0, 8))

        # help button
        ctk.CTkButton(
            sb,
            text="[?] Help",
            height=30,
            corner_radius=6,
            fg_color="#1a1a1a",
            text_color="#666666",
            hover_color="#330000",
            font=ctk.CTkFont("Consolas", 10),
            command=self._show_help,
        ).pack(fill="x", padx=14, pady=(4, 14))

    # ------------------------------------------------------------------ content
    def _build_content(self):
        self._content = ctk.CTkFrame(self, fg_color=C_BG, corner_radius=0)
        self._content.grid(row=0, column=1, sticky="nsew")
        self._content.grid_columnconfigure(0, weight=1)
        self._content.grid_rowconfigure(0, weight=1)

    def _page_frame(self, key):
        f = ctk.CTkFrame(self._content, fg_color=C_BG, corner_radius=0)
        self._pages[key] = f
        return f

    # ------------------------------------------------------------------ console
    def _build_console(self):
        con_frame = ctk.CTkFrame(
            self, height=150, fg_color="#080808", corner_radius=0, border_width=1, border_color="#1a1a1a"
        )
        con_frame.grid(row=1, column=1, sticky="sew")
        con_frame.grid_columnconfigure(0, weight=1)
        con_frame.grid_rowconfigure(1, weight=1)

        top = ctk.CTkFrame(con_frame, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=12, pady=(6, 0))
        ctk.CTkLabel(top, text="CONSOLE", font=ctk.CTkFont("Consolas", 9, "bold"), text_color="#cc0000").pack(
            side="left"
        )
        self._console_status = ctk.CTkLabel(top, text="[READY]", font=ctk.CTkFont("Consolas", 8), text_color="#444444")
        self._console_status.pack(side="left", padx=(8, 0))
        ctk.CTkButton(
            top,
            text="[CLR]",
            width=50,
            height=22,
            corner_radius=3,
            fg_color="#1a1a1a",
            text_color="#666666",
            hover_color="#330000",
            font=ctk.CTkFont("Consolas", 8),
            command=lambda: self._console_box.delete("1.0", "end"),
        ).pack(side="right")

        self._console_box = ctk.CTkTextbox(
            con_frame,
            fg_color="#0a0a0a",
            text_color=C_GREEN,
            font=ctk.CTkFont("Consolas", 10),
            border_width=0,
            corner_radius=0,
            wrap="word",
        )
        self._console_box.grid(row=1, column=0, sticky="nsew", padx=8, pady=(2, 8))
        self._console_box.configure(state="disabled")

    # ------------------------------------------------------------------ log
    def _log(self, msg, target_box=None):
        _log_queue.put((target_box, msg))

    def _drain_log(self):
        try:
            while True:
                box, msg = _log_queue.get_nowait()
                if box is None:
                    box = self._console_box
                box.configure(state="normal")
                box.insert("end", f"[{_ts()}] {msg}\n")
                box.see("end")
                box.configure(state="disabled")
        except queue.Empty:
            pass
        self.after(100, self._drain_log)

    # ------------------------------------------------------------------ vault
    def _init_vault(self):
        from pathlib import Path as _P

        vault_dir = _P.home() / ".blacksentinel-strike" / "vault"
        key_file = vault_dir / "master.key"
        self._vault_locked = not key_file.exists()
        self._vault_setup_mode = not key_file.exists()

    def _prompt_vault_setup(self):
        if not self._vault_setup_mode:
            return
        self._show_page("vault")

    def _prompt_vault_unlock(self):
        if not self._vault_locked:
            return
        self._show_page("vault")

    def _start_ip_jumper(self):
        ip_cfg = self._config.get("ip_rotation", {})
        if ip_cfg.get("enabled", False):
            self._ip_jumper = IPJumper(ip_cfg, on_event=lambda m: self._log(m))
            self._ip_jumper.start()

    def _save_app_config(self):
        if self._vault_password:
            save_config(self._config, self._vault_password)
            self._log("[+] Configuration saved")

    # ------------------------------------------------------------------ widgets
    def _card(self, parent, title, row=0, col=0, colspan=1):
        c = ctk.CTkFrame(parent, fg_color=C_CARD, corner_radius=8, border_width=1, border_color="#1a1a1a")
        c.grid(row=row, column=col, columnspan=colspan, sticky="nsew", padx=10, pady=6)
        if title:
            header = ctk.CTkFrame(c, fg_color="transparent")
            header.pack(fill="x", padx=14, pady=(12, 6))
            ctk.CTkLabel(
                header, text=title.upper(), font=ctk.CTkFont("Consolas", 10, "bold"), text_color="#cc6600", anchor="w"
            ).pack(side="left")
            ctk.CTkFrame(header, height=1, fg_color="#222222").pack(
                side="left", fill="x", expand=True, padx=(12, 0), pady=4
            )
        return c

    def _card_inner(self, card):
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        return inner

    def _input(self, parent, placeholder=""):
        e = ctk.CTkEntry(
            parent,
            placeholder_text=placeholder,
            fg_color="#0a0a0a",
            text_color="#ffffff",
            border_color="#222222",
            border_width=1,
            corner_radius=4,
            height=32,
            font=ctk.CTkFont("Consolas", 11),
        )
        return e

    def _combo(self, parent, values):
        return ctk.CTkComboBox(
            parent,
            values=values,
            fg_color="#0a0a0a",
            button_color="#330000",
            button_hover_color="#660000",
            dropdown_fg_color="#111111",
            dropdown_hover_color="#330000",
            text_color="#ffffff",
            border_color="#222222",
            border_width=1,
            corner_radius=4,
            height=32,
            font=ctk.CTkFont("Consolas", 11),
        )

    def _btn(self, parent, text, color="red", cmd=None):
        styles = {
            "red": {"fg": "#cc6600", "hover": "#ff8c00", "txt": "#ffffff"},
            "green": {"fg": "#006600", "hover": "#009900", "txt": "#ffffff"},
            "gray": {"fg": "#1a1a1a", "hover": "#2a2a2a", "txt": "#999999"},
        }
        s = styles.get(color, styles["red"])
        return ctk.CTkButton(
            parent,
            text=text,
            command=cmd,
            fg_color=s["fg"],
            hover_color=s["hover"],
            text_color=s["txt"],
            corner_radius=4,
            height=32,
            font=ctk.CTkFont("Consolas", 10, "bold"),
        )

    def _textbox(self, parent):
        t = ctk.CTkTextbox(
            parent,
            fg_color="#0a0a0a",
            text_color=C_GREEN,
            font=ctk.CTkFont("Consolas", 10),
            border_width=1,
            border_color="#1a1a1a",
            corner_radius=4,
            wrap="word",
        )
        return t

    def _title(self, parent, text):
        return ctk.CTkLabel(
            parent, text=text, font=ctk.CTkFont("Consolas", 20, "bold"), text_color="#ffffff", anchor="w"
        )

    def _subtitle(self, parent, text):
        return ctk.CTkLabel(parent, text=text, font=ctk.CTkFont("Consolas", 11), text_color="#555555", anchor="w")

    def _checkbox(self, parent, text):
        return ctk.CTkCheckBox(
            parent,
            text=text,
            fg_color="#cc6600",
            hover_color="#ff8c00",
            text_color="#aaaaaa",
            font=ctk.CTkFont("Consolas", 10),
            corner_radius=3,
            border_color="#333333",
            checkmark_color="#ffffff",
        )

    # ------------------------------------------------------------------ nav
    def _show_page(self, key):
        if self._vault_locked and key != "vault":
            key = "vault"
        if not self._vault_unlocked and key != "vault":
            key = "vault"
        if self._current_page == key and key in self._pages:
            return
        if self._current_page and self._current_page in self._pages:
            self._pages[self._current_page].grid_forget()
        if not self._vault_unlocked:
            for k, b in self._nav_btns.items():
                if k == "vault":
                    b.configure(fg_color="#1a0d00", text_color="#ff8c00", font=ctk.CTkFont("Consolas", 11, "bold"))
                else:
                    b.configure(
                        fg_color="transparent", text_color="#333333", font=ctk.CTkFont("Consolas", 11), state="disabled"
                    )
        else:
            for k, b in self._nav_btns.items():
                if k == key:
                    b.configure(
                        fg_color="#1a0d00",
                        text_color="#ff8c00",
                        font=ctk.CTkFont("Consolas", 11, "bold"),
                        state="normal",
                    )
                else:
                    b.configure(
                        fg_color="transparent", text_color="#888888", font=ctk.CTkFont("Consolas", 11), state="normal"
                    )
        if key not in self._pages:
            self._build_page(key)
        self._pages[key].grid(row=0, column=0, sticky="nsew", in_=self._content)
        self._pages[key].lift()
        self._current_page = key

    def _build_page(self, key):
        builders = {
            "vault": self._build_vault,
            "dashboard": self._build_dashboard,
            "war exploit": self._build_war_exploit,
            "netscan": self._build_netscan,
            "portscan": self._build_portscan,
            "webexploit": self._build_webexploit,
            "exploits": self._build_exploits,
            "postexploit": self._build_postexploit,
            "password": self._build_password,
            "reports": self._build_reports,
            "settings": self._build_settings,
            "mitre": self._build_mitre,
            "malware": self._build_malware,
            "rootkit": self._build_rootkit,
            "honeypot": self._build_honeypot,
            "cloud": self._build_cloud,
            "container": self._build_container,
            "ad_attack": self._build_ad_attack,
            "wireless_adv": self._build_wireless_adv,
            "web_adv": self._build_web_adv,
            "net_adv": self._build_net_adv,
            "forensic_adv": self._build_forensic_adv,
            "social_adv": self._build_social_adv,
            "post_adv": self._build_post_adv,
            "recon_adv": self._build_recon_adv,
        }
        builders.get(key, lambda: None)()

    # ================================================================ VAULT
    def _build_vault(self):
        f = self._page_frame("vault")
        f.grid_columnconfigure(0, weight=1)

        self._title(f, "BlackSentinel Vault").grid(row=0, column=0, sticky="w", padx=24, pady=(20, 0))
        self._subtitle(f, "AES-256-CBC + HMAC-SHA512 + PBKDF2-SHA512 (1M iterations)").grid(
            row=1, column=0, sticky="w", padx=24, pady=(0, 12)
        )

        card = self._card(f, "Vault Access", 2, 0)
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=20, pady=20)

        if self._vault_setup_mode:
            ctk.CTkLabel(
                inner,
                text="FIRST RUN - CREATE MASTER PASSWORD",
                font=ctk.CTkFont("Consolas", 14, "bold"),
                text_color="#ff8c00",
            ).pack(pady=(0, 20))
            ctk.CTkLabel(
                inner,
                text="This password encrypts ALL scan data and metadata.\nIt CANNOT be recovered if lost.",
                font=ctk.CTkFont("Consolas", 10),
                text_color="#888888",
                justify="center",
            ).pack(pady=(0, 12))
            ctk.CTkLabel(
                inner,
                text="Password must contain:\n  - At least 1 uppercase letter\n  - At least 1 lowercase letter\n  - At least 3 numbers\n  - At least 1 special character (!@#$%^&*...)",
                font=ctk.CTkFont("Consolas", 9),
                text_color="#666666",
                justify="left",
            ).pack(pady=(0, 12))
        else:
            ctk.CTkLabel(
                inner, text="VAULT LOCKED", font=ctk.CTkFont("Consolas", 14, "bold"), text_color="#ff8c00"
            ).pack(pady=(0, 20))
            ctk.CTkLabel(
                inner,
                text="Enter your master password to unlock.",
                font=ctk.CTkFont("Consolas", 10),
                text_color="#888888",
                justify="center",
            ).pack(pady=(0, 20))

        ctk.CTkLabel(
            inner, text="MASTER PASSWORD:", font=ctk.CTkFont("Consolas", 10, "bold"), text_color="#cc6600"
        ).pack(anchor="w", pady=(0, 4))

        self._vault_entry = ctk.CTkEntry(
            inner,
            placeholder_text="Enter password...",
            fg_color="#0a0a0a",
            text_color="#ffffff",
            border_color="#cc6600",
            border_width=1,
            corner_radius=4,
            height=36,
            show="*",
            font=ctk.CTkFont("Consolas", 12),
        )
        self._vault_entry.pack(fill="x", pady=(0, 4))
        self._vault_entry.bind("<Return>", lambda e: self._vault_submit())

        if self._vault_setup_mode:
            ctk.CTkLabel(
                inner, text="CONFIRM PASSWORD:", font=ctk.CTkFont("Consolas", 10, "bold"), text_color="#cc6600"
            ).pack(anchor="w", pady=(8, 4))
            self._vault_entry_confirm = ctk.CTkEntry(
                inner,
                placeholder_text="Re-enter password...",
                fg_color="#0a0a0a",
                text_color="#ffffff",
                border_color="#cc6600",
                border_width=1,
                corner_radius=4,
                height=36,
                show="*",
                font=ctk.CTkFont("Consolas", 12),
            )
            self._vault_entry_confirm.pack(fill="x", pady=(0, 4))
            self._vault_entry_confirm.bind("<Return>", lambda e: self._vault_submit())

        self._vault_error = ctk.CTkLabel(inner, text="", font=ctk.CTkFont("Consolas", 10), text_color="#ff8c00")
        self._vault_error.pack(anchor="w", pady=(0, 12))

        btn_frame = ctk.CTkFrame(inner, fg_color="transparent")
        btn_frame.pack(fill="x")

        if self._vault_setup_mode:
            self._btn(btn_frame, "CREATE VAULT", "red", self._vault_submit).pack(side="left")
        else:
            self._btn(btn_frame, "UNLOCK VAULT", "red", self._vault_submit).pack(side="left")

    def _vault_submit(self):
        pwd = self._vault_entry.get().strip()
        if not pwd:
            self._vault_error.configure(text="[!] Please enter a password.")
            return

        if self._vault_setup_mode:
            is_valid, errors = validate_password_policy(pwd)
            if not is_valid:
                error_text = "[!] Password policy: " + "; ".join(errors)
                self._vault_error.configure(text=error_text)
                return
            confirm = self._vault_entry_confirm.get().strip() if hasattr(self, "_vault_entry_confirm") else ""
            if confirm != pwd:
                self._vault_error.configure(text="[!] Passwords do not match.")
                return
            ok = init_vault(pwd)
            if ok:
                self._vault_password = pwd
                self._config = load_config(pwd)
                self._vault_locked = False
                self._vault_setup_mode = False
                self._vault_unlocked = True
                self._log("[+] Vault initialized successfully")
                self._start_ip_jumper()
                self._destroy_vault_page()
                self._unlock_interface()
                self._show_page("dashboard")
            else:
                self._vault_error.configure(text="Vault setup failed. Try again.")
        else:
            ok = unlock_vault(pwd)
            if ok:
                self._vault_password = pwd
                self._config = load_config(pwd)
                self._vault_locked = False
                self._vault_unlocked = True
                self._log("[+] Vault unlocked")
                self._start_ip_jumper()
                self._destroy_vault_page()
                self._unlock_interface()
                self._show_page("dashboard")
            else:
                self._vault_error.configure(text="Wrong password. Try again.")
                self._vault_entry.delete(0, "end")

    def _destroy_vault_page(self):
        if "vault" in self._pages:
            self._pages["vault"].grid_forget()
            self._pages["vault"].destroy()
            del self._pages["vault"]
        self._current_page = None

    # ================================================================ DASHBOARD
    def _build_dashboard(self):
        f = self._page_frame("dashboard")
        f.grid_columnconfigure((0, 1, 2), weight=1)
        f.grid_rowconfigure(2, weight=1)

        self._title(f, "Dashboard").grid(row=0, column=0, columnspan=3, sticky="w", padx=24, pady=(20, 0))
        self._subtitle(f, "System overview and quick actions").grid(
            row=1, column=0, columnspan=3, sticky="w", padx=24, pady=(0, 12)
        )

        # row 2 cards
        c1 = self._card(f, "Platform", 2, 0)
        c1.grid_columnconfigure(0, weight=1)
        for lbl, val in [
            ("System", platform.system()),
            ("Release", platform.release()[:30]),
            ("Machine", platform.machine()),
            ("Python", platform.python_version()),
        ]:
            row = ctk.CTkFrame(c1, fg_color="transparent")
            row.pack(fill="x", padx=14, pady=2)
            ctk.CTkLabel(
                row, text=f"{lbl}:", font=ctk.CTkFont("Consolas", 10), text_color="#666666", width=80, anchor="w"
            ).pack(side="left")
            ctk.CTkLabel(row, text=val, font=ctk.CTkFont("Consolas", 10), text_color="#cccccc", anchor="w").pack(
                side="left"
            )

        c2 = self._card(f, "Tools Status", 2, 1)
        c2.grid_columnconfigure(0, weight=1)
        tools = [
            "nmap",
            "nikto",
            "sqlmap",
            "gobuster",
            "hydra",
            "whatweb",
            "masscan",
            "nuclei",
            "subfinder",
            "httpx",
            "ffuf",
            "dirsearch",
        ]
        for t in tools:
            row = ctk.CTkFrame(c2, fg_color="transparent")
            row.pack(fill="x", padx=14, pady=1)
            ctk.CTkLabel(
                row, text=t, font=ctk.CTkFont("Consolas", 10), text_color="#888888", anchor="w", width=90
            ).pack(side="left")
            found = shutil.which(t) is not None
            st = "[OK]" if found else "[--]"
            sc = C_GREEN if found else "#ff0000"
            ctk.CTkLabel(row, text=st, font=ctk.CTkFont("Consolas", 10, "bold"), text_color=sc, anchor="w").pack(
                side="left"
            )

        c3 = self._card(f, "Network Info", 2, 2)
        c3.grid_columnconfigure(0, weight=1)
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
        except Exception:
            hostname = "unknown"
            local_ip = "127.0.0.1"
        for lbl, val in [("Hostname", hostname), ("Local IP", local_ip)]:
            row = ctk.CTkFrame(c3, fg_color="transparent")
            row.pack(fill="x", padx=14, pady=2)
            ctk.CTkLabel(
                row, text=f"{lbl}:", font=ctk.CTkFont("Consolas", 10), text_color="#666666", width=80, anchor="w"
            ).pack(side="left")
            ctk.CTkLabel(row, text=val, font=ctk.CTkFont("Consolas", 10), text_color="#cccccc", anchor="w").pack(
                side="left"
            )

        # quick actions
        qa = self._card(f, "Quick Actions", 2, 0, 3)
        qa_row = ctk.CTkFrame(qa, fg_color="transparent")
        qa_row.pack(fill="x", padx=14, pady=(0, 12))
        self._btn(qa_row, "WAR EXPLOIT", "red", lambda: self._show_page("war exploit")).pack(
            side="left", expand=True, fill="x", padx=4
        )
        self._btn(qa_row, "Network Scan", "red", lambda: self._show_page("netscan")).pack(
            side="left", expand=True, fill="x", padx=4
        )
        self._btn(qa_row, "Port Scan", "red", lambda: self._show_page("portscan")).pack(
            side="left", expand=True, fill="x", padx=4
        )
        self._btn(qa_row, "Web Explorer", "red", lambda: self._show_page("webexploit")).pack(
            side="left", expand=True, fill="x", padx=4
        )
        self._btn(qa_row, "Reports", "gray", lambda: self._show_page("reports")).pack(
            side="left", expand=True, fill="x", padx=4
        )

    # ================================================================ WAR EXPLOIT
    def _build_war_exploit(self):
        f = self._page_frame("war exploit")
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(4, weight=1)
        f.grid_rowconfigure(5, weight=1)

        self._title(f, "War Exploit").grid(row=0, column=0, sticky="w", padx=24, pady=(20, 0))
        self._subtitle(f, "Automated multi-vector attack - select target type and attack").grid(
            row=1, column=0, sticky="w", padx=24, pady=(0, 12)
        )

        # Target input + type selection
        opts = self._card(f, "Target Configuration", 2, 0)
        row1 = ctk.CTkFrame(opts, fg_color="transparent")
        row1.pack(fill="x", padx=14, pady=8)
        self._we_target = self._input(row1, "Target IP (e.g. 192.168.1.50)")
        self._we_target.pack(side="left", padx=(0, 8), expand=True, fill="x")

        row2 = ctk.CTkFrame(opts, fg_color="transparent")
        row2.pack(fill="x", padx=14, pady=(0, 8))
        ctk.CTkLabel(row2, text="TARGET TYPE:", font=ctk.CTkFont("Consolas", 9, "bold"), text_color="#cc0000").pack(
            side="left", padx=(0, 8)
        )

        # Target type buttons
        self._we_type = "auto"
        self._we_type_btns = {}
        types = [
            ("auto", "Auto (All)"),
            ("windows", "Windows"),
            ("linux", "Linux"),
            ("web", "Web App"),
            ("cloud", "Cloud"),
            ("firewall", "Firewall"),
            ("database", "Database"),
        ]
        for key, label in types:
            btn = ctk.CTkButton(
                row2,
                text=label,
                width=80,
                height=28,
                corner_radius=4,
                font=ctk.CTkFont("Consolas", 9),
                fg_color="#1a1a1a" if key != "auto" else "#8b0000",
                text_color="#ffffff",
                hover_color="#330000",
                command=lambda k=key: self._we_set_type(k),
            )
            btn.pack(side="left", padx=2)
            self._we_type_btns[key] = btn

        row3 = ctk.CTkFrame(opts, fg_color="transparent")
        row3.pack(fill="x", padx=14, pady=(0, 8))
        self._btn(row3, "TEST CONNECTION", "gray", self._we_test_target).pack(side="left", padx=(0, 4))
        self._btn(row3, "START ATTACK", "red", self._we_start_attack).pack(side="left", padx=(0, 4))
        self._btn(row3, "STOP", "gray", self._we_stop_attack).pack(side="left")

        # Status card
        status_card = self._card(f, "Attack Status", 3, 0)
        status_inner = ctk.CTkFrame(status_card, fg_color="transparent")
        status_inner.pack(fill="x", padx=14, pady=8)

        self._we_status_lbl = ctk.CTkLabel(
            status_inner, text="Status: IDLE", font=ctk.CTkFont("Consolas", 11, "bold"), text_color="#888888"
        )
        self._we_status_lbl.pack(side="left")

        self._we_progress_lbl = ctk.CTkLabel(
            status_inner, text="Stage: --", font=ctk.CTkFont("Consolas", 10), text_color="#666666"
        )
        self._we_progress_lbl.pack(side="right")

        # Stage indicators
        stages_frame = ctk.CTkFrame(status_card, fg_color="transparent")
        stages_frame.pack(fill="x", padx=12, pady=(0, 8))

        self._we_stage1 = ctk.CTkLabel(
            stages_frame, text="[1] Ping", font=ctk.CTkFont("Consolas", 9), text_color="#666666"
        )
        self._we_stage1.pack(side="left", padx=(0, 8))
        self._we_stage2 = ctk.CTkLabel(
            stages_frame, text="[2] OS", font=ctk.CTkFont("Consolas", 9), text_color="#666666"
        )
        self._we_stage2.pack(side="left", padx=(0, 8))
        self._we_stage3 = ctk.CTkLabel(
            stages_frame, text="[3] Ports", font=ctk.CTkFont("Consolas", 9), text_color="#666666"
        )
        self._we_stage3.pack(side="left", padx=(0, 8))
        self._we_stage4 = ctk.CTkLabel(
            stages_frame, text="[4] Services", font=ctk.CTkFont("Consolas", 9), text_color="#666666"
        )
        self._we_stage4.pack(side="left", padx=(0, 8))
        self._we_stage5 = ctk.CTkLabel(
            stages_frame, text="[5] Vulns", font=ctk.CTkFont("Consolas", 9), text_color="#666666"
        )
        self._we_stage5.pack(side="left", padx=(0, 8))
        self._we_stage6 = ctk.CTkLabel(
            stages_frame, text="[6] Exploit", font=ctk.CTkFont("Consolas", 9), text_color="#666666"
        )
        self._we_stage6.pack(side="left", padx=(0, 8))
        self._we_stage7 = ctk.CTkLabel(
            stages_frame, text="[7] Post", font=ctk.CTkFont("Consolas", 9), text_color="#666666"
        )
        self._we_stage7.pack(side="left")

        # Vulnerabilities Found panel
        vulns_card = self._card(f, "Vulnerabilities Found", 4, 0)
        vulns_scroll = ctk.CTkScrollableFrame(
            vulns_card, fg_color="transparent", scrollbar_button_color="#330000", scrollbar_button_hover_color="#660000"
        )
        vulns_scroll.pack(fill="both", expand=True, padx=6, pady=6)

        self._we_vulns_frame = vulns_scroll
        self._we_vulns_empty = ctk.CTkLabel(
            vulns_scroll,
            text="No vulnerabilities found yet. Run an attack to see results.",
            font=ctk.CTkFont("Consolas", 10),
            text_color="#555555",
        )
        self._we_vulns_empty.pack(pady=30)

        # Results
        res_card = self._card(f, "Attack Output", 4, 0)
        self._we_out = self._textbox(res_card)
        self._we_out.pack(fill="both", expand=True, padx=8, pady=8)

        self._war_engine = None

    def _we_set_type(self, target_type):
        self._we_type = target_type
        for key, btn in self._we_type_btns.items():
            if key == target_type:
                btn.configure(fg_color="#8b0000")
            else:
                btn.configure(fg_color="#1a1a1a")

    def _we_test_target(self):
        target = self._we_target.get().strip()
        if not target:
            self._log("[!] No target specified", self._we_out)
            return

        self._we_out.configure(state="normal")
        self._we_out.delete("1.0", "end")
        self._we_out.configure(state="disabled")

        self._log(f"[*] Testing connection to {target}...", self._we_out)

        def _test():
            import sys as _sys

            try:
                if _sys.platform == "win32":
                    ping_cmd = f"ping -n 2 -w 2000 {target}"
                elif _sys.platform == "darwin":
                    ping_cmd = f"ping -c 2 -t 2 {target}"
                else:
                    ping_cmd = f"ping -c 2 -W 2 {target}"
                result = subprocess.run(ping_cmd, shell=True, capture_output=True, text=True, timeout=10)
                if "bytes from" in result.stdout:
                    self._log("[+] Ping: REACHABLE", self._we_out)
                else:
                    self._log("[!] Ping: No response (may be firewalled)", self._we_out)
            except Exception as e:
                self._log(f"[!] Ping failed: {e}", self._we_out)

            self._log("[*] Quick port scan (top 20)...", self._we_out)
            try:
                result = subprocess.run(
                    f"nmap --top-ports 20 {target} 2>&1", shell=True, capture_output=True, text=True, timeout=30
                )
                self._log(f"{result.stdout}", self._we_out)
            except Exception as e:
                self._log(f"[!] Scan failed: {e}", self._we_out)

            self._log("[*] Test complete. Click START ATTACK to proceed.", self._we_out)

        threading.Thread(target=_test, daemon=True).start()

    def _we_start_attack(self):
        target = self._we_target.get().strip()
        if not target:
            self._log("[!] No target specified", self._we_out)
            return

        target_type = self._we_type

        self._we_out.configure(state="normal")
        self._we_out.delete("1.0", "end")
        self._we_out.configure(state="disabled")

        for lbl in [
            self._we_stage1,
            self._we_stage2,
            self._we_stage3,
            self._we_stage4,
            self._we_stage5,
            self._we_stage6,
        ]:
            lbl.configure(text_color="#666666")

        self._we_status_lbl.configure(text="Status: RUNNING", text_color="#ff0000")
        self._we_progress_lbl.configure(text="Starting attack pipeline...")

        self._war_engine = WarExploit(callback=lambda msg, lvl: self._log(msg, self._we_out))
        vectors = self._war_engine.get_vectors_for_type(target_type)
        type_name = vectors.get("name", target_type)

        self._log("[*] WAR EXPLOIT initiated", self._we_out)
        self._log(f"[*] Target: {target}", self._we_out)
        self._log(f"[*] Type: {type_name}", self._we_out)
        self._log(f"[*] Scans: {len(vectors.get('scans', []))} parallel", self._we_out)
        self._log(f"[*] Exploits: {len(vectors.get('exploits', []))} parallel", self._we_out)

        def _monitor():
            if self._war_engine and self._war_engine.is_running:
                stages = self._war_engine.scan_stages
                current = stages[-1]["stage"] if stages else "Initializing"
                self._we_progress_lbl.configure(text=f"Stage: {current}")

                stage_map = {
                    "Connectivity": self._we_stage1,
                    "OS Detection": self._we_stage2,
                    "Port Scan": self._we_stage3,
                    "Service Detection": self._we_stage4,
                    "Vulnerability Scans": self._we_stage5,
                    "Exploitation": self._we_stage6,
                    "Post-Exploitation": self._we_stage7,
                }
                for name, lbl in stage_map.items():
                    for s in stages:
                        if s["stage"] == name:
                            if s.get("status") == "completed":
                                lbl.configure(text_color=C_GREEN)
                            elif s.get("status") == "running":
                                lbl.configure(text_color="#ff0000")

                self.after(1000, _monitor)
            else:
                self._update_we_status()

        def _run_attack():
            self._war_engine.run_attack(target, target_type)
            self.after(0, self._update_we_status)

        threading.Thread(target=_run_attack, daemon=True).start()
        self.after(1000, _monitor)

    def _we_stop_attack(self):
        if self._war_engine and self._war_engine.is_running:
            self._war_engine.stop()
            self._log("[!] Attack stopped by user", self._we_out)
            self._update_we_status()

    def _update_we_status(self):
        if self._war_engine:
            status = self._war_engine.get_status()
            if status["exploits_successful"] > 0:
                self._we_status_lbl.configure(
                    text=f"Status: EXPLOITED ({status['exploits_successful']})", text_color=C_GREEN
                )
                self._we_progress_lbl.configure(text="SYSTEM COMPROMISED")
            elif status["vulns_found"] > 0:
                self._we_status_lbl.configure(text=f"Status: VULNS ({status['vulns_found']})", text_color="#ff6600")
                self._we_progress_lbl.configure(text="Vulnerabilities found")
            else:
                self._we_status_lbl.configure(text="Status: COMPLETED", text_color="#888888")
                self._we_progress_lbl.configure(text="Attack finished")
            self._update_we_vulns()
        else:
            self._we_status_lbl.configure(text="Status: IDLE", text_color="#888888")
            self._we_progress_lbl.configure(text="Stage: --")

    def _update_we_vulns(self):
        """Populate the Vulnerabilities Found panel with detailed results."""
        for w in self._we_vulns_frame.winfo_children():
            w.destroy()

        if not self._war_engine:
            return

        all_vulns = self._war_engine.found_vulns + self._war_engine.successful_exploits

        if not all_vulns:
            ctk.CTkLabel(
                self._we_vulns_frame,
                text="No vulnerabilities found.",
                font=ctk.CTkFont("Consolas", 10),
                text_color="#555555",
            ).pack(pady=20)
            return

        sev_colors = {
            "CRITICAL": "#ff0000",
            "HIGH": "#ff3300",
            "MEDIUM": "#ff6600",
            "LOW": "#ffaa00",
            "UNKNOWN": "#888888",
        }

        for vuln in all_vulns:
            sev = vuln.get("severity", "UNKNOWN")
            sev_color = sev_colors.get(sev, "#888888")

            # Main vuln card
            card = ctk.CTkFrame(
                self._we_vulns_frame, fg_color="#111111", corner_radius=6, border_width=1, border_color=sev_color
            )
            card.pack(fill="x", padx=4, pady=4)

            # Header row: name + CVE + severity badge
            hdr = ctk.CTkFrame(card, fg_color="transparent")
            hdr.pack(fill="x", padx=10, pady=(8, 2))

            sev_badge = ctk.CTkLabel(
                hdr,
                text=f" {sev} ",
                font=ctk.CTkFont("Consolas", 9, "bold"),
                fg_color=sev_color,
                text_color="#000000",
                corner_radius=3,
            )
            sev_badge.pack(side="left", padx=(0, 8))

            name_lbl = ctk.CTkLabel(
                hdr, text=vuln["name"], font=ctk.CTkFont("Consolas", 11, "bold"), text_color="#ffffff"
            )
            name_lbl.pack(side="left", padx=(0, 8))

            cve = vuln.get("cve", "N/A")
            if cve and cve != "N/A":
                cve_lbl = ctk.CTkLabel(hdr, text=cve, font=ctk.CTkFont("Consolas", 9), text_color="#cc0000")
                cvss = vuln.get("cvss")
                if cvss:
                    cve_lbl.configure(text=f"{cve} (CVSS {cvss})")
                cve_lbl.pack(side="left")

            # WHERE section
            where = vuln.get("where", "N/A")
            if where and where != "N/A":
                where_frame = ctk.CTkFrame(card, fg_color="transparent")
                where_frame.pack(fill="x", padx=10, pady=(4, 2))
                ctk.CTkLabel(
                    where_frame, text="WHERE:", font=ctk.CTkFont("Consolas", 9, "bold"), text_color="#cc0000"
                ).pack(side="left", padx=(0, 6))
                ctk.CTkLabel(
                    where_frame,
                    text=where,
                    font=ctk.CTkFont("Consolas", 9),
                    text_color="#cccccc",
                    wraplength=700,
                    justify="left",
                ).pack(side="left", fill="x")

            # HOW section
            how = vuln.get("how", "N/A")
            if how and how != "N/A":
                how_frame = ctk.CTkFrame(card, fg_color="transparent")
                how_frame.pack(fill="x", padx=10, pady=(2, 2))
                ctk.CTkLabel(
                    how_frame, text="HOW:", font=ctk.CTkFont("Consolas", 9, "bold"), text_color="#cc0000"
                ).pack(side="left", padx=(0, 6))
                ctk.CTkLabel(
                    how_frame,
                    text=how,
                    font=ctk.CTkFont("Consolas", 9),
                    text_color="#cccccc",
                    wraplength=700,
                    justify="left",
                ).pack(side="left", fill="x")

            # WHY section
            why = vuln.get("why", "N/A")
            if why and why != "N/A":
                why_frame = ctk.CTkFrame(card, fg_color="transparent")
                why_frame.pack(fill="x", padx=10, pady=(2, 2))
                ctk.CTkLabel(
                    why_frame, text="WHY:", font=ctk.CTkFont("Consolas", 9, "bold"), text_color="#cc0000"
                ).pack(side="left", padx=(0, 6))
                ctk.CTkLabel(
                    why_frame,
                    text=why,
                    font=ctk.CTkFont("Consolas", 9),
                    text_color="#cccccc",
                    wraplength=700,
                    justify="left",
                ).pack(side="left", fill="x")

            # IMPACT section
            impact = vuln.get("impact", "N/A")
            if impact and impact != "N/A":
                imp_frame = ctk.CTkFrame(card, fg_color="transparent")
                imp_frame.pack(fill="x", padx=10, pady=(2, 2))
                ctk.CTkLabel(
                    imp_frame, text="IMPACT:", font=ctk.CTkFont("Consolas", 9, "bold"), text_color="#cc0000"
                ).pack(side="left", padx=(0, 6))
                ctk.CTkLabel(
                    imp_frame,
                    text=impact,
                    font=ctk.CTkFont("Consolas", 9),
                    text_color="#cccccc",
                    wraplength=700,
                    justify="left",
                ).pack(side="left", fill="x")

            # FIX section
            fix = vuln.get("fix", "N/A")
            if fix and fix != "N/A":
                fix_frame = ctk.CTkFrame(card, fg_color="transparent")
                fix_frame.pack(fill="x", padx=10, pady=(2, 8))
                ctk.CTkLabel(
                    fix_frame, text="FIX:", font=ctk.CTkFont("Consolas", 9, "bold"), text_color="#00cc44"
                ).pack(side="left", padx=(0, 6))
                ctk.CTkLabel(
                    fix_frame,
                    text=fix,
                    font=ctk.CTkFont("Consolas", 9),
                    text_color="#cccccc",
                    wraplength=700,
                    justify="left",
                ).pack(side="left", fill="x")

    # ================================================================ NETSCAN
    def _build_netscan(self):
        f = self._page_frame("netscan")
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(2, weight=1)

        self._title(f, "Network Scan").grid(row=0, column=0, sticky="w", padx=24, pady=(20, 0))
        self._subtitle(f, "Discover hosts and services on a target network").grid(
            row=1, column=0, sticky="w", padx=24, pady=(0, 12)
        )

        opts = self._card(f, "Scan Options", 2, 0)
        row1 = ctk.CTkFrame(opts, fg_color="transparent")
        row1.pack(fill="x", padx=14, pady=8)
        self._ns_target = self._input(row1, "Target (IP/CIDR)")
        self._ns_target.pack(side="left", padx=(0, 8), expand=True, fill="x")
        self._ns_type = self._combo(row1, ["Ping", "TSYN", "TConnect", "UDP", "Full"])
        self._ns_type.set("Ping")
        self._ns_type.pack(side="left", padx=(0, 8))
        self._btn(row1, "Start", "red", self._ns_start).pack(side="left", padx=(0, 4))
        self._btn(row1, "Stop", "gray", self._ns_stop).pack(side="left")

        res_card = self._card(f, "Results", 3, 0)
        self._ns_out = self._textbox(res_card)
        self._ns_out.pack(fill="both", expand=True, padx=8, pady=8)
        self._ns_proc = None

    def _ns_start(self):
        target = self._ns_target.get().strip()
        if not target:
            self._log("[!] No target specified", self._ns_out)
            return
        scan_type = self._ns_type.get()
        self._ns_out.configure(state="normal")
        self._ns_out.delete("1.0", "end")
        self._ns_out.configure(state="disabled")
        self._log(f"[*] Starting {scan_type} scan on {target}", self._ns_out)

        type_flag = {"Ping": "-sn", "TSYN": "-sS", "TConnect": "-sT", "UDP": "-sU", "Full": "-A"}
        flag = type_flag.get(scan_type, "-sn")
        _scan_dir = tempfile.gettempdir()
        cmd = f"nmap {flag} -oN {_scan_dir}/ns_scan.txt {target}"
        self._ns_proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        def _run():
            full_out = []
            for line in iter(self._ns_proc.stdout.readline, ""):
                if line:
                    full_out.append(line)
                    _log_queue.put((self._ns_out, f"[+] {line.rstrip()}"))
            rc = self._ns_proc.wait()
            if self._vault_password and self._config.get("encryption", {}).get("auto_encrypt_scans", True):
                path = save_scan_result("netscan", "".join(full_out), self._vault_password)
                _log_queue.put((self._ns_out, f"[*] Scan finished (exit {rc}) -- encrypted: {path}"))
            else:
                _log_queue.put((self._ns_out, f"[*] Scan finished (exit {rc}) -- saved {_scan_dir}/ns_scan.txt"))

        threading.Thread(target=_run, daemon=True).start()

    def _ns_stop(self):
        if self._ns_proc and self._ns_proc.poll() is None:
            self._ns_proc.terminate()
            self._log("[!] Scan terminated", self._ns_out)

    # ================================================================ PORTSCAN
    def _build_portscan(self):
        f = self._page_frame("portscan")
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(2, weight=1)

        self._title(f, "Port Scanner").grid(row=0, column=0, sticky="w", padx=24, pady=(20, 0))
        self._subtitle(f, "Scan open ports and detect running services").grid(
            row=1, column=0, sticky="w", padx=24, pady=(0, 12)
        )

        opts = self._card(f, "Scan Options", 2, 0)
        row1 = ctk.CTkFrame(opts, fg_color="transparent")
        row1.pack(fill="x", padx=14, pady=8)
        self._ps_target = self._input(row1, "Target (IP/Hostname)")
        self._ps_target.pack(side="left", padx=(0, 8), expand=True, fill="x")
        self._ps_range = self._combo(row1, ["Common 1000", "Top 100", "Top 50", "Full 65535", "Custom", "Masscan Fast"])
        self._ps_range.set("Common 1000")
        self._ps_range.pack(side="left", padx=(0, 8))

        row2 = ctk.CTkFrame(opts, fg_color="transparent")
        row2.pack(fill="x", padx=12, pady=(0, 8))
        self._ps_custom = self._input(row2, "Custom ports (e.g. 22,80,443)")
        self._ps_custom.pack(side="left", padx=(0, 8), expand=True, fill="x")
        self._ps_svc = self._checkbox(row2, "Service detection (-sV)")
        self._ps_svc.pack(side="left", padx=(0, 8))
        self._ps_script = self._checkbox(row2, "Default scripts (-sC)")
        self._ps_script.pack(side="left", padx=(0, 8))
        self._btn(row2, "Start", "red", self._ps_start).pack(side="left", padx=(0, 4))
        self._btn(row2, "Stop", "gray", self._ps_stop).pack(side="left")

        res_card = self._card(f, "Results", 3, 0)
        self._ps_out = self._textbox(res_card)
        self._ps_out.pack(fill="both", expand=True, padx=8, pady=8)
        self._ps_proc = None

    def _ps_start(self):
        target = self._ps_target.get().strip()
        if not target:
            self._log("[!] No target specified", self._ps_out)
            return
        self._ps_out.configure(state="normal")
        self._ps_out.delete("1.0", "end")
        self._ps_out.configure(state="disabled")
        self._log(f"[*] Starting port scan on {target}", self._ps_out)

        port_flag = {
            "Common 1000": "",
            "Top 100": "--top-ports 100",
            "Top 50": "--top-ports 50",
            "Full 65535": "-p-",
            "Custom": "",
        }
        pf = port_flag.get(self._ps_range.get(), "")
        if self._ps_range.get() == "Custom":
            custom = self._ps_custom.get().strip()
            if custom:
                pf = f"-p {custom}"
            else:
                self._log("[!] Enter custom ports", self._ps_out)
                return

        # masscan fast mode
        if self._ps_range.get() == "Masscan Fast":
            cmd = f"masscan -p1-65535 --rate=1000 {target} -oL {tempfile.gettempdir()}/masscan.txt 2>&1 | tee {tempfile.gettempdir()}/ps_scan.txt"
            self._ps_proc = subprocess.Popen(
                cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )

            def _run_masscan():
                full_out = []
                for line in iter(self._ps_proc.stdout.readline, ""):
                    if line:
                        full_out.append(line)
                        _log_queue.put((self._ps_out, f"[+] {line.rstrip()}"))
                rc = self._ps_proc.wait()
                if self._vault_password and self._config.get("encryption", {}).get("auto_encrypt_scans", True):
                    path = save_scan_result("portscan_masscan", "".join(full_out), self._vault_password)
                    _log_queue.put((self._ps_out, f"[*] Masscan finished (exit {rc}) -- encrypted: {path}"))
                else:
                    _log_queue.put(
                        (self._ps_out, f"[*] Masscan finished (exit {rc}) -- saved {tempfile.gettempdir()}/ps_scan.txt")
                    )

            threading.Thread(target=_run_masscan, daemon=True).start()
            return

        flags = []
        if pf:
            flags.append(pf)
        if self._ps_svc.get():
            flags.append("-sV")
        if self._ps_script.get():
            flags.append("-sC")
        flag_str = " ".join(flags)
        cmd = f"nmap {flag_str} -oN {tempfile.gettempdir()}/ps_scan.txt {target}"
        self._ps_proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        def _run():
            full_out = []
            for line in iter(self._ps_proc.stdout.readline, ""):
                if line:
                    full_out.append(line)
                    _log_queue.put((self._ps_out, f"[+] {line.rstrip()}"))
            rc = self._ps_proc.wait()
            if self._vault_password and self._config.get("encryption", {}).get("auto_encrypt_scans", True):
                path = save_scan_result("portscan", "".join(full_out), self._vault_password)
                _log_queue.put((self._ps_out, f"[*] Scan finished (exit {rc}) -- encrypted: {path}"))
            else:
                _log_queue.put(
                    (self._ps_out, f"[*] Scan finished (exit {rc}) -- saved {tempfile.gettempdir()}/ps_scan.txt")
                )

        threading.Thread(target=_run, daemon=True).start()

    def _ps_stop(self):
        if self._ps_proc and self._ps_proc.poll() is None:
            self._ps_proc.terminate()
            self._log("[!] Scan terminated", self._ps_out)

    # ================================================================ WEB EXPLORER
    def _build_webexploit(self):
        f = self._page_frame("webexploit")
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(2, weight=1)

        self._title(f, "Web Explorer").grid(row=0, column=0, sticky="w", padx=24, pady=(20, 0))
        self._subtitle(f, "Web application reconnaissance and vulnerability scanning").grid(
            row=1, column=0, sticky="w", padx=24, pady=(0, 12)
        )

        opts = self._card(f, "Target", 2, 0)
        row1 = ctk.CTkFrame(opts, fg_color="transparent")
        row1.pack(fill="x", padx=14, pady=8)
        self._we_url = self._input(row1, "Target URL (http://...)")
        self._we_url.pack(side="left", padx=(0, 8), expand=True, fill="x")

        btn_card = self._card(f, "Tools", 3, 0)
        tools = [
            ("WhatWeb", "whatweb"),
            ("Gobuster", "gobuster"),
            ("Nikto", "nikto"),
            ("SQLMap", "sqlmap"),
            ("FFuf", "ffuf"),
            ("Dirsearch", "dirsearch"),
            ("Nuclei", "nuclei"),
            ("Subfinder", "subfinder"),
        ]
        btn_row = ctk.CTkFrame(btn_card, fg_color="transparent")
        btn_row.pack(fill="x", padx=14, pady=8)
        for lbl, t in tools:
            self._btn(btn_row, lbl, "red", lambda t=t: self._we_run(t)).pack(side="left", expand=True, fill="x", padx=4)

        res_card = self._card(f, "Results", 4, 0)
        self._we_out = self._textbox(res_card)
        self._we_out.pack(fill="both", expand=True, padx=8, pady=8)
        self._we_procs = {}

    def _we_run(self, tool):
        url = self._we_url.get().strip()
        if not url:
            self._log("[!] No URL specified", self._we_out)
            return
        self._log(f"[*] Running {tool}...", self._we_out)
        cmds = {
            "whatweb": f"whatweb -a 3 {url} 2>&1 | tee {tempfile.gettempdir()}/we_whatweb.txt",
            "gobuster": f"gobuster dir -u {url} -w {_DEFAULT_WORDLIST} -t 10 -o {tempfile.gettempdir()}/we_gobuster.txt 2>&1",
            "nikto": f"nikto -h {url} -o {tempfile.gettempdir()}/we_nikto.txt 2>&1",
            "sqlmap": f"sqlmap -u {url} --batch --crawl=2 --level=2 -o {tempfile.gettempdir()}/we_sqlmap.txt 2>&1",
            "ffuf": f"ffuf -u {url}/FUZZ -w {_DEFAULT_WORDLIST} -mc 200,301,302,403 -o {tempfile.gettempdir()}/we_ffuf.json -of json 2>&1",
            "dirsearch": f"dirsearch -u {url} -e php,html,js,txt -o {tempfile.gettempdir()}/we_dirsearch.txt 2>&1",
            "nuclei": f"nuclei -u {url} -severity low,medium,high,critical -o {tempfile.gettempdir()}/we_nuclei.txt 2>&1",
            "subfinder": f"subfinder -d {url.replace('http://', '').replace('https://', '').split('/')[0]} -o {tempfile.gettempdir()}/we_subfinder.txt 2>&1",
        }
        cmd = cmds.get(tool, f"echo 'Unknown tool {tool}'")

        def _run():
            try:
                p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                full_out = []
                for line in iter(p.stdout.readline, ""):
                    if line:
                        full_out.append(line)
                        _log_queue.put((self._we_out, f"[+] {tool}: {line.rstrip()}"))
                p.wait()
                _log_queue.put((self._we_out, f"[*] {tool} finished (exit {p.returncode})"))
                # auto-encrypt if vault is unlocked
                if self._vault_password and self._config.get("encryption", {}).get("auto_encrypt_scans", True):
                    path = save_scan_result(f"web_{tool}", "".join(full_out), self._vault_password)
                    _log_queue.put((self._we_out, f"[+] Results encrypted: {path}"))
            except Exception as e:
                _log_queue.put((self._we_out, f"[!] {tool} error: {e}"))

        threading.Thread(target=_run, daemon=True).start()

    # ================================================================ EXPLOITS
    def _build_exploits(self):
        f = self._page_frame("exploits")
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(2, weight=1)

        self._title(f, "Exploits").grid(row=0, column=0, sticky="w", padx=24, pady=(20, 0))
        self._subtitle(f, "Exploitation framework (authorized use only)").grid(
            row=1, column=0, sticky="w", padx=24, pady=(0, 12)
        )

        opts = self._card(f, "Exploit Options", 2, 0)
        row1 = ctk.CTkFrame(opts, fg_color="transparent")
        row1.pack(fill="x", padx=14, pady=8)
        self._ex_target = self._input(row1, "Target IP")
        self._ex_target.pack(side="left", padx=(0, 8), expand=True, fill="x")
        self._ex_exploit = self._combo(
            row1,
            [
                "EternalBlue (MS17-010)",
                "vsftpd 2.3.4",
                "Apache Struts 2",
                "Tomcat Manager",
                "Samba CVE-2017-7494",
                "WordPress XML-RPC",
                "SMB Vuln Scan",
                "SSH Audit",
                "FTP Anonymous",
                "HTTP Put",
            ],
        )
        self._ex_exploit.set("EternalBlue (MS17-010)")
        self._ex_exploit.pack(side="left", padx=(0, 8))

        row2 = ctk.CTkFrame(opts, fg_color="transparent")
        row2.pack(fill="x", padx=12, pady=(0, 8))
        self._ex_lhost = self._input(row2, "LHOST (your IP)")
        self._ex_lhost.pack(side="left", padx=(0, 8), expand=True, fill="x")
        self._btn(row2, "Execute", "red", self._ex_run).pack(side="left")

        res_card = self._card(f, "Results", 3, 0)
        self._ex_out = self._textbox(res_card)
        self._ex_out.pack(fill="both", expand=True, padx=8, pady=8)

    def _ex_run(self):
        target = self._ex_target.get().strip()
        exploit = self._ex_exploit.get()
        lhost = self._ex_lhost.get().strip()
        if not target:
            self._log("[!] No target specified", self._ex_out)
            return
        self._ex_out.configure(state="normal")
        self._ex_out.delete("1.0", "end")
        self._ex_out.configure(state="disabled")
        self._log(f"[*] Configuring exploit: {exploit}", self._ex_out)
        self._log(f"[*] Target: {target}  LHOST: {lhost or 'auto'}", self._ex_out)

        exploit_cmds = {
            "EternalBlue (MS17-010)": f"nmap --script smb-vuln-ms17-010 -p 445 {target} 2>&1 | tee {tempfile.gettempdir()}/exploit.txt",
            "vsftpd 2.3.4": f"nmap --script ftp-vsftpd-backdoor -p 21 {target} 2>&1 | tee {tempfile.gettempdir()}/exploit.txt",
            "Apache Struts 2": f"nmap --script http-vuln-cve2017-5638 -p 8080 {target} 2>&1 | tee {tempfile.gettempdir()}/exploit.txt",
            "Tomcat Manager": f"nmap --script http-tomcat-manager-brute -p 8080 {target} 2>&1 | tee {tempfile.gettempdir()}/exploit.txt",
            "Samba CVE-2017-7494": f"nmap --script smb-vuln-cve-2017-7494 -p 445 {target} 2>&1 | tee {tempfile.gettempdir()}/exploit.txt",
            "WordPress XML-RPC": f"nmap --script http-wordpress-brute -p 80 {target} 2>&1 | tee {tempfile.gettempdir()}/exploit.txt",
            "SMB Vuln Scan": f"nmap --script smb-vuln* -p 139,445 {target} 2>&1 | tee {tempfile.gettempdir()}/exploit.txt",
            "SSH Audit": f"nmap --script ssh2-enum-algos,ssh-hostkey -p 22 {target} 2>&1 | tee {tempfile.gettempdir()}/exploit.txt",
            "FTP Anonymous": f"nmap --script ftp-anon,ftp-syst -p 21 {target} 2>&1 | tee {tempfile.gettempdir()}/exploit.txt",
            "HTTP Put": f"nmap --script http-methods,http-put -p 80,443 {target} 2>&1 | tee {tempfile.gettempdir()}/exploit.txt",
        }
        cmd = exploit_cmds.get(exploit, "echo '[!] Unknown exploit'")

        def _run():
            try:
                p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                for line in iter(p.stdout.readline, ""):
                    if line:
                        _log_queue.put((self._ex_out, f"[+] {line.rstrip()}"))
                p.wait()
                _log_queue.put((self._ex_out, f"[*] Exploit finished (exit {p.returncode})"))
            except Exception as e:
                _log_queue.put((self._ex_out, f"[!] Error: {e}"))

        threading.Thread(target=_run, daemon=True).start()

    # ================================================================ POST-EXPLOIT
    def _build_postexploit(self):
        f = self._page_frame("postexploit")
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(2, weight=1)

        self._title(f, "Post-Exploitation").grid(row=0, column=0, sticky="w", padx=24, pady=(20, 0))
        self._subtitle(f, "System enumeration and data extraction").grid(
            row=1, column=0, sticky="w", padx=24, pady=(0, 12)
        )

        btn_card = self._card(f, "Post-Exploitation Tools", 2, 0)
        tools = [
            ("SystemInfo", "sysinfo"),
            ("Whoami", "whoami"),
            ("Processes", "ps"),
            ("HashDump", "hashdump"),
            ("Network", "netstat"),
        ]
        btn_row = ctk.CTkFrame(btn_card, fg_color="transparent")
        btn_row.pack(fill="x", padx=14, pady=8)
        for lbl, t in tools:
            self._btn(btn_row, lbl, "red", lambda t=t: self._pe_run(t)).pack(side="left", expand=True, fill="x", padx=4)

        res_card = self._card(f, "Output", 3, 0)
        self._pe_out = self._textbox(res_card)
        self._pe_out.pack(fill="both", expand=True, padx=8, pady=8)

    def _pe_run(self, tool):
        self._log(f"[*] Running {tool}...", self._pe_out)
        cmds = {
            "sysinfo": "uname -a && echo '---' && cat /etc/os-release 2>/dev/null || ver 2>/dev/null",
            "whoami": "whoami && id && hostname",
            "ps": "ps aux --sort=-%cpu 2>/dev/null | head -30 || tasklist 2>/dev/null | head -30",
            "hashdump": "cat /etc/shadow 2>/dev/null || echo '[-] Insufficient permissions or not available'",
            "netstat": "netstat -tuln 2>/dev/null || ss -tuln 2>/dev/null || echo '[-] netstat not available'",
        }
        cmd = cmds.get(tool, "echo '[-] Unknown tool'")

        def _run():
            try:
                p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                for line in iter(p.stdout.readline, ""):
                    if line:
                        _log_queue.put((self._pe_out, f"[+] {line.rstrip()}"))
                p.wait()
                _log_queue.put((self._pe_out, f"[*] {tool} finished (exit {p.returncode})"))
            except Exception as e:
                _log_queue.put((self._pe_out, f"[!] {tool} error: {e}"))

        threading.Thread(target=_run, daemon=True).start()

    # ================================================================ PASSWORD
    def _build_password(self):
        f = self._page_frame("password")
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(2, weight=1)

        self._title(f, "Password Attack").grid(row=0, column=0, sticky="w", padx=24, pady=(20, 0))
        self._subtitle(f, "Credential brute-force and dictionary attacks").grid(
            row=1, column=0, sticky="w", padx=24, pady=(0, 12)
        )

        opts = self._card(f, "Attack Options", 2, 0)
        row1 = ctk.CTkFrame(opts, fg_color="transparent")
        row1.pack(fill="x", padx=14, pady=8)
        self._pw_target = self._input(row1, "Target IP/Hostname")
        self._pw_target.pack(side="left", padx=(0, 8), expand=True, fill="x")
        self._pw_proto = self._combo(row1, ["SSH", "FTP", "HTTP", "SMB", "RDP", "MySQL"])
        self._pw_proto.set("SSH")
        self._pw_proto.pack(side="left", padx=(0, 8))

        row2 = ctk.CTkFrame(opts, fg_color="transparent")
        row2.pack(fill="x", padx=12, pady=(0, 8))
        self._pw_user = self._input(row2, "Username")
        self._pw_user.pack(side="left", padx=(0, 8), expand=True, fill="x")
        self._pw_wl = self._combo(
            row2,
            [
                _DEFAULT_WORDLIST,
                "/usr/share/wordlists/seclists/Passwords/Common-Credentials/top-20.txt",
                "/usr/share/wordlists/rockyou.txt",
                "Custom",
            ],
        )
        self._pw_wl.set(_DEFAULT_WORDLIST)
        self._pw_wl.pack(side="left", padx=(0, 8))
        self._btn(row2, "Attack", "red", self._pw_run).pack(side="left")

        res_card = self._card(f, "Results", 3, 0)
        self._pw_out = self._textbox(res_card)
        self._pw_out.pack(fill="both", expand=True, padx=8, pady=8)

    def _pw_run(self):
        target = self._pw_target.get().strip()
        user = self._pw_user.get().strip()
        proto = self._pw_proto.get()
        wordlist = self._pw_wl.get().strip()
        if not target:
            self._log("[!] No target specified", self._pw_out)
            return
        if not user:
            self._log("[!] No username specified", self._pw_out)
            return
        self._pw_out.configure(state="normal")
        self._pw_out.delete("1.0", "end")
        self._pw_out.configure(state="disabled")
        self._log(f"[*] {proto} brute-force on {target} user={user}", self._pw_out)

        port_map = {"SSH": "22", "FTP": "21", "HTTP": "80", "SMB": "445", "RDP": "3389", "MySQL": "3306"}
        port = port_map.get(proto, "22")

        cmds = {
            "SSH": f"hydra -l {user} -P {wordlist} -s {port} -t 4 -f {target} ssh 2>&1 | tee {tempfile.gettempdir()}/pw_hydra.txt",
            "FTP": f"hydra -l {user} -P {wordlist} -s {port} -t 4 -f {target} ftp 2>&1 | tee {tempfile.gettempdir()}/pw_hydra.txt",
            "HTTP": f"hydra -l {user} -P {wordlist} -s {port} -t 4 -f {target} http-get-form '/:username=^USER^&password=^PASS^:F=incorrect' 2>&1 | tee {tempfile.gettempdir()}/pw_hydra.txt",
            "SMB": f"hydra -l {user} -P {wordlist} -s {port} -t 4 -f {target} smb 2>&1 | tee {tempfile.gettempdir()}/pw_hydra.txt",
            "RDP": f"hydra -l {user} -P {wordlist} -s {port} -t 4 -f {target} rdp 2>&1 | tee {tempfile.gettempdir()}/pw_hydra.txt",
            "MySQL": f"hydra -l {user} -P {wordlist} -s {port} -t 4 -f {target} mysql 2>&1 | tee {tempfile.gettempdir()}/pw_hydra.txt",
        }
        cmd = cmds.get(proto, cmds["SSH"])

        def _run():
            try:
                p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                for line in iter(p.stdout.readline, ""):
                    if line:
                        _log_queue.put((self._pw_out, f"[+] {line.rstrip()}"))
                p.wait()
                _log_queue.put((self._pw_out, f"[*] Attack finished (exit {p.returncode})"))
            except Exception as e:
                _log_queue.put((self._pw_out, f"[!] Error: {e}"))

        threading.Thread(target=_run, daemon=True).start()

    # ================================================================ REPORTS
    def _build_reports(self):
        f = self._page_frame("reports")
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(2, weight=1)

        self._title(f, "Reports").grid(row=0, column=0, sticky="w", padx=24, pady=(20, 0))
        self._subtitle(f, "Generate penetration testing reports").grid(
            row=1, column=0, sticky="w", padx=24, pady=(0, 12)
        )

        opts = self._card(f, "Report Options", 2, 0)
        row1 = ctk.CTkFrame(opts, fg_color="transparent")
        row1.pack(fill="x", padx=14, pady=8)
        self._rp_name = self._input(row1, "Project Name")
        self._rp_name.pack(side="left", padx=(0, 8), expand=True, fill="x")
        self._rp_type = self._combo(row1, ["Full", "Executive", "Technical", "Compliance"])
        self._rp_type.set("Full")
        self._rp_type.pack(side="left")

        row2 = ctk.CTkFrame(opts, fg_color="transparent")
        row2.pack(fill="x", padx=12, pady=(0, 8))
        self._rp_execsum = self._checkbox(row2, "Executive Summary")
        self._rp_execsum.pack(side="left", padx=(0, 12))
        self._rp_methods = self._checkbox(row2, "Methodology")
        self._rp_methods.pack(side="left", padx=(0, 12))
        self._rp_findings = self._checkbox(row2, "Findings")
        self._rp_findings.pack(side="left", padx=(0, 12))
        self._rp_recom = self._checkbox(row2, "Recommendations")
        self._rp_recom.pack(side="left")
        self._btn(row2, "Generate", "green", self._rp_gen).pack(side="right", padx=(8, 0))

        res_card = self._card(f, "Report Preview", 3, 0)
        self._rp_out = self._textbox(res_card)
        self._rp_out.pack(fill="both", expand=True, padx=8, pady=8)

    def _rp_gen(self):
        name = self._rp_name.get().strip() or "Untitled"
        rtype = self._rp_type.get()
        self._rp_out.configure(state="normal")
        self._rp_out.delete("1.0", "end")
        self._rp_out.configure(state="disabled")
        self._log(f"[*] Generating {rtype} report: {name}", self._rp_out)

        def _run():
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            report_path = f"{tempfile.gettempdir()}/report_{name.replace(' ', '_')}.txt"
            lines = []
            lines.append("=" * 72)
            lines.append("  PENETRATION TEST REPORT")
            lines.append(f"  Project: {name}")
            lines.append(f"  Type:    {rtype}")
            lines.append(f"  Date:    {ts}")
            lines.append("=" * 72)
            lines.append("")
            sections = []
            if self._rp_execsum.get():
                sections.append(
                    (
                        "Executive Summary",
                        "This report presents the findings of a penetration test\n"
                        "conducted against the target infrastructure. The assessment\n"
                        "was performed to identify vulnerabilities and provide\n"
                        "actionable recommendations for improving security posture.",
                    )
                )
            if self._rp_methods.get():
                sections.append(
                    (
                        "Methodology",
                        "[*] Information gathering and reconnaissance\n"
                        "[*] Network scanning and enumeration\n"
                        "[*] Vulnerability identification\n"
                        "[*] Exploitation attempts\n"
                        "[*] Post-exploitation activities\n"
                        "[*] Reporting and documentation",
                    )
                )
            if self._rp_findings.get():
                sections.append(
                    (
                        "Findings",
                        f"[+] Network scan results available in {tempfile.gettempdir()}/ns_scan.txt\n"
                        f"[+] Port scan results available in {tempfile.gettempdir()}/ps_scan.txt\n"
                        "[!] Review all scan outputs for detailed findings",
                    )
                )
            if self._rp_recom.get():
                sections.append(
                    (
                        "Recommendations",
                        "[-] Apply all available security patches and updates\n"
                        "[-] Implement network segmentation\n"
                        "[-] Enable host-based firewalls\n"
                        "[-] Enforce strong password policies\n"
                        "[-] Conduct regular security assessments",
                    )
                )
            if not sections:
                sections.append(("No Sections Selected", "Select at least one section checkbox above."))
            for title, body in sections:
                lines.append(f"--- {title} " + "-" * (68 - len(title)))
                lines.append(body)
                lines.append("")
            lines.append("=" * 72)
            lines.append("  END OF REPORT")
            lines.append("=" * 72)
            content = "\n".join(lines)
            try:
                with open(report_path, "w") as fobj:
                    fobj.write(content)
            except Exception:
                pass
            _log_queue.put((self._rp_out, content))
            _log_queue.put((self._rp_out, f"\n[*] Report saved to {report_path}"))

        threading.Thread(target=_run, daemon=True).start()

    # ================================================================ SETTINGS
    def _build_settings(self):
        f = self._page_frame("settings")
        f.grid_columnconfigure(0, weight=1)

        self._title(f, "Settings").grid(row=0, column=0, sticky="w", padx=24, pady=(20, 0))
        self._subtitle(f, "Vault, encryption, network privacy and system config").grid(
            row=1, column=0, sticky="w", padx=24, pady=(0, 12)
        )

        # ---- Vault Status card ----
        vault_card = self._card(f, "Vault Status", 2, 0)
        vault_inner = ctk.CTkFrame(vault_card, fg_color="transparent")
        vault_inner.pack(fill="x", padx=14, pady=8)
        self._st_vault_lbl = ctk.CTkLabel(
            vault_inner,
            text=f"Status: {'LOCKED' if not self._vault_password else 'UNLOCKED'}",
            font=ctk.CTkFont("Consolas", 11, "bold"),
            text_color="#ff8c00" if not self._vault_password else C_GREEN,
        )
        self._st_vault_lbl.pack(side="left")
        self._btn(vault_inner, "Change Password", "gray", self._settings_change_pwd).pack(side="right", padx=4)

        # ---- Network Info card ----
        net_card = self._card(f, "Current Network Info", 3, 0)
        net_inner = ctk.CTkFrame(net_card, fg_color="transparent")
        net_inner.pack(fill="x", padx=14, pady=8)
        ninfo = get_network_info()
        self._st_ip_lbl = ctk.CTkLabel(
            net_inner, text=f"IP: {ninfo['ip']}", font=ctk.CTkFont("Consolas", 10), text_color="#ffffff", anchor="w"
        )
        self._st_ip_lbl.pack(anchor="w")
        for iface, data in ninfo.get("interfaces", {}).items():
            lbl = ctk.CTkLabel(
                net_inner,
                text=f"{iface}: MAC {data['mac']}  [{'UP' if data['is_up'] else 'DOWN'}]",
                font=ctk.CTkFont("Consolas", 9),
                text_color="#888888",
                anchor="w",
            )
            lbl.pack(anchor="w")
        self._btn(net_inner, "Refresh", "gray", self._settings_refresh_net).pack(anchor="w", pady=(4, 0))

        # ---- IP Jumper card ----
        ip_card = self._card(f, "IP Jumper (Auto Rotation)", 4, 0)
        ip_cfg = self._config.get("ip_rotation", {})
        row1 = ctk.CTkFrame(ip_card, fg_color="transparent")
        row1.pack(fill="x", padx=14, pady=8)
        self._set_ip_enabled = self._checkbox(row1, "Enable IP Jumper")
        self._set_ip_enabled.pack(side="left", padx=(0, 12))
        if ip_cfg.get("enabled", False):
            self._set_ip_enabled.select()
        ctk.CTkLabel(row1, text="Interval (sec):", font=ctk.CTkFont("Consolas", 10), text_color="#888888").pack(
            side="left", padx=(0, 4)
        )
        self._set_ip_interval = ctk.CTkEntry(
            row1,
            width=80,
            fg_color="#0a0a0a",
            text_color="#ffffff",
            border_color=C_BORDER,
            border_width=1,
            corner_radius=4,
            font=ctk.CTkFont("Consolas", 10),
        )
        self._set_ip_interval.insert(0, str(ip_cfg.get("interval_seconds", 300)))
        self._set_ip_interval.pack(side="left", padx=(0, 8))

        row2 = ctk.CTkFrame(ip_card, fg_color="transparent")
        row2.pack(fill="x", padx=12, pady=(0, 8))
        ctk.CTkLabel(row2, text="Method:", font=ctk.CTkFont("Consolas", 10), text_color="#888888").pack(
            side="left", padx=(0, 4)
        )
        self._set_ip_method = self._combo(row2, ["dhcp", "mac_rotate"])
        self._set_ip_method.set(ip_cfg.get("method", "dhcp"))
        self._set_ip_method.pack(side="left", padx=(0, 8))
        ctk.CTkLabel(row2, text="Interface:", font=ctk.CTkFont("Consolas", 10), text_color="#888888").pack(
            side="left", padx=(0, 4)
        )
        self._set_ip_iface = self._combo(row2, get_interfaces())
        self._set_ip_iface.set(ip_cfg.get("interface", "en0"))
        self._set_ip_iface.pack(side="left", padx=(0, 8))
        self._btn(row2, "Rotate Now", "red", self._settings_rotate_now).pack(side="left", padx=(0, 4))
        self._btn(row2, "Stop Jumper", "gray", self._settings_stop_jumper).pack(side="left")

        # ---- DNS card ----
        dns_card = self._card(f, "DNS Configuration", 4, 0)
        dns_cfg = self._config.get("dns", {})
        dns_row = ctk.CTkFrame(dns_card, fg_color="transparent")
        dns_row.pack(fill="x", padx=14, pady=8)
        ctk.CTkLabel(dns_row, text="Primary:", font=ctk.CTkFont("Consolas", 10), text_color="#888888").pack(
            side="left", padx=(0, 4)
        )
        self._set_dns1 = ctk.CTkEntry(
            dns_row,
            width=140,
            fg_color="#0a0a0a",
            text_color="#ffffff",
            border_color=C_BORDER,
            border_width=1,
            corner_radius=4,
            font=ctk.CTkFont("Consolas", 10),
        )
        self._set_dns1.insert(0, dns_cfg.get("primary", "8.8.8.8"))
        self._set_dns1.pack(side="left", padx=(0, 8))
        ctk.CTkLabel(dns_row, text="Secondary:", font=ctk.CTkFont("Consolas", 10), text_color="#888888").pack(
            side="left", padx=(0, 4)
        )
        self._set_dns2 = ctk.CTkEntry(
            dns_row,
            width=140,
            fg_color="#0a0a0a",
            text_color="#ffffff",
            border_color=C_BORDER,
            border_width=1,
            corner_radius=4,
            font=ctk.CTkFont("Consolas", 10),
        )
        self._set_dns2.insert(0, dns_cfg.get("secondary", "8.8.4.4"))
        self._set_dns2.pack(side="left", padx=(0, 8))
        self._btn(dns_row, "Apply DNS", "red", self._settings_apply_dns).pack(side="left", padx=(0, 4))
        self._btn(dns_row, "Restore Default", "gray", self._settings_restore_dns).pack(side="left")

        dns_presets = ctk.CTkFrame(dns_card, fg_color="transparent")
        dns_presets.pack(fill="x", padx=12, pady=(0, 8))
        ctk.CTkLabel(dns_presets, text="Presets:", font=ctk.CTkFont("Consolas", 9), text_color="#666666").pack(
            side="left", padx=(0, 4)
        )
        for name, ip in [
            ("Google", "8.8.8.8"),
            ("Cloudflare", "1.1.1.1"),
            ("Quad9", "9.9.9.9"),
            ("OpenDNS", "208.67.222.222"),
        ]:
            self._btn(dns_presets, f"{name} ({ip})", "gray", lambda i=ip: self._set_dns1.insert(0, i)).pack(
                side="left", padx=2
            )

        # ---- MAC Randomization card ----
        mac_card = self._card(f, "MAC Address Randomization", 5, 0)
        mac_cfg = self._config.get("mac_randomization", {})
        mac_row = ctk.CTkFrame(mac_card, fg_color="transparent")
        mac_row.pack(fill="x", padx=14, pady=8)
        self._set_mac_enabled = self._checkbox(mac_row, "Randomize MAC on startup")
        self._set_mac_enabled.pack(side="left", padx=(0, 12))
        if mac_cfg.get("enabled", False):
            self._set_mac_enabled.select()
        ctk.CTkLabel(mac_row, text="Interface:", font=ctk.CTkFont("Consolas", 10), text_color="#888888").pack(
            side="left", padx=(0, 4)
        )
        self._set_mac_iface = self._combo(mac_row, get_interfaces())
        self._set_mac_iface.set(mac_cfg.get("interface", "en0"))
        self._set_mac_iface.pack(side="left", padx=(0, 8))
        self._btn(mac_row, "Randomize Now", "red", self._settings_randomize_mac).pack(side="left")

        # ---- Encryption card ----
        enc_card = self._card(f, "Encryption Settings", 6, 0)
        enc_cfg = self._config.get("encryption", {})
        enc_row = ctk.CTkFrame(enc_card, fg_color="transparent")
        enc_row.pack(fill="x", padx=14, pady=8)
        self._set_enc_scans = self._checkbox(enc_row, "Auto-encrypt scan results")
        self._set_enc_scans.pack(side="left", padx=(0, 12))
        if enc_cfg.get("auto_encrypt_scans", True):
            self._set_enc_scans.select()
        self._set_enc_meta = self._checkbox(enc_row, "Auto-encrypt metadata")
        self._set_enc_meta.pack(side="left", padx=(0, 12))
        if enc_cfg.get("auto_encrypt_metadata", True):
            self._set_enc_meta.select()

        enc_info = ctk.CTkFrame(enc_card, fg_color="transparent")
        enc_info.pack(fill="x", padx=12, pady=(0, 8))
        ctk.CTkLabel(
            enc_info,
            text="Algorithm: AES-256-CBC + HMAC-SHA512 | PBKDF2-SHA512 1M iterations | Vault: ~/.blacksentinel-strike/vault/",
            font=ctk.CTkFont("Consolas", 9),
            text_color="#666666",
        ).pack(anchor="w")

        # ---- General Info card ----
        gen_card = self._card(f, "Operator Info", 7, 0)
        gen_cfg = self._config.get("general", {})
        gen_inner = ctk.CTkFrame(gen_card, fg_color="transparent")
        gen_inner.pack(fill="x", padx=14, pady=8)
        ctk.CTkLabel(gen_inner, text="Company:", font=ctk.CTkFont("Consolas", 10), text_color="#888888").pack(
            side="left", padx=(0, 4)
        )
        self._set_company = ctk.CTkEntry(
            gen_inner,
            width=160,
            fg_color="#0a0a0a",
            text_color="#ffffff",
            border_color=C_BORDER,
            border_width=1,
            corner_radius=4,
            font=ctk.CTkFont("Consolas", 10),
        )
        self._set_company.insert(0, gen_cfg.get("company_name", ""))
        self._set_company.pack(side="left", padx=(0, 8))
        ctk.CTkLabel(gen_inner, text="Operator:", font=ctk.CTkFont("Consolas", 10), text_color="#888888").pack(
            side="left", padx=(0, 4)
        )
        self._set_operator = ctk.CTkEntry(
            gen_inner,
            width=160,
            fg_color="#0a0a0a",
            text_color="#ffffff",
            border_color=C_BORDER,
            border_width=1,
            corner_radius=4,
            font=ctk.CTkFont("Consolas", 10),
        )
        self._set_operator.insert(0, gen_cfg.get("operator_name", ""))
        self._set_operator.pack(side="left", padx=(0, 8))

        gen_row2 = ctk.CTkFrame(gen_card, fg_color="transparent")
        gen_row2.pack(fill="x", padx=12, pady=(0, 8))
        ctk.CTkLabel(
            gen_row2, text="Authorized Targets (comma-sep):", font=ctk.CTkFont("Consolas", 10), text_color="#888888"
        ).pack(side="left", padx=(0, 4))
        self._set_targets = ctk.CTkEntry(
            gen_row2,
            width=300,
            fg_color="#0a0a0a",
            text_color="#ffffff",
            border_color=C_BORDER,
            border_width=1,
            corner_radius=4,
            font=ctk.CTkFont("Consolas", 10),
        )
        self._set_targets.insert(0, gen_cfg.get("authorized_targets", ""))
        self._set_targets.pack(side="left")

        # ---- Upgrade card ----
        upg_card = self._card(f, "System Upgrade", 8, 0)
        upg_row = ctk.CTkFrame(upg_card, fg_color="transparent")
        upg_row.pack(fill="x", padx=14, pady=8)
        ver = get_current_version()
        self._st_ver_lbl = ctk.CTkLabel(
            upg_row, text=f"Current Version: v{ver}", font=ctk.CTkFont("Consolas", 10, "bold"), text_color="#ffffff"
        )
        self._st_ver_lbl.pack(side="left")
        self._btn(upg_row, "Check Updates", "gray", self._settings_check_update).pack(side="right", padx=4)
        self._btn(upg_row, "Install Deps", "gray", self._settings_install_deps).pack(side="right", padx=4)
        self._btn(upg_row, "Backup Now", "gray", self._settings_backup).pack(side="right", padx=4)
        self._btn(upg_row, "View Log", "gray", self._settings_upgrade_log).pack(side="right", padx=4)

        upg_row2 = ctk.CTkFrame(upg_card, fg_color="transparent")
        upg_row2.pack(fill="x", padx=12, pady=(0, 8))
        ctk.CTkLabel(upg_row2, text="Update Source URL:", font=ctk.CTkFont("Consolas", 10), text_color="#888888").pack(
            side="left", padx=(0, 4)
        )
        self._set_update_url = ctk.CTkEntry(
            upg_row2,
            width=350,
            fg_color="#0a0a0a",
            text_color="#ffffff",
            border_color=C_BORDER,
            border_width=1,
            corner_radius=4,
            font=ctk.CTkFont("Consolas", 10),
            placeholder_text="https://your-server.com/blacksentinel-strike-updates",
        )
        self._set_update_url.pack(side="left", padx=(0, 8))
        self._btn(upg_row2, "Apply Update", "red", self._settings_apply_update).pack(side="left")

        # ---- Save button ----
        save_row = ctk.CTkFrame(f, fg_color="transparent")
        save_row.grid(row=9, column=0, sticky="ew", padx=20, pady=(8, 16))
        self._btn(save_row, "SAVE ALL SETTINGS", "green", self._settings_save).pack(side="right", padx=(8, 0))
        self._btn(save_row, "Export Encrypted Backup", "gray", self._settings_export_backup).pack(
            side="right", padx=(8, 0)
        )
        self._btn(save_row, "Destroy Vault", "red", self._settings_destroy_vault).pack(side="left")

    def _settings_refresh_net(self):
        ninfo = get_network_info()
        self._st_ip_lbl.configure(text=f"IP: {ninfo['ip']}")
        self._log(f"[+] Network refreshed: IP {ninfo['ip']}")

    def _settings_rotate_now(self):
        if not self._ip_jumper:
            cfg = {
                "enabled": True,
                "interval_seconds": int(self._set_ip_interval.get() or 300),
                "method": self._set_ip_method.get(),
                "interface": self._set_ip_iface.get(),
            }
            self._ip_jumper = IPJumper(cfg, on_event=lambda m: self._log(m))
        self._ip_jumper._rotate()

    def _settings_stop_jumper(self):
        if self._ip_jumper:
            self._ip_jumper.stop()
            self._ip_jumper = None
            self._log("[+] IP Jumper stopped")

    def _settings_apply_dns(self):
        primary = self._set_dns1.get().strip()
        secondary = self._set_dns2.get().strip()
        if primary:
            ok, msg = set_dns(primary, secondary)
            status = "[+]" if ok else "[!]"
            self._log(f"{status} {msg}")

    def _settings_restore_dns(self):
        ok, msg = restore_dns()
        status = "[+]" if ok else "[!]"
        self._log(f"{status} {msg}")

    def _settings_randomize_mac(self):
        iface = self._set_mac_iface.get()
        ok, new_mac, msg = randomize_mac(iface)
        status = "[+]" if ok else "[!]"
        self._log(f"{status} {msg}")

    def _settings_save(self):
        self._config["ip_rotation"] = {
            "enabled": self._set_ip_enabled.get(),
            "interval_seconds": int(self._set_ip_interval.get() or 300),
            "method": self._set_ip_method.get(),
            "interface": self._set_ip_iface.get(),
        }
        self._config["dns"] = {
            "primary": self._set_dns1.get().strip(),
            "secondary": self._set_dns2.get().strip(),
        }
        self._config["mac_randomization"] = {
            "enabled": self._set_mac_enabled.get(),
            "interface": self._set_mac_iface.get(),
        }
        self._config["encryption"] = {
            "auto_encrypt_scans": self._set_enc_scans.get(),
            "auto_encrypt_metadata": self._set_enc_meta.get(),
        }
        self._config["general"] = {
            "company_name": self._set_company.get().strip(),
            "operator_name": self._set_operator.get().strip(),
            "authorized_targets": self._set_targets.get().strip(),
        }
        self._save_app_config()

        # apply IP jumper
        ip_cfg = self._config["ip_rotation"]
        if ip_cfg["enabled"]:
            if self._ip_jumper:
                self._ip_jumper.update_config(ip_cfg)
            else:
                self._start_ip_jumper()
        else:
            self._settings_stop_jumper()

    def _settings_export_backup(self):
        if not self._vault_password:
            self._log("[!] Vault not unlocked")
            return
        try:
            backup = {
                "config": self._config,
                "timestamp": datetime.datetime.now().isoformat(),
            }
            enc = encrypt_data(json.dumps(backup).encode(), self._vault_password)
            backup_path = Path.home() / ".blacksentinel-strike" / "backup.enc"
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            backup_path.write_bytes(enc)
            self._log(f"[+] Encrypted backup saved to {backup_path}")
        except Exception as e:
            self._log(f"[!] Backup failed: {e}")

    def _settings_change_pwd(self):
        if not self._vault_password:
            self._log("[!] Vault not unlocked")
            return
        dialog = ctk.CTkInputDialog(text="Enter current password:", title="Change Password")
        old = dialog.get_input()
        if old != self._vault_password:
            self._log("[!] Wrong current password")
            return
        dialog2 = ctk.CTkInputDialog(
            text="Enter new password:\n  - At least 1 uppercase letter\n  - At least 1 lowercase letter\n  - At least 3 numbers\n  - At least 1 special character (!@#$%^&*...)",
            title="New Password",
        )
        new = dialog2.get_input()
        if new:
            is_valid, errors = validate_password_policy(new)
            if not is_valid:
                self._log("[!] Password policy: " + "; ".join(errors))
                return
            self._vault_password = new
            save_config(self._config, new)
            self._log("[+] Password changed successfully")

    def _settings_destroy_vault(self):
        if not self._vault_password:
            self._log("[!] Vault not unlocked")
            return
        dialog = ctk.CTkInputDialog(
            text="TYPE 'DESTROY' TO CONFIRM:\nAll encrypted data will be permanently deleted.",
            title="DANGER - Destroy Vault",
        )
        confirm = dialog.get_input()
        if confirm == "DESTROY":
            from vault import destroy_vault

            destroy_vault(self._vault_password)
            self._vault_password = None
            self._config = {}
            self._log("[!] Vault destroyed. Restart app to reinitialize.")
        else:
            self._log("[*] Vault destruction cancelled")

    def _settings_check_update(self):
        url = self._set_update_url.get().strip()
        if not url:
            self._log("[!] Enter update source URL first")
            return
        self._log(f"[*] Checking for updates at {url}...")

        def _run():
            result = check_for_updates(url)
            if result.get("update_available"):
                self._log(f"[+] Update available: v{result['latest_version']}")
                if result.get("changelog"):
                    self._log(f"    Changelog: {result['changelog']}")
            else:
                self._log(f"[*] Already up to date (v{result['current_version']})")

        threading.Thread(target=_run, daemon=True).start()

    def _settings_install_deps(self):
        self._log("[*] Installing/updating dependencies...")

        def _run():
            ok, msg = install_deps()
            status = "[+]" if ok else "[!]"
            self._log(f"{status} {msg}")

        threading.Thread(target=_run, daemon=True).start()

    def _settings_backup(self):
        self._log("[*] Creating backup...")

        def _run():
            path = backup_current()
            self._log(f"[+] Backup created: {path}")

        threading.Thread(target=_run, daemon=True).start()

    def _settings_upgrade_log(self):
        log = get_upgrade_log()
        self._log(f"[+] Upgrade log:\n{log}")

    def _settings_apply_update(self):
        url = self._set_update_url.get().strip()
        if not url:
            self._log("[!] Enter update source URL first")
            return
        dialog = ctk.CTkInputDialog(
            text="Enter local path to update files\nor confirm remote download:", title="Apply Update"
        )
        path = dialog.get_input()
        if path:
            self._log(f"[*] Applying update from {path}...")

            def _run():
                ok, msg = apply_update(path)
                status = "[+]" if ok else "[!]"
                self._log(f"{status} {msg}")

            threading.Thread(target=_run, daemon=True).start()

    # ================================================================ HELP
    def _show_help(self):
        f = self._page_frame("help")
        f.grid_columnconfigure(0, weight=1)
        self._title(f, "Help").grid(row=0, column=0, sticky="w", padx=24, pady=(20, 0))
        card = self._card(f, None, 1, 0)
        t = self._textbox(card)
        t.pack(fill="both", expand=True, padx=8, pady=8)
        help_text = (
            "BlackSentinel Strike v4.0\n"
            "==========================\n\n"
            "Modules:\n"
            "[*] Dashboard     - System overview and quick access\n"
            "[*] Network Scan  - Discover hosts via nmap scans\n"
            "[*] Port Scanner  - Enumerate open ports and services\n"
            "[*] Web Explorer  - Web app recon (WhatWeb, Nikto, etc.)\n"
            "[*] Exploits      - Exploitation framework\n"
            "[*] Post-Exploit  - Post-compromise enumeration\n"
            "[*] Password      - Credential brute-force with hydra\n"
            "[*] Reports       - Generate assessment reports\n"
            "[*] Settings      - Vault, encryption, network privacy\n\n"
            "Security Features:\n"
            "[+] AES-256 encryption for all scan results\n"
            "[+] IP Jumper for automatic IP rotation\n"
            "[+] DNS switcher with presets\n"
            "[+] MAC address randomization\n"
            "[+] Encrypted vault for metadata and config\n"
            "[+] Encrypted backup export\n\n"
            "Tips:\n"
            "[-] Always ensure you have authorization before testing\n"
            "[-] Results are encrypted in ~/.blacksentinel-strike/vault/scans/\n"
            "[-] Use the console at the bottom for live output\n"
            "[-] Check Settings for network privacy options\n\n"
            "Disclaimer:\n"
            "[!] This tool is for authorized security testing only.\n"
            "[!] Unauthorized access to computer systems is illegal.\n"
        )
        t.configure(state="normal")
        t.insert("1.0", help_text)
        t.configure(state="disabled")
        self._pages["help"] = f
        f.grid(row=0, column=0, sticky="nsew", in_=self._content)
        f.lift()

    # ================================================================ SYSTEM INFO
    def _tick_sysinfo(self):
        def _update():
            cpu = 0.0
            ram = 0.0
            try:
                import psutil

                cpu = psutil.cpu_percent(interval=0.1)
                ram = psutil.virtual_memory().percent
            except ImportError:
                pass
            except Exception:
                pass
            self.after(0, lambda: self._update_syslbls(cpu, ram))

        threading.Thread(target=_update, daemon=True).start()
        self.after(2000, self._tick_sysinfo)

    def _update_syslbls(self, cpu, ram):
        self._lbl_cpu.configure(text=f"CPU: {cpu}%")
        self._lbl_ram.configure(text=f"RAM: {ram}%")

    # ================================================================ MITRE ATT&CK
    def _build_mitre(self):
        f = self._page_frame("mitre")
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(2, weight=1)
        self._title(f, "MITRE ATT&CK Coverage").grid(row=0, column=0, sticky="w", padx=24, pady=(20, 0))
        self._subtitle(f, "15 tactics - 222 techniques - 475 sub-techniques").grid(
            row=1, column=0, sticky="w", padx=24, pady=(0, 12)
        )
        opts = self._card(f, "Target", 2, 0)
        row1 = ctk.CTkFrame(opts, fg_color="transparent")
        row1.pack(fill="x", padx=14, pady=8)
        self._mitre_target = self._input(row1, "Target IP/Hostname")
        self._mitre_target.pack(side="left", padx=(0, 8), expand=True, fill="x")
        self._btn(row1, "Full Scan", "red", self._mitre_full_scan).pack(side="left")
        res_card = self._card(f, "Results", 3, 0)
        self._mitre_out = self._textbox(res_card)
        self._mitre_out.pack(fill="both", expand=True, padx=8, pady=8)
        self._mitre_engine = MITREAttack(callback=lambda m: _log_queue.put((self._mitre_out, m)))

    def _mitre_full_scan(self):
        target = self._mitre_target.get().strip()
        if not target:
            self._log("[!] No target specified", self._mitre_out)
            return
        self._log(f"[*] Running MITRE ATT&CK scan on {target}...", self._mitre_out)

        def _run():
            try:
                results = []
                for name, method in [
                    ("Recon", self._mitre_engine.t1595_active_scanning),
                    ("Initial Access", self._mitre_engine.t1190_exploit_public_app),
                    ("Discovery", self._mitre_engine.t1046_network_service),
                    ("Credential", self._mitre_engine.t1110_brute_force),
                    ("Lateral", self._mitre_engine.t1021_remote_services),
                ]:
                    _log_queue.put((self._mitre_out, f"[*] Running {name}..."))
                    try:
                        r = method(target)
                        _log_queue.put((self._mitre_out, f"[+] {name}: {r[:200]}"))
                        results.append(f"{name}: {r}")
                    except Exception as e:
                        _log_queue.put((self._mitre_out, f"[!] {name} error: {e}"))
                _log_queue.put((self._mitre_out, "[+] MITRE ATT&CK scan complete"))
            except Exception as e:
                _log_queue.put((self._mitre_out, f"[!] Error: {e}"))

        threading.Thread(target=_run, daemon=True).start()

    # ================================================================ MALWARE SIM
    def _build_malware(self):
        f = self._page_frame("malware")
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(2, weight=1)
        self._title(f, "Malware Simulation").grid(row=0, column=0, sticky="w", padx=24, pady=(20, 0))
        self._subtitle(f, "Ransomware, Infostealer, RAT, Worm, Fileless simulation").grid(
            row=1, column=0, sticky="w", padx=24, pady=(0, 12)
        )
        opts = self._card(f, "Simulation", 2, 0)
        row1 = ctk.CTkFrame(opts, fg_color="transparent")
        row1.pack(fill="x", padx=14, pady=8)
        self._mal_target = self._input(row1, "Target IP/Path")
        self._mal_target.pack(side="left", padx=(0, 8), expand=True, fill="x")
        self._mal_type = self._combo(row1, ["Ransomware", "Infostealer", "RAT", "Worm", "Fileless", "Full Audit"])
        self._mal_type.set("Full Audit")
        self._mal_type.pack(side="left", padx=(0, 8))
        self._btn(row1, "Simulate", "red", self._mal_run).pack(side="left")
        res_card = self._card(f, "Results", 3, 0)
        self._mal_out = self._textbox(res_card)
        self._mal_out.pack(fill="both", expand=True, padx=8, pady=8)
        self._mal_engine = MalwareSimulation(callback=lambda m: _log_queue.put((self._mal_out, m)))

    def _mal_run(self):
        target = self._mal_target.get().strip()
        mal_type = self._mal_type.get()
        if not target:
            self._log("[!] No target specified", self._mal_out)
            return
        self._log(f"[*] Running {mal_type} simulation on {target}...", self._mal_out)

        def _run():
            try:
                engine = self._mal_engine
                if mal_type == "Ransomware":
                    r = engine.simulate_ransomware(target)
                elif mal_type == "Infostealer":
                    r = engine.simulate_infostealer(target)
                elif mal_type == "RAT":
                    r = engine.simulate_rat(target)
                elif mal_type == "Worm":
                    r = engine.simulate_worm(target)
                elif mal_type == "Fileless":
                    r = engine.simulate_fileless(target)
                else:
                    r = engine.analyze_target(target)
                _log_queue.put((self._mal_out, f"[+] {r}"))
                _log_queue.put((self._mal_out, "[+] Simulation complete"))
            except Exception as e:
                _log_queue.put((self._mal_out, f"[!] Error: {e}"))

        threading.Thread(target=_run, daemon=True).start()

    # ================================================================ ROOTKIT DETECT
    def _build_rootkit(self):
        f = self._page_frame("rootkit")
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(2, weight=1)
        self._title(f, "Rootkit Detection").grid(row=0, column=0, sticky="w", padx=24, pady=(20, 0))
        self._subtitle(f, "User-space, Kernel, eBPF, Bootkit, Cross-view detection").grid(
            row=1, column=0, sticky="w", padx=24, pady=(0, 12)
        )
        opts = self._card(f, "Target", 2, 0)
        row1 = ctk.CTkFrame(opts, fg_color="transparent")
        row1.pack(fill="x", padx=14, pady=8)
        self._rk_target = self._input(row1, "Target IP/Localhost")
        self._rk_target.pack(side="left", padx=(0, 8), expand=True, fill="x")
        self._btn(row1, "Full Scan", "red", self._rk_full).pack(side="left")
        res_card = self._card(f, "Results", 3, 0)
        self._rk_out = self._textbox(res_card)
        self._rk_out.pack(fill="both", expand=True, padx=8, pady=8)
        self._rk_engine = RootkitDetection(callback=lambda m: _log_queue.put((self._rk_out, m)))

    def _rk_full(self):
        target = self._rk_target.get().strip() or "localhost"
        self._log(f"[*] Running rootkit scan on {target}...", self._rk_out)

        def _run():
            try:
                r = self._rk_engine.run_full_scan(target)
                _log_queue.put((self._rk_out, f"[+] {r}"))
            except Exception as e:
                _log_queue.put((self._rk_out, f"[!] Error: {e}"))

        threading.Thread(target=_run, daemon=True).start()

    # ================================================================ HONEYPOT DETECT
    def _build_honeypot(self):
        f = self._page_frame("honeypot")
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(2, weight=1)
        self._title(f, "Honeypot Detection").grid(row=0, column=0, sticky="w", padx=24, pady=(20, 0))
        self._subtitle(f, "Active, Passive, Anti-detection, Evasion techniques").grid(
            row=1, column=0, sticky="w", padx=24, pady=(0, 12)
        )
        opts = self._card(f, "Target", 2, 0)
        row1 = ctk.CTkFrame(opts, fg_color="transparent")
        row1.pack(fill="x", padx=14, pady=8)
        self._hp_target = self._input(row1, "Target IP")
        self._hp_target.pack(side="left", padx=(0, 8), expand=True, fill="x")
        self._btn(row1, "Detect", "red", self._hp_run).pack(side="left")
        res_card = self._card(f, "Results", 3, 0)
        self._hp_out = self._textbox(res_card)
        self._hp_out.pack(fill="both", expand=True, padx=8, pady=8)
        self._hp_engine = HoneypotDetection(callback=lambda m: _log_queue.put((self._hp_out, m)))

    def _hp_run(self):
        target = self._hp_target.get().strip()
        if not target:
            self._log("[!] No target specified", self._hp_out)
            return
        self._log(f"[*] Detecting honeypots on {target}...", self._hp_out)

        def _run():
            try:
                r = self._hp_engine.comprehensive_analysis(target)
                _log_queue.put((self._hp_out, f"[+] {r}"))
            except Exception as e:
                _log_queue.put((self._hp_out, f"[!] Error: {e}"))

        threading.Thread(target=_run, daemon=True).start()

    # ================================================================ CLOUD ATTACK
    def _build_cloud(self):
        f = self._page_frame("cloud")
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(2, weight=1)
        self._title(f, "Cloud Attack").grid(row=0, column=0, sticky="w", padx=24, pady=(20, 0))
        self._subtitle(f, "AWS, Azure, GCP - Metadata, IAM, Storage, Compute").grid(
            row=1, column=0, sticky="w", padx=24, pady=(0, 12)
        )
        opts = self._card(f, "Target", 2, 0)
        row1 = ctk.CTkFrame(opts, fg_color="transparent")
        row1.pack(fill="x", padx=14, pady=8)
        self._cl_target = self._input(row1, "Target IP/Endpoint")
        self._cl_target.pack(side="left", padx=(0, 8), expand=True, fill="x")
        self._cl_provider = self._combo(row1, ["AWS", "Azure", "GCP", "All"])
        self._cl_provider.set("AWS")
        self._cl_provider.pack(side="left", padx=(0, 8))
        self._btn(row1, "Scan", "red", self._cl_run).pack(side="left")
        res_card = self._card(f, "Results", 3, 0)
        self._cl_out = self._textbox(res_card)
        self._cl_out.pack(fill="both", expand=True, padx=8, pady=8)
        self._cl_engine = CloudAttack(callback=lambda m: _log_queue.put((self._cl_out, m)))

    def _cl_run(self):
        target = self._cl_target.get().strip()
        provider = self._cl_provider.get()
        if not target:
            self._log("[!] No target specified", self._cl_out)
            return
        self._log(f"[*] Scanning {provider} target: {target}...", self._cl_out)

        def _run():
            try:
                engine = self._cl_engine
                if provider == "AWS":
                    r = engine.aws_metadata_exploit(target)
                elif provider == "Azure":
                    r = engine.azure_metadata_exploit(target)
                elif provider == "GCP":
                    r = engine.gcp_metadata_exploit(target)
                else:
                    r = engine.aws_metadata_exploit(target)
                _log_queue.put((self._cl_out, f"[+] {r}"))
            except Exception as e:
                _log_queue.put((self._cl_out, f"[!] Error: {e}"))

        threading.Thread(target=_run, daemon=True).start()

    # ================================================================ CONTAINER ESCAPE
    def _build_container(self):
        f = self._page_frame("container")
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(2, weight=1)
        self._title(f, "Container Escape").grid(row=0, column=0, sticky="w", padx=24, pady=(20, 0))
        self._subtitle(f, "Docker, Kubernetes, Container breakout techniques").grid(
            row=1, column=0, sticky="w", padx=24, pady=(0, 12)
        )
        opts = self._card(f, "Target", 2, 0)
        row1 = ctk.CTkFrame(opts, fg_color="transparent")
        row1.pack(fill="x", padx=14, pady=8)
        self._ct_target = self._input(row1, "Target Container/Host")
        self._ct_target.pack(side="left", padx=(0, 8), expand=True, fill="x")
        self._ct_type = self._combo(row1, ["Docker", "Kubernetes", "Both"])
        self._ct_type.set("Docker")
        self._ct_type.pack(side="left", padx=(0, 8))
        self._btn(row1, "Escape Test", "red", self._ct_run).pack(side="left")
        res_card = self._card(f, "Results", 3, 0)
        self._ct_out = self._textbox(res_card)
        self._ct_out.pack(fill="both", expand=True, padx=8, pady=8)
        self._ct_engine = ContainerEscape(callback=lambda m: _log_queue.put((self._ct_out, m)))

    def _ct_run(self):
        target = self._ct_target.get().strip()
        ctype = self._ct_type.get()
        if not target:
            self._log("[!] No target specified", self._ct_out)
            return
        self._log(f"[*] Testing {ctype} container escape on {target}...", self._ct_out)

        def _run():
            try:
                engine = self._ct_engine
                if ctype == "Docker":
                    r = engine.docker_privileged_escape(target)
                elif ctype == "Kubernetes":
                    r = engine.k8s_privileged_escape(target)
                else:
                    r = engine.docker_privileged_escape(target)
                _log_queue.put((self._ct_out, f"[+] {r}"))
            except Exception as e:
                _log_queue.put((self._ct_out, f"[!] Error: {e}"))

        threading.Thread(target=_run, daemon=True).start()

    # ================================================================ AD ATTACK
    def _build_ad_attack(self):
        f = self._page_frame("ad_attack")
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(2, weight=1)
        self._title(f, "Active Directory Attack").grid(row=0, column=0, sticky="w", padx=24, pady=(20, 0))
        self._subtitle(f, "Enumeration, Kerberos, DCSync, Golden/Silver Ticket, Lateral").grid(
            row=1, column=0, sticky="w", padx=24, pady=(0, 12)
        )
        opts = self._card(f, "Target", 2, 0)
        row1 = ctk.CTkFrame(opts, fg_color="transparent")
        row1.pack(fill="x", padx=14, pady=8)
        self._ad_target = self._input(row1, "Domain Controller IP")
        self._ad_target.pack(side="left", padx=(0, 8), expand=True, fill="x")
        self._btn(row1, "Enumerate", "red", self._ad_run).pack(side="left")
        res_card = self._card(f, "Results", 3, 0)
        self._ad_out = self._textbox(res_card)
        self._ad_out.pack(fill="both", expand=True, padx=8, pady=8)
        self._ad_engine = ADAttack(callback=lambda m: _log_queue.put((self._ad_out, m)))

    def _ad_run(self):
        target = self._ad_target.get().strip()
        if not target:
            self._log("[!] No target specified", self._ad_out)
            return
        self._log(f"[*] Enumerating AD on {target}...", self._ad_out)

        def _run():
            try:
                r = self._ad_engine.enumerate_domain_info(target)
                _log_queue.put((self._ad_out, f"[+] {r}"))
            except Exception as e:
                _log_queue.put((self._ad_out, f"[!] Error: {e}"))

        threading.Thread(target=_run, daemon=True).start()

    # ================================================================ WIRELESS ADV
    def _build_wireless_adv(self):
        f = self._page_frame("wireless_adv")
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(2, weight=1)
        self._title(f, "Wireless Advanced").grid(row=0, column=0, sticky="w", padx=24, pady=(20, 0))
        self._subtitle(f, "WiFi, Bluetooth, RF, IoT attacks").grid(row=1, column=0, sticky="w", padx=24, pady=(0, 12))
        opts = self._card(f, "Target", 2, 0)
        row1 = ctk.CTkFrame(opts, fg_color="transparent")
        row1.pack(fill="x", padx=14, pady=8)
        self._wa_target = self._input(row1, "Target BSSID/Interface")
        self._wa_target.pack(side="left", padx=(0, 8), expand=True, fill="x")
        self._btn(row1, "Scan", "red", self._wa_run).pack(side="left")
        res_card = self._card(f, "Results", 3, 0)
        self._wa_out = self._textbox(res_card)
        self._wa_out.pack(fill="both", expand=True, padx=8, pady=8)
        self._wa_engine = WirelessAdvanced(callback=lambda m: _log_queue.put((self._wa_out, m)))

    def _wa_run(self):
        target = self._wa_target.get().strip()
        if not target:
            self._log("[!] No target specified", self._wa_out)
            return
        self._log(f"[*] Scanning wireless target: {target}...", self._wa_out)

        def _run():
            try:
                r = self._wa_engine.scan_wifi_networks(target)
                _log_queue.put((self._wa_out, f"[+] {r}"))
            except Exception as e:
                _log_queue.put((self._wa_out, f"[!] Error: {e}"))

        threading.Thread(target=_run, daemon=True).start()

    # ================================================================ WEB ADV
    def _build_web_adv(self):
        f = self._page_frame("web_adv")
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(2, weight=1)
        self._title(f, "Web Attack Advanced").grid(row=0, column=0, sticky="w", padx=24, pady=(20, 0))
        self._subtitle(f, "SQLi, XSS, SSRF, Deserialization, Business Logic").grid(
            row=1, column=0, sticky="w", padx=24, pady=(0, 12)
        )
        opts = self._card(f, "Target", 2, 0)
        row1 = ctk.CTkFrame(opts, fg_color="transparent")
        row1.pack(fill="x", padx=14, pady=8)
        self._wa2_target = self._input(row1, "Target URL (http://...)")
        self._wa2_target.pack(side="left", padx=(0, 8), expand=True, fill="x")
        self._wa2_type = self._combo(row1, ["SQLi", "XSS", "SSRF", "Deserialization", "Full Scan"])
        self._wa2_type.set("Full Scan")
        self._wa2_type.pack(side="left", padx=(0, 8))
        self._btn(row1, "Attack", "red", self._wa2_run).pack(side="left")
        res_card = self._card(f, "Results", 3, 0)
        self._wa2_out = self._textbox(res_card)
        self._wa2_out.pack(fill="both", expand=True, padx=8, pady=8)
        self._wa2_engine = WebAdvanced(callback=lambda m: _log_queue.put((self._wa2_out, m)))

    def _wa2_run(self):
        target = self._wa2_target.get().strip()
        atype = self._wa2_type.get()
        if not target:
            self._log("[!] No target specified", self._wa2_out)
            return
        self._log(f"[*] Running {atype} attack on {target}...", self._wa2_out)

        def _run():
            try:
                engine = self._wa2_engine
                if atype == "SQLi":
                    r = engine.sqlmap_auto_detect(target)
                elif atype == "XSS":
                    r = engine.reflected_scan(target)
                elif atype == "SSRF":
                    r = engine.basic_detection(target)
                else:
                    r = engine.full_scan(target)
                _log_queue.put((self._wa2_out, f"[+] {r}"))
            except Exception as e:
                _log_queue.put((self._wa2_out, f"[!] Error: {e}"))

        threading.Thread(target=_run, daemon=True).start()

    # ================================================================ NETWORK ADV
    def _build_net_adv(self):
        f = self._page_frame("net_adv")
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(2, weight=1)
        self._title(f, "Network Advanced").grid(row=0, column=0, sticky="w", padx=24, pady=(20, 0))
        self._subtitle(f, "MITM, DoS, Protocol Analysis, Discovery").grid(
            row=1, column=0, sticky="w", padx=24, pady=(0, 12)
        )
        opts = self._card(f, "Target", 2, 0)
        row1 = ctk.CTkFrame(opts, fg_color="transparent")
        row1.pack(fill="x", padx=14, pady=8)
        self._na_target = self._input(row1, "Target IP/Subnet")
        self._na_target.pack(side="left", padx=(0, 8), expand=True, fill="x")
        self._btn(row1, "Audit", "red", self._na_run).pack(side="left")
        res_card = self._card(f, "Results", 3, 0)
        self._na_out = self._textbox(res_card)
        self._na_out.pack(fill="both", expand=True, padx=8, pady=8)
        self._na_engine = NetworkAdvanced(callback=lambda m: _log_queue.put((self._na_out, m)))

    def _na_run(self):
        target = self._na_target.get().strip()
        if not target:
            self._log("[!] No target specified", self._na_out)
            return
        self._log(f"[*] Running network audit on {target}...", self._na_out)

        def _run():
            try:
                r = self._na_engine.full_network_audit(target)
                _log_queue.put((self._na_out, f"[+] {r}"))
            except Exception as e:
                _log_queue.put((self._na_out, f"[!] Error: {e}"))

        threading.Thread(target=_run, daemon=True).start()

    # ================================================================ FORENSIC ADV
    def _build_forensic_adv(self):
        f = self._page_frame("forensic_adv")
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(2, weight=1)
        self._title(f, "Forensic Advanced").grid(row=0, column=0, sticky="w", padx=24, pady=(20, 0))
        self._subtitle(f, "Disk, Memory, Network, Mobile forensics").grid(
            row=1, column=0, sticky="w", padx=24, pady=(0, 12)
        )
        opts = self._card(f, "Target", 2, 0)
        row1 = ctk.CTkFrame(opts, fg_color="transparent")
        row1.pack(fill="x", padx=14, pady=8)
        self._fa_target = self._input(row1, "Target/Image Path")
        self._fa_target.pack(side="left", padx=(0, 8), expand=True, fill="x")
        self._fa_type = self._combo(row1, ["Disk", "Memory", "Network", "Mobile"])
        self._fa_type.set("Disk")
        self._fa_type.pack(side="left", padx=(0, 8))
        self._btn(row1, "Analyze", "red", self._fa_run).pack(side="left")
        res_card = self._card(f, "Results", 3, 0)
        self._fa_out = self._textbox(res_card)
        self._fa_out.pack(fill="both", expand=True, padx=8, pady=8)
        self._fa_engine = ForensicAdvanced(callback=lambda m: _log_queue.put((self._fa_out, m)))

    def _fa_run(self):
        target = self._fa_target.get().strip()
        ftype = self._fa_type.get()
        if not target:
            self._log("[!] No target specified", self._fa_out)
            return
        self._log(f"[*] Running {ftype} forensics on {target}...", self._fa_out)

        def _run():
            try:
                engine = self._fa_engine
                if ftype == "Disk":
                    r = engine.disk_image_acquisition(target)
                elif ftype == "Memory":
                    r = engine.memory_acquisition(target)
                elif ftype == "Network":
                    r = engine.network_pcap_analysis(target)
                else:
                    r = engine.mobile_android_acquisition(target)
                _log_queue.put((self._fa_out, f"[+] {r}"))
            except Exception as e:
                _log_queue.put((self._fa_out, f"[!] Error: {e}"))

        threading.Thread(target=_run, daemon=True).start()

    # ================================================================ SOCIAL ADV
    def _build_social_adv(self):
        f = self._page_frame("social_adv")
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(2, weight=1)
        self._title(f, "Social Engineering Advanced").grid(row=0, column=0, sticky="w", padx=24, pady=(20, 0))
        self._subtitle(f, "Phishing, Pretexting, Baiting, Physical security").grid(
            row=1, column=0, sticky="w", padx=24, pady=(0, 12)
        )
        opts = self._card(f, "Scenario", 2, 0)
        row1 = ctk.CTkFrame(opts, fg_color="transparent")
        row1.pack(fill="x", padx=14, pady=8)
        self._se_target = self._input(row1, "Target Domain/Company")
        self._se_target.pack(side="left", padx=(0, 8), expand=True, fill="x")
        self._se_type = self._combo(row1, ["Phishing", "Pretexting", "Baiting", "Physical"])
        self._se_type.set("Phishing")
        self._se_type.pack(side="left", padx=(0, 8))
        self._btn(row1, "Generate", "red", self._se_run).pack(side="left")
        res_card = self._card(f, "Results", 3, 0)
        self._se_out = self._textbox(res_card)
        self._se_out.pack(fill="both", expand=True, padx=8, pady=8)
        self._se_engine = SocialEngineeringAdvanced(callback=lambda m: _log_queue.put((self._se_out, m)))

    def _se_run(self):
        target = self._se_target.get().strip()
        stype = self._se_type.get()
        if not target:
            self._log("[!] No target specified", self._se_out)
            return
        self._log(f"[*] Generating {stype} scenario for {target}...", self._se_out)

        def _run():
            try:
                self._se_engine.authorize("AUTHORIZED_PENTEST")
                engine = self._se_engine
                if stype == "Phishing":
                    r = engine.create_phishing_email("credential_harvest")
                elif stype == "Pretexting":
                    r = engine.generate_pretext("tech_support")
                elif stype == "Baiting":
                    r = engine.create_usb_bait("rubber_ducky")
                else:
                    r = engine.tailgating_plan(target)
                _log_queue.put((self._se_out, f"[+] {r}"))
            except Exception as e:
                _log_queue.put((self._se_out, f"[!] Error: {e}"))

        threading.Thread(target=_run, daemon=True).start()

    # ================================================================ POST-EXP ADV
    def _build_post_adv(self):
        f = self._page_frame("post_adv")
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(2, weight=1)
        self._title(f, "Post-Exploitation Advanced").grid(row=0, column=0, sticky="w", padx=24, pady=(20, 0))
        self._subtitle(f, "Privilege Escalation, Persistence, Exfil, Lateral Movement").grid(
            row=1, column=0, sticky="w", padx=24, pady=(0, 12)
        )
        opts = self._card(f, "Target", 2, 0)
        row1 = ctk.CTkFrame(opts, fg_color="transparent")
        row1.pack(fill="x", padx=14, pady=8)
        self._pe_target = self._input(row1, "Target IP/User@Host")
        self._pe_target.pack(side="left", padx=(0, 8), expand=True, fill="x")
        self._btn(row1, "Enumerate", "red", self._pe_adv_run).pack(side="left")
        res_card = self._card(f, "Results", 3, 0)
        self._pe_out = self._textbox(res_card)
        self._pe_out.pack(fill="both", expand=True, padx=8, pady=8)
        self._pe_engine = PostExploitationAdvanced(callback=lambda m: _log_queue.put((self._pe_out, m)))

    def _pe_adv_run(self):
        target = self._pe_target.get().strip()
        if not target:
            self._log("[!] No target specified", self._pe_out)
            return
        self._log(f"[*] Running post-exploitation on {target}...", self._pe_out)

        def _run():
            try:
                r = self._pe_engine.full_enumeration(target)
                _log_queue.put((self._pe_out, f"[+] {r}"))
            except Exception as e:
                _log_queue.put((self._pe_out, f"[!] Error: {e}"))

        threading.Thread(target=_run, daemon=True).start()

    # ================================================================ RECON ADV
    def _build_recon_adv(self):
        f = self._page_frame("recon_adv")
        f.grid_columnconfigure(0, weight=1)
        f.grid_rowconfigure(2, weight=1)
        self._title(f, "Recon Advanced").grid(row=0, column=0, sticky="w", padx=24, pady=(20, 0))
        self._subtitle(f, "OSINT, Passive, Active, Network reconnaissance").grid(
            row=1, column=0, sticky="w", padx=24, pady=(0, 12)
        )
        opts = self._card(f, "Target", 2, 0)
        row1 = ctk.CTkFrame(opts, fg_color="transparent")
        row1.pack(fill="x", padx=14, pady=8)
        self._ra_target = self._input(row1, "Target Domain/IP")
        self._ra_target.pack(side="left", padx=(0, 8), expand=True, fill="x")
        self._btn(row1, "Recon", "red", self._ra_run).pack(side="left")
        res_card = self._card(f, "Results", 3, 0)
        self._ra_out = self._textbox(res_card)
        self._ra_out.pack(fill="both", expand=True, padx=8, pady=8)
        self._ra_engine = ReconAdvanced(callback=lambda m: _log_queue.put((self._ra_out, m)))

    def _ra_run(self):
        target = self._ra_target.get().strip()
        if not target:
            self._log("[!] No target specified", self._ra_out)
            return
        self._log(f"[*] Running advanced recon on {target}...", self._ra_out)

        def _run():
            try:
                r = self._ra_engine.run_all(target)
                _log_queue.put((self._ra_out, f"[+] {r}"))
            except Exception as e:
                _log_queue.put((self._ra_out, f"[!] Error: {e}"))

        threading.Thread(target=_run, daemon=True).start()

    # ------------------------------------------------------------------ close
    def _on_close(self):
        # stop IP jumper
        if self._ip_jumper:
            self._ip_jumper.stop()
        # save metadata before closing
        if self._vault_password and self._config.get("encryption", {}).get("auto_encrypt_metadata", True):
            try:
                meta = {
                    "last_ip": get_current_ip(),
                    "last_close": datetime.datetime.now().isoformat(),
                    "interfaces": get_network_info().get("interfaces", {}),
                }
                save_metadata(meta, self._vault_password)
            except Exception:
                pass
        # terminate running scans
        for attr in ["_ns_proc", "_ps_proc"]:
            proc = getattr(self, attr, None)
            if proc and proc.poll() is None:
                proc.terminate()
        self.destroy()


# Alias for backward compatibility
BlackSentinelStrike = App

if __name__ == "__main__":
    app = App()
    app.mainloop()

#!/usr/bin/env python3
"""
THEMES AND STYLES - BlackSentinel Strike
Professional dark orange/black theme for penetration testing
"""


class BlackSentinelTheme:
    """Professional BlackSentinel Strike theme - Orange/Black/Gray"""
    BG_DARK = "#000000"
    BG_MEDIUM = "#0a0a0a"
    BG_LIGHT = "#111111"
    BG_CARD = "#1a1a1a"
    ACCENT = "#cc6600"
    ACCENT_BRIGHT = "#ff8c00"
    PRIMARY = "#ff8c00"
    SECONDARY = "#663300"
    SUCCESS = "#00cc44"
    WARNING = "#ffaa00"
    ERROR = "#ff3333"
    TEXT = "#ffffff"
    TEXT_DIM = "#888888"
    BORDER = "#333333"
    HOVER = "#222222"
    ORANGE = "#ff8c00"
    ORANGE_DARK = "#cc6600"
    ORANGE_LIGHT = "#ffb366"
    GRAY_DARK = "#1a1a1a"
    GRAY_MEDIUM = "#444444"
    GRAY_LIGHT = "#888888"


class DarkTheme:
    """Default dark theme"""
    BG_DARK = "#0a0a0f"
    BG_MEDIUM = "#12121a"
    BG_LIGHT = "#1a1a2e"
    BG_CARD = "#16213e"
    ACCENT = "#0f3460"
    ACCENT_BRIGHT = "#533483"
    PRIMARY = "#00d4ff"
    SECONDARY = "#7b2cbf"
    SUCCESS = "#00ff88"
    WARNING = "#ffaa00"
    ERROR = "#ff3366"
    TEXT = "#ffffff"
    TEXT_DIM = "#8892b0"
    BORDER = "#233554"
    HOVER = "#1f4068"


def get_theme(name="blacksentinel"):
    themes = {
        "blacksentinel": BlackSentinelTheme,
        "dark": DarkTheme,
    }
    return themes.get(name, BlackSentinelTheme)


DEFAULT_THEME = BlackSentinelTheme

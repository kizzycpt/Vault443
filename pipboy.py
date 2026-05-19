#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
    Vault 443 - Web Parsing / DNS Mapping Dashboard
    
    Developed by kizzycpt

    - Web Scraping and Filtering
    - TLS Certificate Inspection
    - Mass IP Enumeration and Logging

"""

import os, sys, argparse, ctypes

# ── Windows VT100 / UTF-8 setup ───────────────────────────────────────────────
if sys.platform == "win32":
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# ── Boot animation ────────────────────────────────────────────────────────────
from frontend.startup import run_boot_animation

# ── Dashboard ─────────────────────────────────────────────────────────────────
from frontend.dashboard import Dashboard


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Vault 443 - Web Parsing and DNS Mapping Dashboard"
    )
    parser.add_argument(
        "--theme",
        choices=list(Dashboard.THEMES),
        default="pipboy",
        help="Colour theme (default: pipboy)",
    )
    parser.add_argument(
        "--animate",
        type=int,
        default=10,
        help="Animation speed in seconds (default: 10)",
    )
    parser.add_argument(
        "--log_path",
        type=str,
        default=None,
        help="Custom scrape log path",
    )
    parser.add_argument(
        "--skip-intro",
        action="store_true",
        help="Skip the boot animation and go straight to the dashboard",
    )

    args = parser.parse_args()

    # play boot animation unless --skip-intro flag is passed
    if not args.skip_intro:
        try:
            run_boot_animation()
        except KeyboardInterrupt:
            pass   # Ctrl-C during animation → just launch the dashboard

    dashboard = Dashboard(theme=args.theme, animate=args.animate)

    try:
        dashboard.run()
    finally:
        # always restore cursor on exit
        print("\033[?25h", end="", flush=True)


# good luck bruh
if __name__ == "__main__":
    main()
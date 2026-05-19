#!/usr/bin/env python3
"""
frontend/startup.py
Plays the startup gif frames fullscreen in the terminal.
Called by main.py before the dashboard loop starts.
Press any key to skip.
"""

import os
import sys
import time
import select
import shutil

from PIL import Image

RESET = "\033[0m"

def _rgb(r, g, b):
    return f"\033[38;2;{r};{g};{b}m"

def _rgb_bg(r, g, b):
    return f"\033[48;2;{r};{g};{b}m"


def _check_skip() -> bool:
    """Non-blocking check — return True if any keypress is waiting."""
    if sys.platform == "win32":
        import msvcrt
        return msvcrt.kbhit()
    return bool(select.select([sys.stdin], [], [], 0)[0])


def _render_frame_fullscreen(frame: Image.Image, tw: int, th: int) -> str:
    
    if tw < 1 or th < 1:
        return ""

    # target pixel dimensions
    target_px_w = tw          # 1 pixel per column
    target_px_h = th * 2     # 2 pixels per row (half-block)

    # scale uniformly to fit, preserving aspect ratio
    scale = min(target_px_w / frame.width, target_px_h / frame.height)
    new_w = max(1, int(frame.width  * scale))
    new_h = max(2, int(frame.height * scale))
    if new_h % 2:             # must be even for clean row pairing
        new_h -= 1

    frame = frame.resize((new_w, new_h), Image.LANCZOS)

    # pixel-space centering
    off_px_x = (target_px_w - new_w) // 2
    off_px_y = (target_px_h - new_h) // 2
    if off_px_y % 2:          # keep even so pixel pairs stay aligned
        off_px_y -= 1

    lines = []
    for cy in range(th):
        py_top = cy * 2 - off_px_y      # pixel y — upper half-block
        py_bot = py_top + 1             # pixel y — lower half-block
        row    = []
        for cx in range(tw):
            px     = cx - off_px_x     # pixel x — 1:1 with column
            in_top = 0 <= py_top < new_h and 0 <= px < new_w
            in_bot = 0 <= py_bot < new_h and 0 <= px < new_w
            if in_top or in_bot:
                tr, tg, tb  = frame.getpixel((px, py_top)) if in_top else (0, 0, 0)
                br, bg_, bb = frame.getpixel((px, py_bot)) if in_bot else (0, 0, 0)
                row.append(_rgb_bg(tr, tg, tb) + _rgb(br, bg_, bb) + "▄" + RESET)
            else:
                row.append(" ")
        lines.append("".join(row))

    # move to top-left then join rows
    return "\033[H" + "\n".join(lines)


def run_boot_animation(frames_dir: str = "frontend/frames/startup",
                       fps: int = 10) -> None:
    """
    Load PNG frames from frames_dir and play them fullscreen at fps.
    Returns when the sequence ends or the user presses any key to skip.
    """
    if not os.path.isdir(frames_dir):
        return

    png_files = [f for f in os.listdir(frames_dir) if f.endswith(".png")]
    if not png_files:
        return

    # sort by the trailing number after the last dash
    # e.g. "616ea0e1-...-10.png" → 10
    png_files = sorted(
        png_files,
        key=lambda f: int(f.rsplit("-", 1)[-1].replace(".png", ""))
    )

    frames = [
        Image.open(os.path.join(frames_dir, f)).convert("RGB")
        for f in png_files
    ]

    spf = 1.0 / fps

    # hide cursor, clear screen
    sys.stdout.write("\033[?25l\033[2J\033[H")
    sys.stdout.flush()

    try:
        for frame in frames:
            if _check_skip():
                break

            tw, th = shutil.get_terminal_size(fallback=(80, 24))
            sys.stdout.write(_render_frame_fullscreen(frame, tw, th))
            sys.stdout.flush()
            time.sleep(spf)

    except KeyboardInterrupt:
        pass
    finally:
        # clear screen, restore cursor, reset colours before dashboard takes over
        sys.stdout.write("\033[2J\033[H\033[?25h" + RESET)
        sys.stdout.flush()
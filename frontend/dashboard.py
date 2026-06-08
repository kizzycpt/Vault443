#!/usr/bin/env python3
# any front end is rendered by claude AI. all backend work is mine

import time, os, sys, socket, random, uuid

from threading  import Thread
from PIL        import Image
from blessed    import Terminal

# ── escape helpers ────────────────────────────────────────────────────────────
RESET = "\033[0m"

def rgb(r, g, b):
    return f"\033[38;2;{r};{g};{b}m"

def rgb_bg(r, g, b):
    return f"\033[48;2;{r};{g};{b}m"

# ── tool imports ──────────────────────────────────────────────────────────────
try:
    from modes.web_scraper import web_scraper
except Exception:
    web_scraper = None

try:
    from modes.tls_inspect import tls_inspection
except Exception:
    tls_inspection = None




# ─────────────────────────────────────────────────────────────────────────────
class Dashboard:

    THEMES = {
        "pipboy": {"name": "pipboy", "feed": "bright_yellow", "stats": "bright_cyan",  "matrix": (0, 255, 65)},
        "olive":  {"name": "olive",  "feed": "green",         "stats": "green",         "matrix": (0, 150, 40)},
        "bleed":  {"name": "bleed",  "feed": "bright_red",    "stats": "bright_red",    "matrix": (255, 30,  0)},
    }

    _RGB = {
        "bright_green":   (0,   255, 65),  "green":        (0,   150, 40),
        "bright_yellow":  (255, 255, 0),   "yellow":       (255, 176, 0),
        "bright_cyan":    (0,   255, 255), "cyan":         (0,   191, 255),
        "bright_magenta": (255, 0,   255), "magenta":      (255, 0,   255),
        "bright_blue":    (100, 149, 237), "blue":         (0,   0,   255),
        "bright_white":   (255, 255, 255), "white":        (200, 200, 200),
        "bright_red":     (255, 0,   0),   "red":          (200, 0,   0),
        "orange":         (255, 165, 0),   "purple":       (138, 43,  226),
    }

    _MATRIX_CHARS = (
        "ｦｧｨｩｪｫｬｭｮｯｰｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ"
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ@#$%&"
    )

    # ── init ──────────────────────────────────────────────────────────────────
    def __init__(self, theme="pipboy", animate=10):

        self.term                = Terminal()
        self.animate             = animate
        self.start_time          = time.time()
        self.theme_names         = list(self.THEMES)
        tidx                     = self.theme_names.index(theme) if theme in self.THEMES else 0
        self.current_theme_index = tidx
        self.theme               = self.THEMES[self.theme_names[tidx]]

        self.paused              = False
        self.show_legend         = False
        self.running             = True

        # tool references
        self.web_scraper_panel   = web_scraper
        self.tls_inspect_panel   = tls_inspection

        # panel visibility flags
        self.web_scraper_mode    = False
        self.tls_inspect_mode    = False

        # lifecycle  0=closed 1=input 2=running 3=done
        self.web_scraper_state   = 0
        self.tls_inspect_state   = 0

        # input routing  None | "tls_host" | "scraper_domain" | "scraper_flag" | "ip_threads"
        self.active_input_mode   = None
        self.input_buffer        = ""
        self._scraper_domain     = ""

        # matrix
        self.matrix_cols         = {}
        self.matrix_last_update  = 0.0

        # animations
        self.animations          = {"vaultboy": [], "success": []}
        self.current_animation   = "vaultboy"
        self.anim_start_time     = time.time()

        self.load_frames("frontend/frames/vaultboy", "vaultboy")
        self.load_frames("frontend/frames/success",  "success")

    # ── theme ─────────────────────────────────────────────────────────────────

    def cycle_theme(self):
        self.current_theme_index = (self.current_theme_index + 1) % len(self.theme_names)
        self.theme               = self.THEMES[self.theme_names[self.current_theme_index]]
        self.matrix_cols         = {}

    def get_color(self, color_name, dim=False):
        r, g, b = self._RGB.get(color_name, (255, 255, 255))
        if dim:
            r, g, b = int(r * .55), int(g * .55), int(b * .55)
        code = rgb(r, g, b)
        return lambda text: code + str(text) + RESET

    # ── animation ─────────────────────────────────────────────────────────────

    def load_frames(self, folder, key):
        if not os.path.isdir(folder):
            return
        all_files = [f for f in os.listdir(folder) if f.endswith(".png")]
        if not all_files:
            return
        if key == "vaultboy":
            files = sorted(all_files,
                           key=lambda f: int(f.replace("frame_", "").replace(".png", "")))
        else:
            files = sorted(all_files,
                           key=lambda f: int(f.rsplit("-", 1)[-1].replace(".png", "")))

        self.animations[key] = [
            Image.open(os.path.join(folder, f)).convert("RGB")
            for f in files
        ]

    def switch_animation(self, name):
        if name in self.animations:
            self.current_animation = name
            self.anim_start_time   = time.time()

    def get_frame(self):
        frames = self.animations.get(self.current_animation, [])
        if not frames:
            return None
        fps = 10
        idx = int((time.time() - self.anim_start_time) * fps)
        if self.current_animation == "success":
            if idx >= len(frames):
                self.switch_animation("vaultboy")
                return self.get_frame()
            return frames[idx]
        return frames[idx % len(frames)]

    # ── matrix rain ───────────────────────────────────────────────────────────

    def _init_matrix(self, width, height):
        for col in range(width):
            if col not in self.matrix_cols:
                self.matrix_cols[col] = {
                    "pos":   random.uniform(0, height),
                    "speed": random.uniform(0.3, 1.2),
                    "trail": random.randint(4, 20),
                    "chars": [random.choice(self._MATRIX_CHARS) for _ in range(max(height, 1))],
                }

    def _update_matrix(self, width, height):
        now = time.time()
        if now - self.matrix_last_update < 0.05:
            return
        self.matrix_last_update = now
        for col in range(width):
            c = self.matrix_cols[col]
            c["pos"] += c["speed"]
            if c["pos"] > height + c["trail"]:
                c["pos"]   = random.uniform(-c["trail"], 0)
                c["speed"] = random.uniform(0.3, 1.2)
                c["trail"] = random.randint(4, 20)
            if random.random() < 0.15:
                r = random.randint(0, height - 1)
                c["chars"][r] = random.choice(self._MATRIX_CHARS)

    def render_matrix(self, width, height):
        self._init_matrix(width, height)
        self._update_matrix(width, height)
        mr, mg, mb = self.theme.get("matrix", (0, 255, 65))

        screen = [[(" ", False)] * width for _ in range(height)]
        for row in range(height):
            for col in range(width):
                c    = self.matrix_cols[col]
                ch   = c["chars"][row % len(c["chars"])]
                head = int(c["pos"]) % max(height, 1)
                dist = (head - row) % max(height, 1)
                if dist == 0:
                    screen[row][col] = (rgb(255, 255, 255) + ch + RESET, False)
                elif dist < c["trail"]:
                    fade             = 1.0 - dist / c["trail"]
                    screen[row][col] = (
                        rgb(int(mr * fade), int(mg * fade), int(mb * fade)) + ch + RESET,
                        False,
                    )
        return screen

    # ── gif / halfblock panel ─────────────────────────────────────────────────

    def _render_halfblock(self, frame: Image.Image, cols: int, rows: int) -> list:
        if frame is None or cols < 1 or rows < 1:
            return [" " * cols] * rows

        target_w = cols
        target_h = rows * 2
        scale    = min(target_w / frame.width, target_h / frame.height)
        new_w    = max(1, int(frame.width  * scale))
        new_h    = max(2, int(frame.height * scale) // 2 * 2)

        frame  = frame.resize((new_w, new_h), Image.NEAREST)
        pixels = frame.load()
        ox     = (target_w - new_w) // 2
        oy     = (target_h - new_h) // 2 // 2

        lines = []
        for row in range(rows):
            line = []
            for col in range(cols):
                src_x = col - ox
                src_y = (row - oy) * 2

                def get_px(x, y):
                    if 0 <= x < new_w and 0 <= y < new_h:
                        return pixels[x, y]
                    return (0, 0, 0)

                tr, tg, tb  = get_px(src_x, src_y)
                br, bg_, bb = get_px(src_x, src_y + 1)
                line.append(rgb_bg(tr, tg, tb) + rgb(br, bg_, bb) + "▄" + RESET)
            lines.append("".join(line))
        return lines

    def gif_panel_render(self, cols: int, rows: int) -> list:
        frame = self.get_frame()
        if frame is None:
            return [" " * cols] * rows
        return self._render_halfblock(frame, cols, rows)

    # ── panel helpers ─────────────────────────────────────────────────────────

    def _blank_screen(self, width, height):
        return [[(" ", False)] * width for _ in range(height)]

    def _write_line(self, screen, row, col, text, width):
        for i, ch in enumerate(text):
            if col + i >= width:
                break
            screen[row][col + i] = (ch, False)

    # ── TLS inspect panel ─────────────────────────────────────────────────────

    def render_tls_panel(self, width, height):
        screen = self._blank_screen(width, height)
        p      = self.tls_inspect_panel
        inner  = width - 4
        pad_x  = 2

        if p and p.scanning:
            status = f"SCANNING  {p.host}..."
        elif p and p.scan_done and p.results:
            status = "COMPLETE"
        else:
            status = "READY"

        sep  = "═" * inner
        dash = "─" * inner

        lines = [
            sep,
            "TLS INSPECT".center(inner),
            sep,
            f"  Status  : {status}",
            dash,
        ]

        if self.active_input_mode == "tls_host":
            lines += [
                "  Enter domain to inspect:",
                f"  > {self.input_buffer}█",
                "",
                "  ENTER to scan  |  ESC to cancel",
            ]
        elif p and p.scanning:
            dots   = "." * (int(time.time() * 2) % 4)
            lines += [f"  Connecting{dots}"]
        elif p and p.scan_done and p.results:
            r     = p.results
            col_w = max(1, inner - 14)
            if r.get("error"):
                lines += ["  ERROR", f"  {r['error'][:inner - 4]}"]
            else:
                lines += [
                    f"  {'Domain':<10}: {str(r.get('domain',  '?'))[:col_w]}",
                    f"  {'Status':<10}: {str(r.get('status',  '?'))[:col_w]}",
                    f"  {'Issuer':<10}: {str(r.get('issuer',  '?'))[:col_w]}",
                    f"  {'Expires':<10}: {str(r.get('expires','?'))[:col_w]}",
                    f"  {'TLS':<10}: {str(r.get('tls',    '?'))[:col_w]}",
                    f"  {'Cipher':<10}: {str(r.get('cipher', '?'))[:col_w]}",
                ]
            lines += ["", "  [W] scan again  |  [X] close"]
        else:
            lines += ["  Press [W] to scan a domain"]

        lines += [
            dash,
            "  [W] New scan   [X] Close   [Q] Quit",
            sep,
        ]

        start_y = max(0, (height - len(lines)) // 2)
        for i, line in enumerate(lines):
            y = start_y + i
            if y >= height:
                break
            self._write_line(screen, y, pad_x, line[:inner], width)

        return screen

    # ── web scraper panel ─────────────────────────────────────────────────────

    def render_scraper_panel(self, width, height):
        screen = self._blank_screen(width, height)
        p      = self.web_scraper_panel
        inner  = width - 4
        pad_x  = 2

        if p and p.scanning:
            status = f"SCRAPING  {getattr(p, 'domain', '...')}..."
        elif p and p.scan_done and p.results:
            status = "COMPLETE"
        else:
            status = "READY"

        sep  = "═" * inner
        dash = "─" * inner

        lines = [
            sep,
            "WEB SCRAPER".center(inner),
            sep,
            f"  Status  : {status}",
            dash,
        ]

        if self.active_input_mode == "scraper_domain":
            lines += [
                "  Enter domain (without https://):",
                f"  > {self.input_buffer}█",
                "",
                "  ENTER to continue  |  ESC to cancel",
            ]
        elif self.active_input_mode == "scraper_flag":
            lines += [
                f"  Domain  : {self._scraper_domain}",
                "  Enter text to search for:",
                f"  > {self.input_buffer}█",
                "",
                "  ENTER to scrape  |  ESC to cancel",
            ]
        elif p and p.scanning:
            dots   = "." * (int(time.time() * 2) % 4)
            lines += [f"  Fetching page{dots}"]
        elif p and p.scan_done and p.results:
            r     = p.results
            col_w = max(1, inner - 14)
            if r.get("error"):
                lines += ["  ERROR", f"  {r['error'][:inner - 4]}"]
            else:
                result       = str(r.get("result", "Not found"))
                result_lines = [result[i:i + col_w]
                                for i in range(0, min(len(result), col_w * 3), col_w)]
                lines += [
                    f"  {'Code':<10}: {r.get('status_code', '?')}",
                    f"  {'Engine':<10}: {r.get('engine',     '?')}",
                    f"  {'Result':<10}:",
                ]
                for rl in result_lines:
                    lines.append(f"    {rl}")
            lines += ["", "  [S] scrape again  |  [X] close"]
        else:
            lines += ["  Press [S] to scrape a domain"]

        lines += [
            dash,
            "  [S] New scrape   [X] Close   [Q] Quit",
            sep,
        ]

        start_y = max(0, (height - len(lines)) // 2)
        for i, line in enumerate(lines):
            y = start_y + i
            if y >= height:
                break
            self._write_line(screen, y, pad_x, line[:inner], width)

        return screen

    # ── main render ───────────────────────────────────────────────────────────

    def render(self):
        tw = self.term.width
        th = self.term.height

        right_w        = max(26, int(tw * 0.28))
        main_w         = tw - right_w - 1
        main_h         = th - 2
        feed_x         = main_w + 1
        stats_h        = 6
        feed_h         = th - stats_h - 7
        stats_y        = feed_h + 1
        left_inner_w   = main_w - 2
        left_inner_h   = main_h
        matrix_inner_h = max(1, left_inner_h - 2)

        fc = self.get_color(self.theme["feed"])
        sc = self.get_color(self.theme["stats"])
        mc = self.get_color(self.theme["feed"], dim=True)

        out = ["\033[?25l", self.term.home]

        # ── left panel border ─────────────────────────────────────────────────
        if self.tls_inspect_mode:
            left_title = " TLS Inspect "
        elif self.web_scraper_mode:
            left_title = " Web Scraper "
        
        else:
            left_title = " Matrix "

        top_dash = "─" * (main_w - len(left_title) - 2)
        out.append(self.term.move(0, 0) + fc("┌" + left_title + top_dash + "┐"))

        for y in range(1, main_h + 1):
            out.append(self.term.move(y, 0)          + fc("│"))
            out.append(self.term.move(y, main_w - 1) + fc("│"))

        out.append(self.term.move(main_h + 1, 0) + fc("└" + "─" * (main_w - 2) + "┘"))

        # ── left panel content ────────────────────────────────────────────────
        if self.tls_inspect_mode:
            left_screen = self.render_tls_panel(left_inner_w, left_inner_h)
        elif self.web_scraper_mode:
            left_screen = self.render_scraper_panel(left_inner_w, left_inner_h)
        
        else:
            left_screen = self.render_matrix(left_inner_w, matrix_inner_h)

        for y, row in enumerate(left_screen):
            if y >= left_inner_h:
                break
            line = []
            for cell in row:
                line.append(cell[0] if isinstance(cell, tuple) else cell)
            out.append(self.term.move(y + 1, 1) + "".join(line))

        # ── gif panel ─────────────────────────────────────────────────────────
        gif_inner_w = right_w - 2
        gif_inner_h = feed_h  - 1

        gif_title = " Vault Boy "
        gif_fill  = "─" * (right_w - len(gif_title) - 2)
        out.append(self.term.move(0,      feed_x) + fc("┌" + gif_title + gif_fill + "┐"))
        out.append(self.term.move(feed_h, feed_x) + fc("└" + "─" * (right_w - 2) + "┘"))

        for y in range(1, feed_h):
            out.append(self.term.move(y, feed_x)               + fc("│"))
            out.append(self.term.move(y, feed_x + right_w - 1) + fc("│"))

        for y, row_str in enumerate(self.gif_panel_render(gif_inner_w, gif_inner_h)):
            out.append(self.term.move(y + 1, feed_x + 1) + row_str)

        # ── stats panel ───────────────────────────────────────────────────────
        st_title = f" Stats — {self.theme['name'].upper()} "
        st_fill  = "─" * (right_w - len(st_title) - 2)
        out.append(self.term.move(stats_y, feed_x) + sc("┌" + st_title + st_fill + "┐"))
        out.append(self.term.move(th - 1,  feed_x) + sc("└" + "─" * (right_w - 2) + "┘"))

        for y in range(stats_y + 1, th - 1):
            out.append(self.term.move(y, feed_x)               + sc("│"))
            out.append(self.term.move(y, feed_x + right_w - 1) + sc("│"))

        try:
            local_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            local_ip = "unknown"
        try:
            mac = ":".join(f"{(uuid.getnode() >> (8*i)) & 0xff:02x}" for i in range(5, -1, -1))
        except Exception:
            mac = "unknown"

        elapsed     = int(time.time() - self.start_time)
        h, rem      = divmod(elapsed, 3600)
        m, s        = divmod(rem, 60)
        stats_inner = right_w - 4

        tls_stat = (
            "scanning" if (self.tls_inspect_panel and self.tls_inspect_panel.scanning) else
            "done"     if (self.tls_inspect_panel and self.tls_inspect_panel.scan_done) else
            "idle"
        )
        scraper_stat = (
            "scanning" if (self.web_scraper_panel and self.web_scraper_panel.scanning) else
            "done"     if (self.web_scraper_panel and self.web_scraper_panel.scan_done) else
            "idle"
        )
        

        stat_lines = [
            f"IP      : {local_ip}",
            f"MAC     : {mac}",
            f"Uptime  : {h:02d}:{m:02d}:{s:02d}",
            f"Anim    : {self.current_animation}",
            "─" * stats_inner,
            f"TLS     : {tls_stat}",
            f"Scraper : {scraper_stat}"
        ]

        for i, line in enumerate(stat_lines):
            y = stats_y + 2 + i
            if y >= th - 2:
                break
            out.append(
                self.term.move(y, feed_x + 2) +
                sc(line[:stats_inner].ljust(stats_inner))
            )

        # ── legend bar ────────────────────────────────────────────────────────
        legend    = " [W]TLS  [S]Scrape  [T]Theme  [C]Legend  [Q]Quit"
        st_txt    = "PAUSED" if self.paused else "LIVE"
        st_col    = self.get_color("bright_red") if self.paused else self.get_color("bright_green")
        bar_inner = main_w - 2

        if self.show_legend:
            out.append(self.term.move(main_h, 1) + fc(legend[:bar_inner].center(bar_inner)))
        else:
            tag    = f" {st_txt} "
            rest_w = max(0, bar_inner - len(tag))
            out.append(
                self.term.move(main_h, 1) +
                st_col(tag) +
                mc(legend[:rest_w].ljust(rest_w))
            )

        out.append(self.term.move(th - 1, tw - 1) + "\033[?25l")
        sys.stdout.write("".join(out))
        sys.stdout.flush()

    # ── input handling ────────────────────────────────────────────────────────

    def handle_input(self):
        with self.term.cbreak():
            while self.running:
                key = self.term.inkey(timeout=0.05)
                if not key:
                    continue

                k = str(key).lower()

                # ── text input intercept ──────────────────────────────────────
                if self.active_input_mode is not None:
                    if key.code == self.term.KEY_ENTER:
                        self._commit_input()
                    elif key.code == self.term.KEY_BACKSPACE:
                        self.input_buffer = self.input_buffer[:-1]
                    elif key.code == self.term.KEY_ESCAPE:
                        self.active_input_mode = None
                        self.input_buffer      = ""
                    elif not key.is_sequence:
                        self.input_buffer += str(key)
                    continue

                # ── hotkeys ───────────────────────────────────────────────────
                if k == "q" or key.code == self.term.KEY_ESCAPE:
                    self.running = False
                elif key == " ":
                    self.paused = not self.paused
                elif k == "t":
                    self.cycle_theme()
                elif k == "c":
                    self.show_legend = not self.show_legend
                elif k == "x":
                    self._close_all_panels()
                elif k == "w":
                    self._open_tls()
                elif k == "s":
                    self._open_scraper()
                

    # ── panel open / close ────────────────────────────────────────────────────

    def _close_all_panels(self):
        self.tls_inspect_mode  = False
        self.web_scraper_mode  = False
        self.ip_scan_mode      = False
        self.tls_inspect_state = 0
        self.web_scraper_state = 0
        self.active_input_mode = None
        self.input_buffer      = ""
        self._scraper_domain   = ""

        if self.tls_inspect_panel:
            self.tls_inspect_panel.scan_done = False
            self.tls_inspect_panel.scanning  = False
            self.tls_inspect_panel.results   = {}
        if self.web_scraper_panel:
            self.web_scraper_panel.scan_done = False
            self.web_scraper_panel.scanning  = False
            self.web_scraper_panel.results   = {}
     

    def _open_tls(self):
        self.tls_inspect_mode  = True
        self.web_scraper_mode  = False
        self.ip_scan_mode      = False
        self.tls_inspect_state = 1
        self.active_input_mode = "tls_host"
        self.input_buffer      = ""
        if self.tls_inspect_panel:
            self.tls_inspect_panel.scan_done = False
            self.tls_inspect_panel.results   = {}

    def _open_scraper(self):
        self.web_scraper_mode  = True
        self.tls_inspect_mode  = False
        self.ip_scan_mode      = False
        self.web_scraper_state = 1
        self.active_input_mode = "scraper_domain"
        self.input_buffer      = ""
        self._scraper_domain   = ""
        if self.web_scraper_panel:
            self.web_scraper_panel.scan_done = False
            self.web_scraper_panel.results   = {}



    # ── commit input ──────────────────────────────────────────────────────────

    def _commit_input(self):
        val  = self.input_buffer.strip()
        mode = self.active_input_mode
        self.input_buffer      = ""
        self.active_input_mode = None

        if mode == "tls_host":
            if val and self.tls_inspect_panel:
                self.tls_inspect_state = 2
                Thread(target=self.tls_inspect_panel.start, args=(val,), daemon=True).start()

        elif mode == "scraper_domain":
            if val:
                self._scraper_domain   = val
                self.active_input_mode = "scraper_flag"

        elif mode == "scraper_flag":
            if self._scraper_domain and self.web_scraper_panel:
                self.web_scraper_state = 2
                Thread(
                    target=self.web_scraper_panel.start,
                    args=(self._scraper_domain, val),
                    daemon=True,
                ).start()
            self._scraper_domain = ""

       

    # ── watch for tool completion ─────────────────────────────────────────────

    def _watch_tools(self):
        while self.running:
            time.sleep(0.2)

            tls = self.tls_inspect_panel
            if tls and tls.scan_done and self.tls_inspect_state == 2:
                self.tls_inspect_state = 3
                self.switch_animation("success")

            ws = self.web_scraper_panel
            if ws and ws.scan_done and self.web_scraper_state == 2:
                self.web_scraper_state = 3
                self.switch_animation("success")

            

    # ── run ───────────────────────────────────────────────────────────────────

    def run(self):
        Thread(target=self.handle_input, daemon=True).start()
        Thread(target=self._watch_tools, daemon=True).start()

        sys.stdout.write("\033[?25l\033[2J\033[H")
        sys.stdout.flush()

        with self.term.fullscreen(), self.term.hidden_cursor():
            try:
                while self.running:
                    t0    = time.time()
                    self.render()
                    sleep = max(0, 0.05 - (time.time() - t0))
                    if sleep:
                        time.sleep(sleep)
            except KeyboardInterrupt:
                pass
            finally:
                self.running = False
                sys.stdout.write("\033[?25h")
                sys.stdout.flush()
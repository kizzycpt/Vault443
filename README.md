# Vault 443 ☢️

> *A Fallout-inspired terminal dashboard for network reconnaissance and web intelligence.*

Vault 443 is a Python-based OSINT toolkit wrapped in a Pip-Boy aesthetic. It runs fully in the terminal with an animated fullscreen dashboard — matrix rain background, a live Vault Boy animation, and real-time stats. Three core modules handle TLS certificate inspection, web scraping with keyword search, and mass IP scanning.

---

## Features

- **TLS Inspection** — connects to any domain on port 443 and extracts certificate details: issuer, expiry, TLS version, cipher suite, and validity status
- **Web Scraper** — fetches a target domain and searches for a keyword; falls back to headless Playwright if the page is JavaScript-rendered. Scrape logs are saved automatically to `peels/<domain>/`
- **IP Scanner** — mass public IP enumeration and logging (drop `ip_scanner.py` into `modes/` to enable)
- **Terminal Dashboard** — fullscreen TUI built with `blessed`, featuring matrix rain, half-block Vault Boy GIF animation, live stats (IP, MAC, uptime, module status), and a boot animation
- **Themes** — cycle between `pipboy` (yellow/cyan), `olive` (green), and `bleed` (red) with `[T]`

---

## Requirements

- Python 3.10+
- A terminal with UTF-8 and ANSI true-colour support

```bash
pip install -r requirements.txt
```

Dependencies include `requests`, `beautifulsoup4`, `playwright`, `blessed`, and `Pillow`. After install, run:

```bash
playwright install chromium
```

---

## Usage

```bash
python pipboy.py
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--theme` | `pipboy` | Colour theme: `pipboy`, `olive`, `bleed` |
| `--animate` | `10` | Animation speed in seconds |
| `--log_path` | auto | Custom path for scrape logs |
| `--skip-intro` | off | Skip boot animation |

---

## Keybindings

| Key | Action |
|-----|--------|
| `W` | Open TLS Inspect panel |
| `S` | Open Web Scraper panel |
| `I` | Start IP Scanner |
| `T` | Cycle theme |
| `C` | Toggle keybinding legend |
| `X` | Close active panel |
| `Space` | Pause / resume |
| `Q` / `Esc` | Quit |

---

## Project Structure

```
Vault443/
├── pipboy.py              # Entry point
├── requirements.txt
├── frontend/
│   ├── dashboard.py       # TUI dashboard and panel renderers
│   ├── startup.py         # Boot animation (PNG frames → half-block)
│   ├── frames/
│   │   ├── vaultboy/      # Vault Boy idle animation frames
│   │   ├── success/       # Scan complete animation frames
│   │   └── startup/       # Boot sequence frames
│   └── constants.py       # ANSI colour helpers, version
├── modes/
│   ├── tls_inspect.py     # TLS certificate inspector
│   ├── web_scraper.py     # requests + Playwright scraper
│   └── ip_scanner.py      # Mass IP scanner (add your own)
└── peels/                 # Auto-generated scrape logs
    └── <domain>/
        └── <timestamp>.json
```

---

## Web Scraper — CSS Selector Cheat Sheet

The scraper accepts any text string as a search flag. Use CSS selector syntax for precise targeting:

| Syntax | Type | Example | Matches |
|--------|------|---------|---------|
| `.class` | Class | `.price` | Any element with class `price` |
| `#id` | ID | `#main-content` | Element with id `main-content` |
| `tag` | Tag | `h1` | Top-level headings |
| `tag.class` | Combined | `div.price` | `<div>` with class `price` |
| `parent child` | Descendant | `.card h2` | `h2` inside `.card` |
| `[attr]` | Attribute | `[data-price]` | Has a `data-price` attribute |
| `[attr='val']` | Exact attr | `[data-id='42']` | Exact attribute value match |

---

## Disclaimer

Vault 443 is intended for use on systems and domains you own or have explicit permission to scan. Unauthorised scanning of third-party infrastructure may violate laws in your jurisdiction.

---

*Developed by [kizzycpt](https://github.com/kizzycpt) — Version 1.0.0*
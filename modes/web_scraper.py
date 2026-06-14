#!/usr/bin/env python3

import requests
import threading

from bs4                 import BeautifulSoup
from playwright.sync_api import sync_playwright
from pathlib             import Path
from datetime            import datetime

base_dir = Path(__file__).resolve().parent.parent / "database"


class WebScraper:

    def __init__(self):
        self.scanning     = False
        self.scan_done    = False
        self.fetch_done   = False
        self.results      = {}
        self.domain       = None
        self.search_flag  = None
        self._soup        = None
        self._log_path    = None

    def fetch(self, domain):
        self.scanning   = True
        self.scan_done  = False
        self.fetch_done = False
        self.results    = {}
        self.domain     = domain
        self._soup      = None

        try:
            url        = f"https://www.{domain}"
            time_stamp = datetime.now().strftime("%Y_%B_%d_%H_%M%p")
            log_path   = base_dir / "peels" / f"{domain}" / f"{time_stamp}.html"
            log_path.parent.mkdir(parents=True, exist_ok=True)

            response = requests.get(url, timeout=15)

            self.results["status_code"] = response.status_code
            self.results["headers"]     = dict(response.headers)

            soup = BeautifulSoup(response.text, "html.parser")
            log_path.write_text(soup.prettify())

            self._soup     = soup
            self._log_path = log_path
            self.results["result"] = f"Saved {log_path.name}"
            self.results["engine"] = "requests"

        except Exception as e:
            self.results["error"] = str(e)

        finally:
            self.scanning   = False
            self.fetch_done = True
            self.scan_done  = True

    def search(self, search_flag):
        self.scanning   = True
        self.scan_done  = False
        self.search_flag = search_flag

        try:
            if self._soup is None:
                self.results["error"] = "No page fetched yet"
                return

            soup   = self._soup
            result = soup.find(string=search_flag)

            if result:
                self.results["result"] = result
                self.results["engine"] = "requests"
            else:
                # fall back to playwright for JS-rendered content
                url = f"https://www.{self.domain}"
                with sync_playwright() as p:
                    browser = p.chromium.launch(headless=True)
                    page    = browser.new_page()
                    page.goto(url)
                    html    = page.content()
                    browser.close()

                soup = BeautifulSoup(html, "html.parser")
                if self._log_path:
                    self._log_path.write_text(soup.prettify())

                result = soup.find(string=search_flag)
                self.results["result"] = result or "Not found"
                self.results["engine"] = "playwright"

        except Exception as e:
            self.results["error"] = str(e)

        finally:
            self.scanning  = False
            self.scan_done = True

    # ── thread starters ─────────────────────────────────────────────
    def start_fetch(self, domain):
        threading.Thread(target=self.fetch, args=(domain,), daemon=True).start()

    def start_search(self, search_flag):
        threading.Thread(target=self.search, args=(search_flag,), daemon=True).start()


web_scraper = WebScraper()
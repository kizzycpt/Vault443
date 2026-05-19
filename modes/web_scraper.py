#!/usr/bin/env python3

import requests
import threading
import time

from threading           import Thread
from bs4                 import BeautifulSoup
from playwright.sync_api import sync_playwright
from pathlib             import Path
from datetime            import datetime

base_dir = Path(__file__).resolve().parent


class WebScraper:

    def __init__(self):
        self.scanning    = False
        self.scan_done   = False
        self.results     = {}
        self.domain      = None
        self.search_flag = None

    def fetch_data(self, domain, search_flag):
        self.scanning    = True
        self.scan_done   = False
        self.results     = {}
        self.domain      = domain
        self.search_flag = search_flag

        try:
            url        = f"https://www.{domain}"
            time_stamp = datetime.now().strftime("%Y_%B_%d_%H_%M%p")
            log_path   = base_dir / "peels" / f"{domain}" / f"{time_stamp}.json"
            log_path.parent.mkdir(parents=True, exist_ok=True)

            response = requests.get(url, timeout=15)

            self.results["status_code"] = response.status_code
            self.results["headers"]     = dict(response.headers)

            if search_flag in response.text:
                soup   = BeautifulSoup(response.text, "html.parser")
                result = soup.find(string=search_flag)
                log_path.write_text(soup.prettify())          # was missing ()
                self.results["result"] = result or "Found (no exact text node)"
                self.results["engine"] = "requests"

            else:
                with sync_playwright() as p:
                    browser = p.chromium.launch(headless=True)
                    page    = browser.new_page()
                    page.goto(url)
                    html    = page.content()
                    soup    = BeautifulSoup(html, "html.parser")
                    result  = soup.find(string=search_flag)
                    log_path.write_text(soup.prettify())
                    self.results["result"] = result or "Not found"
                    self.results["engine"] = "playwright"
                    browser.close()

        except Exception as e:
            self.results["error"] = str(e)

        finally:
            self.scanning  = False
            self.scan_done = True

    def start(self, domain, search_flag):
        threading.Thread(
            target=self.fetch_data,
            args=(domain, search_flag),
            daemon=True
        ).start()


web_scraper = WebScraper()

if __name__ == "__main__":
    domain      = input("Enter domain: ").strip()
    search_flag = input("Enter search filter: ").strip()
    web_scraper.start(domain, search_flag)
    # wait for result
    while web_scraper.scanning:
        time.sleep(0.2)
    print(web_scraper.results)
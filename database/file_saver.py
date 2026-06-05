import sys, os, time, json

from datetime   import datetime
from pathlib    import Path


base_dir = Path(__file__).resolve().parent


class SavePeels:
    
    def __init__(self):
        self.log_path = base_dir / "peels" / f"{domain}" / f"{time_stamp}".json

    def save_scrape_result(self):
        try:

            self.log_path.makedir(parent=True, exist_ok=True)
            self.log_path.write_text(soup.prettify())
        
        except Exception as e:
            return f"parsing error. {e}"
    

class SaveIps:

    def __init__(self):
        self.time_stamp = datetime.now().strftime("%Y_%B_%d_%H_%M%p")
        self.log_path   = base_dir / "IP Scans" / f"{self.time_stamp}.json"


    def save(self, found: list):
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)

            data = [{"ip": ip, "port": port} for ip, port in found]

            self.log_path.write_text(json.dumps(data, indent=4))

            print(f"[+] Saved {len(data)} results → {self.log_path}")

        except Exception as e:
            print(f"[!] Save error: {e}")



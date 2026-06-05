import sys, os, time, json


from pathlib import Path


base_dir = Path(__file__).resolve().parent


class SavePeels:
    
    log_path = base_dir / "peels" / f"{domain}" / f"{time_stamp}".json

    def save_result():
        try:

            log_path.makedir(parent=True, exist_ok=True)
            log_path.write_text(soup.prettify())
        
        except Exception as e:
            return "error. {e}"
    

class SaveIps:

    time_stamp = datetime.now().strftime("%Y_%B_%d_%H_%M%p")
    log_path = base_dir / "IP Scans" / f"{time_stamp}".json

    try:
        log_path.makedir(parent=True, exist_ok=True)
        





class SaveCerts:

    time_stamp = datetime.now().strftime("%Y_%B_%d_%H_%M%p")
    log_path = base_dir / "TLS Inspections" / f"{self.results[domain]}" / f"{time_stamp}".json
    
    try:
        log_path.makedir(parent=True, exist_ok=True)
        log_path.write_text(self.results)



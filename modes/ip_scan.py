import socket, random, ipaddress

from threading              import Thread, Lock
from concurrent.futures     import ThreadPoolExecutor
from database.file_saver    import SaveIps


class MassIPScanner:

    def __init__(self):
        self.scanning       = False
        self.scan_done      = False

        self.online_ips     = 0
        self.scanned_ips    = 0
        self.found          = []
        self.errors         = 0

        self.country        = None
        self.ports          = [7, 19, 20, 21, 22, 23, 25, 42, 43, 49, 53, 67, 68, 69, 70, 79, 80, 88,
                                102, 110, 113, 119, 123, 135, 137, 138, 139, 143, 161, 162, 177, 179,
                                194, 201, 264, 318, 381, 383, 389, 411, 412, 427, 443, 445, 464, 465,
                                497, 500, 512, 513, 514, 515, 520, 521, 540, 548, 554, 546, 547, 560,
                                563, 587, 591, 593, 596, 631, 636, 639, 646, 691, 860, 873, 902, 989,
                                990, 993, 995,]
        
        self.threads        = 250
        self.timeout        = 1
        self.save           = False
        self.save_results   = SaveIps()

        self.blocks         = []
        self.ip_pool        = []
        self.lock           = Lock()


    def _track_ip_blocks(self):

        with self.lock: 
            while self.blocks or self.ip_pool:

                if not self.ip_pool:
                    block           = self.blocks.pop(0)
                    network         = ipaddress.IPv4Network(block)
                    self.ip_pool    = [str(ip) for ip in network]
                
                if self.ip_pool:
 
                    self.scanned_ips = self.scanned_ips + 1
                    return self.ip_pool.pop(0)
            return None                   

    
    def _make_random_ip(self):

        try:

            ip = f'{random.randint(1,254)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,254)}'

            with self.lock:
                self.scanned_ips = self.scanned_ips + 1
            
            return ip

        except Exception as e:

            return f"Exception Error: {e}"
    
            
    def _get_ip(self):

        if self.country:
            return self._track_ip_blocks()
        
        return self._make_random_ip()


    def _validate_ip(self, ip):

        for port in self.ports:

            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(self.timeout)
                    result = s.connect_ex((ip, int(port)))
                
                    if result == 0:
                        with self.lock:
                            self.online_ips = self.online_ips + 1
                            self.found.append((ip, port))

                            return f"[+] {ip} --> {port}"
                        
            except OSError:
                with self.lock:
                    self.errors = self.errors + 1


    def _ip_threadder(self):
        while self.scanning:
            ip = self._get_ip()
            
            if ip is None:
                self.scanning  = False
                break
            self._validate_ip(ip)
    
    def run(self, ports=None, threads=None, blocks=None):

        self.scanning       = True
        self.scan_done      = False

        self.online_ips     = 0
        self.scanned_ips    = 0

        self.found          = []
        self.errors         = 0

        self.ip_pool        = []

        if ports:
            self.ports      = ports

        if threads:
            self.threads    = threads
        
        if blocks:
            self.blocks     = list(blocks)
        

        try:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = [executor.submit(self._ip_threadder) for _ in range(self.threads)]
                for f in futures:
                    f.result()
        
        except KeyboardInterrupt:
            self.scanning   = False

        except Exception as e:
            self.scanning   = False
            return f"Fatal Error: {e}"
        
        finally:
            self.scanning   = False
            self.scan_done  = True

            if self.save and self.found:
                self.save_results.save(self.found)
    
    def start(self, ports=None, threads=None, blocks=None):
        Thread(target=self.run, kwargs={"ports": ports, "threads": threads, "blocks": blocks}, daemon=True).start()

    @property
    def status(self):

        return {
            "Scanning"  : self.scanning,
            "Scanned"   : self.scanned_ips,
            "Online"    : self.online_ips,
            "Errors"    : self.errors,
            "Found"     : self.found
            
        }
    

mass_ip_scanner = MassIPScanner()

  


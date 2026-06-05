import ipaddress, socket, requests, time, threading, sys, random

from scapy.all              import IP, TCP, sr1, send
from concurrent.futures     import ThreadPoolExecutor, as_completed


T_LOCK = threading.Lock()



class IPScanner:

    # Arguments
    
    country         = False
    asn             = False
    lookfor         = False

    all             = False
    save            = False
    bloom_size      = 100_000_000



    iot             = False
    nas             = False
    router          = False
    remote          = False
    camera          = False

    total_blocks    = []
    current_block   = False
    blocks_done     = 0

    bf_all          = None
    ips_in_block    = 0

    terminate       = False



    @classmethod
    def _track_ip_blocks(self):

        try:

            if not self.ips_in_block or len(self.ips_in_block) == 0:
                if not self.blocks:
                    total_time = time.time() - self.start_time

                    if self.scan:
                        if self.save and self.curent_ips:
                            with T_LOCK: 

    @classmethod
    def iterate_ips_in_block():
        
        #Define target blocks
        network = ipaddress.ip_network("Insert Blocks", strict=False)


        for ip in network.hosts():
            pkt = ImportError

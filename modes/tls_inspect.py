#!/usr/bin/env python3

import ssl, socket

from threading  import Thread
from datetime   import datetime


class TLSInspect:

    def __init__(self):
        self.scanning  = False
        self.scan_done = False
        self.results   = {}
        self.host      = None

    def run(self, host):
        self.scanning  = True
        self.scan_done = False
        self.results   = {}
        self.host      = host

        try:
            PORT = 443

            with socket.create_connection((host, PORT), timeout=10) as socks:
                context = ssl.create_default_context()
                with context.wrap_socket(socks, server_hostname=host) as ssocks:

                    cert = ssocks.getpeercert()

                    subject     = dict(x[0] for x in cert["subject"])
                    issuer      = dict(x[0] for x in cert["issuer"])
                    common_name = subject.get("commonName", host)
                    org         = issuer.get("organizationName", "Unknown")

                    expiry_str  = cert["notAfter"]
                    expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                    days_left   = (expiry_date - datetime.utcnow()).days

                    if days_left < 0:
                        status = "Expired"
                    elif days_left < 30:
                        status = "Expiring soon"
                    else:
                        status = "Valid"

                    tls_version                 = ssocks.version()
                    cipher_name, _, cipher_bits = ssocks.cipher()

                    self.results["domain"]      = common_name
                    self.results["status"]      = f"{status} ({days_left} days left)"
                    self.results["issuer"]      = org
                    self.results["expires"]     = expiry_str
                    self.results["tls"]         = tls_version
                    self.results["cipher"]      = f"{cipher_name} ({cipher_bits} bits)"

        except ssl.SSLCertVerificationError as e:
            self.results["error"] = f"Certificate error: {e}"
        except ssl.SSLError as e:
            self.results["error"] = f"SSL error: {e}"
        except socket.timeout:
            self.results["error"] = "Connection timed out"
        except ConnectionRefusedError:
            self.results["error"] = "Connection refused — check port 443"
        except Exception as e:
            self.results["error"] = f"Error: {e}"
        finally:
            self.scanning  = False
            self.scan_done = True

    def start(self, host):
        Thread(target=self.run, args=(host,), daemon=True).start()


tls_inspection = TLSInspect()
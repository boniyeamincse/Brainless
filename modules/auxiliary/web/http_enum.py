#!/usr/bin/env python3
"""
HTTP Service Enumerator
=======================

Web application enumeration module for discovering directories, files,
and gathering information about web services.

Author: Brainless Security Team
Module: auxiliary/web/http_enum
Type: auxiliary
Rank: excellent
"""

import os
import sys
import socket
import urllib.request
import urllib.parse
import urllib.error
from urllib.request import Request
from urllib.error import HTTPError, URLError
import ssl
import threading
import time
from pathlib import Path

# Add framework path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.logger import LoggerMixin

NAME = "HTTP Service Enumerator"
DESCRIPTION = "Web application enumeration for directories, files, and service information"
AUTHOR = "Brainless Security Team"
VERSION = "1.0"
RANK = "excellent"
MODULE_TYPE = "auxiliary"

class HTTPEnumerator(LoggerMixin):
    """
    Web application enumeration module
    """
    
    def __init__(self):
        super().__init__('HTTPEnumerator')
        self.target = None
        self.port = 80
        self.https = False
        self.wordlist = None
        self.threads = 50
        self.timeout = 10
        self.delay = 0
        self.max_results = 1000
        self.extensions = ['php', 'html', 'htm', 'asp', 'aspx', 'jsp', 'txt', 'xml', 'json']
        self.results = []
        self.lock = threading.Lock()
        
        # Common directories and files
        self.common_directories = [
            'admin', 'administrator', 'backup', 'backups', 'config', 'configs',
            'test', 'tmp', 'temp', 'upload', 'downloads', 'images', 'img',
            'css', 'js', 'javascript', 'scripts', 'includes', 'inc', 'lib',
            'public', 'private', 'secure', 'webdav', 'svn', 'git', 'logs',
            'error', 'errors', 'debug', 'debugging', 'install', 'setup'
        ]
        
        self.common_files = [
            'index', 'default', 'home', 'login', 'admin', 'administrator',
            'config', 'backup', 'test', 'readme', 'readme.txt', 'license',
            'robots', 'robots.txt', 'sitemap', 'sitemap.xml', 'crossdomain',
            'crossdomain.xml', 'security', 'security.txt', 'humans', 'humans.txt'
        ]
    
    def set_option(self, option: str, value: str):
        """Set module options"""
        if option.lower() == 'target':
            self.target = value
        elif option.lower() == 'port':
            self.port = int(value)
        elif option.lower() == 'https':
            self.https = value.lower() == 'true'
        elif option.lower() == 'wordlist':
            self.wordlist = value
        elif option.lower() == 'threads':
            self.threads = int(value)
        elif option.lower() == 'timeout':
            self.timeout = int(value)
        elif option.lower() == 'delay':
            self.delay = float(value)
        elif option.lower() == 'max_results':
            self.max_results = int(value)
        elif option.lower() == 'extensions':
            self.extensions = value.split(',')
    
    def get_options(self) -> dict:
        """Get module options"""
        return {
            'TARGET': {'description': 'Target IP or domain', 'required': True, 'default': ''},
            'PORT': {'description': 'Target port (default: 80)', 'required': False, 'default': '80'},
            'HTTPS': {'description': 'Use HTTPS (true/false)', 'required': False, 'default': 'false'},
            'WORDLIST': {'description': 'Custom wordlist file', 'required': False, 'default': ''},
            'THREADS': {'description': 'Number of threads', 'required': False, 'default': '50'},
            'TIMEOUT': {'description': 'Request timeout in seconds', 'required': False, 'default': '10'},
            'DELAY': {'description': 'Delay between requests in seconds', 'required': False, 'default': '0'},
            'MAX_RESULTS': {'description': 'Maximum results to collect', 'required': False, 'default': '1000'},
            'EXTENSIONS': {'description': 'File extensions to test', 'required': False, 'default': 'php,html,htm,asp,aspx,jsp'}
        }
    
    def build_url(self, path: str) -> str:
        """
        Build complete URL
        """
        protocol = 'https' if self.https else 'http'
        return f"{protocol}://{self.target}:{self.port}/{path.lstrip('/')}"
    
    def make_request(self, url: str) -> dict:
        """
        Make HTTP request and return response info
        """
        try:
            # Create request
            req = Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36')
            req.add_header('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
            req.add_header('Accept-Language', 'en-US,en;q=0.5')
            req.add_header('Connection', 'keep-alive')
            
            # Create SSL context if needed
            context = None
            if self.https:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            
            # Make request
            start_time = time.time()
            
            if context:
                response = urllib.request.urlopen(req, timeout=self.timeout, context=context)
            else:
                response = urllib.request.urlopen(req, timeout=self.timeout)
            
            end_time = time.time()
            
            # Get response info
            status_code = response.getcode()
            content_length = response.headers.get('Content-Length', '0')
            content_type = response.headers.get('Content-Type', '')
            server = response.headers.get('Server', '')
            
            response.close()
            
            return {
                'url': url,
                'status_code': status_code,
                'content_length': int(content_length),
                'content_type': content_type,
                'server': server,
                'response_time': round((end_time - start_time) * 1000, 2),
                'found': True
            }
            
        except HTTPError as e:
            return {
                'url': url,
                'status_code': e.code,
                'content_length': 0,
                'content_type': '',
                'server': '',
                'response_time': 0,
                'found': False,
                'error': str(e)
            }
        except URLError as e:
            return {
                'url': url,
                'status_code': 0,
                'content_length': 0,
                'content_type': '',
                'server': '',
                'response_time': 0,
                'found': False,
                'error': str(e)
            }
        except Exception as e:
            return {
                'url': url,
                'status_code': 0,
                'content_length': 0,
                'content_type': '',
                'server': '',
                'response_time': 0,
                'found': False,
                'error': str(e)
            }
    
    def test_path(self, path: str):
        """
        Test a single path
        """
        if self.delay > 0:
            time.sleep(self.delay)
        
        url = self.build_url(path)
        result = self.make_request(url)
        
        if result['found'] and result['status_code'] in [200, 201, 202, 301, 302]:
            with self.lock:
                if len(self.results) < self.max_results:
                    self.results.append(result)
                    self.info(f"[{result['status_code']}] {path} ({result['content_length']} bytes)")
    
    def enumerate_directories(self):
        """
        Enumerate common directories
        """
        self.info("Enumerating directories...")
        
        paths = []
        for directory in self.common_directories:
            paths.append(directory + '/')
            # Also test without trailing slash
            paths.append(directory)
        
        self.enumerate_paths(paths)
    
    def enumerate_files(self):
        """
        Enumerate common files
        """
        self.info("Enumerating files...")
        
        paths = []
        for filename in self.common_files:
            # Test with each extension
            for ext in self.extensions:
                paths.append(f"{filename}.{ext}")
            # Also test without extension
            paths.append(filename)
        
        self.enumerate_paths(paths)
    
    def enumerate_paths(self, paths: list):
        """
        Enumerate given paths using threading
        """
        if not paths:
            return
        
        from queue import Queue
        
        # Create queue
        path_queue = Queue()
        for path in paths:
            path_queue.put(path)
        
        # Start worker threads
        threads = []
        for _ in range(min(self.threads, len(paths))):
            t = threading.Thread(target=self.worker_thread, args=(path_queue,), daemon=True)
            t.start()
            threads.append(t)
        
        # Wait for completion
        path_queue.join()
    
    def worker_thread(self, path_queue):
        """
        Worker thread for testing paths
        """
        while True:
            try:
                path = path_queue.get(timeout=1)
                self.test_path(path)
                path_queue.task_done()
            except:
                break
    
    def load_wordlist(self) -> list:
        """
        Load custom wordlist
        """
        paths = []
        
        if not self.wordlist:
            return paths
        
        try:
            with open(self.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    path = line.strip()
                    if path and not path.startswith('#'):
                        paths.append(path)
            
            self.info(f"Loaded {len(paths)} paths from wordlist")
        
        except Exception as e:
            self.error(f"Failed to load wordlist: {e}")
        
        return paths
    
    def get_server_info(self) -> dict:
        """
        Get server information
        """
        try:
            url = self.build_url('')
            result = self.make_request(url)
            
            return {
                'server': result.get('server', 'Unknown'),
                'status_code': result.get('status_code', 0),
                'content_type': result.get('content_type', ''),
                'response_time': result.get('response_time', 0)
            }
            
        except Exception as e:
            self.error(f"Failed to get server info: {e}")
            return {}
    
    def check_common_vulnerabilities(self) -> list:
        """
        Check for common vulnerabilities and misconfigurations
        """
        vulnerabilities = []
        
        # Test for directory listing
        test_paths = ['admin/', 'backup/', 'logs/', 'tmp/', 'uploads/']
        
        for path in test_paths:
            url = self.build_url(path)
            result = self.make_request(url)
            
            if result['found'] and result['status_code'] == 200:
                # Check if it's directory listing
                if 'index of' in result.get('content_type', '').lower() or \
                   'directory' in result.get('content_type', '').lower():
                    vulnerabilities.append({
                        'type': 'Directory Listing',
                        'path': path,
                        'severity': 'Medium',
                        'description': f'Directory listing enabled for {path}'
                    })
        
        # Test for sensitive files
        sensitive_files = [
            '.env', '.git/config', '.svn/entries', 'backup.sql', 'dump.sql',
            'config.php.bak', 'database.yml', 'secrets.yml'
        ]
        
        for file_path in sensitive_files:
            url = self.build_url(file_path)
            result = self.make_request(url)
            
            if result['found'] and result['status_code'] == 200:
                vulnerabilities.append({
                    'type': 'Sensitive File Exposure',
                    'path': file_path,
                    'severity': 'High',
                    'description': f'Sensitive file accessible: {file_path}'
                })
        
        return vulnerabilities
    
    def run_enumeration(self) -> dict:
        """
        Run the complete enumeration
        """
        if not self.target:
            return {'success': False, 'message': 'Target not specified'}
        
        try:
            self.info(f"Starting HTTP enumeration on {self.target}:{self.port}")
            
            # Get server info
            server_info = self.get_server_info()
            self.info(f"Server: {server_info.get('server', 'Unknown')}")
            self.info(f"Status: {server_info.get('status_code', 0)}")
            
            # Enumerate directories
            self.enumerate_directories()
            
            # Enumerate files
            self.enumerate_files()
            
            # Load and test custom wordlist
            custom_paths = self.load_wordlist()
            if custom_paths:
                self.enumerate_paths(custom_paths)
            
            # Check for vulnerabilities
            vulnerabilities = self.check_common_vulnerabilities()
            
            # Generate summary
            summary = {
                'target': self.target,
                'port': self.port,
                'https': self.https,
                'total_found': len(self.results),
                'server_info': server_info,
                'vulnerabilities': vulnerabilities,
                'results': self.results
            }
            
            self.info(f"Enumeration completed. Found {len(self.results)} items.")
            
            return {'success': True, 'summary': summary}
            
        except Exception as e:
            self.error(f"Enumeration failed: {e}")
            return {'success': False, 'message': f'Enumeration failed: {str(e)}'}
    
    def run(self) -> dict:
        """
        Main module execution
        """
        return self.run_enumeration()


def run(options: dict = None) -> dict:
    """
    Entry point for the module
    """
    enumerator = HTTPEnumerator()
    
    # Set options if provided
    if options:
        for key, value in options.items():
            enumerator.set_option(key, value)
    
    return enumerator.run()


if __name__ == '__main__':
    # Example usage
    options = {
        'TARGET': 'example.com',
        'PORT': '80',
        'HTTPS': 'false',
        'THREADS': '50',
        'TIMEOUT': '10',
        'DELAY': '0',
        'MAX_RESULTS': '1000',
        'EXTENSIONS': 'php,html,htm,asp,aspx,jsp'
    }
    
    result = run(options)
    print(result)
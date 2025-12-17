#!/usr/bin/env python3
"""
HTTP Admin Module
=================

Administrative operations for HTTP/HTTPS services.
Performs web server configuration analysis, directory enumeration,
and HTTP service administration tasks.

Author: Brainless Security Team
Module: auxiliary/admin/http/http_admin
Type: auxiliary
Rank: excellent
"""

import os
import sys
import socket
import urllib.request
import urllib.parse
import urllib.error
import ssl
import json
import re
from pathlib import Path

# Add framework path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from core.logger import LoggerMixin

NAME = "HTTP Admin Module"
DESCRIPTION = "Administrative operations for HTTP/HTTPS services including configuration analysis"
AUTHOR = "Brainless Security Team"
VERSION = "1.0"
RANK = "excellent"
MODULE_TYPE = "auxiliary"

class HTTPAdmin(LoggerMixin):
    """
    HTTP administrative operations module
    """
    
    def __init__(self):
        super().__init__('HTTPAdmin')
        self.target = None
        self.port = 80
        self.use_ssl = False
        self.path = '/'
        self.username = None
        self.password = None
        self.timeout = 10
        self.auth_type = 'basic'  # basic, digest, bearer
        
    def set_option(self, option: str, value: str):
        """Set module options"""
        if option.lower() == 'target':
            self.target = value
        elif option.lower() == 'port':
            self.port = int(value)
        elif option.lower() == 'use_ssl':
            self.use_ssl = value.lower() == 'true'
        elif option.lower() == 'path':
            self.path = value
        elif option.lower() == 'username':
            self.username = value
        elif option.lower() == 'password':
            self.password = value
        elif option.lower() == 'timeout':
            self.timeout = int(value)
        elif option.lower() == 'auth_type':
            self.auth_type = value.lower()
    
    def get_options(self) -> dict:
        """Get module options"""
        return {
            'TARGET': {'description': 'Target host or IP', 'required': True, 'default': ''},
            'PORT': {'description': 'Target port', 'required': False, 'default': '80'},
            'USE_SSL': {'description': 'Use HTTPS', 'required': False, 'default': 'false'},
            'PATH': {'description': 'Base path to test', 'required': False, 'default': '/'},
            'USERNAME': {'description': 'Username for authentication', 'required': False, 'default': ''},
            'PASSWORD': {'description': 'Password for authentication', 'required': False, 'default': ''},
            'TIMEOUT': {'description': 'Request timeout', 'required': False, 'default': '10'},
            'AUTH_TYPE': {'description': 'Authentication type (basic, digest, bearer)', 'required': False, 'default': 'basic'}
        }
    
    def build_url(self, path: str = None) -> str:
        """Build complete URL"""
        if not path:
            path = self.path
            
        protocol = 'https' if self.use_ssl else 'http'
        return f"{protocol}://{self.target}:{self.port}/{path.lstrip('/')}"
    
    def create_auth_handler(self):
        """Create authentication handler"""
        if not self.username or not self.password:
            return None
            
        if self.auth_type == 'basic':
            from urllib.request import HTTPBasicAuthHandler
            return HTTPBasicAuthHandler()
        elif self.auth_type == 'digest':
            from urllib.request import HTTPDigestAuthHandler
            return HTTPDigestAuthHandler()
        else:
            return None
    
    def analyze_server_headers(self, response) -> dict:
        """Analyze HTTP server headers"""
        headers = {}
        
        # Common security headers
        security_headers = {
            'Server': 'Server information disclosure',
            'X-Powered-By': 'Technology stack disclosure',
            'X-Frame-Options': 'Clickjacking protection',
            'X-XSS-Protection': 'XSS protection',
            'X-Content-Type-Options': 'MIME type sniffing protection',
            'Strict-Transport-Security': 'HTTPS enforcement',
            'Content-Security-Policy': 'Content Security Policy',
            'X-Content-Security-Policy': 'CSP (legacy)',
            'Referrer-Policy': 'Referrer policy',
            'Permissions-Policy': 'Feature permissions policy'
        }
        
        for header_name, description in security_headers.items():
            if header_name in response.headers:
                headers[header_name] = {
                    'value': response.headers[header_name],
                    'description': description,
                    'secure': self.is_header_secure(header_name, response.headers[header_name])
                }
        
        return headers
    
    def is_header_secure(self, header_name: str, header_value: str) -> bool:
        """Check if security header is properly configured"""
        if header_name == 'Server':
            return False  # Server header always discloses information
        elif header_name == 'X-Powered-By':
            return False  # X-Powered-By always discloses information
        elif header_name == 'X-Frame-Options':
            return header_value.lower() in ['deny', 'sameorigin']
        elif header_name == 'Strict-Transport-Security':
            return 'max-age=' in header_value.lower()
        elif header_name == 'X-XSS-Protection':
            return header_value == '1; mode=block'
        elif header_name == 'X-Content-Type-Options':
            return header_value == 'nosniff'
        
        return True  # Default to secure for unknown headers
    
    def test_directory_traversal(self) -> list:
        """Test for directory traversal vulnerabilities"""
        traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '....//....//....//etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '..%252f..%252f..%252fetc%252fpasswd'
        ]
        
        vulnerabilities = []
        
        for payload in traversal_payloads:
            try:
                url = self.build_url(payload)
                req = urllib.request.Request(url)
                req.add_header('User-Agent', 'Brainless-Admin/1.0')
                
                if self.use_ssl:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    response = urllib.request.urlopen(req, timeout=self.timeout, context=context)
                else:
                    response = urllib.request.urlopen(req, timeout=self.timeout)
                
                content = response.read().decode('utf-8', errors='ignore')
                
                # Check for sensitive file contents
                if 'root:' in content or 'localhost' in content:
                    vulnerabilities.append({
                        'payload': payload,
                        'url': url,
                        'vulnerable': True,
                        'response_length': len(content),
                        'description': 'Directory traversal vulnerability detected'
                    })
                
                response.close()
                
            except Exception as e:
                self.debug(f"Traversal test failed for {payload}: {e}")
        
        return vulnerabilities
    
    def test_sql_injection_basic(self) -> list:
        """Basic SQL injection testing"""
        sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "1' AND '1'='1",
            "admin'--",
            "' OR 'a'='a"
        ]
        
        vulnerabilities = []
        
        for payload in sql_payloads:
            try:
                # Test in query parameters
                test_url = self.build_url(f"?id={payload}")
                req = urllib.request.Request(test_url)
                req.add_header('User-Agent', 'Brainless-Admin/1.0')
                
                if self.use_ssl:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    response = urllib.request.urlopen(req, timeout=self.timeout, context=context)
                else:
                    response = urllib.request.urlopen(req, timeout=self.timeout)
                
                content = response.read().decode('utf-8', errors='ignore')
                response.close()
                
                # Check for SQL error messages
                sql_errors = [
                    'mysql_fetch_array',
                    'ORA-00942',
                    'Microsoft Access Driver',
                    'SQLServer JDBC Driver',
                    'PostgreSQL query failed',
                    'Warning: mysql_',
                    'valid MySQL result'
                ]
                
                for error in sql_errors:
                    if error.lower() in content.lower():
                        vulnerabilities.append({
                            'payload': payload,
                            'url': test_url,
                            'vulnerable': True,
                            'error_detected': error,
                            'description': 'SQL injection vulnerability detected'
                        })
                        break
                
            except Exception as e:
                self.debug(f"SQL injection test failed for {payload}: {e}")
        
        return vulnerabilities
    
    def check_default_files(self) -> list:
        """Check for default/admin files"""
        default_files = [
            'admin/', 'administrator/', 'wp-admin/', 'login/',
            'config.php', 'config.inc.php', 'settings.php',
            'database.php', 'db.php', 'sql.php',
            '.env', '.git/config', 'backup.sql', 'dump.sql',
            'test.php', 'info.php', 'phpinfo.php',
            'robots.txt', 'sitemap.xml', 'crossdomain.xml'
        ]
        
        found_files = []
        
        for file_path in default_files:
            try:
                url = self.build_url(file_path)
                req = urllib.request.Request(url)
                req.add_header('User-Agent', 'Brainless-Admin/1.0')
                
                if self.use_ssl:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    response = urllib.request.urlopen(req, timeout=self.timeout, context=context)
                else:
                    response = urllib.request.urlopen(req, timeout=self.timeout)
                
                found_files.append({
                    'file': file_path,
                    'url': url,
                    'status_code': response.getcode(),
                    'content_length': len(response.read()),
                    'content_type': response.headers.get('Content-Type', 'unknown')
                })
                
                response.close()
                
            except urllib.error.HTTPError as e:
                if e.code != 404:
                    found_files.append({
                        'file': file_path,
                        'url': url,
                        'status_code': e.code,
                        'error': str(e)
                    })
            except Exception as e:
                self.debug(f"Default file check failed for {file_path}: {e}")
        
        return found_files
    
    def test_authentication_bypass(self) -> dict:
        """Test for authentication bypass techniques"""
        bypass_attempts = []
        
        # Common authentication bypass payloads
        bypass_payloads = [
            {'Cookie': 'admin=true; authenticated=1; user=admin'},
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZG1pbiI6dHJ1ZX0.fake'},
            {'X-Auth-Token': 'admin'},
            {'User-Agent': 'admin'}
        ]
        
        for headers in bypass_payloads:
            try:
                url = self.build_url()
                req = urllib.request.Request(url)
                req.add_header('User-Agent', 'Brainless-Admin/1.0')
                
                # Add bypass headers
                for header_name, header_value in headers.items():
                    req.add_header(header_name, header_value)
                
                if self.use_ssl:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    response = urllib.request.urlopen(req, timeout=self.timeout, context=context)
                else:
                    response = urllib.request.urlopen(req, timeout=self.timeout)
                
                content = response.read().decode('utf-8', errors='ignore')
                
                # Check if response indicates successful bypass
                admin_indicators = [
                    'dashboard', 'admin panel', 'administrator',
                    'welcome admin', 'logout', 'settings',
                    'user management', 'system admin'
                ]
                
                bypassed = False
                for indicator in admin_indicators:
                    if indicator.lower() in content.lower():
                        bypassed = True
                        break
                
                bypass_attempts.append({
                    'headers': headers,
                    'status_code': response.getcode(),
                    'bypassed': bypassed,
                    'content_length': len(content)
                })
                
                response.close()
                
            except Exception as e:
                bypass_attempts.append({
                    'headers': headers,
                    'error': str(e)
                })
        
        return bypass_attempts
    
    def analyze_http_security(self) -> dict:
        """Comprehensive HTTP security analysis"""
        try:
            url = self.build_url()
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Brainless-Admin/1.0')
            
            if self.use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                response = urllib.request.urlopen(req, timeout=self.timeout, context=context)
            else:
                response = urllib.request.urlopen(req, timeout=self.timeout)
            
            # Analyze response
            analysis = {
                'status_code': response.getcode(),
                'content_length': len(response.read()),
                'content_type': response.headers.get('Content-Type', 'unknown'),
                'server_headers': self.analyze_server_headers(response),
                'ssl_info': None
            }
            
            # SSL analysis if HTTPS
            if self.use_ssl:
                try:
                    analysis['ssl_info'] = {
                        'protocol': response.version,
                        'cipher': response._connection.sock.cipher(),
                        'cert': response._connection.sock.getpeercert()
                    }
                except:
                    pass
            
            response.close()
            return analysis
            
        except Exception as e:
            self.error(f"HTTP security analysis failed: {e}")
            return {'error': str(e)}
    
    def run(self) -> dict:
        """Main module execution"""
        if not self.target:
            return {'success': False, 'message': 'TARGET not specified'}
        
        try:
            self.info(f"Starting HTTP admin analysis for {self.target}:{self.port}")
            
            # Perform comprehensive analysis
            results = {
                'target': self.target,
                'port': self.port,
                'use_ssl': self.use_ssl,
                'security_analysis': self.analyze_http_security(),
                'default_files': self.check_default_files(),
                'directory_traversal': self.test_directory_traversal(),
                'sql_injection': self.test_sql_injection_basic(),
                'auth_bypass': self.test_authentication_bypass()
            }
            
            # Generate summary
            vulnerabilities = []
            vulnerabilities.extend(results['directory_traversal'])
            vulnerabilities.extend(results['sql_injection'])
            
            summary = {
                'target': self.target,
                'total_vulnerabilities': len(vulnerabilities),
                'default_files_found': len([f for f in results['default_files'] if f.get('status_code') == 200]),
                'security_headers_analysis': len(results['security_analysis'].get('server_headers', {})),
                'auth_bypass_attempts': len(results['auth_bypass'])
            }
            
            self.info(f"HTTP admin analysis completed for {self.target}")
            self.info(f"Found {len(vulnerabilities)} potential vulnerabilities")
            self.info(f"Found {summary['default_files_found']} accessible default files")
            
            return {
                'success': True,
                'summary': summary,
                'results': results
            }
            
        except Exception as e:
            self.error(f"HTTP admin analysis failed: {e}")
            return {'success': False, 'message': f'Analysis failed: {str(e)}'}


def run(options: dict = None) -> dict:
    """Entry point for the module"""
    admin = HTTPAdmin()
    
    if options:
        for key, value in options.items():
            admin.set_option(key, value)
    
    return admin.run()


if __name__ == '__main__':
    # Example usage
    options = {
        'TARGET': 'example.com',
        'PORT': '80',
        'USE_SSL': 'false',
        'TIMEOUT': '10'
    }
    
    result = run(options)
    print(result)
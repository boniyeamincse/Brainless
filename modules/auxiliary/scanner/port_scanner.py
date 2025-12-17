#!/usr/bin/env python3
"""
Advanced Port Scanner
====================

Comprehensive port scanning module for network reconnaissance.
Supports multiple scan types and detailed service detection.

Author: Brainless Security Team
Module: auxiliary/scanner/port_scanner
Type: auxiliary
Rank: excellent
"""

import os
import sys
import socket
import threading
import time
import subprocess
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Add framework path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.logger import LoggerMixin

NAME = "Advanced Port Scanner"
DESCRIPTION = "Comprehensive port scanner with service detection and banner grabbing"
AUTHOR = "Brainless Security Team"
VERSION = "1.0"
RANK = "excellent"
MODULE_TYPE = "auxiliary"

class PortScanner(LoggerMixin):
    """
    Advanced port scanner with multiple scan types and service detection
    """
    
    def __init__(self):
        super().__init__('PortScanner')
        self.target = None
        self.ports = "1-1000"
        self.scan_type = "tcp_connect"
        self.timeout = 3
        self.threads = 100
        self.service_detection = True
        self.banner_grabbing = True
        self.results = []
        
        # Common ports and services
        self.common_ports = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 143: "imap", 443: "https", 993: "imaps",
            995: "pop3s", 3306: "mysql", 5432: "postgresql", 6379: "redis",
            8080: "http-proxy", 27017: "mongodb"
        }
    
    def set_option(self, option: str, value: str):
        """Set module options"""
        if option.lower() == 'target':
            self.target = value
        elif option.lower() == 'ports':
            self.ports = value
        elif option.lower() == 'scan_type':
            self.scan_type = value.lower()
        elif option.lower() == 'timeout':
            self.timeout = int(value)
        elif option.lower() == 'threads':
            self.threads = int(value)
        elif option.lower() == 'service_detection':
            self.service_detection = value.lower() == 'true'
        elif option.lower() == 'banner_grabbing':
            self.banner_grabbing = value.lower() == 'true'
    
    def get_options(self) -> dict:
        """Get module options"""
        return {
            'TARGET': {'description': 'Target IP or range', 'required': True, 'default': ''},
            'PORTS': {'description': 'Port range (e.g., 1-1000 or 22,80,443)', 'required': False, 'default': '1-1000'},
            'SCAN_TYPE': {'description': 'Scan type (tcp_connect, syn, udp)', 'required': False, 'default': 'tcp_connect'},
            'TIMEOUT': {'description': 'Connection timeout in seconds', 'required': False, 'default': '3'},
            'THREADS': {'description': 'Number of threads', 'required': False, 'default': '100'},
            'SERVICE_DETECTION': {'description': 'Enable service detection', 'required': False, 'default': 'true'},
            'BANNER_GRABBING': {'description': 'Enable banner grabbing', 'required': False, 'default': 'true'}
        }
    
    def parse_ports(self) -> list:
        """
        Parse port specification into list of ports
        """
        ports = []
        
        if ',' in self.ports:
            # Comma-separated list
            for port in self.ports.split(','):
                ports.append(int(port.strip()))
        elif '-' in self.ports:
            # Range
            start, end = map(int, self.ports.split('-'))
            ports = list(range(start, end + 1))
        else:
            # Single port
            ports = [int(self.ports)]
        
        return sorted(list(set(ports)))  # Remove duplicates and sort
    
    def parse_targets(self) -> list:
        """
        Parse target specification into list of IPs
        """
        targets = []
        
        try:
            if '/' in self.target:
                # CIDR notation
                network = ipaddress.ip_network(self.target, strict=False)
                targets = [str(ip) for ip in network.hosts()]
            elif '-' in self.target:
                # Range notation (e.g., 192.168.1.1-192.168.1.10)
                start_ip, end_ip = self.target.split('-')
                start = ipaddress.ip_address(start_ip.strip())
                end = ipaddress.ip_address(end_ip.strip())
                
                current = start
                while current <= end:
                    targets.append(str(current))
                    current += 1
            elif ',' in self.target:
                # Comma-separated list
                targets = [ip.strip() for ip in self.target.split(',')]
            else:
                # Single IP
                targets = [self.target]
        
        except Exception as e:
            self.error(f"Error parsing targets: {e}")
            return []
        
        return targets
    
    def tcp_connect_scan(self, target: str, port: int) -> dict:
        """
        Perform TCP connect scan
        """
        result = {
            'target': target,
            'port': port,
            'status': 'closed',
            'service': None,
            'banner': None,
            'response_time': 0
        }
        
        try:
            start_time = time.time()
            
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Connect
            result_code = sock.connect_ex((target, port))
            
            end_time = time.time()
            result['response_time'] = round((end_time - start_time) * 1000, 2)
            
            if result_code == 0:
                result['status'] = 'open'
                
                # Service detection
                if self.service_detection:
                    result['service'] = self.detect_service(port)
                
                # Banner grabbing
                if self.banner_grabbing:
                    result['banner'] = self.grab_banner(sock)
            
            sock.close()
            
        except Exception as e:
            self.debug(f"Error scanning {target}:{port} - {e}")
        
        return result
    
    def syn_scan(self, target: str, port: int) -> dict:
        """
        Perform SYN scan (requires root privileges)
        """
        result = {
            'target': target,
            'port': port,
            'status': 'closed',
            'service': None,
            'response_time': 0
        }
        
        try:
            # This is a simplified SYN scan implementation
            # In practice, you'd use raw sockets or tools like nmap
            
            # For now, fall back to TCP connect scan
            return self.tcp_connect_scan(target, port)
            
        except Exception as e:
            self.error(f"SYN scan failed: {e}")
            return result
    
    def udp_scan(self, target: str, port: int) -> dict:
        """
        Perform UDP scan
        """
        result = {
            'target': target,
            'port': port,
            'status': 'closed',
            'service': None,
            'response_time': 0
        }
        
        try:
            start_time = time.time()
            
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            # Send empty UDP packet
            sock.sendto(b'', (target, port))
            
            try:
                # Try to receive response (ICMP port unreachable or application response)
                data, addr = sock.recvfrom(1024)
                result['status'] = 'open'
                result['banner'] = data.decode('utf-8', errors='ignore')[:100]
            except socket.timeout:
                # No response - port might be open or filtered
                result['status'] = 'filtered'
            
            end_time = time.time()
            result['response_time'] = round((end_time - start_time) * 1000, 2)
            
            sock.close()
            
        except Exception as e:
            self.debug(f"Error UDP scanning {target}:{port} - {e}")
        
        return result
    
    def detect_service(self, port: int) -> str:
        """
        Detect service based on port number
        """
        # Check common ports
        if port in self.common_ports:
            return self.common_ports[port]
        
        # Try to get service name from system
        try:
            service = socket.getservbyport(port)
            return service
        except:
            return "unknown"
    
    def grab_banner(self, sock) -> str:
        """
        Grab banner from open port
        """
        try:
            # Send common banner grabbing strings
            banner_strings = [
                b'GET / HTTP/1.0\r\n\r\n',
                b'\r\n',
                b'HELP\r\n',
                b'SMTP\r\n',
                b'USER test\r\n'
            ]
            
            for banner_string in banner_strings:
                try:
                    sock.send(banner_string)
                    data = sock.recv(1024)
                    if data:
                        return data.decode('utf-8', errors='ignore').strip()[:200]
                except:
                    continue
            
            return "No banner"
            
        except Exception as e:
            return f"Banner grab failed: {e}"
    
    def scan_host(self, target: str, ports: list) -> list:
        """
        Scan a single host
        """
        host_results = []
        
        self.info(f"Scanning {target}...")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            
            # Submit scan tasks
            for port in ports:
                if self.scan_type == 'syn':
                    future = executor.submit(self.syn_scan, target, port)
                elif self.scan_type == 'udp':
                    future = executor.submit(self.udp_scan, target, port)
                else:
                    future = executor.submit(self.tcp_connect_scan, target, port)
                
                futures.append(future)
            
            # Collect results
            for future in as_completed(futures):
                result = future.result()
                if result['status'] in ['open', 'filtered']:
                    host_results.append(result)
                    self.info(f"  {result['target']}:{result['port']} - {result['status']} ({result['service']})")
        
        return host_results
    
    def run_scan(self) -> dict:
        """
        Run the port scan
        """
        if not self.target:
            return {'success': False, 'message': 'Target not specified'}
        
        try:
            # Parse targets and ports
            targets = self.parse_targets()
            ports = self.parse_ports()
            
            if not targets or not ports:
                return {'success': False, 'message': 'Invalid target or port specification'}
            
            self.info(f"Starting {self.scan_type} scan on {len(targets)} targets, {len(ports)} ports")
            self.info(f"Targets: {', '.join(targets[:5])}{'...' if len(targets) > 5 else ''}")
            self.info(f"Ports: {self.ports}")
            
            start_time = time.time()
            
            # Scan all targets
            all_results = []
            for target in targets:
                host_results = self.scan_host(target, ports)
                all_results.extend(host_results)
            
            end_time = time.time()
            scan_duration = round(end_time - start_time, 2)
            
            # Generate summary
            open_ports = [r for r in all_results if r['status'] == 'open']
            filtered_ports = [r for r in all_results if r['status'] == 'filtered']
            
            summary = {
                'scan_type': self.scan_type,
                'targets_scanned': len(targets),
                'ports_scanned': len(ports),
                'total_results': len(all_results),
                'open_ports': len(open_ports),
                'filtered_ports': len(filtered_ports),
                'scan_duration': scan_duration,
                'results': all_results
            }
            
            self.info(f"Scan completed in {scan_duration}s")
            self.info(f"Found {len(open_ports)} open ports, {len(filtered_ports)} filtered ports")
            
            return {'success': True, 'summary': summary}
            
        except Exception as e:
            self.error(f"Scan failed: {e}")
            return {'success': False, 'message': f'Scan failed: {str(e)}'}
    
    def save_results(self, results: dict, filename: str = None):
        """
        Save scan results to file
        """
        if not filename:
            filename = f"scan_results_{int(time.time())}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
            
            self.info(f"Results saved to: {filename}")
            return filename
            
        except Exception as e:
            self.error(f"Failed to save results: {e}")
            return None
    
    def run(self) -> dict:
        """
        Main module execution
        """
        return self.run_scan()


def run(options: dict = None) -> dict:
    """
    Entry point for the module
    """
    scanner = PortScanner()
    
    # Set options if provided
    if options:
        for key, value in options.items():
            scanner.set_option(key, value)
    
    return scanner.run()


if __name__ == '__main__':
    # Example usage
    options = {
        'TARGET': '192.168.1.1',
        'PORTS': '1-1000',
        'SCAN_TYPE': 'tcp_connect',
        'TIMEOUT': '3',
        'THREADS': '100',
        'SERVICE_DETECTION': 'true',
        'BANNER_GRABBING': 'true'
    }
    
    result = run(options)
    print(result)
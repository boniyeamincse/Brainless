#!/usr/bin/env python3
"""
Wi-Fi Network Scanner
=====================

Wireless network discovery and analysis module for Linux systems.
Scans for Wi-Fi networks, captures information, and performs basic analysis.

Author: Brainless Security Team
Module: auxiliary/wireless/wifi_scanner
Type: auxiliary
Rank: excellent
"""

import os
import sys
import subprocess
import re
import time
import threading
from pathlib import Path

# Add framework path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.logger import LoggerMixin

NAME = "Wi-Fi Network Scanner"
DESCRIPTION = "Wireless network discovery and analysis for Linux systems"
AUTHOR = "Brainless Security Team"
VERSION = "1.0"
RANK = "excellent"
MODULE_TYPE = "auxiliary"

class WiFiScanner(LoggerMixin):
    """
    Wi-Fi network scanner and analyzer
    """
    
    def __init__(self):
        super().__init__('WiFiScanner')
        self.interface = None
        self.duration = 30
        self.channel = None
        self.monitor_mode = False
        self.results = []
        self.running = False
        
        # Security types mapping
        self.security_types = {
            'wpa': ['WPA', 'WPA2', 'WPA3'],
            'wep': ['WEP'],
            'open': ['None', 'Open']
        }
    
    def set_option(self, option: str, value: str):
        """Set module options"""
        if option.lower() == 'interface':
            self.interface = value
        elif option.lower() == 'duration':
            self.duration = int(value)
        elif option.lower() == 'channel':
            self.channel = int(value)
        elif option.lower() == 'monitor_mode':
            self.monitor_mode = value.lower() == 'true'
    
    def get_options(self) -> dict:
        """Get module options"""
        return {
            'INTERFACE': {'description': 'Wireless interface (e.g., wlan0)', 'required': True, 'default': ''},
            'DURATION': {'description': 'Scan duration in seconds', 'required': False, 'default': '30'},
            'CHANNEL': {'description': 'Specific channel to scan (optional)', 'required': False, 'default': ''},
            'MONITOR_MODE': {'description': 'Enable monitor mode', 'required': False, 'default': 'false'}
        }
    
    def check_root_privileges(self) -> bool:
        """
        Check if running with root privileges
        """
        return os.geteuid() == 0
    
    def get_wireless_interfaces(self) -> list:
        """
        Get list of wireless interfaces
        """
        interfaces = []
        
        try:
            # Use iwconfig to find wireless interfaces
            result = subprocess.run(['iwconfig'], capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if 'IEEE 802.11' in line or 'ESSID' in line:
                    # Extract interface name from previous line
                    interface = line.split()[0]
                    interfaces.append(interface)
        
        except Exception as e:
            self.error(f"Failed to get wireless interfaces: {e}")
        
        return interfaces
    
    def enable_monitor_mode(self) -> bool:
        """
        Enable monitor mode on the wireless interface
        """
        if not self.interface:
            self.error("No interface specified")
            return False
        
        try:
            # Bring interface down
            subprocess.run(['ifconfig', self.interface, 'down'], check=True)
            
            # Enable monitor mode
            subprocess.run(['iwconfig', self.interface, 'mode', 'monitor'], check=True)
            
            # Bring interface up
            subprocess.run(['ifconfig', self.interface, 'up'], check=True)
            
            self.info(f"Monitor mode enabled on {self.interface}")
            return True
            
        except subprocess.CalledProcessError as e:
            self.error(f"Failed to enable monitor mode: {e}")
            return False
        except Exception as e:
            self.error(f"Error enabling monitor mode: {e}")
            return False
    
    def disable_monitor_mode(self):
        """
        Disable monitor mode on the wireless interface
        """
        if not self.interface:
            return
        
        try:
            # Bring interface down
            subprocess.run(['ifconfig', self.interface, 'down'], check=True)
            
            # Disable monitor mode
            subprocess.run(['iwconfig', self.interface, 'mode', 'managed'], check=True)
            
            # Bring interface up
            subprocess.run(['ifconfig', self.interface, 'up'], check=True)
            
            self.info(f"Monitor mode disabled on {self.interface}")
            
        except Exception as e:
            self.error(f"Error disabling monitor mode: {e}")
    
    def set_channel(self, channel: int):
        """
        Set wireless interface to specific channel
        """
        try:
            subprocess.run(['iwconfig', self.interface, 'channel', str(channel)], check=True)
            self.info(f"Set channel to {channel}")
        except Exception as e:
            self.error(f"Failed to set channel {channel}: {e}")
    
    def parse_iwlist_output(self, output: str) -> list:
        """
        Parse iwlist scan output
        """
        networks = []
        current_network = {}
        
        for line in output.split('\n'):
            line = line.strip()
            
            # Cell identifier
            if line.startswith('Cell'):
                if current_network:
                    networks.append(current_network)
                current_network = {'cell': line}
            
            # ESSID
            elif 'ESSID:' in line:
                essid = line.split('ESSID:')[1].strip().strip('"')
                current_network['essid'] = essid if essid != '' else '<hidden>'
            
            # Protocol
            elif 'Protocol:' in line:
                current_network['protocol'] = line.split('Protocol:')[1].strip()
            
            # Mode
            elif 'Mode:' in line:
                current_network['mode'] = line.split('Mode:')[1].strip()
            
            # Frequency/Channel
            elif 'Frequency:' in line:
                freq_info = line.split('Frequency:')[1].strip()
                current_network['frequency'] = freq_info
                
                # Extract channel from frequency
                if '2.4' in freq_info:
                    # 2.4 GHz band
                    freq_match = re.search(r'(\d+\.\d+) GHz', freq_info)
                    if freq_match:
                        freq = float(freq_match.group(1))
                        # Convert frequency to channel
                        channel = int((freq * 1000 - 2407) / 5)
                        current_network['channel'] = channel
                elif '5.' in freq_info:
                    # 5 GHz band
                    freq_match = re.search(r'(\d+\.\d+) GHz', freq_info)
                    if freq_match:
                        freq = float(freq_match.group(1))
                        # Convert frequency to channel
                        channel = int((freq * 1000 - 5000) / 5)
                        current_network['channel'] = channel
            
            # Access Point MAC
            elif 'Access Point:' in line:
                mac = line.split('Access Point:')[1].strip()
                current_network['bssid'] = mac
            
            # Bit Rates
            elif 'Bit Rates:' in line:
                rates = line.split('Bit Rates:')[1].strip()
                current_network['rates'] = rates
            
            # Encryption Key
            elif 'Encryption key:' in line:
                encrypted = line.split('Encryption key:')[1].strip()
                current_network['encrypted'] = encrypted == 'on'
            
            # Quality/Signal
            elif 'Quality=' in line:
                quality_info = line.split('Quality=')[1].strip()
                current_network['quality'] = quality_info
                
                # Extract signal level
                if 'Signal level=' in line:
                    signal_match = re.search(r'Signal level=([-]?\d+)', line)
                    if signal_match:
                        current_network['signal_level'] = int(signal_match.group(1))
        
        # Add last network
        if current_network:
            networks.append(current_network)
        
        return networks
    
    def scan_networks(self) -> list:
        """
        Scan for Wi-Fi networks
        """
        if not self.interface:
            self.error("No wireless interface specified")
            return []
        
        try:
            self.info(f"Scanning for Wi-Fi networks on {self.interface}...")
            
            # Build command
            cmd = ['iwlist', self.interface, 'scan']
            
            # Execute scan
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode != 0:
                self.error(f"Scan failed: {result.stderr}")
                return []
            
            # Parse results
            networks = self.parse_iwlist_output(result.stdout)
            
            self.info(f"Found {len(networks)} networks")
            
            return networks
            
        except subprocess.TimeoutExpired:
            self.error("Scan timed out")
            return []
        except Exception as e:
            self.error(f"Scan failed: {e}")
            return []
    
    def analyze_networks(self, networks: list) -> dict:
        """
        Analyze discovered networks
        """
        analysis = {
            'total_networks': len(networks),
            'open_networks': 0,
            'wep_networks': 0,
            'wpa_networks': 0,
            'hidden_networks': 0,
            'by_channel': {},
            'by_signal': {'excellent': 0, 'good': 0, 'fair': 0, 'poor': 0},
            'by_encryption': {}
        }
        
        for network in networks:
            # Count by encryption type
            if not network.get('encrypted', False):
                analysis['open_networks'] += 1
                enc_type = 'Open'
            else:
                # Try to determine encryption type from other fields
                enc_type = 'WPA/WPA2'
                # This would need more sophisticated detection
            
            if enc_type not in analysis['by_encryption']:
                analysis['by_encryption'][enc_type] = 0
            analysis['by_encryption'][enc_type] += 1
            
            # Count hidden networks
            if network.get('essid') == '<hidden>':
                analysis['hidden_networks'] += 1
            
            # Count by channel
            channel = network.get('channel')
            if channel:
                if channel not in analysis['by_channel']:
                    analysis['by_channel'][channel] = 0
                analysis['by_channel'][channel] += 1
            
            # Count by signal strength
            signal = network.get('signal_level', 0)
            if signal >= -50:
                analysis['by_signal']['excellent'] += 1
            elif signal >= -60:
                analysis['by_signal']['good'] += 1
            elif signal >= -70:
                analysis['by_signal']['fair'] += 1
            else:
                analysis['by_signal']['poor'] += 1
        
        return analysis
    
    def continuous_scan(self):
        """
        Perform continuous scanning
        """
        start_time = time.time()
        scan_interval = 5  # seconds
        
        self.info(f"Starting continuous scan for {self.duration} seconds...")
        
        while self.running:
            current_time = time.time()
            if current_time - start_time > self.duration:
                break
            
            # Perform scan
            networks = self.scan_networks()
            
            if networks:
                # Analyze results
                analysis = self.analyze_networks(networks)
                
                # Log interesting findings
                if analysis['open_networks'] > 0:
                    self.info(f"Found {analysis['open_networks']} open networks")
                
                if analysis['hidden_networks'] > 0:
                    self.info(f"Found {analysis['hidden_networks']} hidden networks")
            
            # Wait before next scan
            time.sleep(scan_interval)
    
    def run_scan(self) -> dict:
        """
        Run the Wi-Fi scan
        """
        if not self.check_root_privileges():
            return {'success': False, 'message': 'Root privileges required for Wi-Fi scanning'}
        
        if not self.interface:
            # Try to auto-detect interface
            interfaces = self.get_wireless_interfaces()
            if not interfaces:
                return {'success': False, 'message': 'No wireless interfaces found'}
            
            self.interface = interfaces[0]
            self.info(f"Using auto-detected interface: {self.interface}")
        
        try:
            self.info(f"Starting Wi-Fi scan on {self.interface}")
            
            # Enable monitor mode if requested
            if self.monitor_mode:
                if not self.enable_monitor_mode():
                    return {'success': False, 'message': 'Failed to enable monitor mode'}
            
            # Set specific channel if requested
            if self.channel:
                self.set_channel(self.channel)
            
            # Perform scan
            self.running = True
            if self.duration > 0:
                # Continuous scan
                self.continuous_scan()
            else:
                # Single scan
                networks = self.scan_networks()
                if networks:
                    analysis = self.analyze_networks(networks)
                    self.results = networks
            
            # Disable monitor mode
            if self.monitor_mode:
                self.disable_monitor_mode()
            
            # Generate summary
            summary = {
                'interface': self.interface,
                'duration': self.duration,
                'monitor_mode': self.monitor_mode,
                'networks_found': len(self.results),
                'analysis': self.analyze_networks(self.results) if self.results else {}
            }
            
            self.info(f"Scan completed. Found {len(self.results)} networks.")
            
            return {'success': True, 'summary': summary, 'results': self.results}
            
        except Exception as e:
            self.error(f"Wi-Fi scan failed: {e}")
            return {'success': False, 'message': f'Scan failed: {str(e)}'}
    
    def stop_scan(self):
        """
        Stop the continuous scan
        """
        self.running = False
    
    def run(self) -> dict:
        """
        Main module execution
        """
        return self.run_scan()


def run(options: dict = None) -> dict:
    """
    Entry point for the module
    """
    scanner = WiFiScanner()
    
    # Set options if provided
    if options:
        for key, value in options.items():
            scanner.set_option(key, value)
    
    return scanner.run()


if __name__ == '__main__':
    # Example usage
    options = {
        'INTERFACE': 'wlan0',
        'DURATION': '30',
        'CHANNEL': '',
        'MONITOR_MODE': 'false'
    }
    
    result = run(options)
    print(result)
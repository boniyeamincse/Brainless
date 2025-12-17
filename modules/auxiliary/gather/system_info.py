#!/usr/bin/env python3
"""
System Information Gatherer
===========================

Comprehensive system information gathering module for Linux systems.
Collects hardware, software, network, and security-related information.

Author: Brainless Security Team
Module: auxiliary/gather/system_info
Type: auxiliary
Rank: excellent
"""

import os
import sys
import subprocess
import platform
import socket
import json
import re
import pwd
import grp
from pathlib import Path

# Add framework path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.logger import LoggerMixin

NAME = "System Information Gatherer"
DESCRIPTION = "Comprehensive system information gathering for Linux systems"
AUTHOR = "Brainless Security Team"
VERSION = "1.0"
RANK = "excellent"
MODULE_TYPE = "auxiliary"

class SystemInfoGatherer(LoggerMixin):
    """
    Comprehensive system information gathering module
    """
    
    def __init__(self):
        super().__init__('SystemInfoGatherer')
        self.target = 'localhost'
        self.include_sensitive = False
        self.include_network = True
        self.include_processes = True
        self.include_files = True
        self.results = {}
    
    def set_option(self, option: str, value: str):
        """Set module options"""
        if option.lower() == 'target':
            self.target = value
        elif option.lower() == 'include_sensitive':
            self.include_sensitive = value.lower() == 'true'
        elif option.lower() == 'include_network':
            self.include_network = value.lower() == 'true'
        elif option.lower() == 'include_processes':
            self.include_processes = value.lower() == 'true'
        elif option.lower() == 'include_files':
            self.include_files = value.lower() == 'true'
    
    def get_options(self) -> dict:
        """Get module options"""
        return {
            'TARGET': {'description': 'Target system (localhost or IP)', 'required': False, 'default': 'localhost'},
            'INCLUDE_SENSITIVE': {'description': 'Include sensitive information', 'required': False, 'default': 'false'},
            'INCLUDE_NETWORK': {'description': 'Include network information', 'required': False, 'default': 'true'},
            'INCLUDE_PROCESSES': {'description': 'Include process information', 'required': False, 'default': 'true'},
            'INCLUDE_FILES': {'description': 'Include file system information', 'required': False, 'default': 'true'}
        }
    
    def get_basic_system_info(self) -> dict:
        """
        Get basic system information
        """
        try:
            return {
                'hostname': platform.node(),
                'platform': platform.platform(),
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'architecture': platform.architecture(),
                'processor': platform.processor(),
                'machine': platform.machine(),
                'python_version': platform.python_version(),
                'current_time': os.times()[4],
                'uptime': self.get_uptime(),
                'boot_time': self.get_boot_time()
            }
        except Exception as e:
            self.error(f"Failed to get basic system info: {e}")
            return {}
    
    def get_uptime(self) -> str:
        """
        Get system uptime
        """
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.read().split()[0])
                uptime_string = self.format_uptime(uptime_seconds)
                return uptime_string
        except:
            return "Unknown"
    
    def get_boot_time(self) -> str:
        """
        Get system boot time
        """
        try:
            with open('/proc/stat', 'r') as f:
                for line in f:
                    if line.startswith('btime'):
                        boot_timestamp = int(line.split()[1])
                        from datetime import datetime
                        boot_time = datetime.fromtimestamp(boot_timestamp)
                        return boot_time.strftime('%Y-%m-%d %H:%M:%S')
        except:
            return "Unknown"
    
    def format_uptime(self, seconds: float) -> str:
        """
        Format uptime in a human-readable format
        """
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        
        return f"{days} days, {hours} hours, {minutes} minutes"
    
    def get_hardware_info(self) -> dict:
        """
        Get hardware information
        """
        hardware = {}
        
        try:
            # CPU information
            cpu_info = {}
            try:
                with open('/proc/cpuinfo', 'r') as f:
                    cpu_data = f.read()
                
                cpu_lines = cpu_data.strip().split('\n')
                cpu_info['processors'] = len([l for l in cpu_lines if l.startswith('processor')])
                
                # Get model name
                for line in cpu_lines:
                    if 'model name' in line:
                        cpu_info['model'] = line.split(':')[1].strip()
                        break
                
                # Get CPU flags
                for line in cpu_lines:
                    if 'flags' in line:
                        cpu_info['flags'] = line.split(':')[1].strip().split()
                        break
                
            except Exception as e:
                self.warning(f"Could not read CPU info: {e}")
            
            hardware['cpu'] = cpu_info
            
            # Memory information
            memory_info = {}
            try:
                with open('/proc/meminfo', 'r') as f:
                    mem_data = f.read()
                
                mem_lines = mem_data.strip().split('\n')
                for line in mem_lines:
                    parts = line.split(':')
                    if len(parts) == 2:
                        key = parts[0].strip()
                        value = parts[1].strip().replace(' kB', '')
                        memory_info[key] = int(value) * 1024  # Convert to bytes
                
            except Exception as e:
                self.warning(f"Could not read memory info: {e}")
            
            hardware['memory'] = memory_info
            
            # Disk information
            disk_info = {}
            try:
                result = subprocess.run(['df', '-h'], capture_output=True, text=True)
                disk_lines = result.stdout.strip().split('\n')
                
                disks = []
                for line in disk_lines[1:]:  # Skip header
                    parts = line.split()
                    if len(parts) >= 6:
                        disk = {
                            'filesystem': parts[0],
                            'size': parts[1],
                            'used': parts[2],
                            'available': parts[3],
                            'use_percent': parts[4],
                            'mount_point': parts[5]
                        }
                        disks.append(disk)
                
                disk_info['partitions'] = disks
                
            except Exception as e:
                self.warning(f"Could not read disk info: {e}")
            
            hardware['disk'] = disk_info
            
        except Exception as e:
            self.error(f"Failed to get hardware info: {e}")
        
        return hardware
    
    def get_network_info(self) -> dict:
        """
        Get network information
        """
        network = {}
        
        if not self.include_network:
            return network
        
        try:
            # Network interfaces
            interfaces = {}
            try:
                result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True)
                
                current_interface = None
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    
                    if line and not line.startswith('inet6'):
                        if line.startswith('inet '):
                            parts = line.split()
                            if len(parts) >= 2:
                                ip_info = {
                                    'ip': parts[1],
                                    'interface': current_interface
                                }
                                if current_interface not in interfaces:
                                    interfaces[current_interface] = []
                                interfaces[current_interface].append(ip_info)
                        
                        elif line.startswith('link/'):
                            continue
                        
                        elif line and not line.startswith('valid_lft'):
                            # New interface
                            interface_name = line.split(':')[1].strip()
                            current_interface = interface_name
            
            except Exception as e:
                self.warning(f"Could not get interface info: {e}")
            
            network['interfaces'] = interfaces
            
            # Routing information
            routes = []
            try:
                result = subprocess.run(['ip', 'route', 'show'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if line.strip():
                        routes.append(line.strip())
            except:
                pass
            
            network['routes'] = routes
            
            # ARP table
            arp_entries = []
            try:
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if line.strip():
                        arp_entries.append(line.strip())
            except:
                pass
            
            network['arp_table'] = arp_entries
            
            # Network connections
            connections = []
            try:
                result = subprocess.run(['ss', '-tuln'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if line.strip() and not line.startswith('Netid'):
                        connections.append(line.strip())
            except:
                pass
            
            network['connections'] = connections
            
            # DNS configuration
            dns_config = []
            try:
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            dns_config.append(line)
            except:
                pass
            
            network['dns'] = dns_config
            
        except Exception as e:
            self.error(f"Failed to get network info: {e}")
        
        return network
    
    def get_user_info(self) -> dict:
        """
        Get user and group information
        """
        users = []
        groups = []
        
        try:
            # Get user information
            for user in pwd.getpwall():
                user_info = {
                    'username': user.pw_name,
                    'uid': user.pw_uid,
                    'gid': user.pw_gid,
                    'home': user.pw_dir,
                    'shell': user.pw_shell,
                    'gecos': user.pw_gecos
                }
                users.append(user_info)
            
            # Get group information
            for group in grp.getgrall():
                group_info = {
                    'name': group.gr_name,
                    'gid': group.gr_gid,
                    'members': group.gr_mem
                }
                groups.append(group_info)
        
        except Exception as e:
            self.error(f"Failed to get user/group info: {e}")
        
        return {'users': users, 'groups': groups}
    
    def get_process_info(self) -> list:
        """
        Get running process information
        """
        processes = []
        
        if not self.include_processes:
            return processes
        
        try:
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            
            lines = result.stdout.strip().split('\n')
            headers = lines[0].split()
            
            for line in lines[1:]:
                parts = line.split(None, 10)
                if len(parts) >= 11:
                    process = {
                        'user': parts[0],
                        'pid': parts[1],
                        'cpu': parts[2],
                        'memory': parts[3],
                        'vsz': parts[4],
                        'rss': parts[5],
                        'tty': parts[6],
                        'stat': parts[7],
                        'start': parts[8],
                        'time': parts[9],
                        'command': parts[10]
                    }
                    processes.append(process)
        
        except Exception as e:
            self.error(f"Failed to get process info: {e}")
        
        return processes
    
    def get_installed_packages(self) -> dict:
        """
        Get information about installed packages
        """
        packages = {}
        
        try:
            # Try different package managers
            package_managers = {
                'dpkg': ['dpkg', '-l'],
                'rpm': ['rpm', '-qa'],
                'pacman': ['pacman', '-Q'],
                'apk': ['apk', 'info']
            }
            
            for manager, cmd in package_managers.items():
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    if result.returncode == 0:
                        packages[manager] = result.stdout.strip().split('\n')
                        break
                except:
                    continue
        
        except Exception as e:
            self.error(f"Failed to get package info: {e}")
        
        return packages
    
    def get_service_info(self) -> dict:
        """
        Get service information
        """
        services = {}
        
        try:
            # Try systemctl
            try:
                result = subprocess.run(['systemctl', 'list-units', '--type=service'], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    services['systemd'] = result.stdout.strip().split('\n')
            except:
                pass
            
            # Try service command
            try:
                result = subprocess.run(['service', '--status-all'], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    services['sysv'] = result.stdout.strip().split('\n')
            except:
                pass
        
        except Exception as e:
            self.error(f"Failed to get service info: {e}")
        
        return services
    
    def get_security_info(self) -> dict:
        """
        Get security-related information
        """
        security = {}
        
        if not self.include_sensitive:
            return security
        
        try:
            # Sudo configuration
            sudo_config = []
            try:
                with open('/etc/sudoers', 'r') as f:
                    sudo_config = f.read().strip().split('\n')
            except:
                pass
            
            security['sudoers'] = sudo_config
            
            # SSH configuration
            ssh_config = {}
            try:
                ssh_files = [
                    '/etc/ssh/sshd_config',
                    '/etc/ssh/ssh_config'
                ]
                
                for ssh_file in ssh_files:
                    try:
                        with open(ssh_file, 'r') as f:
                            ssh_config[ssh_file] = f.read().strip().split('\n')
                    except:
                        pass
            except:
                pass
            
            security['ssh_config'] = ssh_config
            
            # Firewall status
            firewall = {}
            try:
                # Check iptables
                result = subprocess.run(['iptables', '-L'], capture_output=True, text=True)
                firewall['iptables'] = result.stdout.strip().split('\n')
            except:
                pass
            
            try:
                # Check ufw
                result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
                firewall['ufw'] = result.stdout.strip().split('\n')
            except:
                pass
            
            security['firewall'] = firewall
        
        except Exception as e:
            self.error(f"Failed to get security info: {e}")
        
        return security
    
    def get_filesystem_info(self) -> dict:
        """
        Get filesystem information
        """
        filesystem = {}
        
        if not self.include_files:
            return filesystem
        
        try:
            # Find sensitive files
            sensitive_files = [
                '/etc/passwd',
                '/etc/shadow',
                '/etc/group',
                '/etc/sudoers',
                '/etc/hosts',
                '/etc/crontab'
            ]
            
            file_info = {}
            for file_path in sensitive_files:
                try:
                    stat_info = os.stat(file_path)
                    file_info[file_path] = {
                        'size': stat_info.st_size,
                        'permissions': oct(stat_info.st_mode),
                        'owner': stat_info.st_uid,
                        'group': stat_info.st_gid,
                        'modified': stat_info.st_mtime
                    }
                except:
                    file_info[file_path] = None
            
            filesystem['sensitive_files'] = file_info
            
            # Check for world-writable files
            world_writable = []
            try:
                result = subprocess.run(['find', '/', '-type', 'f', '-perm', '-002', '-ls'], 
                                      capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    world_writable = result.stdout.strip().split('\n')
            except:
                pass
            
            filesystem['world_writable'] = world_writable
        
        except Exception as e:
            self.error(f"Failed to get filesystem info: {e}")
        
        return filesystem
    
    def run(self) -> dict:
        """
        Main module execution
        """
        try:
            self.info("Starting system information gathering...")
            
            # Gather all information
            self.results = {
                'basic_info': self.get_basic_system_info(),
                'hardware': self.get_hardware_info(),
                'network': self.get_network_info(),
                'users': self.get_user_info(),
                'processes': self.get_process_info(),
                'packages': self.get_installed_packages(),
                'services': self.get_service_info(),
                'security': self.get_security_info(),
                'filesystem': self.get_filesystem_info()
            }
            
            # Generate summary
            summary = {
                'hostname': self.results['basic_info'].get('hostname', 'Unknown'),
                'platform': self.results['basic_info'].get('platform', 'Unknown'),
                'users_found': len(self.results['users'].get('users', [])),
                'processes_found': len(self.results['processes']),
                'packages_found': sum(len(p) for p in self.results['packages'].values()),
                'collection_time': self.results['basic_info'].get('current_time', 0)
            }
            
            self.info(f"Information gathering completed for {summary['hostname']}")
            
            return {
                'success': True,
                'summary': summary,
                'results': self.results
            }
            
        except Exception as e:
            self.error(f"System information gathering failed: {e}")
            return {'success': False, 'message': f'Gathering failed: {str(e)}'}


def run(options: dict = None) -> dict:
    """
    Entry point for the module
    """
    gatherer = SystemInfoGatherer()
    
    # Set options if provided
    if options:
        for key, value in options.items():
            gatherer.set_option(key, value)
    
    return gatherer.run()


if __name__ == '__main__':
    # Example usage
    options = {
        'TARGET': 'localhost',
        'INCLUDE_SENSITIVE': 'true',
        'INCLUDE_NETWORK': 'true',
        'INCLUDE_PROCESSES': 'true',
        'INCLUDE_FILES': 'true'
    }
    
    result = run(options)
    print(json.dumps(result, indent=2))
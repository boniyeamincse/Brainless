#!/usr/bin/env python3
"""
System Admin Module
===================

Administrative operations for Linux systems.
Performs system analysis, service management, and configuration auditing.

Author: Brainless Security Team
Module: auxiliary/admin/misc/system_admin
Type: auxiliary
Rank: excellent
"""

import os
import sys
import subprocess
import pwd
import grp
import stat
import time
import json
from pathlib import Path

# Add framework path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from core.logger import LoggerMixin

NAME = "System Admin Module"
DESCRIPTION = "Administrative operations for Linux systems including analysis and configuration auditing"
AUTHOR = "Brainless Security Team"
VERSION = "1.0"
RANK = "excellent"
MODULE_TYPE = "auxiliary"

class SystemAdmin(LoggerMixin):
    """
    Linux system administrative operations module
    """
    
    def __init__(self):
        super().__init__('SystemAdmin')
        self.target = 'localhost'
        self.include_sensitive = True
        self.include_services = True
        self.include_network = True
        self.include_files = True
        self.include_processes = True
        self.depth = 2  # Directory traversal depth
        
    def set_option(self, option: str, value: str):
        """Set module options"""
        if option.lower() == 'target':
            self.target = value
        elif option.lower() == 'include_sensitive':
            self.include_sensitive = value.lower() == 'true'
        elif option.lower() == 'include_services':
            self.include_services = value.lower() == 'true'
        elif option.lower() == 'include_network':
            self.include_network = value.lower() == 'true'
        elif option.lower() == 'include_files':
            self.include_files = value.lower() == 'true'
        elif option.lower() == 'include_processes':
            self.include_processes = value.lower() == 'true'
        elif option.lower() == 'depth':
            self.depth = int(value)
    
    def get_options(self) -> dict:
        """Get module options"""
        return {
            'TARGET': {'description': 'Target system (localhost or IP)', 'required': False, 'default': 'localhost'},
            'INCLUDE_SENSITIVE': {'description': 'Include sensitive file analysis', 'required': False, 'default': 'true'},
            'INCLUDE_SERVICES': {'description': 'Include service analysis', 'required': False, 'default': 'true'},
            'INCLUDE_NETWORK': {'description': 'Include network configuration', 'required': False, 'default': 'true'},
            'INCLUDE_FILES': {'description': 'Include file system analysis', 'required': False, 'default': 'true'},
            'INCLUDE_PROCESSES': {'description': 'Include process analysis', 'required': False, 'default': 'true'},
            'DEPTH': {'description': 'Directory traversal depth', 'required': False, 'default': '2'}
        }
    
    def analyze_system_users(self) -> dict:
        """Analyze system users and permissions"""
        user_analysis = {
            'total_users': 0,
            'users_with_shell': 0,
            'privileged_users': [],
            'weak_passwords': [],
            'password_policies': {},
            'suid_sgid_files': []
        }
        
        try:
            # Analyze passwd file
            users = []
            try:
                with open('/etc/passwd', 'r') as f:
                    for line in f:
                        parts = line.strip().split(':')
                        if len(parts) >= 7:
                            user_info = {
                                'username': parts[0],
                                'uid': parts[2],
                                'gid': parts[3],
                                'shell': parts[6],
                                'home': parts[5],
                                'gecos': parts[4]
                            }
                            users.append(user_info)
                            
                            # Check for privileged users
                            if user_info['uid'] == '0' or user_info['username'] in ['root', 'sudo', 'admin']:
                                user_analysis['privileged_users'].append(user_info)
                            
                            # Count users with shell access
                            if user_info['shell'] not in ['/bin/false', '/sbin/nologin', '/usr/sbin/nologin']:
                                user_analysis['users_with_shell'] += 1
                
                user_analysis['total_users'] = len(users)
                
            except Exception as e:
                self.warning(f"Could not analyze passwd file: {e}")
            
            # Analyze shadow file (if accessible)
            if self.include_sensitive:
                try:
                    with open('/etc/shadow', 'r') as f:
                        for line in f:
                            parts = line.strip().split(':')
                            if len(parts) >= 2:
                                username = parts[0]
                                password_hash = parts[1]
                                
                                # Check for weak passwords or empty passwords
                                if password_hash == '' or password_hash == '!':
                                    user_analysis['weak_passwords'].append({
                                        'username': username,
                                        'issue': 'Empty or locked password'
                                    })
                                elif password_hash in ['x', '*']:
                                    # Password is in shadow file but not accessible
                                    pass
                
                except PermissionError:
                    self.warning("Cannot read /etc/shadow (requires root privileges)")
                except Exception as e:
                    self.warning(f"Could not analyze shadow file: {e}")
            
            # Find SUID/SGID files
            if self.include_files:
                user_analysis['suid_sgid_files'] = self.find_suid_sgid_files()
            
        except Exception as e:
            self.error(f"User analysis failed: {e}")
        
        return user_analysis
    
    def find_suid_sgid_files(self) -> list:
        """Find SUID and SGID files"""
        suid_sgid_files = []
        
        try:
            # Find SUID files
            result = subprocess.run(['find', '/', '-type', 'f', '-perm', '-4000', '-ls'], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 11:
                            suid_sgid_files.append({
                                'path': parts[10],
                                'owner': parts[2],
                                'group': parts[3],
                                'permissions': parts[0],
                                'type': 'SUID'
                            })
            
            # Find SGID files
            result = subprocess.run(['find', '/', '-type', 'f', '-perm', '-2000', '-ls'], 
                                  capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 11:
                            suid_sgid_files.append({
                                'path': parts[10],
                                'owner': parts[2],
                                'group': parts[3],
                                'permissions': parts[0],
                                'type': 'SGID'
                            })
        
        except subprocess.TimeoutExpired:
            self.warning("SUID/SGID file search timed out")
        except Exception as e:
            self.error(f"SUID/SGID file search failed: {e}")
        
        return suid_sgid_files
    
    def analyze_system_services(self) -> dict:
        """Analyze system services and their security"""
        service_analysis = {
            'systemd_services': [],
            'sysv_services': [],
            'network_services': [],
            'security_issues': [],
            'recommendations': []
        }
        
        if not self.include_services:
            return service_analysis
        
        try:
            # Check systemd services
            try:
                result = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=running'], 
                                      capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    lines = result.stdout.strip().split('\n')[1:]  # Skip header
                    for line in lines:
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 4:
                                service_name = parts[0].replace('.service', '')
                                service_analysis['systemd_services'].append({
                                    'name': service_name,
                                    'status': 'running',
                                    'type': 'systemd'
                                })
            except Exception as e:
                self.warning(f"Could not analyze systemd services: {e}")
            
            # Check network services
            if self.include_network:
                try:
                    result = subprocess.run(['ss', '-tuln'], capture_output=True, text=True)
                    
                    for line in result.stdout.split('\n'):
                        if line.strip() and not line.startswith('Netid'):
                            parts = line.split()
                            if len(parts) >= 4:
                                service_analysis['network_services'].append({
                                    'protocol': parts[0],
                                    'local_address': parts[4],
                                    'state': parts[0] if len(parts) > 0 else 'unknown'
                                })
                except Exception as e:
                    self.warning(f"Could not analyze network services: {e}")
            
            # Check for common security issues
            security_checks = [
                {'service': 'ssh', 'port': 22, 'issue': 'SSH service running'},
                {'service': 'ftp', 'port': 21, 'issue': 'FTP service running (unencrypted)'},
                {'service': 'telnet', 'port': 23, 'issue': 'Telnet service running (unencrypted)'},
                {'service': 'rsh', 'port': 514, 'issue': 'RSH service running (unencrypted)'},
                {'service': 'mysql', 'port': 3306, 'issue': 'MySQL service accessible'},
                {'service': 'postgres', 'port': 5432, 'issue': 'PostgreSQL service accessible'}
            ]
            
            for check in security_checks:
                # Check if service is running
                try:
                    result = subprocess.run(['ss', '-tuln'], capture_output=True, text=True)
                    if f':{check["port"]}' in result.stdout:
                        service_analysis['security_issues'].append({
                            'service': check['service'],
                            'port': check['port'],
                            'issue': check['issue'],
                            'severity': 'Medium'
                        })
                except:
                    pass
            
        except Exception as e:
            self.error(f"Service analysis failed: {e}")
        
        return service_analysis
    
    def analyze_network_configuration(self) -> dict:
        """Analyze network configuration and security"""
        network_analysis = {
            'interfaces': {},
            'routing_table': [],
            'dns_configuration': [],
            'firewall_status': {},
            'security_issues': [],
            'recommendations': []
        }
        
        if not self.include_network:
            return network_analysis
        
        try:
            # Network interfaces
            try:
                result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True)
                
                current_interface = None
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    
                    if ':' in line and 'link/' not in line:
                        # New interface
                        parts = line.split(':')
                        current_interface = parts[1].strip()
                        network_analysis['interfaces'][current_interface] = {
                            'addresses': [],
                            'state': 'unknown'
                        }
                    
                    elif line.startswith('inet '):
                        # IP address
                        parts = line.split()
                        if len(parts) >= 2:
                            network_analysis['interfaces'][current_interface]['addresses'].append({
                                'address': parts[1],
                                'scope': parts[2] if len(parts) > 2 else 'global'
                            })
                    
                    elif 'state' in line:
                        # Interface state
                        state = 'up' if 'UP' in line else 'down'
                        network_analysis['interfaces'][current_interface]['state'] = state
            
            except Exception as e:
                self.warning(f"Could not analyze network interfaces: {e}")
            
            # Routing table
            try:
                result = subprocess.run(['ip', 'route', 'show'], capture_output=True, text=True)
                
                for line in result.stdout.split('\n'):
                    if line.strip():
                        network_analysis['routing_table'].append(line.strip())
            
            except Exception as e:
                self.warning(f"Could not analyze routing table: {e}")
            
            # DNS configuration
            try:
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            network_analysis['dns_configuration'].append(line)
            except Exception as e:
                self.warning(f"Could not analyze DNS configuration: {e}")
            
            # Firewall status
            try:
                # Check iptables
                result = subprocess.run(['iptables', '-L'], capture_output=True, text=True)
                if result.returncode == 0:
                    network_analysis['firewall_status']['iptables'] = {
                        'status': 'active',
                        'rules': len([l for l in result.stdout.split('\n') if 'ACCEPT' in l or 'DROP' in l or 'REJECT' in l])
                    }
                else:
                    network_analysis['firewall_status']['iptables'] = {'status': 'inactive'}
            except:
                network_analysis['firewall_status']['iptables'] = {'status': 'unknown'}
            
            try:
                # Check UFW
                result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
                if result.returncode == 0:
                    active = 'active' in result.stdout.lower()
                    network_analysis['firewall_status']['ufw'] = {'status': 'active' if active else 'inactive'}
                else:
                    network_analysis['firewall_status']['ufw'] = {'status': 'inactive'}
            except:
                network_analysis['firewall_status']['ufw'] = {'status': 'unknown'}
            
            # Security checks
            security_issues = []
            
            # Check for exposed interfaces
            for interface, info in network_analysis['interfaces'].items():
                if info['state'] == 'up' and any('127.0.0.1' not in addr['address'] for addr in info['addresses']):
                    security_issues.append({
                        'interface': interface,
                        'issue': f'Interface {interface} is exposed',
                        'severity': 'Low'
                    })
            
            network_analysis['security_issues'] = security_issues
            
        except Exception as e:
            self.error(f"Network analysis failed: {e}")
        
        return network_analysis
    
    def analyze_file_system_security(self) -> dict:
        """Analyze file system security"""
        fs_analysis = {
            'sensitive_files': {},
            'world_writable_files': [],
            'important_directories': {},
            'security_issues': [],
            'recommendations': []
        }
        
        if not self.include_files:
            return fs_analysis
        
        try:
            # Sensitive files analysis
            sensitive_files = [
                '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/sudoers',
                '/etc/ssh/sshd_config', '/etc/hosts', '/etc/crontab',
                '/etc/fstab', '/etc/inetd.conf', '/etc/xinetd.conf'
            ]
            
            for file_path in sensitive_files:
                try:
                    stat_info = os.stat(file_path)
                    fs_analysis['sensitive_files'][file_path] = {
                        'exists': True,
                        'size': stat_info.st_size,
                        'permissions': oct(stat_info.st_mode),
                        'owner': stat_info.st_uid,
                        'group': stat_info.st_gid,
                        'readable': os.access(file_path, os.R_OK),
                        'writable': os.access(file_path, os.W_OK),
                        'accessible': os.access(file_path, os.X_OK)
                    }
                except:
                    fs_analysis['sensitive_files'][file_path] = {'exists': False}
            
            # World writable files (limited scope to avoid timeout)
            try:
                result = subprocess.run(['find', '/tmp', '/var/tmp', '-type', 'f', '-perm', '-002', '-ls'], 
                                      capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 11:
                                fs_analysis['world_writable_files'].append({
                                    'path': parts[10],
                                    'owner': parts[2],
                                    'group': parts[3]
                                })
            except subprocess.TimeoutExpired:
                self.warning("World writable file search timed out")
            except Exception as e:
                self.warning(f"Could not search world writable files: {e}")
            
            # Important directories analysis
            important_dirs = ['/etc', '/var', '/usr', '/home', '/root', '/bin', '/sbin']
            
            for dir_path in important_dirs:
                try:
                    if os.path.exists(dir_path):
                        stat_info = os.stat(dir_path)
                        fs_analysis['important_directories'][dir_path] = {
                            'exists': True,
                            'permissions': oct(stat_info.st_mode),
                            'owner': stat_info.st_uid,
                            'group': stat_info.st_gid
                        }
                except:
                    pass
            
            # Security issues
            security_issues = []
            
            # Check for accessible sensitive files
            for file_path, info in fs_analysis['sensitive_files'].items():
                if info.get('exists') and info.get('readable'):
                    if 'shadow' in file_path and os.geteuid() != 0:
                        # Shadow file should not be readable by non-root
                        security_issues.append({
                            'file': file_path,
                            'issue': f'Sensitive file {file_path} is readable',
                            'severity': 'High'
                        })
            
            fs_analysis['security_issues'] = security_issues
            
        except Exception as e:
            self.error(f"File system analysis failed: {e}")
        
        return fs_analysis
    
    def analyze_process_security(self) -> dict:
        """Analyze running processes for security issues"""
        process_analysis = {
            'running_processes': [],
            'suspicious_processes': [],
            'privilege_escalation': [],
            'recommendations': []
        }
        
        if not self.include_processes:
            return process_analysis
        
        try:
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                
                for line in lines:
                    parts = line.split(None, 10)
                    if len(parts) >= 11:
                        process = {
                            'user': parts[0],
                            'pid': parts[1],
                            'cpu': parts[2],
                            'memory': parts[3],
                            'command': parts[10]
                        }
                        process_analysis['running_processes'].append(process)
                        
                        # Check for suspicious processes
                        suspicious_patterns = [
                            'nc ', 'netcat', 'ncat', 'tcpdump', 'wireshark',
                            'john', 'hashcat', 'nmap', 'masscan',
                            'proxychains', 'tor', 'bitcoin', 'xmrig'
                        ]
                        
                        for pattern in suspicious_patterns:
                            if pattern in process['command'].lower():
                                process_analysis['suspicious_processes'].append({
                                    'pid': process['pid'],
                                    'user': process['user'],
                                    'command': process['command'],
                                    'pattern': pattern
                                })
                                break
                        
                        # Check for privilege escalation opportunities
                        if process['user'] == 'root' and 'su ' in process['command']:
                            process_analysis['privilege_escalation'].append({
                                'pid': process['pid'],
                                'user': process['user'],
                                'command': process['command'],
                                'issue': 'Root process potentially for privilege escalation'
                            })
        
        except Exception as e:
            self.error(f"Process analysis failed: {e}")
        
        return process_analysis
    
    def generate_security_recommendations(self, analysis_results: dict) -> list:
        """Generate comprehensive security recommendations"""
        recommendations = []
        
        # User security recommendations
        if 'users' in analysis_results:
            users = analysis_results['users']
            if users.get('weak_passwords'):
                recommendations.append({
                    'category': 'User Security',
                    'priority': 'High',
                    'recommendation': 'Implement strong password policies and reset weak passwords'
                })
            
            if users.get('suid_sgid_files'):
                recommendations.append({
                    'category': 'File Permissions',
                    'priority': 'Medium',
                    'recommendation': 'Review and remove unnecessary SUID/SGID files'
                })
        
        # Service security recommendations
        if 'services' in analysis_results:
            services = analysis_results['services']
            if services.get('security_issues'):
                recommendations.append({
                    'category': 'Service Security',
                    'priority': 'High',
                    'recommendation': 'Secure or disable unnecessary network services'
                })
        
        # Network security recommendations
        if 'network' in analysis_results:
            network = analysis_results['network']
            if network.get('firewall_status', {}).get('iptables', {}).get('status') == 'inactive':
                recommendations.append({
                    'category': 'Network Security',
                    'priority': 'High',
                    'recommendation': 'Enable and configure firewall (iptables/ufw)'
                })
        
        # File system security recommendations
        if 'filesystem' in analysis_results:
            fs = analysis_results['filesystem']
            if fs.get('world_writable_files'):
                recommendations.append({
                    'category': 'File System Security',
                    'priority': 'Medium',
                    'recommendation': 'Remove world-writable permissions from sensitive files'
                })
        
        return recommendations
    
    def run(self) -> dict:
        """Main module execution"""
        try:
            self.info("Starting comprehensive system administration analysis...")
            
            # Perform all analyses
            analysis_results = {
                'users': self.analyze_system_users(),
                'services': self.analyze_system_services(),
                'network': self.analyze_network_configuration(),
                'filesystem': self.analyze_file_system_security(),
                'processes': self.analyze_process_security()
            }
            
            # Generate recommendations
            recommendations = self.generate_security_recommendations(analysis_results)
            
            # Generate summary
            total_issues = 0
            total_issues += len(analysis_results['users'].get('privileged_users', []))
            total_issues += len(analysis_results['services'].get('security_issues', []))
            total_issues += len(analysis_results['network'].get('security_issues', []))
            total_issues += len(analysis_results['filesystem'].get('security_issues', []))
            total_issues += len(analysis_results['processes'].get('suspicious_processes', []))
            
            summary = {
                'target': self.target,
                'total_users': analysis_results['users'].get('total_users', 0),
                'privileged_users': len(analysis_results['users'].get('privileged_users', [])),
                'running_services': len(analysis_results['services'].get('systemd_services', [])),
                'network_interfaces': len(analysis_results['network'].get('interfaces', {})),
                'sensitive_files': len(analysis_results['filesystem'].get('sensitive_files', {})),
                'running_processes': len(analysis_results['processes'].get('running_processes', [])),
                'total_security_issues': total_issues,
                'recommendations_count': len(recommendations)
            }
            
            self.info(f"System administration analysis completed")
            self.info(f"Found {total_issues} potential security issues")
            self.info(f"Generated {len(recommendations)} recommendations")
            
            return {
                'success': True,
                'summary': summary,
                'results': analysis_results,
                'recommendations': recommendations
            }
            
        except Exception as e:
            self.error(f"System administration analysis failed: {e}")
            return {'success': False, 'message': f'Analysis failed: {str(e)}'}


def run(options: dict = None) -> dict:
    """Entry point for the module"""
    admin = SystemAdmin()
    
    if options:
        for key, value in options.items():
            admin.set_option(key, value)
    
    return admin.run()


if __name__ == '__main__':
    # Example usage
    options = {
        'TARGET': 'localhost',
        'INCLUDE_SENSITIVE': 'true',
        'INCLUDE_SERVICES': 'true',
        'INCLUDE_NETWORK': 'true',
        'INCLUDE_FILES': 'true',
        'INCLUDE_PROCESSES': 'true',
        'DEPTH': '2'
    }
    
    result = run(options)
    print(json.dumps(result, indent=2))
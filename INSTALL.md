# Brainless Framework Installation Guide

This guide provides detailed instructions for installing and setting up the Brainless Framework on Debian-based Linux systems.

## System Requirements

### Operating System
- Debian 10+ 
- Ubuntu 18.04+
- Kali Linux
- Parrot Security OS

### Python Requirements
- Python 3.10 or higher
- pip3 package manager

### Hardware Requirements
- Minimum: 2GB RAM, 500MB disk space
- Recommended: 4GB RAM, 1GB disk space

## Installation Steps

### 1. System Update
First, ensure your system is up to date:

```bash
sudo apt update && sudo apt upgrade -y
```

### 2. Install Python and pip
```bash
# Install Python 3 and pip
sudo apt install python3 python3-pip python3-venv -y

# Verify installation
python3 --version
pip3 --version
```

### 3. Clone the Repository
```bash
# Clone the framework
git clone https://github.com/brainless-security/brainless-framework.git

# Navigate to the framework directory
cd brainless-framework
```

### 4. Install Python Dependencies
```bash
# Install required packages
pip3 install -r requirements.txt
```

**Note**: For system-wide installation, use `sudo pip3 install -r requirements.txt`

### 5. Set Up Permissions
```bash
# Make the main script executable
chmod +x brainless.py

# For certain modules that require root access
# Note: Only run as root when necessary for specific modules
```

### 6. Verify Installation
```bash
# Test the framework
python3 brainless.py --help

# Or start the interactive interface
python3 brainless.py
```

## Dependencies

### Required Packages
- `paramiko` - SSH operations
- `ssl` - SSL/TLS support
- `socket` - Network operations
- `subprocess` - System command execution
- `threading` - Multi-threading support
- `json` - JSON processing
- `os`, `sys`, `pathlib` - System operations

### Optional Packages for Enhanced Functionality
- `scapy` - Advanced network packet manipulation
- `cryptography` - Enhanced encryption
- `requests` - HTTP operations
- `beautifulsoup4` - Web scraping

Install optional packages:
```bash
pip3 install scapy cryptography requests beautifulsoup4
```

## Configuration

### Basic Configuration
The framework will automatically create a default configuration file at `config/brainless.conf`. You can customize settings as needed:

```ini
[framework]
version = 0.1
author = Brainless Security Team

[cli]
prompt = "brainless > "
banner = true
history_file = ".brainless_history"

[modules]
modules_directory = "modules"
auto_load = true
validate_metadata = true

[logging]
level = "INFO"
file = "logs/brainless.log"
console_output = true

[security]
require_root = false
sandbox_modules = true
```

### Environment Variables
Optional environment variables for customization:

```bash
export BRAINLESS_CONFIG="/path/to/custom/config.conf"
export BRAINLESS_MODULES="/path/to/custom/modules"
export BRAINLESS_LOGS="/path/to/custom/logs"
```

## Module Installation

### Built-in Modules
All core modules are included in the repository. After cloning, they're ready to use.

### Custom Modules
To add custom modules:

1. Create your module file in the appropriate directory:
   - Exploits: `modules/exploits/`
   - Payloads: `modules/payloads/`
   - Auxiliary: `modules/auxiliary/`
   - Post-exploitation: `modules/post/`

2. Ensure your module follows the framework structure:
   ```python
   NAME = "Module Name"
   DESCRIPTION = "Module description"
   AUTHOR = "Your Name"
   MODULE_TYPE = "exploit|payload|auxiliary|post"
   
   def run(options=None):
       # Module implementation
       return {'success': True, 'message': 'Module executed'}
   ```

3. Restart the framework to load new modules.

## Troubleshooting

### Common Installation Issues

#### 1. Python Version Issues
```bash
# Check Python version
python3 --version

# If version is too old, install a newer version
sudo apt install python3.10 python3.10-pip
```

#### 2. Permission Denied Errors
```bash
# Make scripts executable
chmod +x brainless.py

# For system-wide installation
sudo chmod +x /usr/local/bin/brainless.py
```

#### 3. Missing Dependencies
```bash
# Reinstall dependencies
pip3 install --upgrade -r requirements.txt

# Install system dependencies
sudo apt install build-essential libssl-dev libffi-dev
```

#### 4. Module Import Errors
```bash
# Check Python path
python3 -c "import sys; print(sys.path)"

# Add framework to Python path if needed
export PYTHONPATH="${PYTHONPATH}:/path/to/brainless-framework"
```

### Verification Steps

1. **Check Framework Startup**:
   ```bash
   python3 brainless.py --version
   ```

2. **Verify Module Loading**:
   ```bash
   python3 brainless.py --verbose
   # Should show loaded modules count
   ```

3. **Test Basic Functionality**:
   ```bash
   # Start framework
   python3 brainless.py
   
   # In CLI:
   brainless > help
   brainless > search ssh
   brainless > use auxiliary/scanner/port_scanner
   ```

## Security Considerations

### Running with Root Privileges
Some modules require root access for network operations, file system access, or system reconnaissance:

```bash
# Only use when necessary
sudo python3 brainless.py

# Check which modules need root:
# - Network sniffing modules
# - System privilege escalation
# - Raw socket operations
# - File system analysis
```

### Security Best Practices
1. **Run as non-root user when possible**
2. **Use in isolated environments for testing**
3. **Keep the framework updated**
4. **Review module code before execution**
5. **Use proper authorization and legal documentation**

## Uninstallation

To completely remove Brainless Framework:

```bash
# Remove framework directory
rm -rf /path/to/brainless-framework

# Remove configuration files (if in home directory)
rm -rf ~/.brainless*

# Remove from system path (if added)
# Edit ~/.bashrc or ~/.zshrc and remove BRAINLESS entries

# Clean up Python packages (optional)
pip3 uninstall paramiko
```

## Getting Help

### Documentation
- `README.md` - Main documentation
- Module docstrings - Detailed module documentation
- `brainless.py --help` - Command-line help

### Support Channels
- GitHub Issues - Bug reports and feature requests
- Framework CLI - Built-in help system
- Module info - Use `info <module>` in CLI

### Debug Mode
Enable debug mode for troubleshooting:
```bash
python3 brainless.py --verbose
```

## Next Steps

After installation:

1. **Explore the framework**:
   ```bash
   python3 brainless.py
   brainless > help
   brainless > show modules
   ```

2. **Try example modules**:
   ```bash
   brainless > use auxiliary/scanner/port_scanner
   brainless > set TARGET 127.0.0.1
   brainless > run
   ```

3. **Read module documentation**:
   ```bash
   brainless > info auxiliary/scanner/port_scanner
   ```

4. **Create custom modules** following the development guidelines

## Legal Notice

⚠️ **Important**: Brainless Framework is intended for authorized security testing, research, and educational purposes only. Users are responsible for:
- Obtaining proper authorization before testing
- Complying with all applicable laws and regulations
- Using the framework ethically and responsibly

The developers assume no liability for misuse or unauthorized use of this framework.
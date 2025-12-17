#!/usr/bin/env python3
"""
Brainless Framework - Main Entry Point
=======================================

A modular penetration testing and security research framework inspired by Metasploit,
designed exclusively for Debian-based Linux distributions.

⚠️ Legal Notice: Brainless is intended ONLY for authorized security testing, research,
and educational purposes. Unauthorized use against systems you do not own or have
permission to test is illegal.

Author: Brainless Security Team
Version: 0.1 (Alpha)
"""

import os
import sys
import signal
import argparse
from pathlib import Path

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

from core.engine import BrainlessEngine
from core.logger import setup_logger
from core.cli import BrainlessCLI


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n\n[!] Shutting down Brainless Framework...")
    sys.exit(0)


def check_requirements():
    """Check if running on supported Debian-based system"""
    try:
        # Check Python version
        if sys.version_info < (3, 10):
            print("[-] Error: Python 3.10 or higher is required")
            print(f"[*] Current version: {sys.version_info.major}.{sys.version_info.minor}")
            return False
        
        # Check if running on Linux
        if sys.platform != 'linux':
            print("[-] Error: Brainless Framework only supports Linux")
            return False
        
        # Check for Debian-based distribution
        try:
            with open('/etc/os-release', 'r') as f:
                os_release = f.read()
                if 'debian' not in os_release.lower() and \
                   'ubuntu' not in os_release.lower() and \
                   'kali' not in os_release.lower() and \
                   'parrot' not in os_release.lower():
                    print("[-] Warning: This distribution may not be fully supported")
                    print("[*] Brainless Framework officially supports: Debian, Ubuntu, Kali, Parrot")
        except FileNotFoundError:
            print("[-] Warning: Could not determine distribution")
        
        return True
        
    except Exception as e:
        print(f"[-] Error checking requirements: {e}")
        return False


def main():
    """Main entry point for Brainless Framework"""
    
    # Set up signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Brainless Framework - Modular penetration testing framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 brainless.py                    # Start interactive CLI
  python3 brainless.py --help            # Show help
  python3 brainless.py --version         # Show version
        """
    )
    
    parser.add_argument('--version', action='version', version='Brainless Framework 0.1 (Alpha)')
    parser.add_argument('--config', type=str, default='config/brainless.conf', 
                       help='Path to configuration file')
    parser.add_argument('--verbose', '-v', action='store_true', 
                       help='Enable verbose logging')
    parser.add_argument('--no-banner', action='store_true', 
                       help='Skip banner display')
    
    args = parser.parse_args()
    
    # Check system requirements
    if not check_requirements():
        sys.exit(1)
    
    # Set up logging
    log_level = 'DEBUG' if args.verbose else 'INFO'
    logger = setup_logger('brainless', log_level=log_level)
    
    try:
        # Initialize the framework engine
        logger.info("Initializing Brainless Framework...")
        engine = BrainlessEngine(config_path=args.config)
        
        # Start the CLI interface
        if not args.no_banner:
            engine.show_banner()
        
        logger.info("Starting Brainless CLI...")
        cli = BrainlessCLI(engine)
        cli.start()
        
    except KeyboardInterrupt:
        print("\n\n[!] Shutting down Brainless Framework...")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
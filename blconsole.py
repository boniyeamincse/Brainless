#!/usr/bin/env python3
"""
Brainless Framework Console Entry Point
Main entry point for the Brainless Framework console interface.
"""

import sys
import argparse
from core.console import BLConsole
from core.engine import BrainlessEngine

def execute_single_command(command: str):
    """Execute a single console command and exit."""
    try:
        console = BLConsole()
        # Initialize components manually for single command
        console.engine = BrainlessEngine()
        console.module_loader = console.engine.module_loader
        console.session_manager = console.engine.session_manager
        
        # Execute the command
        console.onecmd(command)
        print()  # Add a newline for cleaner output
    except Exception as e:
        print(f"Error executing command: {e}")
        if hasattr(console, 'debug_mode') and console.debug_mode:
            import traceback
            traceback.print_exc()

def main():
    """Main entry point for the Brainless Framework console."""
    parser = argparse.ArgumentParser(description='Brainless Framework Console')
    parser.add_argument('-c', '--command', help='Execute a single command and exit')
    parser.add_argument('--version', action='version', version='Brainless Framework Console v0.1-alpha')
    
    args = parser.parse_args()
    
    console = BLConsole()
    
    if args.command:
        # Execute single command
        execute_single_command(args.command)
        return
    
    # Start the console normally
    console.start()

if __name__ == "__main__":
    main()
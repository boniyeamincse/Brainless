#!/usr/bin/env python3
"""
Brainless Framework Console Entry Point
Main entry point for the Brainless Framework console interface.
"""

from core.console import BLConsole

def main():
    """Main entry point for the Brainless Framework console."""
    console = BLConsole()
    console.cmdloop()

if __name__ == "__main__":
    main()
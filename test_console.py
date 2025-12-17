#!/usr/bin/env python3
"""
Test script for Brainless Framework Console
"""

import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_console():
    """Test the console functionality"""
    try:
        print("[*] Testing Brainless Framework Console...")
        
        # Test imports
        from core.console import BLConsole
        print("[+] Console import successful")
        
        from core.engine import BrainlessEngine
        print("[+] Engine import successful")
        
        # Test console creation
        console = BLConsole()
        print("[+] Console creation successful")
        
        # Test engine initialization
        engine = BrainlessEngine()
        print("[+] Engine initialization successful")
        
        print("[+] All tests passed!")
        return True
        
    except Exception as e:
        print(f"[-] Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_console()
    sys.exit(0 if success else 1)
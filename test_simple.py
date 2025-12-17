#!/usr/bin/env python3
"""
Simple test for Brainless Framework
"""

import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_basic():
    """Basic functionality test."""
    print("Testing Brainless Framework...")
    
    try:
        # Test module loader
        from core.module_loader import ModuleLoader
        loader = ModuleLoader()
        modules = loader.get_all_modules()
        print(f"Found {len(modules)} modules")
        
        for module in modules:
            print(f"  - {module['name']}")
        
        # Test search
        from core.search import search_modules
        results = search_modules("demo", loader)
        print(f"Search 'demo' found {len(results)} modules")
        
        # Test console creation
        from core.console import BLConsole
        console = BLConsole()
        print("Console created successfully")
        
        print("All tests passed!")
        return True
        
    except Exception as e:
        print(f"Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    test_basic()
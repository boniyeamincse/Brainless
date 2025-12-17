#!/usr/bin/env python3
"""
Test script for Brainless Framework
"""

import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_module_loader():
    """Test the module loader."""
    print("Testing Module Loader...")
    try:
        from core.module_loader import ModuleLoader
        loader = ModuleLoader()
        modules = loader.get_all_modules()
        print(f"✓ Found {len(modules)} modules")
        for module in modules:
            print(f"  - {module['name']}")
        return True
    except Exception as e:
        print(f"✗ Module loader test failed: {e}")
        return False

def test_search():
    """Test the search functionality."""
    print("\nTesting Search...")
    try:
        from core.search import search_modules
        from core.module_loader import ModuleLoader
        loader = ModuleLoader()
        results = search_modules("demo", loader)
        print(f"✓ Found {len(results)} modules matching 'demo'")
        for module in results:
            print(f"  - {module['name']}")
        return True
    except Exception as e:
        print(f"✗ Search test failed: {e}")
        return False

def test_console():
    """Test the console (banner only)."""
    print("\nTesting Console Banner...")
    try:
        from core.console import BLConsole
        console = BLConsole()
        print("✓ Console created successfully")
        print("Banner preview:")
        print(console.intro)
        return True
    except Exception as e:
        print(f"✗ Console test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("Brainless Framework Test Suite")
    print("=" * 40)
    
    tests = [
        test_module_loader,
        test_search,
        test_console,
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print(f"\n{passed}/{total} tests passed")
    
    if passed == total:
        print("✓ All tests passed! Framework is ready.")
    else:
        print("✗ Some tests failed. Check the errors above.")

if __name__ == "__main__":
    main()
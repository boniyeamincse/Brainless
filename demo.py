#!/usr/bin/env python3
"""
Brainless Framework Demo
Demonstrates the basic functionality of the framework.
"""

import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def demo():
    """Demonstrate framework functionality."""
    print("Brainless Framework Demo")
    print("=" * 40)
    
    # Import framework components
    from core.module_loader import ModuleLoader
    from core.search import search_modules
    from core.console import BLConsole
    
    # 1. Show banner
    print("\n1. Framework Banner:")
    console = BLConsole()
    print(console.intro)
    
    # 2. List modules
    print("2. Available Modules:")
    loader = ModuleLoader()
    modules = loader.get_all_modules()
    print(f"Found {len(modules)} module(s):")
    for module in modules:
        print(f"  - {module['name']}")
        print(f"    Description: {module['description']}")
        print(f"    Tags: {', '.join(module.get('tags', []))}")
        print()
    
    # 3. Search modules
    print("3. Search Demo:")
    results = search_modules("demo", loader)
    print(f"Search 'demo' found {len(results)} module(s):")
    for module in results:
        print(f"  - {module['name']}")
    
    # 4. Show module info
    print("\n4. Module Information:")
    if modules:
        module = modules[0]
        print(f"Module: {module['name']}")
        print(f"Description: {module['description']}")
        print(f"Author: {module.get('author', 'Unknown')}")
        print(f"Version: {module.get('version', '1.0')}")
        if module.get('options'):
            print("Options:")
            for option, default in module['options'].items():
                print(f"  {option}: {default}")
    
    print("\n" + "=" * 40)
    print("Demo completed successfully!")
    print("\nTo start the interactive console, run:")
    print("  python blconsole.py")

if __name__ == "__main__":
    demo()
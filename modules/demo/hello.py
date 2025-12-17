#!/usr/bin/env python3
"""
Hello World Demo Module for Brainless Framework
A simple demonstration module showing module structure.
"""

# Module metadata
MODULE_METADATA = {
    'name': 'demo/hello',
    'description': 'A simple hello world demonstration module',
    'tags': ['demo', 'hello', 'example'],
    'author': 'Brainless Framework Team',
    'version': '1.0',
    'options': {
        'name': 'World',
        'greeting': 'Hello'
    }
}

def run(options=None):
    """
    Main execution function for the hello module.
    
    Args:
        options: Dictionary of module options
    """
    if options is None:
        options = {}
        
    name = options.get('name', 'World')
    greeting = options.get('greeting', 'Hello')
    
    print(f"{greeting}, {name}!")
    print("This is a demonstration module for the Brainless Framework.")
    print("Module execution completed successfully.")
    
    return True

def info():
    """Return module information."""
    return {
        'name': MODULE_METADATA['name'],
        'description': MODULE_METADATA['description'],
        'author': MODULE_METADATA['author'],
        'version': MODULE_METADATA['version']
    }
# Brainless Framework (Python)

A modular penetration testing framework written in Python, inspired by Metasploit's console interface.

## Features

- **Console Interface**: Interactive command-line interface with banner and help
- **Module System**: Python modules with metadata (name, description, tags, options)
- **Module Management**: List, search, load, and execute modules
- **Extensible**: Easy to add new modules with metadata

## Quick Start

1. Run the framework:
   ```bash
   python blconsole.py
   ```

2. Basic commands:
   - `list` - Show all available modules
   - `search <keyword>` - Search modules by name/description/tags
   - `use <module_name>` - Load a module
   - `info` - Show current module information
   - `set <option> <value>` - Configure module options
   - `run` - Execute the loaded module
   - `back` - Unload current module
   - `quit` - Exit the framework

## Module Structure

Modules are Python files with metadata:

```python
MODULE_METADATA = {
    'name': 'module/path',
    'description': 'Module description',
    'tags': ['tag1', 'tag2'],
    'author': 'Author Name',
    'version': '1.0',
    'options': {
        'option_name': 'default_value'
    }
}

def run(options=None):
    # Module execution logic
    pass
```

## Project Structure

```
brainless_framework/
├── blconsole.py          # Main entry point
├── core/                 # Core framework modules
│   ├── __init__.py
│   ├── console.py        # Console interface
│   ├── module_loader.py  # Module loading system
│   ├── search.py         # Search functionality
│   └── utils.py          # Utility functions
├── modules/              # Framework modules
│   └── demo/             # Demo modules
│       ├── __init__.py
│       └── hello.py      # Hello world demo
└── data/                 # Static data
    └── banner.txt        # ASCII banner
```

## Creating Modules

1. Create a Python file in the `modules/` directory
2. Add `MODULE_METADATA` dictionary with module information
3. Implement a `run(options)` function
4. Optionally implement an `info()` function

## Requirements

- Python 3.6+
- No external dependencies (uses only standard library)

## License

This project is open source and available under the MIT License.
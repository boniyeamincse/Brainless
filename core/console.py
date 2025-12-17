#!/usr/bin/env python3
"""
Brainless Framework Console Interface
Provides the main command-line interface for the framework.
"""

import cmd
import os
import sys
from typing import Optional
from core.module_loader import ModuleLoader
from core.search import search_modules
from core.utils import get_version

class BLConsole(cmd.Cmd):
    """Main console interface for the Brainless Framework."""
    
    intro = ""
    prompt = "blconsole> "
    
    def __init__(self):
        super().__init__()
        self.module_loader = ModuleLoader()
        self.current_module = None
        self._load_banner()
        
    def _load_banner(self):
        """Load and display the ASCII banner."""
        banner_path = os.path.join(os.path.dirname(__file__), "..", "data", "banner.txt")
        version = get_version()
        
        if os.path.exists(banner_path):
            with open(banner_path, 'r') as f:
                banner_content = f.read()
            self.intro = f"{banner_content}\nBrainless Framework (Python) - v{version}\nType 'help' to see commands.\n"
        else:
            # Fallback banner if file doesn't exist
            self.intro = f"""
 ____  _      ____                      _
| __ )| |    / ___|___  _ __  ___  ___ | | ___
|  _ \| |   | |   / _ \\| '_ \\/ __|/ _ \\| |/ _ \\
| |_) | |___| |__| (_) | | | \\__ \\ (_) | |  __/
|____/|_____|\____\___/|_| |_|___/\\___/|_|\\___/

Brainless Framework (Python) - v{version}
Type 'help' to see commands.
"""
    
    def do_help(self, arg: str) -> None:
        """Show help for available commands."""
        if arg:
            # Show help for specific command
            super().do_help(arg)
        else:
            # Show general help
            print("\nAvailable commands:")
            print("  help [command]    - Show help for commands")
            print("  list              - List all available modules")
            print("  search <keyword>  - Search modules by name/description/tags")
            print("  use <module>      - Load a module")
            print("  info              - Show current module info")
            print("  set <option> <value> - Set module option")
            print("  run               - Execute current module")
            print("  back              - Unload current module")
            print("  quit/exit         - Exit the framework\n")
    
    def do_list(self, arg: str) -> None:
        """List all available modules."""
        modules = self.module_loader.get_all_modules()
        if not modules:
            print("No modules found.")
            return
            
        print(f"\nFound {len(modules)} module(s):")
        for module in modules:
            print(f"  {module['name']:<30} - {module['description']}")
        print()
    
    def do_search(self, arg: str) -> None:
        """Search modules by keyword."""
        if not arg:
            print("Usage: search <keyword>")
            return
            
        results = search_modules(arg, self.module_loader)
        if not results:
            print(f"No modules found matching '{arg}'")
            return
            
        print(f"\nFound {len(results)} module(s) matching '{arg}':")
        for module in results:
            print(f"  {module['name']:<30} - {module['description']}")
        print()
    
    def do_use(self, arg: str) -> None:
        """Load a module."""
        if not arg:
            print("Usage: use <module_name>")
            return
            
        module = self.module_loader.load_module(arg)
        if not module:
            print(f"Module '{arg}' not found.")
            return
            
        self.current_module = module
        self.prompt = f"blconsole({module['name']})> "
        print(f"Loaded module: {module['name']}")
        print(f"Description: {module['description']}")
        if module.get('options'):
            print("Options:")
            for option, default in module['options'].items():
                print(f"  {option:<20} - Default: {default}")
        print()
    
    def do_info(self, arg: str) -> None:
        """Show current module information."""
        if not self.current_module:
            print("No module loaded. Use 'use <module_name>' to load a module.")
            return
            
        module = self.current_module
        print(f"\nModule: {module['name']}")
        print(f"Description: {module['description']}")
        print(f"Tags: {', '.join(module.get('tags', []))}")
        print(f"Author: {module.get('author', 'Unknown')}")
        print(f"Version: {module.get('version', '1.0')}")
        
        if module.get('options'):
            print("\nOptions:")
            for option, default in module['options'].items():
                print(f"  {option:<20} - Default: {default}")
        print()
    
    def do_set(self, arg: str) -> None:
        """Set module option."""
        if not self.current_module:
            print("No module loaded. Use 'use <module_name>' to load a module.")
            return
            
        parts = arg.split(' ', 1)
        if len(parts) < 2:
            print("Usage: set <option> <value>")
            return
            
        option, value = parts[0], parts[1]
        if not self.current_module.get('options') or option not in self.current_module['options']:
            print(f"Unknown option '{option}' for module '{self.current_module['name']}'")
            return
            
        # Store the option value (in a real implementation, this would be passed to the module)
        if not hasattr(self.current_module, 'configured_options'):
            self.current_module['configured_options'] = {}
        self.current_module['configured_options'][option] = value
        print(f"Set {option} = {value}")
    
    def do_run(self, arg: str) -> None:
        """Execute the current module."""
        if not self.current_module:
            print("No module loaded. Use 'use <module_name>' to load a module.")
            return
            
        print(f"Running module: {self.current_module['name']}")
        # In a real implementation, this would call the module's run method
        # For now, just show what would be executed
        if hasattr(self.current_module, 'configured_options'):
            print(f"Configured options: {self.current_module['configured_options']}")
        else:
            print("No options configured.")
        print("Module execution completed.")
    
    def do_back(self, arg: str) -> None:
        """Unload current module."""
        if not self.current_module:
            print("No module loaded.")
            return
            
        print(f"Unloaded module: {self.current_module['name']}")
        self.current_module = None
        self.prompt = "blconsole> "
    
    def do_quit(self, arg: str) -> bool:
        """Exit the framework."""
        print("Goodbye!")
        return True
    
    def do_exit(self, arg: str) -> bool:
        """Exit the framework."""
        return self.do_quit(arg)
    
    def emptyline(self) -> None:
        """Do nothing on empty line."""
        pass
    
    def precmd(self, line: str) -> str:
        """Called after the line has been input but before it has been interpreted."""
        return line.strip()
    
    def cmdloop(self, intro: Optional[str] = None) -> None:
        """Override cmdloop to use our custom intro."""
        try:
            super().cmdloop(self.intro)
        except KeyboardInterrupt:
            print("\n\nKeyboard interrupt received. Exiting...")
            return

# Alias for backward compatibility
if __name__ == "__main__":
    BLConsole().cmdloop()
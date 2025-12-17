#!/usr/bin/env python3
"""
Brainless Framework Console Interface
Provides the main command-line interface for the framework with comprehensive
command support including core commands, module discovery, module interaction,
workspaces, output management, and diagnostics.
"""

import cmd
import os
import sys
import shlex
import configparser
from typing import Optional, Dict, List, Any
from pathlib import Path
from datetime import datetime

# Try to import readline for better CLI experience (Unix/Linux only)
try:
    import readline
    HAS_READLINE = True
except ImportError:
    HAS_READLINE = False
    print("[*] readline not available (Windows). Tab completion disabled.")

from core.module_loader import ModuleLoader
from core.search import search_modules
from core.utils import get_version
from core.engine import BrainlessEngine
from core.session import SessionManager


class BLConsole(cmd.Cmd):
    """Main console interface for the Brainless Framework with comprehensive command support."""
    
    intro = ""
    prompt = "blconsole> "
    
    def __init__(self):
        super().__init__()
        self.engine = None
        self.module_loader = None
        self.session_manager = None
        self.current_module = None
        self.module_options = {}
        self.global_options = {}
        self.current_workspace = "default"
        self.spool_file = None
        self.debug_mode = False
        self._load_banner()
        self._setup_readline()
        
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
    
    def _setup_readline(self):
        r"""Set up readline for command history and completion"""
        if not HAS_READLINE:
            return
            
        try:
            # Enable tab completion
            readline.parse_and_bind("tab: complete")
            
            # Set up command history
            history_file = ".blconsole_history"
            try:
                readline.read_history_file(history_file)
            except FileNotFoundError:
                pass
            
            # Limit history size
            max_history = 1000
            if len(readline.get_history_events()) > max_history:
                readline.clear_history()
                # Re-add last N entries
                hist_end = readline.get_current_history_length()
                for i in range(max(1, hist_end - max_history + 1), hist_end):
                    readline.add_history(readline.get_history_item(i))
            
            # Save history on exit
            import atexit
            atexit.register(readline.write_history_file, history_file)
            
        except Exception as e:
            print(f"[*] Warning: Failed to setup readline: {e}")
    
    def start(self):
        """Start the console interface"""
        try:
            # Initialize the engine
            self.engine = BrainlessEngine()
            self.module_loader = self.engine.module_loader
            self.session_manager = self.engine.session_manager
            
            print("[*] Brainless Framework Console started successfully")
            print("[*] Type 'help' for available commands")
            print()
            
            # Start the command loop
            self.cmdloop()
            
        except KeyboardInterrupt:
            print("\n\n[*] Exiting Brainless Framework Console...")
        except Exception as e:
            print(f"[-] Error starting console: {e}")
            if self.debug_mode:
                import traceback
                traceback.print_exc()
    
    def precmd(self, line: str) -> str:
        """Called after the line has been input but before it has been interpreted."""
        # Update prompt based on current context
        if self.current_module:
            module_name = self.current_module.get('name', 'unknown')
            self.prompt = f"blconsole({module_name})> "
        else:
            self.prompt = "blconsole> "
        
        # Handle spooling
        if self.spool_file:
            try:
                with open(self.spool_file, 'a') as f:
                    f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {line}\n")
            except Exception as e:
                print(f"[*] Warning: Failed to write to spool file: {e}")
        
        return line.strip()
    
    # Core Commands
    def do_help(self, arg: str) -> None:
        """Show help for available commands."""
        if arg:
            # Show help for specific command
            try:
                func = getattr(self, f'do_{arg}')
                if func.__doc__:
                    print(f"Usage: {arg} {func.__doc__.strip()}")
                else:
                    print(f"No help available for '{arg}'")
            except AttributeError:
                print(f"Unknown command: {arg}")
        else:
            # Show general help
            self.print_help()
    
    def print_help(self):
        """Print comprehensive help information"""
        help_text = """
Brainless Framework Console Commands:

CORE COMMANDS:
  help [command]        - Show help information
  banner                - Display the framework banner
  version               - Show framework version
  clear                 - Clear the console screen
  exit/quit             - Exit the framework

MODULE DISCOVERY:
  list                  - List all available modules
  search <keyword>      - Search modules by name/description/tags
  use <module>          - Load a module for use

MODULE INTERACTION:
  info                  - Show current module information
  show options          - Show module options
  set <option> <value>  - Set module option
  unset <option>        - Unset module option
  setg <option> <value> - Set global option
  unsetg <option>       - Unset global option
  run                   - Execute current module
  back                  - Unload current module

WORKSPACES & OUTPUT:
  workspace list        - List available workspaces
  workspace new <name>  - Create new workspace
  workspace use <name>  - Switch to workspace
  spool <file>          - Start spooling output to file
  spool off             - Stop spooling output

DIAGNOSTICS:
  debug on|off          - Enable/disable debug mode
  check                 - Run diagnostic checks

EXAMPLES:
  use exploit/linux/ssh/weak_ssh
  set RHOST 192.168.1.10
  set PAYLOAD reverse_tcp
  set LHOST 192.168.1.100
  run
  sessions
        """
        print(help_text)
    
    def do_banner(self, arg: str) -> None:
        """Display the framework banner."""
        print(self.intro)
    
    def do_version(self, arg: str) -> None:
        """Show framework version."""
        if self.engine:
            info = self.engine.get_framework_info()
            print(f"Brainless Framework v{info['version']}")
            print(f"Author: {info['author']}")
            print(f"Modules loaded: {info['modules_loaded']}")
            print(f"Active sessions: {info['active_sessions']}")
        else:
            print(f"Brainless Framework v{get_version()}")
    
    def do_clear(self, arg: str) -> None:
        """Clear the console screen."""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def do_exit(self, arg: str) -> bool:
        """Exit the framework."""
        return self.do_quit(arg)
    
    def do_quit(self, arg: str) -> bool:
        """Exit the framework."""
        print("[*] Cleaning up...")
        if self.engine:
            self.engine.shutdown()
        print("Goodbye!")
        return True
    
    # Module Discovery Commands
    def do_list(self, arg: str) -> None:
        """List all available modules."""
        if not self.module_loader:
            print("[-] Module loader not initialized")
            return
            
        modules = self.module_loader.get_all_modules()
        if not modules:
            print("No modules found.")
            return
            
        # Group modules by type
        module_types = {}
        for module in modules:
            module_type = module.get('module_type', 'unknown')
            if module_type not in module_types:
                module_types[module_type] = []
            module_types[module_type].append(module)
        
        print(f"\nFound {len(modules)} module(s):")
        for module_type, type_modules in module_types.items():
            print(f"\n{module_type.upper()}:")
            print("-" * 40)
            for module in sorted(type_modules, key=lambda x: x['name']):
                print(f"  {module['name']:<30} - {module['description']}")
        print()
    
    def do_search(self, arg: str) -> None:
        """Search modules by keyword."""
        if not arg:
            print("Usage: search <keyword>")
            return
        
        if not self.module_loader:
            print("[-] Module loader not initialized")
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
        
        if not self.module_loader:
            print("[-] Module loader not initialized")
            return
            
        # Try to load module by name or path
        module = self.module_loader.load_module(arg)
        if not module:
            # Try searching for the module
            results = search_modules(arg, self.module_loader)
            if results:
                if len(results) == 1:
                    module = results[0]
                else:
                    print(f"Multiple modules found matching '{arg}':")
                    for m in results:
                        print(f"  {m['name']}")
                    print("Please specify the full module name.")
                    return
            else:
                print(f"Module '{arg}' not found.")
                return
        
        self.current_module = module
        self.module_options = {}
        print(f"[+] Using module: {module['name']}")
        print(f"[*] Description: {module['description']}")
        if module.get('author'):
            print(f"[*] Author: {module['author']}")
        print()
    
    # Module Interaction Commands
    def do_info(self, arg: str) -> None:
        """Show current module information."""
        if not self.current_module:
            print("No module loaded. Use 'use <module_name>' to load a module.")
            return
            
        module = self.current_module
        print(f"\nModule: {module['name']}")
        print(f"Description: {module['description']}")
        if module.get('tags'):
            print(f"Tags: {', '.join(module['tags'])}")
        if module.get('author'):
            print(f"Author: {module['author']}")
        if module.get('version'):
            print(f"Version: {module['version']}")
        
        if module.get('options'):
            print("\nOptions:")
            for option, default in module['options'].items():
                value = self.module_options.get(option, default)
                print(f"  {option:<20} - Value: {value} (Default: {default})")
        print()
    
    def do_show(self, arg: str) -> None:
        """Show module information or options."""
        if not self.current_module:
            print("No module loaded. Use 'use <module_name>' to load a module.")
            return
        
        if arg == 'options' or not arg:
            # Show module options
            self._show_module_options()
        else:
            print(f"Unknown show option: {arg}")
            print("Usage: show [options]")
    
    def _show_module_options(self):
        """Show module options"""
        module = self.current_module
        print(f"\nModule Options for {module['name']}:\n")
        print(f"{'Name':<15} {'Current Value':<20} {'Default':<15} {'Required':<10} {'Description':<30}")
        print("-" * 100)
        
        options = module.get('options', {})
        for option_name, option_info in options.items():
            current = self.module_options.get(option_name, option_info.get('default', ''))
            default = option_info.get('default', '')
            required = option_info.get('required', 'no')
            description = option_info.get('description', '')
            print(f"{option_name:<15} {str(current):<20} {str(default):<15} {required:<10} {description:<30}")
        print()
    
    def do_set(self, arg: str) -> None:
        """Set module option."""
        if not self.current_module:
            print("No module loaded. Use 'use <module_name>' to load a module.")
            return
        
        parts = shlex.split(arg)
        if len(parts) < 2:
            print("Usage: set <option> <value>")
            return
        
        option, value = parts[0], ' '.join(parts[1:])
        options = self.current_module.get('options', {})
        
        if option not in options:
            print(f"Unknown option '{option}' for module '{self.current_module['name']}'")
            return
        
        self.module_options[option] = value
        print(f"[+] Set {option} = {value}")
    
    def do_unset(self, arg: str) -> None:
        """Unset module option."""
        if not self.current_module:
            print("No module loaded. Use 'use <module_name>' to load a module.")
            return
        
        if not arg:
            print("Usage: unset <option>")
            return
        
        if arg in self.module_options:
            del self.module_options[arg]
            print(f"[+] Unset {arg}")
        else:
            print(f"Option '{arg}' not set")
    
    def do_setg(self, arg: str) -> None:
        """Set global option."""
        parts = shlex.split(arg)
        if len(parts) < 2:
            print("Usage: setg <option> <value>")
            return
        
        option, value = parts[0], ' '.join(parts[1:])
        self.global_options[option] = value
        print(f"[+] Set global {option} = {value}")
    
    def do_unsetg(self, arg: str) -> None:
        """Unset global option."""
        if not arg:
            print("Usage: unsetg <option>")
            return
        
        if arg in self.global_options:
            del self.global_options[arg]
            print(f"[+] Unset global {arg}")
        else:
            print(f"Global option '{arg}' not set")
    
    def do_run(self, arg: str) -> None:
        """Execute the current module."""
        if not self.current_module:
            print("No module loaded. Use 'use <module_name>' to load a module.")
            return
        
        try:
            print(f"[*] Running module: {self.current_module['name']}")
            
            # Combine global and module options
            all_options = self.global_options.copy()
            all_options.update(self.module_options)
            
            # Execute the module (placeholder for actual execution)
            print(f"[*] Module would execute with options: {all_options}")
            print("[+] Module execution completed")
            
        except Exception as e:
            print(f"[-] Module execution failed: {e}")
            if self.debug_mode:
                import traceback
                traceback.print_exc()
    
    def do_back(self, arg: str) -> None:
        """Unload current module."""
        if not self.current_module:
            print("No module loaded.")
            return
        
        print(f"[*] Unloaded module: {self.current_module['name']}")
        self.current_module = None
        self.module_options = {}
    
    # Workspaces & Output Commands
    def do_workspace(self, arg: str) -> None:
        """Manage workspaces."""
        parts = shlex.split(arg)
        if not parts:
            print("Usage: workspace list|new <name>|use <name>")
            return
        
        command = parts[0]
        if command == 'list':
            self._workspace_list()
        elif command == 'new' and len(parts) > 1:
            self._workspace_new(parts[1])
        elif command == 'use' and len(parts) > 1:
            self._workspace_use(parts[1])
        else:
            print("Usage: workspace list|new <name>|use <name>")
    
    def _workspace_list(self):
        """List available workspaces."""
        print(f"\nWorkspaces:")
        print("-" * 20)
        print(f"  {self.current_workspace} (current)")
        print()
    
    def _workspace_new(self, name: str):
        """Create new workspace."""
        print(f"[*] Workspaces not fully implemented yet")
        print(f"[*] Would create workspace: {name}")
    
    def _workspace_use(self, name: str):
        """Switch to workspace."""
        old_workspace = self.current_workspace
        self.current_workspace = name
        print(f"[*] Switched from workspace '{old_workspace}' to '{name}'")
    
    def do_spool(self, arg: str) -> None:
        """Manage output spooling."""
        if not arg or arg == 'off':
            if self.spool_file:
                print(f"[*] Stopped spooling to {self.spool_file}")
                self.spool_file = None
            else:
                print("Usage: spool <file>|off")
            return
        
        self.spool_file = arg
        print(f"[*] Started spooling to {self.spool_file}")
    
    # Diagnostics Commands
    def do_debug(self, arg: str) -> None:
        """Enable/disable debug mode."""
        if arg == 'on':
            self.debug_mode = True
            print("[+] Debug mode enabled")
        elif arg == 'off':
            self.debug_mode = False
            print("[-] Debug mode disabled")
        else:
            print("Usage: debug on|off")
            print(f"Current state: {'on' if self.debug_mode else 'off'}")
    
    def do_check(self, arg: str) -> None:
        """Run diagnostic checks."""
        print("\n[*] Running diagnostic checks...")
        
        # Check engine
        if self.engine:
            info = self.engine.get_framework_info()
            print(f"[+] Framework: {info['name']} v{info['version']}")
            print(f"[+] Modules loaded: {info['modules_loaded']}")
            print(f"[+] Active sessions: {info['active_sessions']}")
        else:
            print("[-] Engine not initialized")
        
        # Check module loader
        if self.module_loader:
            print(f"[+] Module loader: Active")
        else:
            print("[-] Module loader not initialized")
        
        # Check session manager
        if self.session_manager:
            stats = self.session_manager.get_session_stats()
            print(f"[+] Session manager: {stats['total_sessions']} active sessions")
        else:
            print("[-] Session manager not initialized")
        
        # Check current state
        print(f"[+] Current workspace: {self.current_workspace}")
        print(f"[+] Debug mode: {'on' if self.debug_mode else 'off'}")
        print(f"[+] Spooling: {'on' if self.spool_file else 'off'}")
        
        if self.current_module:
            print(f"[+] Current module: {self.current_module['name']}")
        else:
            print("[-] No module loaded")
        
        print()
    
    def emptyline(self) -> None:
        """Do nothing on empty line."""
        pass
    
    def cmdloop(self, intro: Optional[str] = None) -> None:
        """Override cmdloop to use our custom intro."""
        try:
            super().cmdloop(self.intro if intro is None else intro)
        except (KeyboardInterrupt, EOFError):
            print("\n\n[*] Exiting...")
            return
    
    # Tab completion methods
    def complete_use(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        """Complete module names for 'use' command."""
        if not self.module_loader:
            return []
        
        all_modules = self.module_loader.get_all_modules()
        module_names = [m['name'] for m in all_modules]
        
        if not text:
            return module_names
        
        return [m for m in module_names if m.startswith(text)]
    
    def complete_set(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        """Complete option names for 'set' command."""
        if not self.current_module:
            return []
        
        options = self.current_module.get('options', {})
        option_names = list(options.keys())
        
        if not text:
            return option_names
        
        return [opt for opt in option_names if opt.startswith(text)]
    
    def complete_unset(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        """Complete option names for 'unset' command."""
        if not self.current_module:
            return []
        
        current_options = list(self.module_options.keys())
        
        if not text:
            return current_options
        
        return [opt for opt in current_options if opt.startswith(text)]
    
    def complete_workspace(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        """Complete workspace commands."""
        commands = ['list', 'new', 'use']
        
        if not text:
            return commands
        
        return [cmd for cmd in commands if cmd.startswith(text)]
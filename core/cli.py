"""
Brainless Framework - Command Line Interface
=============================================

Interactive CLI for the Brainless Framework with command parsing,
tab completion, and session management.

Author: Brainless Security Team
"""

import cmd
import os
import sys
import shlex
from typing import List, Dict, Optional, Any
from pathlib import Path

from core.logger import LoggerMixin
from core.session import Session

# Try to import readline for better CLI experience (Unix/Linux only)
try:
    import readline
    HAS_READLINE = True
except ImportError:
    HAS_READLINE = False
    print("[*] readline not available (Windows). Tab completion disabled.")


class BrainlessCLI(cmd.Cmd, LoggerMixin):
    """
    Interactive CLI for Brainless Framework
    
    Provides:
    - Command parsing and execution
    - Tab completion
    - Session management
    - Module interaction
    """
    
    intro = "Welcome to Brainless Framework CLI"
    prompt = "brainless > "
    
    def __init__(self, engine):
        """
        Initialize the CLI interface
        
        Args:
            engine: BrainlessEngine instance
        """
        cmd.Cmd.__init__(self)
        LoggerMixin.__init__(self, 'BrainlessCLI')
        
        self.engine = engine
        self.current_module = None
        self.module_options = {}
        
        # Set up readline for better CLI experience
        self._setup_readline()
        
        # Update prompt if configured
        try:
            cli_config = engine.config['cli']
            if cli_config.getboolean('banner', fallback=True):
                self.intro = ""
        except:
            pass
    
    def _setup_readline(self):
        """Set up readline for command history and completion"""
        try:
            # Enable tab completion
            readline.parse_and_bind("tab: complete")
            
            # Set up command history
            history_file = ".brainless_history"
            try:
                readline.read_history_file(history_file)
            except FileNotFoundError:
                pass
            
            # Limit history size
            max_history = 1000
            try:
                max_history = self.engine.config.getint('cli', 'max_history', fallback=1000)
            except:
                pass
            
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
            self.warning(f"Failed to setup readline: {e}")
    
    def precmd(self, line: str) -> str:
        """Process command before execution"""
        # Update prompt based on current context
        if self.current_module:
            module_name = self.current_module.get('name', 'unknown')
            self.prompt = f"brainless exploit({module_name}) > "
        else:
            self.prompt = "brainless > "
        
        return line
    
    def do_help(self, arg: str):
        """Show help information"""
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
Brainless Framework Commands:

Basic Commands:
  help [command]     - Show help information
  use <module>       - Load a module for use
  set <option> <val> - Set module option
  show [options]     - Show module options or info
  run                - Execute the current module
  back               - Go back to main prompt
  exit/quit          - Exit the framework

Session Management:
  sessions           - List active sessions
  sessions -i <id>   - Interact with a session
  sessions -k <id>   - Kill a session

Module Commands:
  search <keyword>   - Search for modules
  info <module>      - Show module information
  options            - Show current module options

Examples:
  use exploit/linux/ssh/weak_ssh
  set RHOST 192.168.1.10
  set PAYLOAD reverse_tcp
  run
  sessions
        """
        print(help_text)
    
    def do_use(self, module_path: str):
        """
        Load a module for use
        Usage: use <module_path>
        """
        if not module_path:
            print("[-] Error: Module path required")
            print("Usage: use <module_path>")
            print("Example: use exploit/linux/ssh/weak_ssh")
            return
        
        try:
            module = self.engine.get_module(module_path)
            if not module:
                print(f"[-] Module not found: {module_path}")
                return
            
            self.current_module = {
                'path': module_path,
                'module': module,
                'name': getattr(module, 'NAME', module_path),
                'description': getattr(module, 'DESCRIPTION', 'No description available'),
                'author': getattr(module, 'AUTHOR', 'Unknown')
            }
            self.module_options = {}
            
            print(f"[+] Using module: {self.current_module['name']}")
            print(f"[*] Description: {self.current_module['description']}")
            print(f"[*] Author: {self.current_module['author']}")
            
        except Exception as e:
            print(f"[-] Failed to load module: {e}")
    
    def do_set(self, args: str):
        """
        Set module options
        Usage: set <option> <value>
        """
        if not self.current_module:
            print("[-] No module selected. Use 'use <module>' first.")
            return
        
        parts = shlex.split(args)
        if len(parts) < 2:
            print("[-] Error: Option and value required")
            print("Usage: set <option> <value>")
            return
        
        option = parts[0]
        value = ' '.join(parts[1:])
        
        # Store the option
        self.module_options[option] = value
        
        print(f"[+] Set {option} = {value}")
        
        # If it's a common payload option, also set it on the module
        if hasattr(self.current_module['module'], 'set_option'):
            try:
                self.current_module['module'].set_option(option, value)
            except Exception as e:
                print(f"[*] Note: Could not set option on module: {e}")
    
    def do_show(self, args: str):
        """
        Show module information or options
        Usage: show [options|info]
        """
        if not self.current_module:
            print("[-] No module selected. Use 'use <module>' first.")
            return
        
        module = self.current_module['module']
        
        if args == 'options' or not args:
            # Show module options
            self._show_module_options(module)
        elif args == 'info':
            # Show detailed module information
            self._show_module_info(module)
        else:
            print(f"[-] Unknown show option: {args}")
            print("Usage: show [options|info]")
    
    def _show_module_options(self, module):
        """Show module options"""
        print(f"\nModule Options for {self.current_module['name']}:\n")
        print(f"{'Name':<15} {'Current Setting':<20} {'Required':<10} {'Description':<30}")
        print("-" * 80)
        
        # Common options that modules might have
        common_options = [
            ('RHOST', 'Remote host', 'yes'),
            ('RPORT', 'Remote port', 'yes'),
            ('LHOST', 'Local host', 'yes'),
            ('LPORT', 'Local port', 'yes'),
            ('PAYLOAD', 'Payload to use', 'yes'),
            ('TIMEOUT', 'Timeout in seconds', 'no'),
        ]
        
        for option_name, description, required in common_options:
            current = self.module_options.get(option_name, '')
            print(f"{option_name:<15} {current:<20} {required:<10} {description:<30}")
        
        # Show any additional options from the module
        if hasattr(module, 'get_options'):
            try:
                additional_options = module.get_options()
                for option_name, option_info in additional_options.items():
                    current = self.module_options.get(option_name, '')
                    required = option_info.get('required', 'no')
                    description = option_info.get('description', '')
                    print(f"{option_name:<15} {current:<20} {required:<10} {description:<30}")
            except Exception as e:
                print(f"[*] Could not retrieve additional options: {e}")
        
        print()
    
    def _show_module_info(self, module):
        """Show detailed module information"""
        print(f"\nModule Information:\n")
        print(f"Name: {getattr(module, 'NAME', 'Unknown')}")
        print(f"Description: {getattr(module, 'DESCRIPTION', 'No description available')}")
        print(f"Author: {getattr(module, 'AUTHOR', 'Unknown')}")
        print(f"Type: {getattr(module, 'MODULE_TYPE', 'Unknown')}")
        print()
    
    def do_run(self, args: str):
        """
        Execute the current module
        Usage: run
        """
        if not self.current_module:
            print("[-] No module selected. Use 'use <module>' first.")
            return
        
        try:
            print(f"[*] Executing module: {self.current_module['name']}")
            
            # Execute the module with current options
            result = self.engine.execute_module(
                self.current_module['path'], 
                self.module_options
            )
            
            if result:
                print(f"[+] Module execution completed")
                print(f"Result: {result}")
            else:
                print(f"[*] Module executed (no result returned)")
                
        except Exception as e:
            print(f"[-] Module execution failed: {e}")
            import traceback
            traceback.print_exc()
    
    def do_back(self, args: str):
        """
        Go back to main prompt
        Usage: back
        """
        self.current_module = None
        self.module_options = {}
        print("[*] Returning to main prompt")
    
    def do_sessions(self, args: str):
        """
        Manage sessions
        Usage: sessions [-i <id> | -k <id> | -l]
        """
        try:
            if args.startswith('-i '):
                # Interact with session
                session_id = args[3:].strip()
                self._interact_with_session(session_id)
            elif args.startswith('-k '):
                # Kill session
                session_id = args[3:].strip()
                self.engine.remove_session(session_id)
                print(f"[+] Session {session_id} killed")
            elif args == '-l' or args == '--list':
                # List sessions
                self._list_sessions()
            elif not args:
                # List sessions (default)
                self._list_sessions()
            else:
                print("[-] Invalid sessions command")
                print("Usage: sessions [-i <id> | -k <id> | -l]")
        except Exception as e:
            print(f"[-] Failed to manage sessions: {e}")
    
    def _list_sessions(self):
        """List all active sessions"""
        sessions = self.engine.list_sessions()
        
        if not sessions:
            print("[*] No active sessions")
            return
        
        print(f"\nActive Sessions:\n")
        print(f"{'ID':<5} {'Type':<12} {'Host':<20} {'Status':<12} {'Created':<20}")
        print("-" * 80)
        
        for session in sessions:
            session_id = session.get('id', 'unknown')
            session_type = session.get('type', 'unknown')
            host = session.get('host', 'unknown')
            status = session.get('status', 'active')
            created = session.get('created', 'unknown')
            
            print(f"{session_id:<5} {session_type:<12} {host:<20} {status:<12} {created:<20}")
        
        print()
    
    def _interact_with_session(self, session_id: str):
        """Interact with a specific session"""
        session = self.engine.get_session(session_id)
        
        if not session:
            print(f"[-] Session not found: {session_id}")
            return
        
        print(f"[*] Interacting with session {session_id}")
        print(f"[*] Type: {session.session_type}")
        print(f"[*] Host: {session.host}")
        print(f"[*] Status: {session.status}")
        
        # For now, just show session info
        # In a real implementation, this would provide interactive shell
        print(f"[*] Session interaction would be implemented here")
        print(f"[*] Use 'back' to return to main prompt")
    
    def do_search(self, keyword: str):
        """
        Search for modules
        Usage: search <keyword>
        """
        if not keyword:
            print("[-] Error: Search keyword required")
            print("Usage: search <keyword>")
            return
        
        print(f"[*] Searching for modules containing '{keyword}'...")
        
        found_modules = []
        all_modules = self.engine.modules
        
        for module_path, module in all_modules.items():
            # Search in module name, description, and path
            module_name = getattr(module, 'NAME', module_path)
            module_desc = getattr(module, 'DESCRIPTION', '')
            
            if (keyword.lower() in module_name.lower() or 
                keyword.lower() in module_desc.lower() or 
                keyword.lower() in module_path.lower()):
                found_modules.append((module_path, module_name, module_desc))
        
        if found_modules:
            print(f"\nFound {len(found_modules)} module(s):\n")
            for path, name, desc in found_modules:
                print(f"  {path}")
                print(f"    Name: {name}")
                print(f"    Description: {desc}")
                print()
        else:
            print(f"[*] No modules found containing '{keyword}'")
    
    def do_info(self, module_path: str):
        """
        Show module information
        Usage: info <module_path>
        """
        if not module_path:
            if self.current_module:
                self.do_show('info')
            else:
                print("[-] No module selected. Use 'use <module>' first.")
            return
        
        module = self.engine.get_module(module_path)
        if not module:
            print(f"[-] Module not found: {module_path}")
            return
        
        # Temporarily set as current module to use show command
        old_module = self.current_module
        self.current_module = {
            'path': module_path,
            'module': module,
            'name': getattr(module, 'NAME', module_path),
            'description': getattr(module, 'DESCRIPTION', 'No description available'),
            'author': getattr(module, 'AUTHOR', 'Unknown')
        }
        
        self.do_show('info')
        
        # Restore previous module
        self.current_module = old_module
    
    def do_options(self, args: str):
        """
        Show current module options
        Usage: options
        """
        self.do_show('options')
    
    def do_exit(self, args: str):
        """
        Exit the framework
        Usage: exit
        """
        return True
    
    def do_quit(self, args: str):
        """
        Exit the framework
        Usage: quit
        """
        return True
    
    def emptyline(self):
        """Do nothing on empty line"""
        pass
    
    def do_EOF(self, args: str):
        """Handle Ctrl+D"""
        print("\n[*] Exiting...")
        return True
    
    # Tab completion methods
    
    def complete_use(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        """Complete module paths for 'use' command"""
        all_modules = self.engine.modules.keys()
        
        if not text:
            return list(all_modules)
        
        return [m for m in all_modules if m.startswith(text)]
    
    def complete_set(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        """Complete option names for 'set' command"""
        if not self.current_module:
            return []
        
        # Common options
        common_options = ['RHOST', 'RPORT', 'LHOST', 'LPORT', 'PAYLOAD', 'TIMEOUT']
        
        if not text:
            return common_options
        
        return [opt for opt in common_options if opt.startswith(text)]
    
    def complete_sessions(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        """Complete session IDs for 'sessions' command"""
        if text.startswith('-'):
            flags = ['-i', '-k', '-l']
            return [f for f in flags if f.startswith(text)]
        
        # Complete session IDs
        sessions = self.engine.list_sessions()
        session_ids = [s.get('id', '') for s in sessions]
        
        if not text:
            return session_ids
        
        return [sid for sid in session_ids if sid.startswith(text)]
    
    def complete_info(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        """Complete module paths for 'info' command"""
        return self.complete_use(text, line, begidx, endidx)
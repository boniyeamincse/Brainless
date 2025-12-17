"""
Brainless Framework - Core Engine
=================================

The main engine that powers the Brainless Framework. It manages the overall
state, coordinates between different components, and provides the central
API for the framework's functionality.

Author: Brainless Security Team
"""

import os
import sys
import configparser
import importlib.util
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

from core.logger import setup_logger, LoggerMixin
from core.loader import ModuleLoader
from core.session import SessionManager
from core.cli import BrainlessCLI


class BrainlessEngine(LoggerMixin):
    """
    Core engine for the Brainless Framework
    
    Manages:
    - Configuration loading
    - Module loading and management
    - Session management
    - Framework state
    """
    
    def __init__(self, config_path: str = 'config/brainless.conf'):
        """
        Initialize the Brainless Framework engine
        
        Args:
            config_path (str): Path to configuration file
        """
        super().__init__('BrainlessEngine')
        
        self.config_path = config_path
        self.config = None
        self.modules = {}
        self.active_session = None
        self.module_loader = None
        self.session_manager = None
        
        # Framework metadata
        self.version = "0.1"
        self.author = "Brainless Security Team"
        self.framework_name = "Brainless Framework"
        
        # Initialize the engine
        self._load_configuration()
        self._setup_logging()
        self._initialize_components()
        
        self.info(f"{self.framework_name} v{self.version} initialized")
    
    def _load_configuration(self):
        """Load configuration from file"""
        try:
            self.debug(f"Loading configuration from: {self.config_path}")
            
            if not os.path.exists(self.config_path):
                self.warning(f"Configuration file not found: {self.config_path}")
                self.warning("Using default configuration")
                self._create_default_config()
            
            self.config = configparser.ConfigParser()
            self.config.read(self.config_path)
            
            self.debug("Configuration loaded successfully")
            
        except Exception as e:
            self.error(f"Failed to load configuration: {e}")
            raise
    
    def _create_default_config(self):
        """Create a default configuration file"""
        default_config = """[framework]
version = 0.1
author = Brainless Security Team
description = Modular penetration testing framework for Debian-based Linux distributions

[cli]
prompt = "brainless > "
prompt_color = "cyan"
banner = true
history_file = ".brainless_history"
max_history = 1000

[modules]
modules_directory = "modules"
exploits_directory = "modules/exploits"
payloads_directory = "modules/payloads"
auxiliary_directory = "modules/auxiliary"
post_directory = "modules/post"
auto_load = true
validate_metadata = true

[payloads]
default_payload = "reverse_tcp"
max_payload_size = 1048576
encoder_enabled = true
stager_timeout = 30

[handlers]
default_handler = "reverse_tcp"
max_concurrent_sessions = 50
session_timeout = 3600
auto_session_cleanup = true

[database]
enabled = false
type = "sqlite"
name = "brainless.db"
auto_connect = false

[logging]
level = "INFO"
file = "logs/brainless.log"
max_file_size = 10485760
backup_count = 5
format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
console_output = true

[security]
require_root = false
sandbox_modules = true
validate_dependencies = true
allowed_networks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]
restrict_external_calls = true

[plugins]
plugins_directory = "plugins"
auto_load = true
max_plugins = 10

[updates]
check_updates = true
update_channel = "stable"
last_update_check = ""
auto_update = false
"""
        
        # Ensure config directory exists
        config_dir = Path(self.config_path).parent
        config_dir.mkdir(parents=True, exist_ok=True)
        
        # Write default config
        with open(self.config_path, 'w') as f:
            f.write(default_config)
        
        self.info(f"Created default configuration file: {self.config_path}")
    
    def _setup_logging(self):
        """Set up the logging system"""
        try:
            log_level = self.config.get('logging', 'level', fallback='INFO')
            log_file = self.config.get('logging', 'file', fallback='logs/brainless.log')
            console_output = self.config.getboolean('logging', 'console_output', fallback=True)
            
            # Set up the main logger
            self.logger = setup_logger(
                name='brainless',
                log_file=log_file,
                log_level=log_level,
                console_output=console_output
            )
            
            self.debug("Logging system initialized")
            
        except Exception as e:
            print(f"[-] Failed to setup logging: {e}")
            # Fallback to basic logging
            self.logger = setup_logger('brainless', log_level='INFO')
    
    def _initialize_components(self):
        """Initialize framework components"""
        try:
            # Initialize module loader
            modules_dir = self.config.get('modules', 'modules_directory', fallback='modules')
            self.module_loader = ModuleLoader(modules_dir, self.config)
            self.debug("Module loader initialized")
            
            # Initialize session manager
            self.session_manager = SessionManager(self.config)
            self.debug("Session manager initialized")
            
            # Auto-load modules if enabled
            if self.config.getboolean('modules', 'auto_load', fallback=True):
                self.load_all_modules()
                self.info(f"Loaded {len(self.modules)} modules")
            
        except Exception as e:
            self.error(f"Failed to initialize components: {e}")
            raise
    
    def show_banner(self):
        """Display the framework banner"""
        banner = f"""
╔══════════════════════════════════════════════════════════════╗
║                    {self.framework_name} v{self.version}                    ║
║                                                              ║
║  Modular penetration testing framework for Debian-based      ║
║  Linux distributions                                         ║
║                                                              ║
║  Author: {self.author:<46}║
║                                                              ║
║  ⚠️  For authorized security testing only                     ║
╚══════════════════════════════════════════════════════════════╝
        """
        
        print(banner)
        
        # Show framework info
        print(f"[*] Configuration: {self.config_path}")
        print(f"[*] Modules loaded: {len(self.modules)}")
        print(f"[*] Sessions: {self.session_manager.get_session_count()}")
        print(f"[*] Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print()
    
    def load_all_modules(self):
        """Load all available modules"""
        try:
            self.modules = self.module_loader.load_all_modules()
            return len(self.modules)
        except Exception as e:
            self.error(f"Failed to load modules: {e}")
            return 0
    
    def get_module(self, module_path: str):
        """
        Get a specific module by path
        
        Args:
            module_path (str): Module path (e.g., 'exploits/linux/ssh/weak_ssh')
        
        Returns:
            Module instance or None if not found
        """
        return self.modules.get(module_path)
    
    def get_modules_by_type(self, module_type: str) -> Dict[str, Any]:
        """
        Get all modules of a specific type
        
        Args:
            module_type (str): Type of modules (exploits, payloads, auxiliary, post)
        
        Returns:
            Dictionary of modules
        """
        filtered_modules = {}
        for path, module in self.modules.items():
            if path.startswith(f"{module_type}/"):
                filtered_modules[path] = module
        return filtered_modules
    
    def create_session(self, session_type: str = "shell", **kwargs):
        """
        Create a new session
        
        Args:
            session_type (str): Type of session (shell, meterpreter, etc.)
            **kwargs: Additional session parameters
        
        Returns:
            Session ID or None if creation failed
        """
        try:
            session_id = self.session_manager.create_session(session_type, **kwargs)
            self.info(f"Created session {session_id}")
            return session_id
        except Exception as e:
            self.error(f"Failed to create session: {e}")
            return None
    
    def get_session(self, session_id: str):
        """
        Get a session by ID
        
        Args:
            session_id (str): Session identifier
        
        Returns:
            Session object or None if not found
        """
        return self.session_manager.get_session(session_id)
    
    def list_sessions(self) -> List[Dict]:
        """List all active sessions"""
        return self.session_manager.list_sessions()
    
    def remove_session(self, session_id: str):
        """Remove a session"""
        try:
            self.session_manager.remove_session(session_id)
            self.info(f"Removed session {session_id}")
        except Exception as e:
            self.error(f"Failed to remove session {session_id}: {e}")
    
    def execute_module(self, module_path: str, options: Dict[str, Any]):
        """
        Execute a module with given options
        
        Args:
            module_path (str): Path to the module
            options (dict): Module options
        
        Returns:
            Execution result
        """
        try:
            module = self.get_module(module_path)
            if not module:
                raise ValueError(f"Module not found: {module_path}")
            
            # Set module options
            for key, value in options.items():
                if hasattr(module, 'set_option'):
                    module.set_option(key, value)
            
            # Execute the module
            result = module.run()
            return result
            
        except Exception as e:
            self.error(f"Failed to execute module {module_path}: {e}")
            raise
    
    def get_framework_info(self) -> Dict[str, Any]:
        """Get framework information"""
        return {
            'name': self.framework_name,
            'version': self.version,
            'author': self.author,
            'modules_loaded': len(self.modules),
            'active_sessions': self.session_manager.get_session_count(),
            'config_path': self.config_path
        }
    
    def shutdown(self):
        """Shutdown the framework gracefully"""
        self.info("Shutting down Brainless Framework...")
        
        # Clean up sessions
        if self.session_manager:
            self.session_manager.cleanup()
        
        self.info("Brainless Framework shutdown complete")
"""
Brainless Framework - Module Loader
===================================

Dynamically loads Python modules for the Brainless Framework,
validates module metadata, and manages module execution context.

Author: Brainless Security Team
"""

import os
import sys
import importlib.util
import inspect
from pathlib import Path
from typing import Dict, List, Any, Optional, Type
import traceback

from core.logger import LoggerMixin


class ModuleLoader(LoggerMixin):
    """
    Handles dynamic loading and management of Brainless Framework modules
    
    Supports module types:
    - exploits
    - payloads
    - auxiliary
    - post
    """
    
    def __init__(self, modules_directory: str, config=None):
        """
        Initialize the module loader
        
        Args:
            modules_directory (str): Path to the modules directory
            config: Framework configuration
        """
        super().__init__('ModuleLoader')
        
        self.modules_directory = Path(modules_directory)
        self.config = config
        self.modules = {}
        self.module_types = ['exploits', 'payloads', 'auxiliary', 'post']
        
        # Ensure modules directory exists
        if not self.modules_directory.exists():
            self.modules_directory.mkdir(parents=True, exist_ok=True)
            self.warning(f"Created modules directory: {self.modules_directory}")
    
    def load_all_modules(self) -> Dict[str, Any]:
        """
        Load all modules from the modules directory
        
        Returns:
            Dictionary of loaded modules with path as key
        """
        self.modules = {}
        
        for module_type in self.module_types:
            module_dir = self.modules_directory / module_type
            
            if not module_dir.exists():
                self.debug(f"Module directory does not exist: {module_dir}")
                continue
            
            self.debug(f"Loading {module_type} modules from {module_dir}")
            
            # Recursively load modules
            loaded_count = self._load_modules_recursive(module_dir, module_type)
            self.info(f"Loaded {loaded_count} {module_type} modules")
        
        return self.modules
    
    def _load_modules_recursive(self, directory: Path, module_type: str, prefix: str = "") -> int:
        """
        Recursively load modules from a directory
        
        Args:
            directory (Path): Directory to scan
            module_type (str): Type of modules being loaded
            prefix (str): Prefix for module path
        
        Returns:
            Number of modules loaded
        """
        loaded_count = 0
        
        try:
            # Iterate through all files and directories
            for item in directory.iterdir():
                if item.name.startswith('.') or item.name.startswith('__'):
                    continue
                
                if item.is_dir():
                    # Recursively load subdirectories
                    sub_prefix = f"{prefix}{item.name}/" if prefix else f"{item.name}/"
                    loaded_count += self._load_modules_recursive(item, module_type, sub_prefix)
                
                elif item.suffix == '.py':
                    # Load Python module
                    module_path = f"{module_type}/{prefix}{item.stem}"
                    if self._load_module(item, module_path):
                        loaded_count += 1
        
        except Exception as e:
            self.error(f"Error loading modules from {directory}: {e}")
        
        return loaded_count
    
    def _load_module(self, file_path: Path, module_path: str) -> bool:
        """
        Load a single module file
        
        Args:
            file_path (Path): Path to the Python file
            module_path (str): Module path for identification
        
        Returns:
            True if module loaded successfully, False otherwise
        """
        try:
            # Generate module name from path
            module_name = module_path.replace('/', '_').replace('-', '_')
            
            # Load the module spec
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            if spec is None:
                self.warning(f"Could not load spec for {file_path}")
                return False
            
            # Create and load the module
            module = importlib.util.module_from_spec(spec)
            
            # Add to sys.modules to handle imports
            sys.modules[module_name] = module
            
            # Execute the module
            spec.loader.exec_module(module)
            
            # Validate module metadata
            if self._validate_module(module, module_path):
                self.modules[module_path] = module
                self.debug(f"Loaded module: {module_path}")
                return True
            else:
                self.warning(f"Module validation failed: {module_path}")
                return False
                
        except Exception as e:
            self.error(f"Failed to load module {module_path}: {e}")
            if self.config and self.config.get('logging', {}).get('level') == 'DEBUG':
                self.debug(traceback.format_exc())
            return False
    
    def _validate_module(self, module, module_path: str) -> bool:
        """
        Validate that a module has the required attributes
        
        Args:
            module: Loaded module object
            module_path (str): Module path for logging
        
        Returns:
            True if module is valid, False otherwise
        """
        try:
            # Check for required attributes
            required_attrs = ['NAME', 'DESCRIPTION', 'AUTHOR', 'run']
            
            for attr in required_attrs:
                if not hasattr(module, attr):
                    self.warning(f"Module {module_path} missing required attribute: {attr}")
                    return False
            
            # Check that run is callable
            if not callable(getattr(module, 'run')):
                self.warning(f"Module {module_path} run attribute is not callable")
                return False
            
            # Validate NAME is a string
            if not isinstance(getattr(module, 'NAME'), str):
                self.warning(f"Module {module_path} NAME attribute must be a string")
                return False
            
            # Validate DESCRIPTION is a string
            if not isinstance(getattr(module, 'DESCRIPTION'), str):
                self.warning(f"Module {module_path} DESCRIPTION attribute must be a string")
                return False
            
            # Validate AUTHOR is a string
            if not isinstance(getattr(module, 'AUTHOR'), str):
                self.warning(f"Module {module_path} AUTHOR attribute must be a string")
                return False
            
            return True
            
        except Exception as e:
            self.error(f"Error validating module {module_path}: {e}")
            return False
    
    def get_module(self, module_path: str):
        """
        Get a loaded module by path
        
        Args:
            module_path (str): Module path
        
        Returns:
            Module object or None if not found
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
    
    def reload_module(self, module_path: str) -> bool:
        """
        Reload a specific module
        
        Args:
            module_path (str): Module path to reload
        
        Returns:
            True if reload successful, False otherwise
        """
        try:
            # Find the module file
            module_obj = self.modules.get(module_path)
            if not module_obj:
                self.warning(f"Module not found for reload: {module_path}")
                return False
            
            # Get the file path from the module
            if not hasattr(module_obj, '__file__'):
                self.warning(f"Cannot reload module without __file__: {module_path}")
                return False
            
            file_path = Path(module_obj.__file__)
            
            # Remove from loaded modules
            if module_path in self.modules:
                del self.modules[module_path]
            
            # Reload the module
            return self._load_module(file_path, module_path)
            
        except Exception as e:
            self.error(f"Failed to reload module {module_path}: {e}")
            return False
    
    def reload_all_modules(self) -> int:
        """
        Reload all loaded modules
        
        Returns:
            Number of modules successfully reloaded
        """
        reloaded_count = 0
        module_paths = list(self.modules.keys())
        
        for module_path in module_paths:
            if self.reload_module(module_path):
                reloaded_count += 1
        
        self.info(f"Reloaded {reloaded_count}/{len(module_paths)} modules")
        return reloaded_count
    
    def get_module_info(self, module_path: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a specific module
        
        Args:
            module_path (str): Module path
        
        Returns:
            Dictionary with module information or None if not found
        """
        module = self.get_module(module_path)
        if not module:
            return None
        
        info = {
            'path': module_path,
            'name': getattr(module, 'NAME', 'Unknown'),
            'description': getattr(module, 'DESCRIPTION', 'No description available'),
            'author': getattr(module, 'AUTHOR', 'Unknown'),
            'module_type': self._get_module_type(module_path),
            'has_run': hasattr(module, 'run') and callable(getattr(module, 'run'))
        }
        
        # Get additional metadata if available
        if hasattr(module, 'VERSION'):
            info['version'] = getattr(module, 'VERSION')
        
        if hasattr(module, 'RANK'):
            info['rank'] = getattr(module, 'RANK')
        
        # Get function signatures if available
        if hasattr(module, 'run'):
            try:
                sig = inspect.signature(module.run)
                info['run_signature'] = str(sig)
            except:
                info['run_signature'] = 'Unknown'
        
        return info
    
    def _get_module_type(self, module_path: str) -> str:
        """
        Get the type of a module from its path
        
        Args:
            module_path (str): Module path
        
        Returns:
            Module type (exploits, payloads, auxiliary, post)
        """
        for module_type in self.module_types:
            if module_path.startswith(f"{module_type}/"):
                return module_type
        return 'unknown'
    
    def search_modules(self, keyword: str, module_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Search for modules containing a keyword
        
        Args:
            keyword (str): Search keyword
            module_type (str, optional): Limit search to specific module type
        
        Returns:
            List of matching module information
        """
        results = []
        keyword_lower = keyword.lower()
        
        for module_path, module in self.modules.items():
            # Filter by module type if specified
            if module_type and not module_path.startswith(f"{module_type}/"):
                continue
            
            # Check module name, description, and path
            module_name = getattr(module, 'NAME', module_path).lower()
            module_desc = getattr(module, 'DESCRIPTION', '').lower()
            
            if (keyword_lower in module_name or 
                keyword_lower in module_desc or 
                keyword_lower in module_path.lower()):
                
                info = self.get_module_info(module_path)
                if info:
                    results.append(info)
        
        return results
    
    def get_module_count(self) -> int:
        """Get the total number of loaded modules"""
        return len(self.modules)
    
    def get_module_paths(self) -> List[str]:
        """Get all loaded module paths"""
        return list(self.modules.keys())
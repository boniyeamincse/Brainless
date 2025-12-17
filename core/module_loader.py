#!/usr/bin/env python3
"""
Module Loader for Brainless Framework
Handles loading and managing modules with metadata.
"""

import os
import importlib.util
import glob
from typing import Dict, List, Optional, Any
from core.utils import get_modules_path

class ModuleLoader:
    """Handles loading and managing framework modules."""
    
    def __init__(self):
        self.modules_path = get_modules_path()
        self._modules_cache = {}
        
    def get_all_modules(self) -> List[Dict[str, Any]]:
        """Get list of all available modules."""
        if not self._modules_cache:
            self._load_all_modules()
        return list(self._modules_cache.values())
    
    def load_module(self, module_name: str) -> Optional[Dict[str, Any]]:
        """Load a specific module by name."""
        if not self._modules_cache:
            self._load_all_modules()
            
        return self._modules_cache.get(module_name)
    
    def _load_all_modules(self) -> None:
        """Load all modules from the modules directory."""
        if not os.path.exists(self.modules_path):
            return
            
        # Find all Python files in modules directory (recursive)
        pattern = os.path.join(self.modules_path, "**", "*.py")
        module_files = glob.glob(pattern, recursive=True)
        
        for module_file in module_files:
            # Skip __init__.py files
            if os.path.basename(module_file) == "__init__.py":
                continue
                
            module_data = self._parse_module_file(module_file)
            if module_data:
                self._modules_cache[module_data['name']] = module_data
    
    def _parse_module_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Parse a module file and extract metadata."""
        try:
            # Create module spec
            spec = importlib.util.spec_from_file_location("temp_module", file_path)
            if not spec or not spec.loader:
                return None
                
            # Load module
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Extract metadata
            metadata = self._extract_metadata(module)
            if not metadata:
                return None
                
            # Add file path information
            metadata['file_path'] = file_path
            metadata['relative_path'] = os.path.relpath(file_path, self.modules_path)
            
            return metadata
            
        except Exception as e:
            # Silently skip modules that can't be loaded
            return None
    
    def _extract_metadata(self, module) -> Optional[Dict[str, Any]]:
        """Extract metadata from a loaded module."""
        # Check if module has required metadata
        if not hasattr(module, 'MODULE_METADATA'):
            return None
            
        metadata = module.MODULE_METADATA
        
        # Validate required fields
        required_fields = ['name', 'description']
        for field in required_fields:
            if field not in metadata:
                return None
                
        # Set defaults for optional fields
        metadata.setdefault('tags', [])
        metadata.setdefault('author', 'Unknown')
        metadata.setdefault('version', '1.0')
        metadata.setdefault('options', {})
        
        # Ensure tags is a list
        if isinstance(metadata['tags'], str):
            metadata['tags'] = [metadata['tags']]
        elif not isinstance(metadata['tags'], list):
            metadata['tags'] = []
            
        # Ensure options is a dict
        if not isinstance(metadata['options'], dict):
            metadata['options'] = {}
            
        return metadata
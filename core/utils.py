#!/usr/bin/env python3
"""
Utility functions for Brainless Framework
Shared utilities used across the framework.
"""

import os
from typing import Optional

def get_modules_path() -> str:
    """Get the path to the modules directory."""
    # Get the path to the core directory
    core_path = os.path.dirname(os.path.abspath(__file__))
    # Go up one level and then into modules
    return os.path.join(core_path, "..", "modules")

def get_data_path() -> str:
    """Get the path to the data directory."""
    core_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(core_path, "..", "data")

def get_version() -> str:
    """Get the framework version."""
    # Try to read from a version file
    version_path = os.path.join(get_data_path(), "version.txt")
    if os.path.exists(version_path):
        try:
            with open(version_path, 'r') as f:
                return f.read().strip()
        except:
            pass
    
    # Fallback version
    return "0.1"

def safe_import(module_path: str, module_name: str):
    """
    Safely import a module from a file path.
    
    Args:
        module_path: Path to the module file
        module_name: Name for the module
        
    Returns:
        The imported module or None if import failed
    """
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
    except Exception:
        pass
    return None

def format_table(data: list, headers: Optional[list] = None) -> str:
    """
    Format data as a simple table.
    
    Args:
        data: List of lists or tuples containing row data
        headers: Optional list of column headers
        
    Returns:
        Formatted table as string
    """
    if not data:
        return ""
        
    # Use headers if provided, otherwise use first row as headers
    if headers:
        all_data = [headers] + data
    else:
        all_data = data
        
    # Calculate column widths
    col_widths = []
    for col_idx in range(len(all_data[0])):
        max_width = 0
        for row in all_data:
            if col_idx < len(row):
                max_width = max(max_width, len(str(row[col_idx])))
        col_widths.append(max_width)
    
    # Build table
    result = []
    for row_idx, row in enumerate(all_data):
        row_str = "  ".join(str(cell).ljust(col_widths[i]) 
                          for i, cell in enumerate(row))
        result.append(row_str)
        
        # Add separator after headers
        if headers and row_idx == 0:
            separator = "  ".join("-" * width for width in col_widths)
            result.append(separator)
    
    return "\n".join(result)
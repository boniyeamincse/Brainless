#!/usr/bin/env python3
"""
Search functionality for Brainless Framework
Provides module search capabilities.
"""

import re
from typing import List, Dict, Any
from core.module_loader import ModuleLoader

def search_modules(keyword: str, module_loader: ModuleLoader) -> List[Dict[str, Any]]:
    """
    Search modules by keyword in name, description, or tags.
    
    Args:
        keyword: Search term (case-insensitive)
        module_loader: ModuleLoader instance
        
    Returns:
        List of matching modules
    """
    if not keyword or not keyword.strip():
        return []
        
    keyword_lower = keyword.lower().strip()
    results = []
    
    all_modules = module_loader.get_all_modules()
    
    for module in all_modules:
        # Search in name
        if keyword_lower in module['name'].lower():
            results.append(module)
            continue
            
        # Search in description
        if keyword_lower in module['description'].lower():
            results.append(module)
            continue
            
        # Search in tags
        tags = module.get('tags', [])
        if isinstance(tags, list):
            for tag in tags:
                if keyword_lower in str(tag).lower():
                    results.append(module)
                    break
        
        # Search in module type
        module_type = module.get('module_type', '')
        if keyword_lower in module_type.lower():
            results.append(module)
            continue
    
    return results

def fuzzy_search_modules(keyword: str, module_loader: ModuleLoader) -> List[Dict[str, Any]]:
    """
    Perform fuzzy search on modules (basic implementation).
    
    Args:
        keyword: Search term
        module_loader: ModuleLoader instance
        
    Returns:
        List of matching modules sorted by relevance
    """
    if not keyword or not keyword.strip():
        return []
        
    keyword_lower = keyword.lower().strip()
    results_with_score = []
    
    all_modules = module_loader.get_all_modules()
    
    for module in all_modules:
        score = 0
        
        # Exact match bonus
        if keyword_lower == module['name'].lower():
            score += 100
        elif keyword_lower in module['name'].lower():
            score += 50
            
        # Description match
        if keyword_lower in module['description'].lower():
            score += 10
            
        # Tag matches
        tags = module.get('tags', [])
        if isinstance(tags, list):
            for tag in tags:
                if keyword_lower == str(tag).lower():
                    score += 20
                elif keyword_lower in str(tag).lower():
                    score += 5
        
        if score > 0:
            results_with_score.append((module, score))
    
    # Sort by score and return modules
    results_with_score.sort(key=lambda x: x[1], reverse=True)
    return [module for module, score in results_with_score]
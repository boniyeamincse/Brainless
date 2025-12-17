"""
Brainless Framework - Logging System
====================================

Centralized logging system for the Brainless Framework with support for
file logging, console output, and configurable log levels.

Author: Brainless Security Team
"""

import logging
import logging.handlers
import os
import sys
from pathlib import Path
from datetime import datetime


class BrainlessFormatter(logging.Formatter):
    """Custom formatter for Brainless Framework logs"""
    
    # Color codes for console output
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
        'RESET': '\033[0m'      # Reset
    }
    
    def __init__(self, use_colors=True):
        self.use_colors = use_colors
        super().__init__()
    
    def format(self, record):
        # Add timestamp
        timestamp = datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S')
        
        # Format the message
        if self.use_colors and sys.stdout.isatty():
            color = self.COLORS.get(record.levelname, '')
            reset = self.COLORS['RESET']
            formatted = f"{color}[{timestamp}] {record.levelname:8s}{reset} - {record.getMessage()}"
        else:
            formatted = f"[{timestamp}] {record.levelname:8s} - {record.getMessage()}"
        
        # Add exception info if present
        if record.exc_info:
            formatted += '\n' + self.formatException(record.exc_info)
        
        return formatted


def setup_logger(name='brainless', log_file=None, log_level='INFO', console_output=True):
    """
    Set up and configure the logger for Brainless Framework
    
    Args:
        name (str): Logger name
        log_file (str): Path to log file (optional)
        log_level (str): Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        console_output (bool): Whether to output to console
    
    Returns:
        logging.Logger: Configured logger instance
    """
    
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Clear any existing handlers
    logger.handlers.clear()
    
    # Create formatter
    formatter = BrainlessFormatter(use_colors=console_output and sys.stdout.isatty())
    
    # Console handler
    if console_output:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    # File handler
    if log_file:
        # Ensure log directory exists
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Create rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    # Prevent duplicate logs in case of multiple setups
    logger.propagate = False
    
    return logger


class LoggerMixin:
    """Mixin class to provide logging functionality to other classes"""
    
    def __init__(self, logger_name=None):
        """
        Initialize the mixin with a logger
        
        Args:
            logger_name (str): Name for the logger (defaults to class name)
        """
        if logger_name is None:
            logger_name = self.__class__.__name__
        
        self.logger = logging.getLogger(logger_name)
    
    def debug(self, message):
        """Log debug message"""
        self.logger.debug(message)
    
    def info(self, message):
        """Log info message"""
        self.logger.info(message)
    
    def warning(self, message):
        """Log warning message"""
        self.logger.warning(message)
    
    def error(self, message):
        """Log error message"""
        self.logger.error(message)
    
    def critical(self, message):
        """Log critical message"""
        self.logger.critical(message)
    
    def exception(self, message):
        """Log exception with traceback"""
        self.logger.exception(message)


def get_logger(name=None):
    """
    Get a logger instance
    
    Args:
        name (str): Logger name
    
    Returns:
        logging.Logger: Logger instance
    """
    if name is None:
        name = 'brainless'
    return logging.getLogger(name)
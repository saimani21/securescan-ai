"""Enhanced logging with structured output and performance tracking."""

import logging
import sys
import time
from pathlib import Path
from typing import Optional
from datetime import datetime
from logging.handlers import RotatingFileHandler


# ANSI color codes
class Colors:
    RESET = "\033[0m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"


class ColoredFormatter(logging.Formatter):
    """Formatter with color support."""
    
    COLORS = {
        "DEBUG": Colors.GRAY,
        "INFO": Colors.BLUE,
        "WARNING": Colors.YELLOW,
        "ERROR": Colors.RED,
        "CRITICAL": Colors.RED,
    }
    
    def format(self, record):
        """Format log record with colors."""
        if sys.stdout.isatty():  # Only colorize for terminals
            levelname = record.levelname
            if levelname in self.COLORS:
                record.levelname = f"{self.COLORS[levelname]}{levelname}{Colors.RESET}"
        
        return super().format(record)


class PerformanceLogger:
    """Track operation performance."""
    
    def __init__(self, logger: logging.Logger, operation: str):
        """Initialize performance logger."""
        self.logger = logger
        self.operation = operation
        self.start_time = None
    
    def __enter__(self):
        """Start timing."""
        self.start_time = time.time()
        self.logger.debug(f"Started: {self.operation}")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """End timing and log."""
        duration = time.time() - self.start_time
        
        if exc_type is None:
            self.logger.info(f"Completed: {self.operation} ({duration:.2f}s)")
        else:
            self.logger.error(f"Failed: {self.operation} ({duration:.2f}s)")


def setup_logging(
    level: str = "INFO",
    log_file: Optional[Path] = None,
    verbose: bool = False
) -> None:
    """
    Setup application logging.
    
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional log file path
        verbose: Enable verbose logging
    """
    # Convert level
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    
    # Root logger
    root_logger = logging.getLogger("securescan")
    root_logger.setLevel(numeric_level)
    
    # Remove existing handlers
    root_logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)
    
    if verbose:
        console_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    else:
        console_format = "%(asctime)s - %(levelname)s - %(message)s"
    
    console_formatter = ColoredFormatter(
        console_format,
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)  # Always debug in file
        
        file_format = "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s"
        file_formatter = logging.Formatter(
            file_format,
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(file_formatter)
        root_logger.addHandler(file_handler)


def get_logger(name: str) -> logging.Logger:
    """Get logger for module."""
    return logging.getLogger(f"securescan.{name}")

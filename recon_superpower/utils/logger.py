"""
Logging infrastructure for Recon Superpower.
Provides centralized logging with file rotation and security event tracking.
"""

from __future__ import annotations

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

from recon_superpower.config.defaults import (
    CONFIG_DIR_NAME,
    LOG_FILE_NAME,
    LOG_FORMAT,
    LOG_DATE_FORMAT,
    LOG_MAX_BYTES,
    LOG_BACKUP_COUNT,
)

# Module-level logger cache
_loggers: dict[str, logging.Logger] = {}
_initialized: bool = False


class SecurityFilter(logging.Filter):
    """
    Filter that adds security context to log records.
    Marks security-related events for easy filtering and auditing.
    """

    SECURITY_KEYWORDS = (
        'injection', 'traversal', 'validation', 'blocked', 'denied',
        'unauthorized', 'malicious', 'attack', 'exploit', 'security'
    )

    def filter(self, record: logging.LogRecord) -> bool:
        """Add security flag to records containing security keywords."""
        message_lower = record.getMessage().lower()
        record.is_security_event = any(
            keyword in message_lower for keyword in self.SECURITY_KEYWORDS
        )
        return True


class ColoredFormatter(logging.Formatter):
    """
    Formatter that adds color codes for terminal output.
    Only applies colors when output is a TTY.
    """

    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m',       # Reset
    }

    def __init__(self, fmt: Optional[str] = None, datefmt: Optional[str] = None,
                 use_colors: bool = True) -> None:
        super().__init__(fmt, datefmt)
        self.use_colors = use_colors and sys.stderr.isatty()

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with optional color coding."""
        if self.use_colors:
            color = self.COLORS.get(record.levelname, '')
            reset = self.COLORS['RESET']
            record.levelname = f"{color}{record.levelname}{reset}"
        return super().format(record)


def get_log_file_path() -> Path:
    """Get the path to the log file."""
    log_dir = Path.home() / CONFIG_DIR_NAME
    log_dir.mkdir(exist_ok=True)
    return log_dir / LOG_FILE_NAME


def setup_logging(
    level: int = logging.INFO,
    log_to_file: bool = True,
    log_to_console: bool = True,
    console_level: Optional[int] = None
) -> None:
    """
    Set up the logging infrastructure.

    Args:
        level: Default logging level for file output
        log_to_file: Whether to log to file
        log_to_console: Whether to log to console
        console_level: Separate level for console (defaults to WARNING)
    """
    global _initialized

    if _initialized:
        return

    root_logger = logging.getLogger('recon_superpower')
    root_logger.setLevel(logging.DEBUG)  # Capture all, filter at handlers

    # Security filter for all handlers
    security_filter = SecurityFilter()

    # File handler with rotation
    if log_to_file:
        try:
            log_file = get_log_file_path()
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=LOG_MAX_BYTES,
                backupCount=LOG_BACKUP_COUNT,
                encoding='utf-8'
            )
            file_handler.setLevel(level)
            file_handler.setFormatter(logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT))
            file_handler.addFilter(security_filter)
            root_logger.addHandler(file_handler)
        except OSError as e:
            print(f"Warning: Could not set up file logging: {e}", file=sys.stderr)

    # Console handler
    if log_to_console:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(console_level or logging.WARNING)
        console_handler.setFormatter(ColoredFormatter(LOG_FORMAT, LOG_DATE_FORMAT))
        console_handler.addFilter(security_filter)
        root_logger.addHandler(console_handler)

    _initialized = True


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for the given module name.

    Args:
        name: Module name (typically __name__)

    Returns:
        Configured logger instance
    """
    # Ensure logging is set up
    if not _initialized:
        setup_logging()

    # Return cached logger if available
    if name in _loggers:
        return _loggers[name]

    # Create new logger under recon_superpower namespace
    if name.startswith('recon_superpower'):
        logger = logging.getLogger(name)
    else:
        logger = logging.getLogger(f'recon_superpower.{name}')

    _loggers[name] = logger
    return logger


class SecurityLogger:
    """
    Specialized logger for security-related events.
    Provides convenient methods for logging security events with context.
    """

    def __init__(self, module_name: str) -> None:
        """Initialize security logger for a module."""
        self._logger = get_logger(f"{module_name}.security")

    def validation_failed(self, field: str, value: str, reason: str) -> None:
        """Log a failed validation attempt."""
        # Truncate potentially long/malicious values
        safe_value = value[:50] + '...' if len(value) > 50 else value
        self._logger.warning(
            "SECURITY: Validation failed for %s='%s': %s",
            field, safe_value, reason
        )

    def injection_blocked(self, attack_type: str, payload: str) -> None:
        """Log a blocked injection attempt."""
        safe_payload = payload[:100] + '...' if len(payload) > 100 else payload
        self._logger.warning(
            "SECURITY: %s injection blocked: '%s'",
            attack_type, safe_payload
        )

    def path_traversal_blocked(self, path: str) -> None:
        """Log a blocked path traversal attempt."""
        self._logger.warning(
            "SECURITY: Path traversal blocked: '%s'", path
        )

    def resource_limit_exceeded(self, resource: str, limit: int, actual: int) -> None:
        """Log a resource limit violation."""
        self._logger.warning(
            "SECURITY: Resource limit exceeded for %s: limit=%d, actual=%d",
            resource, limit, actual
        )

    def unauthorized_access(self, resource: str, reason: str) -> None:
        """Log an unauthorized access attempt."""
        self._logger.error(
            "SECURITY: Unauthorized access to %s: %s",
            resource, reason
        )

    def scan_started(self, tool: str, target: str, user_confirmed: bool) -> None:
        """Log scan initiation."""
        self._logger.info(
            "AUDIT: Scan started - tool=%s, target=%s, confirmed=%s",
            tool, target[:50], user_confirmed
        )

    def scan_completed(self, tool: str, target: str, duration: float) -> None:
        """Log scan completion."""
        self._logger.info(
            "AUDIT: Scan completed - tool=%s, target=%s, duration=%.2fs",
            tool, target[:50], duration
        )


def get_security_logger(module_name: str) -> SecurityLogger:
    """Get a security logger for the given module."""
    return SecurityLogger(module_name)

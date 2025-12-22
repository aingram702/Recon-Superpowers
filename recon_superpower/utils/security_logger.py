"""
Security event logging module for Recon Superpower.

This module provides centralized security event logging for audit trails.
Logs security-relevant events such as validation failures, unauthorized
access attempts, and configuration changes.
"""

import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

# Configure security logger
security_logger = logging.getLogger("recon_superpower.security")
security_logger.setLevel(logging.INFO)


def setup_security_logging(log_dir: Optional[Path] = None) -> None:
    """
    Configure security event logging to file.
    
    Args:
        log_dir: Directory for security log files. Defaults to ~/.recon_superpower/
    """
    if log_dir is None:
        log_dir = Path.home() / ".recon_superpower"
    
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "security.log"
    
    # Create file handler with rotation
    handler = logging.FileHandler(log_file)
    handler.setLevel(logging.INFO)
    
    # Format: timestamp - level - event - details
    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    handler.setFormatter(formatter)
    
    # Add handler if not already present
    if not security_logger.handlers:
        security_logger.addHandler(handler)
    
    # Set restrictive permissions on log file (user read/write only)
    try:
        os.chmod(log_file, 0o600)  # rw-------
    except (OSError, PermissionError):
        pass  # Skip if permission setting fails


def log_validation_failure(
    validator_name: str, 
    input_value: str, 
    reason: str
) -> None:
    """
    Log a validation failure event (potential attack indicator).
    
    Args:
        validator_name: Name of the validator that failed
        input_value: The input that failed validation (sanitized)
        reason: Why the validation failed
    """
    # Sanitize input value to prevent log injection
    safe_input = input_value.replace("\n", "\\n").replace("\r", "\\r")[:100]
    
    security_logger.warning(
        f"VALIDATION_FAILURE | validator={validator_name} | "
        f"input={safe_input} | reason={reason}"
    )


def log_api_key_change(key_type: str, action: str) -> None:
    """
    Log API key configuration changes.
    
    Args:
        key_type: Type of API key (e.g., "shodan")
        action: Action performed ("set", "updated", "removed")
    """
    security_logger.info(
        f"API_KEY_CHANGE | type={key_type} | action={action}"
    )


def log_process_timeout(
    tool_name: str, 
    timeout_seconds: int
) -> None:
    """
    Log when a process is terminated due to timeout.
    
    Args:
        tool_name: Name of the tool that timed out
        timeout_seconds: Timeout value that was exceeded
    """
    security_logger.warning(
        f"PROCESS_TIMEOUT | tool={tool_name} | timeout={timeout_seconds}s"
    )


def log_concurrent_limit_reached(
    current_scans: int, 
    max_scans: int
) -> None:
    """
    Log when concurrent scan limit is reached.
    
    Args:
        current_scans: Number of currently running scans
        max_scans: Maximum allowed concurrent scans
    """
    security_logger.warning(
        f"CONCURRENT_LIMIT | current={current_scans} | max={max_scans}"
    )


def log_file_access_denied(
    filepath: str, 
    reason: str
) -> None:
    """
    Log when file access is denied.
    
    Args:
        filepath: Path to the file (sanitized)
        reason: Why access was denied
    """
    # Sanitize filepath
    safe_path = str(filepath).replace("\n", "\\n").replace("\r", "\\r")[:200]
    
    security_logger.warning(
        f"FILE_ACCESS_DENIED | path={safe_path} | reason={reason}"
    )


def log_path_traversal_attempt(
    requested_path: str
) -> None:
    """
    Log potential path traversal attack attempt.
    
    Args:
        requested_path: The suspicious path that was requested
    """
    # Sanitize path
    safe_path = requested_path.replace("\n", "\\n").replace("\r", "\\r")[:200]
    
    security_logger.error(
        f"PATH_TRAVERSAL_ATTEMPT | path={safe_path}"
    )


def log_command_injection_attempt(
    suspicious_input: str, 
    blocked_pattern: str
) -> None:
    """
    Log potential command injection attempt.
    
    Args:
        suspicious_input: The input containing injection attempt
        blocked_pattern: The pattern that was detected and blocked
    """
    # Sanitize input
    safe_input = suspicious_input.replace("\n", "\\n").replace("\r", "\\r")[:100]
    safe_pattern = blocked_pattern.replace("\n", "\\n").replace("\r", "\\r")[:50]
    
    security_logger.error(
        f"COMMAND_INJECTION_ATTEMPT | input={safe_input} | "
        f"pattern={safe_pattern}"
    )


def log_resource_limit_exceeded(
    resource_type: str, 
    limit_value: int, 
    attempted_value: int
) -> None:
    """
    Log when a resource limit is exceeded.
    
    Args:
        resource_type: Type of resource ("output_lines", "threads", etc.)
        limit_value: The limit that was set
        attempted_value: The value that was attempted
    """
    security_logger.warning(
        f"RESOURCE_LIMIT_EXCEEDED | resource={resource_type} | "
        f"limit={limit_value} | attempted={attempted_value}"
    )


def log_rate_limit_hit(
    api_name: str, 
    wait_seconds: float
) -> None:
    """
    Log when API rate limit is hit.
    
    Args:
        api_name: Name of the API
        wait_seconds: How long to wait before retry
    """
    security_logger.info(
        f"RATE_LIMIT | api={api_name} | wait={wait_seconds:.1f}s"
    )


def log_security_event(event_type: str, details: str) -> None:
    """
    Log a general security event.
    
    Args:
        event_type: Type of security event
        details: Details about the event
    """
    # Sanitize details
    safe_details = details.replace("\n", "\\n").replace("\r", "\\r")[:500]
    
    security_logger.info(
        f"{event_type.upper()} | {safe_details}"
    )

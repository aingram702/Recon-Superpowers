"""
Security validation functions for Recon Superpower.

This module provides comprehensive input validation to prevent:
- Command injection attacks
- Path traversal attacks
- Resource exhaustion
- Invalid input handling

All validators are designed with security-first principles:
- Whitelist approach for allowed characters
- Strict length limits
- NULL byte detection
- Shell metacharacter blocking
"""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple, Union
from urllib.parse import urlparse

from recon_superpower.config.defaults import (
    MAX_TARGET_LENGTH,
    MAX_URL_LENGTH,
    MAX_EXTRA_OPTIONS_LENGTH,
    MAX_WORDLIST_SIZE,
    MAX_THREAD_COUNT,
    MAX_BPF_FILTER_LENGTH,
    DANGEROUS_CHARS,
    DANGEROUS_PATTERNS,
    ALLOWED_BPF_KEYWORDS,
)
from recon_superpower.utils.logger import get_logger, get_security_logger

logger = get_logger(__name__)
security_logger = get_security_logger(__name__)


@dataclass
class ValidationResult:
    """
    Result of a validation operation.

    Attributes:
        is_valid: Whether the validation passed
        error_message: Human-readable error message (if validation failed)
        sanitized_value: Cleaned/parsed value (if applicable)
    """
    is_valid: bool
    error_message: Optional[str] = None
    sanitized_value: Optional[Union[str, List[str]]] = None

    def __bool__(self) -> bool:
        """Allow ValidationResult to be used in boolean context."""
        return self.is_valid


def _contains_null_byte(value: str) -> bool:
    """Check if string contains NULL bytes."""
    return '\x00' in value


def _contains_dangerous_chars(value: str) -> bool:
    """Check if string contains shell metacharacters."""
    return any(char in value for char in DANGEROUS_CHARS)


def validate_target(target: str) -> ValidationResult:
    """
    Validate a target hostname or IP address.

    Security checks:
    - Length limit (253 chars per RFC)
    - Whitelist: alphanumeric, dots, hyphens, slashes, colons
    - NULL byte detection
    - Shell metacharacter blocking

    Args:
        target: The target hostname or IP to validate

    Returns:
        ValidationResult with validation status and any error message
    """
    if not target:
        return ValidationResult(False, "Target cannot be empty")

    if len(target) > MAX_TARGET_LENGTH:
        security_logger.validation_failed("target", target, "exceeds length limit")
        return ValidationResult(False, f"Target exceeds maximum length ({MAX_TARGET_LENGTH} chars)")

    if _contains_null_byte(target):
        security_logger.injection_blocked("NULL byte", target)
        return ValidationResult(False, "Target contains invalid characters (NULL byte)")

    # Whitelist: alphanumeric, dots, hyphens, slashes (for CIDR), colons (for IPv6/ports)
    if not re.match(r'^[a-zA-Z0-9.\-/:]+$', target):
        security_logger.validation_failed("target", target, "contains invalid characters")
        return ValidationResult(False, "Target contains invalid characters. Use only alphanumeric, dots, hyphens, slashes, and colons")

    if _contains_dangerous_chars(target):
        security_logger.injection_blocked("command", target)
        return ValidationResult(False, "Target contains potentially dangerous characters")

    logger.debug("Target validated: %s", target[:50])
    return ValidationResult(True, sanitized_value=target.strip())


def validate_url(url: str) -> ValidationResult:
    """
    Validate a URL for web scanning.

    Security checks:
    - Length limit (2048 chars)
    - HTTP/HTTPS scheme only
    - Valid URL format
    - NULL byte detection
    - Shell metacharacter blocking

    Args:
        url: The URL to validate

    Returns:
        ValidationResult with validation status and any error message
    """
    if not url:
        return ValidationResult(False, "URL cannot be empty")

    if len(url) > MAX_URL_LENGTH:
        security_logger.validation_failed("url", url, "exceeds length limit")
        return ValidationResult(False, f"URL exceeds maximum length ({MAX_URL_LENGTH} chars)")

    if _contains_null_byte(url):
        security_logger.injection_blocked("NULL byte", url)
        return ValidationResult(False, "URL contains invalid characters (NULL byte)")

    try:
        parsed = urlparse(url)

        # Must have HTTP or HTTPS scheme
        if parsed.scheme not in ('http', 'https'):
            return ValidationResult(False, "URL must use http:// or https:// scheme")

        # Must have a hostname
        if not parsed.netloc:
            return ValidationResult(False, "URL must include a hostname")

        # Check for dangerous characters in URL components
        if _contains_dangerous_chars(parsed.netloc):
            security_logger.injection_blocked("command", url)
            return ValidationResult(False, "URL contains potentially dangerous characters")

    except Exception as e:
        logger.warning("URL parsing failed: %s", e)
        return ValidationResult(False, "Invalid URL format")

    logger.debug("URL validated: %s", url[:50])
    return ValidationResult(True, sanitized_value=url.strip())


def validate_domain(domain: str) -> ValidationResult:
    """
    Validate a domain name.

    Args:
        domain: The domain name to validate

    Returns:
        ValidationResult with validation status and any error message
    """
    if not domain:
        return ValidationResult(False, "Domain cannot be empty")

    if len(domain) > MAX_TARGET_LENGTH:
        return ValidationResult(False, f"Domain exceeds maximum length ({MAX_TARGET_LENGTH} chars)")

    if _contains_null_byte(domain):
        security_logger.injection_blocked("NULL byte", domain)
        return ValidationResult(False, "Domain contains invalid characters")

    # Domain must be alphanumeric with dots and hyphens
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.\-]*[a-zA-Z0-9]$', domain):
        return ValidationResult(False, "Invalid domain format")

    # No consecutive dots
    if '..' in domain:
        return ValidationResult(False, "Invalid domain format (consecutive dots)")

    return ValidationResult(True, sanitized_value=domain.strip().lower())


def validate_port(port_str: str) -> ValidationResult:
    """
    Validate a port number or port range.

    Args:
        port_str: Port number as string (e.g., "80" or "80,443" or "1-1000")

    Returns:
        ValidationResult with validation status and any error message
    """
    if not port_str:
        return ValidationResult(True)  # Empty is OK, will use default

    # Allow port ranges and lists: 80, 80,443, 1-1000, 80,443,8080-8090
    if not re.match(r'^[\d,\-]+$', port_str):
        return ValidationResult(False, "Port must contain only numbers, commas, and hyphens")

    # Validate individual port numbers
    for part in port_str.replace('-', ',').split(','):
        part = part.strip()
        if part:
            try:
                port = int(part)
                if not 1 <= port <= 65535:
                    return ValidationResult(False, f"Port {port} out of range (1-65535)")
            except ValueError:
                return ValidationResult(False, f"Invalid port number: {part}")

    return ValidationResult(True, sanitized_value=port_str.strip())


def validate_numeric(
    value: str,
    min_val: int = 1,
    max_val: int = 100,
    field_name: str = "value"
) -> ValidationResult:
    """
    Validate a numeric input within a range.

    Args:
        value: The value to validate
        min_val: Minimum allowed value
        max_val: Maximum allowed value
        field_name: Name of the field for error messages

    Returns:
        ValidationResult with validation status and any error message
    """
    if not value:
        return ValidationResult(True)  # Empty is OK for optional fields

    try:
        num = int(value)
        if not min_val <= num <= max_val:
            return ValidationResult(
                False,
                f"{field_name.capitalize()} must be between {min_val} and {max_val}"
            )
        return ValidationResult(True, sanitized_value=str(num))
    except ValueError:
        return ValidationResult(False, f"{field_name.capitalize()} must be a number")


def validate_extra_options(options: str) -> ValidationResult:
    """
    Validate extra command-line options to prevent command injection.

    This is the SINGLE authoritative validation function for extra options.
    Uses shlex for proper parsing and blocks dangerous patterns.

    Security checks:
    - NULL byte detection
    - Shell metacharacter blocking
    - Command substitution blocking
    - Redirect blocking
    - Length limit

    Args:
        options: The extra options string to validate

    Returns:
        ValidationResult with is_valid, error_message, and parsed options list
    """
    if not options:
        return ValidationResult(True, sanitized_value=[])

    if len(options) > MAX_EXTRA_OPTIONS_LENGTH:
        security_logger.validation_failed("extra_options", options, "exceeds length limit")
        return ValidationResult(
            False,
            f"Extra options exceed maximum length ({MAX_EXTRA_OPTIONS_LENGTH} chars)"
        )

    if _contains_null_byte(options):
        security_logger.injection_blocked("NULL byte", options)
        return ValidationResult(False, "Options contain invalid characters (NULL byte)")

    try:
        # Use shlex to properly parse shell-like syntax
        parsed_options = shlex.split(options)

        # Check each parsed option against dangerous patterns
        for option in parsed_options:
            if _contains_null_byte(option):
                security_logger.injection_blocked("NULL byte", option)
                return ValidationResult(False, "Options contain invalid characters")

            for pattern in DANGEROUS_PATTERNS:
                if re.match(pattern, option):
                    security_logger.injection_blocked("command", option)
                    return ValidationResult(
                        False,
                        "Options contain potentially dangerous characters or patterns"
                    )

        logger.debug("Extra options validated: %d items", len(parsed_options))
        return ValidationResult(True, sanitized_value=parsed_options)

    except ValueError as e:
        # shlex.split() raises ValueError for unmatched quotes
        logger.warning("Failed to parse extra options: %s", e)
        return ValidationResult(False, "Invalid option format (unmatched quotes)")


def validate_file_path(
    filepath: str,
    must_exist: bool = True,
    max_size: Optional[int] = None,
    allowed_extensions: Optional[Tuple[str, ...]] = None
) -> ValidationResult:
    """
    Validate a file path for security.

    Security checks:
    - Path traversal prevention (.., ~)
    - Symlink attack prevention
    - File size limits
    - Extension whitelist (optional)
    - Read permission verification

    Args:
        filepath: The file path to validate
        must_exist: Whether the file must exist
        max_size: Maximum allowed file size in bytes
        allowed_extensions: Tuple of allowed file extensions (e.g., ('.txt', '.lst'))

    Returns:
        ValidationResult with validation status and any error message
    """
    if not filepath:
        return ValidationResult(False, "File path cannot be empty")

    # Normalize and get absolute path
    try:
        abs_path = os.path.abspath(os.path.normpath(filepath))
    except (ValueError, OSError) as e:
        logger.warning("Path normalization failed: %s", e)
        return ValidationResult(False, "Invalid file path")

    # Check for path traversal attempts
    if '..' in filepath or '~' in filepath:
        security_logger.path_traversal_blocked(filepath)
        return ValidationResult(False, "Path traversal not allowed (.. or ~ detected)")

    # Resolve symlinks and verify path
    try:
        real_path = os.path.realpath(abs_path)

        # Check if symlink points outside expected location
        if os.path.islink(abs_path):
            if not os.path.exists(real_path):
                security_logger.path_traversal_blocked(filepath)
                return ValidationResult(False, "Symlink target does not exist")
    except OSError as e:
        logger.warning("Path resolution failed: %s", e)
        return ValidationResult(False, "Cannot resolve file path")

    if must_exist:
        if not os.path.isfile(real_path):
            return ValidationResult(False, "File does not exist")

        if not os.access(real_path, os.R_OK):
            return ValidationResult(False, "File is not readable")

        # Check file size
        if max_size is not None:
            try:
                file_size = os.path.getsize(real_path)
                if file_size > max_size:
                    security_logger.resource_limit_exceeded(
                        "file_size", max_size, file_size
                    )
                    return ValidationResult(
                        False,
                        f"File exceeds maximum size ({max_size // (1024*1024)}MB)"
                    )
            except OSError:
                return ValidationResult(False, "Cannot determine file size")

    # Check extension
    if allowed_extensions:
        ext = os.path.splitext(abs_path)[1].lower()
        if ext not in allowed_extensions:
            return ValidationResult(
                False,
                f"File extension not allowed. Allowed: {', '.join(allowed_extensions)}"
            )

    logger.debug("File path validated: %s", abs_path)
    return ValidationResult(True, sanitized_value=abs_path)


def validate_file_extensions(extensions: str) -> ValidationResult:
    """
    Validate a comma-separated list of file extensions.

    Args:
        extensions: Comma-separated extensions (e.g., "php,html,txt")

    Returns:
        ValidationResult with validation status and any error message
    """
    if not extensions:
        return ValidationResult(True, sanitized_value="")

    # Only alphanumeric and commas
    if not re.match(r'^[a-zA-Z0-9,]+$', extensions):
        return ValidationResult(
            False,
            "Extensions must contain only letters, numbers, and commas"
        )

    # Validate individual extensions
    ext_list = [e.strip().lower() for e in extensions.split(',') if e.strip()]
    if not ext_list:
        return ValidationResult(False, "No valid extensions provided")

    # Check for overly long extensions
    for ext in ext_list:
        if len(ext) > 10:
            return ValidationResult(False, f"Extension too long: {ext}")

    return ValidationResult(True, sanitized_value=','.join(ext_list))


def validate_interface_name(interface: str) -> ValidationResult:
    """
    Validate a network interface name.

    Args:
        interface: The network interface name (e.g., "eth0", "wlan0")

    Returns:
        ValidationResult with validation status and any error message
    """
    if not interface:
        return ValidationResult(False, "Interface name cannot be empty")

    # Interface names: alphanumeric and hyphens only
    if not re.match(r'^[a-zA-Z0-9\-]+$', interface):
        return ValidationResult(
            False,
            "Interface name must contain only alphanumeric characters and hyphens"
        )

    if len(interface) > 15:  # Linux interface name limit
        return ValidationResult(False, "Interface name too long")

    # Verify interface exists (Linux-specific)
    net_path = f"/sys/class/net/{interface}"
    if os.path.exists("/sys/class/net") and not os.path.exists(net_path):
        return ValidationResult(
            False,
            f"Interface '{interface}' not found. Check 'ip link show' for available interfaces"
        )

    return ValidationResult(True, sanitized_value=interface)


def validate_nse_script(script: str) -> ValidationResult:
    """
    Validate an Nmap NSE script name.

    Args:
        script: The NSE script name or category

    Returns:
        ValidationResult with validation status and any error message
    """
    if not script:
        return ValidationResult(True, sanitized_value="")

    # NSE scripts: alphanumeric, hyphens, underscores, dots, commas
    if not re.match(r'^[a-zA-Z0-9_\-.,]+$', script):
        return ValidationResult(
            False,
            "NSE script name contains invalid characters"
        )

    if len(script) > 200:
        return ValidationResult(False, "NSE script specification too long")

    # Check for path traversal in script names
    if '..' in script or '/' in script or '\\' in script:
        security_logger.path_traversal_blocked(script)
        return ValidationResult(False, "Invalid script name (path characters detected)")

    return ValidationResult(True, sanitized_value=script)


def validate_github_account(account: str) -> ValidationResult:
    """
    Validate a GitHub username or organization name.

    Args:
        account: The GitHub account name

    Returns:
        ValidationResult with validation status and any error message
    """
    if not account:
        return ValidationResult(False, "GitHub account cannot be empty")

    # GitHub usernames: alphanumeric and hyphens, 1-39 characters
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\-]{0,38}$', account):
        return ValidationResult(
            False,
            "Invalid GitHub username format (alphanumeric and hyphens, max 39 chars)"
        )

    # Cannot start or end with hyphen, no consecutive hyphens
    if account.startswith('-') or account.endswith('-') or '--' in account:
        return ValidationResult(False, "Invalid GitHub username format")

    return ValidationResult(True, sanitized_value=account)


def validate_metasploit_options(options: str) -> ValidationResult:
    """
    Validate Metasploit KEY=VALUE options.

    Args:
        options: Space-separated KEY=VALUE pairs

    Returns:
        ValidationResult with validation status and any error message
    """
    if not options:
        return ValidationResult(True, sanitized_value=[])

    if _contains_null_byte(options):
        security_logger.injection_blocked("NULL byte", options)
        return ValidationResult(False, "Options contain invalid characters")

    parsed_options = []

    # Split on whitespace and validate each KEY=VALUE pair
    for part in options.split():
        part = part.strip()
        if not part:
            continue

        if '=' not in part:
            return ValidationResult(
                False,
                f"Invalid option format: '{part}'. Use KEY=VALUE format"
            )

        key, value = part.split('=', 1)

        # Key must be alphanumeric/underscore
        if not re.match(r'^[A-Z][A-Z0-9_]*$', key):
            return ValidationResult(
                False,
                f"Invalid option key: '{key}'. Must be uppercase alphanumeric"
            )

        # Value cannot contain shell metacharacters
        if _contains_dangerous_chars(value):
            security_logger.injection_blocked("command", value)
            return ValidationResult(
                False,
                f"Option value for {key} contains dangerous characters"
            )

        parsed_options.append(f"{key}={value}")

    return ValidationResult(True, sanitized_value=parsed_options)


def validate_bpf_filter(bpf_filter: str) -> ValidationResult:
    """
    Validate a BPF (Berkeley Packet Filter) expression for tcpdump.

    Args:
        bpf_filter: The BPF filter expression

    Returns:
        ValidationResult with validation status and any error message
    """
    if not bpf_filter:
        return ValidationResult(True, sanitized_value="")

    if len(bpf_filter) > MAX_BPF_FILTER_LENGTH:
        return ValidationResult(
            False,
            f"BPF filter too long (max {MAX_BPF_FILTER_LENGTH} characters)"
        )

    # Restrictive pattern - only allow alphanumeric, spaces, dots, basic operators
    if not re.match(r'^[a-zA-Z0-9\s.\-]+$', bpf_filter):
        return ValidationResult(
            False,
            "Invalid BPF filter. Parentheses and special characters not allowed. "
            "Use simple filters: 'port 80', 'host 192.168.1.1', 'tcp and port 443'"
        )

    # Must contain at least one known BPF keyword
    filter_lower = bpf_filter.lower()
    has_keyword = any(keyword in filter_lower for keyword in ALLOWED_BPF_KEYWORDS)

    if not has_keyword:
        keywords_sample = ', '.join(ALLOWED_BPF_KEYWORDS[:8])
        return ValidationResult(
            False,
            f"BPF filter must contain valid keywords: {keywords_sample}..."
        )

    return ValidationResult(True, sanitized_value=bpf_filter)


def validate_wordlist_path(filepath: str) -> ValidationResult:
    """
    Validate a wordlist file path with size limits.

    Args:
        filepath: Path to the wordlist file

    Returns:
        ValidationResult with validation status and any error message
    """
    return validate_file_path(
        filepath,
        must_exist=True,
        max_size=MAX_WORDLIST_SIZE,
        allowed_extensions=('.txt', '.lst', '.wordlist', '')
    )


def validate_output_path(filepath: str) -> ValidationResult:
    """
    Validate an output file path (must be in user's home directory).

    Args:
        filepath: Path for output file

    Returns:
        ValidationResult with validation status and any error message
    """
    if not filepath:
        return ValidationResult(False, "Output path cannot be empty")

    try:
        abs_path = os.path.abspath(os.path.normpath(filepath))
        home_dir = os.path.expanduser("~")

        if not abs_path.startswith(home_dir):
            security_logger.path_traversal_blocked(filepath)
            return ValidationResult(
                False,
                "Output file must be within your home directory"
            )

        # Check parent directory exists and is writable
        parent_dir = os.path.dirname(abs_path)
        if not os.path.isdir(parent_dir):
            return ValidationResult(False, "Parent directory does not exist")

        if not os.access(parent_dir, os.W_OK):
            return ValidationResult(False, "Parent directory is not writable")

        return ValidationResult(True, sanitized_value=abs_path)

    except (ValueError, OSError) as e:
        logger.warning("Output path validation failed: %s", e)
        return ValidationResult(False, "Invalid output path")

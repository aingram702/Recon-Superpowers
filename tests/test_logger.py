"""
Unit tests for logging infrastructure.
"""

import logging
from unittest.mock import patch, MagicMock

import pytest

from recon_superpower.utils.logger import (
    get_logger,
    setup_logging,
    SecurityLogger,
    get_security_logger,
    SecurityFilter,
    ColoredFormatter,
)


class TestSecurityFilter:
    """Tests for SecurityFilter logging filter."""

    def test_marks_security_events(self) -> None:
        """Filter should mark records containing security keywords."""
        filter_obj = SecurityFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.WARNING,
            pathname="",
            lineno=0,
            msg="Command injection blocked",
            args=(),
            exc_info=None
        )
        filter_obj.filter(record)
        assert hasattr(record, 'is_security_event')
        assert record.is_security_event is True

    def test_non_security_events_not_marked(self) -> None:
        """Filter should not mark non-security records."""
        filter_obj = SecurityFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Application started",
            args=(),
            exc_info=None
        )
        filter_obj.filter(record)
        assert hasattr(record, 'is_security_event')
        assert record.is_security_event is False


class TestGetLogger:
    """Tests for get_logger function."""

    def test_returns_logger_instance(self) -> None:
        """get_logger should return a logger instance."""
        logger = get_logger("test_module")
        assert isinstance(logger, logging.Logger)

    def test_caches_loggers(self) -> None:
        """get_logger should return same instance for same name."""
        logger1 = get_logger("cached_module")
        logger2 = get_logger("cached_module")
        assert logger1 is logger2

    def test_namespaces_under_recon_superpower(self) -> None:
        """Loggers should be namespaced under recon_superpower."""
        logger = get_logger("my_module")
        assert "recon_superpower" in logger.name


class TestSecurityLogger:
    """Tests for SecurityLogger class."""

    @pytest.fixture
    def security_logger(self) -> SecurityLogger:
        """Create a SecurityLogger instance for testing."""
        return SecurityLogger("test_module")

    def test_validation_failed_logs_warning(self, security_logger: SecurityLogger) -> None:
        """validation_failed should log at WARNING level."""
        with patch.object(security_logger._logger, 'warning') as mock_warning:
            security_logger.validation_failed("target", "192.168.1.1; rm -rf /", "contains shell chars")
            mock_warning.assert_called_once()
            call_args = mock_warning.call_args[0][0]
            assert "SECURITY" in call_args
            assert "Validation failed" in call_args

    def test_injection_blocked_logs_warning(self, security_logger: SecurityLogger) -> None:
        """injection_blocked should log at WARNING level."""
        with patch.object(security_logger._logger, 'warning') as mock_warning:
            security_logger.injection_blocked("command", "$(whoami)")
            mock_warning.assert_called_once()
            call_args = mock_warning.call_args[0][0]
            assert "injection blocked" in call_args

    def test_truncates_long_values(self, security_logger: SecurityLogger) -> None:
        """Security logger should truncate long values for safety."""
        with patch.object(security_logger._logger, 'warning') as mock_warning:
            long_value = "A" * 200
            security_logger.validation_failed("field", long_value, "test")
            call_args = str(mock_warning.call_args)
            # Should contain truncated value with ...
            assert "..." in call_args

    def test_scan_started_logs_info(self, security_logger: SecurityLogger) -> None:
        """scan_started should log at INFO level."""
        with patch.object(security_logger._logger, 'info') as mock_info:
            security_logger.scan_started("nmap", "192.168.1.1", True)
            mock_info.assert_called_once()
            call_args = mock_info.call_args[0][0]
            assert "AUDIT" in call_args
            assert "Scan started" in call_args


class TestColoredFormatter:
    """Tests for ColoredFormatter class."""

    def test_adds_colors_when_tty(self) -> None:
        """Formatter should add colors when output is TTY."""
        formatter = ColoredFormatter(use_colors=True)
        # Force use_colors since we're not actually on a TTY in tests
        formatter.use_colors = True

        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="",
            lineno=0,
            msg="Error message",
            args=(),
            exc_info=None
        )
        formatted = formatter.format(record)
        # Should contain ANSI escape codes
        assert "\033[" in formatted

    def test_no_colors_when_disabled(self) -> None:
        """Formatter should not add colors when disabled."""
        formatter = ColoredFormatter(use_colors=False)

        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="",
            lineno=0,
            msg="Error message",
            args=(),
            exc_info=None
        )
        formatted = formatter.format(record)
        # Should not contain ANSI escape codes
        assert "\033[31m" not in formatted

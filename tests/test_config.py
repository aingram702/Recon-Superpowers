"""
Unit tests for configuration management.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from recon_superpower.config.settings import Settings, SecuritySettings, UISettings
from recon_superpower.config.defaults import (
    DEFAULT_PROCESS_TIMEOUT,
    DEFAULT_MAX_OUTPUT_LINES,
    THEME_COLORS,
)


class TestSecuritySettings:
    """Tests for SecuritySettings dataclass."""

    def test_default_values(self) -> None:
        """SecuritySettings should have sensible defaults."""
        settings = SecuritySettings()
        assert settings.process_timeout == DEFAULT_PROCESS_TIMEOUT
        assert settings.max_output_lines == DEFAULT_MAX_OUTPUT_LINES
        assert settings.confirm_before_scan is True

    def test_custom_values(self) -> None:
        """SecuritySettings should accept custom values."""
        settings = SecuritySettings(
            process_timeout=7200,
            max_output_lines=5000,
            confirm_before_scan=False
        )
        assert settings.process_timeout == 7200
        assert settings.max_output_lines == 5000
        assert settings.confirm_before_scan is False


class TestUISettings:
    """Tests for UISettings dataclass."""

    def test_default_values(self) -> None:
        """UISettings should have sensible defaults."""
        settings = UISettings()
        assert settings.window_width == 1400
        assert settings.window_height == 900
        assert settings.theme == "monokai"


class TestSettings:
    """Tests for Settings singleton class."""

    @pytest.fixture(autouse=True)
    def reset_singleton(self) -> None:
        """Reset the Settings singleton before each test."""
        Settings._instance = None

    @pytest.fixture
    def temp_config_dir(self) -> Path:
        """Create a temporary config directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_singleton_pattern(self) -> None:
        """Settings should implement singleton pattern."""
        with patch.object(Settings, '_ensure_config_dir'):
            with patch.object(Settings, 'load'):
                with patch.object(Settings, 'load_history'):
                    s1 = Settings()
                    s2 = Settings()
                    assert s1 is s2

    def test_get_color_returns_theme_color(self) -> None:
        """get_color should return theme colors."""
        with patch.object(Settings, '_ensure_config_dir'):
            with patch.object(Settings, 'load'):
                with patch.object(Settings, 'load_history'):
                    settings = Settings()
                    assert settings.get_color("bg_primary") == THEME_COLORS["bg_primary"]

    def test_get_color_returns_fallback(self) -> None:
        """get_color should return fallback for unknown colors."""
        with patch.object(Settings, '_ensure_config_dir'):
            with patch.object(Settings, 'load'):
                with patch.object(Settings, 'load_history'):
                    settings = Settings()
                    result = settings.get_color("nonexistent_color")
                    assert result == "#FFFFFF"  # Default fallback

    def test_add_target_to_history(self) -> None:
        """add_target should add targets to history."""
        with patch.object(Settings, '_ensure_config_dir'):
            with patch.object(Settings, 'load'):
                with patch.object(Settings, 'load_history'):
                    with patch.object(Settings, 'save_history'):
                        settings = Settings()
                        settings.add_target("192.168.1.1")
                        assert "192.168.1.1" in settings.history.recent_targets

    def test_add_target_prevents_duplicates(self) -> None:
        """add_target should not add duplicate targets."""
        with patch.object(Settings, '_ensure_config_dir'):
            with patch.object(Settings, 'load'):
                with patch.object(Settings, 'load_history'):
                    with patch.object(Settings, 'save_history'):
                        settings = Settings()
                        settings.add_target("192.168.1.1")
                        settings.add_target("192.168.1.1")
                        assert settings.history.recent_targets.count("192.168.1.1") == 1

    def test_reset_to_defaults(self) -> None:
        """reset_to_defaults should restore default values."""
        with patch.object(Settings, '_ensure_config_dir'):
            with patch.object(Settings, 'load'):
                with patch.object(Settings, 'load_history'):
                    with patch.object(Settings, 'save'):
                        settings = Settings()
                        settings.security.process_timeout = 9999
                        settings.reset_to_defaults()
                        assert settings.security.process_timeout == DEFAULT_PROCESS_TIMEOUT

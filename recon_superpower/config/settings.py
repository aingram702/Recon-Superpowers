"""
Centralized configuration management for Recon Superpower.
Handles loading, saving, and accessing application settings.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from recon_superpower.config.defaults import (
    DEFAULT_PROCESS_TIMEOUT,
    DEFAULT_MAX_OUTPUT_LINES,
    DEFAULT_WORKFLOW_TIMEOUT,
    DEFAULT_STEP_TIMEOUT,
    MAX_RECENT_TARGETS,
    MAX_RECENT_URLS,
    MAX_COMMAND_HISTORY,
    CONFIG_DIR_NAME,
    CONFIG_FILE_NAME,
    HISTORY_FILE_NAME,
    THEME_COLORS,
)
from recon_superpower.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class SecuritySettings:
    """Security-related configuration settings."""

    process_timeout: int = DEFAULT_PROCESS_TIMEOUT
    workflow_timeout: int = DEFAULT_WORKFLOW_TIMEOUT
    step_timeout: int = DEFAULT_STEP_TIMEOUT
    max_output_lines: int = DEFAULT_MAX_OUTPUT_LINES
    confirm_before_scan: bool = True
    allow_private_ip_targets: bool = False


@dataclass
class UISettings:
    """User interface configuration settings."""

    window_width: int = 1400
    window_height: int = 900
    theme: str = "monokai"
    font_size: int = 10
    show_command_preview: bool = True
    auto_scroll_output: bool = True


@dataclass
class ToolSettings:
    """Tool-specific configuration settings."""

    shodan_api_key: str = ""
    default_wordlist: str = ""
    default_nmap_timing: str = "T4"
    default_threads: int = 10


@dataclass
class HistoryData:
    """Application history data."""

    recent_targets: List[str] = field(default_factory=list)
    recent_urls: List[str] = field(default_factory=list)
    command_history: List[List[str]] = field(default_factory=list)


class Settings:
    """
    Centralized settings manager for Recon Superpower.

    Handles loading, saving, and accessing all application configuration.
    Thread-safe singleton pattern for global access.

    Usage:
        settings = Settings()
        settings.security.process_timeout = 7200
        settings.save()
    """

    _instance: Optional[Settings] = None

    def __new__(cls) -> Settings:
        """Singleton pattern - ensures only one Settings instance exists."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        """Initialize settings, loading from disk if available."""
        if self._initialized:
            return

        self._initialized = True

        # Set up paths
        self.config_dir: Path = Path.home() / CONFIG_DIR_NAME
        self.config_file: Path = self.config_dir / CONFIG_FILE_NAME
        self.history_file: Path = self.config_dir / HISTORY_FILE_NAME

        # Initialize settings groups
        self.security = SecuritySettings()
        self.ui = UISettings()
        self.tools = ToolSettings()
        self.history = HistoryData()

        # Theme colors (loaded from defaults, can be customized)
        self.colors: Dict[str, str] = THEME_COLORS.copy()

        # Ensure config directory exists
        self._ensure_config_dir()

        # Load saved settings
        self.load()
        self.load_history()

        logger.info("Settings initialized from %s", self.config_file)

    def _ensure_config_dir(self) -> None:
        """Create configuration directory if it doesn't exist."""
        try:
            self.config_dir.mkdir(exist_ok=True)
            logger.debug("Config directory ensured: %s", self.config_dir)
        except OSError as e:
            logger.error("Failed to create config directory: %s", e)

    def load(self) -> None:
        """Load settings from configuration file."""
        if not self.config_file.exists():
            logger.info("No config file found, using defaults")
            return

        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Load security settings
            if 'security' in data:
                for key, value in data['security'].items():
                    if hasattr(self.security, key):
                        setattr(self.security, key, value)

            # Load UI settings
            if 'ui' in data:
                for key, value in data['ui'].items():
                    if hasattr(self.ui, key):
                        setattr(self.ui, key, value)

            # Load tool settings
            if 'tools' in data:
                for key, value in data['tools'].items():
                    if hasattr(self.tools, key):
                        setattr(self.tools, key, value)

            # Load custom colors
            if 'colors' in data:
                self.colors.update(data['colors'])

            logger.info("Settings loaded successfully")

        except json.JSONDecodeError as e:
            logger.error("Invalid JSON in config file: %s", e)
        except OSError as e:
            logger.error("Failed to read config file: %s", e)

    def save(self) -> None:
        """Save current settings to configuration file."""
        data = {
            'security': asdict(self.security),
            'ui': asdict(self.ui),
            'tools': asdict(self.tools),
            'colors': self.colors,
        }

        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            logger.info("Settings saved to %s", self.config_file)
        except OSError as e:
            logger.error("Failed to save settings: %s", e)

    def load_history(self) -> None:
        """Load command and target history from file."""
        if not self.history_file.exists():
            return

        try:
            with open(self.history_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            self.history.recent_targets = data.get('recent_targets', [])[:MAX_RECENT_TARGETS]
            self.history.recent_urls = data.get('recent_urls', [])[:MAX_RECENT_URLS]
            self.history.command_history = data.get('command_history', [])[:MAX_COMMAND_HISTORY]

            logger.debug("History loaded: %d targets, %d URLs, %d commands",
                        len(self.history.recent_targets),
                        len(self.history.recent_urls),
                        len(self.history.command_history))

        except (json.JSONDecodeError, OSError) as e:
            logger.error("Failed to load history: %s", e)

    def save_history(self) -> None:
        """Save command and target history to file."""
        data = {
            'recent_targets': self.history.recent_targets[:MAX_RECENT_TARGETS],
            'recent_urls': self.history.recent_urls[:MAX_RECENT_URLS],
            'command_history': self.history.command_history[:MAX_COMMAND_HISTORY],
        }

        try:
            with open(self.history_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
            logger.debug("History saved")
        except OSError as e:
            logger.error("Failed to save history: %s", e)

    def add_target(self, target: str) -> None:
        """Add a target to recent history."""
        if target and target not in self.history.recent_targets:
            self.history.recent_targets.insert(0, target)
            self.history.recent_targets = self.history.recent_targets[:MAX_RECENT_TARGETS]
            self.save_history()

    def add_url(self, url: str) -> None:
        """Add a URL to recent history."""
        if url and url not in self.history.recent_urls:
            self.history.recent_urls.insert(0, url)
            self.history.recent_urls = self.history.recent_urls[:MAX_RECENT_URLS]
            self.save_history()

    def add_command(self, command: List[str]) -> None:
        """Add a command to history."""
        if command:
            self.history.command_history.insert(0, command)
            self.history.command_history = self.history.command_history[:MAX_COMMAND_HISTORY]
            self.save_history()

    def get_color(self, name: str) -> str:
        """Get a theme color by name with fallback."""
        return self.colors.get(name, THEME_COLORS.get(name, "#FFFFFF"))

    def reset_to_defaults(self) -> None:
        """Reset all settings to default values."""
        self.security = SecuritySettings()
        self.ui = UISettings()
        self.tools = ToolSettings()
        self.colors = THEME_COLORS.copy()
        self.save()
        logger.info("Settings reset to defaults")

    @classmethod
    def get_instance(cls) -> Settings:
        """Get the singleton Settings instance."""
        return cls()

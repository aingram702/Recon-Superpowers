"""
Theme management for Recon Superpower UI.
Provides centralized access to colors and styling.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

from recon_superpower.config.defaults import THEME_COLORS


@dataclass
class Theme:
    """
    Theme configuration for the application UI.

    Provides access to all theme colors and styling properties.
    Supports the Monokai terminal theme by default.
    """

    # Main backgrounds
    bg_primary: str = THEME_COLORS["bg_primary"]
    bg_secondary: str = THEME_COLORS["bg_secondary"]
    bg_tertiary: str = THEME_COLORS["bg_tertiary"]

    # Accent colors
    accent_green: str = THEME_COLORS["accent_green"]
    accent_cyan: str = THEME_COLORS["accent_cyan"]
    accent_red: str = THEME_COLORS["accent_red"]
    accent_orange: str = THEME_COLORS["accent_orange"]
    accent_yellow: str = THEME_COLORS["accent_yellow"]
    accent_purple: str = THEME_COLORS["accent_purple"]

    # Text colors
    text_color: str = THEME_COLORS["text_color"]
    text_muted: str = THEME_COLORS["text_muted"]

    # Border and output
    border_color: str = THEME_COLORS["border_color"]
    output_bg: str = THEME_COLORS["output_bg"]

    @classmethod
    def from_dict(cls, colors: Dict[str, str]) -> Theme:
        """Create a Theme from a dictionary of colors."""
        return cls(**{k: v for k, v in colors.items() if hasattr(cls, k)})

    def get(self, name: str, default: Optional[str] = None) -> str:
        """Get a color by name with optional default."""
        return getattr(self, name, default or "#FFFFFF")

    def to_dict(self) -> Dict[str, str]:
        """Convert theme to dictionary."""
        return {
            "bg_primary": self.bg_primary,
            "bg_secondary": self.bg_secondary,
            "bg_tertiary": self.bg_tertiary,
            "accent_green": self.accent_green,
            "accent_cyan": self.accent_cyan,
            "accent_red": self.accent_red,
            "accent_orange": self.accent_orange,
            "accent_yellow": self.accent_yellow,
            "accent_purple": self.accent_purple,
            "text_color": self.text_color,
            "text_muted": self.text_muted,
            "border_color": self.border_color,
            "output_bg": self.output_bg,
        }

    # Semantic color aliases
    @property
    def success(self) -> str:
        """Color for success messages."""
        return self.accent_green

    @property
    def error(self) -> str:
        """Color for error messages."""
        return self.accent_red

    @property
    def warning(self) -> str:
        """Color for warning messages."""
        return self.accent_orange

    @property
    def info(self) -> str:
        """Color for info messages."""
        return self.accent_cyan

    @property
    def highlight(self) -> str:
        """Color for highlighted text."""
        return self.accent_yellow

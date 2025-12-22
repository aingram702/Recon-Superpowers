"""
Theme management for Recon Superpower UI.
Provides centralized access to colors and styling.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from recon_superpower.config.defaults import THEME_COLORS, AVAILABLE_THEMES, DEFAULT_THEME


@dataclass
class Theme:
    """
    Theme configuration for the application UI.

    Provides access to all theme colors and styling properties.
    Supports multiple themes including Monokai, One Dark, Nord, Dracula,
    Darcula, Material, Solarized Dark, Gruvbox Dark, and Obsidian.
    """

    # Theme name
    name: str = DEFAULT_THEME

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
    def from_dict(cls, colors: Dict[str, str], name: str = "Custom") -> Theme:
        """Create a Theme from a dictionary of colors."""
        theme_dict = {k: v for k, v in colors.items() if hasattr(cls, k) and k != "name"}
        theme_dict["name"] = name
        return cls(**theme_dict)

    @classmethod
    def from_name(cls, theme_name: str) -> Theme:
        """Create a Theme from a predefined theme name."""
        if theme_name not in AVAILABLE_THEMES:
            theme_name = DEFAULT_THEME
        return cls.from_dict(AVAILABLE_THEMES[theme_name], name=theme_name)

    @classmethod
    def get_available_themes(cls) -> List[str]:
        """Get list of available theme names."""
        return list(AVAILABLE_THEMES.keys())

    def get(self, name: str, default: Optional[str] = None) -> str:
        """Get a color by name with optional default."""
        return getattr(self, name, default or "#FFFFFF")

    def to_dict(self) -> Dict[str, str]:
        """Convert theme to dictionary."""
        return {
            "name": self.name,
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


def get_theme_colors(theme_name: str) -> Dict[str, str]:
    """Get color dictionary for a theme by name."""
    if theme_name in AVAILABLE_THEMES:
        return AVAILABLE_THEMES[theme_name].copy()
    return AVAILABLE_THEMES[DEFAULT_THEME].copy()


def get_available_theme_names() -> List[str]:
    """Get list of all available theme names."""
    return list(AVAILABLE_THEMES.keys())

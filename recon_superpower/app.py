"""
Main application entry point for Recon Superpower.

This module provides the main() function that initializes and runs the application.
It can be used both as a module entry point and imported for programmatic use.
"""

from __future__ import annotations

import sys
import tkinter as tk
from typing import NoReturn, Optional

from recon_superpower.config.settings import Settings
from recon_superpower.utils.logger import get_logger, setup_logging

logger = get_logger(__name__)


def check_dependencies() -> bool:
    """
    Check that all required dependencies are available.

    Returns:
        True if all dependencies are available, False otherwise.
    """
    missing = []

    # Check for tkinter
    try:
        import tkinter
    except ImportError:
        missing.append("tkinter")

    if missing:
        logger.error("Missing required dependencies: %s", ", ".join(missing))
        return False

    return True


def main(argv: Optional[list[str]] = None) -> int:
    """
    Main entry point for the Recon Superpower application.

    Args:
        argv: Command line arguments (defaults to sys.argv)

    Returns:
        Exit code (0 for success, non-zero for error)
    """
    # Set up logging first
    setup_logging()
    logger.info("Starting Recon Superpower")

    # Check dependencies
    if not check_dependencies():
        print("Error: Missing required dependencies. Please check the installation.")
        return 1

    # Initialize settings
    try:
        settings = Settings()
        logger.info("Configuration loaded from %s", settings.config_file)
    except Exception as e:
        logger.error("Failed to load configuration: %s", e)
        print(f"Warning: Could not load configuration: {e}")

    # Import and run the legacy application
    # This provides backward compatibility while we migrate to the new architecture
    try:
        # Import the legacy monolithic application
        # This will be gradually refactored to use the new modular structure
        import importlib.util
        from pathlib import Path

        # Find the legacy recon_superpower.py in parent directory
        legacy_path = Path(__file__).parent.parent / "recon_superpower.py"

        if legacy_path.exists():
            spec = importlib.util.spec_from_file_location("legacy_app", legacy_path)
            if spec and spec.loader:
                legacy_module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(legacy_module)
                legacy_module.main()
                return 0
        else:
            # Fallback: run minimal tkinter app
            logger.warning("Legacy application not found, running minimal UI")
            root = tk.Tk()
            root.title("Recon Superpower")
            root.geometry("800x600")

            label = tk.Label(
                root,
                text="Recon Superpower v3.3.0\n\nModular architecture initialized.\nLegacy UI not found.",
                font=("Courier", 14)
            )
            label.pack(expand=True)

            root.mainloop()
            return 0

    except Exception as e:
        logger.exception("Application error: %s", e)
        print(f"Error: {e}")
        return 1

    return 0


def run() -> NoReturn:
    """Run the application and exit with the return code."""
    sys.exit(main(sys.argv))


if __name__ == "__main__":
    run()

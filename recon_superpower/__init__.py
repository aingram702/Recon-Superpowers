"""
Recon Superpower - Professional GUI for Security Reconnaissance Tools
For authorized penetration testing, CTF challenges, and security research only.

This package provides a modular architecture for the Recon Superpower application.
"""

__version__ = "3.3.0"
__author__ = "Recon Superpower Team"
__license__ = "MIT"

from recon_superpower.config.settings import Settings
from recon_superpower.utils.logger import get_logger

__all__ = ["Settings", "get_logger", "__version__"]

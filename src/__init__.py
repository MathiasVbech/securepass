"""
SecurePass Package

This package contains the core modules for the SecurePass password security toolkit:

- password_checker: Password strength analysis functionality
- password_generator: Password and passphrase generation
- advanced_analytics: Advanced pattern detection and vulnerability analysis

These modules can be used independently or together through the securepass.py interface.
"""

# Define what gets imported with "from src import *"
__all__ = ['password_checker', 'password_generator', 'advanced_analytics']

# Package metadata
__version__ = '1.0.0'
__author__ = 'Your Name'
__license__ = 'MIT'
# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# Centralized logging configuration for sev_pytools package.

"""
Logging utilities for sev_pytools

This module provides centralized logging configuration for both library and CLI usage.
"""

import copy
import logging
import sys
from typing import Optional, Union


class ColoredFormatter(logging.Formatter):
    """Formatter that adds colors to log levels (for CLI mode)."""

    # ANSI color codes
    COLORS = {
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",  # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[35m",  # Magenta
        "RESET": "\033[0m",  # Reset
    }

    def format(self, record):
        # Apply color to the log level name (on a copy to avoid polluting other handlers)
        record = copy.copy(record)
        if record.levelname in self.COLORS:
            record.levelname = f"{self.COLORS[record.levelname]}{record.levelname}{self.COLORS['RESET']}"
        return super().format(record)


def setup_logging(
    name: str = "sev_pytools",
    level: Union[str, int] = logging.INFO,
    cli_mode: bool = False,
    verbose: bool = False,
    quiet: bool = False,
    log_file: Optional[str] = None,
    format_string: Optional[str] = None,
) -> logging.Logger:
    """
    Set up logging configuration for sev_pytools.

    Args:
        name: Logger name (default: "sev_pytools")
        level: Logging level (default: INFO)
        cli_mode: Whether running in CLI mode (affects formatting)
        verbose: Enable verbose logging (sets level to DEBUG)
        quiet: Enable quiet mode (sets level to WARNING)
        log_file: Optional file path to write logs to
        format_string: Custom format string (if None, uses appropriate default)

    Returns:
        Configured logger instance
    """
    # Determine log level
    if verbose:
        level = logging.DEBUG
    elif quiet:
        level = logging.WARNING
    elif isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)

    # Get or create logger
    logger = logging.getLogger(name)

    # Clear any existing handlers to avoid duplicates
    logger.handlers.clear()

    # Set the logger level
    logger.setLevel(level)

    # Determine format string based on mode
    if format_string is None:
        if cli_mode:
            # Simple format for CLI tools
            format_string = "%(name)s - %(levelname)s: %(message)s"
        else:
            # More detailed format for library usage
            format_string = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)

    if cli_mode:
        # Use colored formatter for CLI
        formatter = ColoredFormatter(format_string)
    else:
        # Use standard formatter for library
        formatter = logging.Formatter(format_string)

    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        # Always use standard formatter for file output (no colors)
        file_formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s"
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str = "sev_pytools") -> logging.Logger:
    """
    Get a logger instance with the given name.

    Args:
        name: Logger name (default: "sev_pytools")

    Returns:
        Logger instance
    """
    return logging.getLogger(name)


def setup_cli_logging(
    verbose: bool = False, quiet: bool = False, log_file: Optional[str] = None
) -> logging.Logger:
    """
    Convenience function to set up logging for CLI tools.

    Args:
        verbose: Enable verbose logging
        quiet: Enable quiet mode
        log_file: Optional log file path

    Returns:
        Configured logger instance
    """
    return setup_logging(cli_mode=True, verbose=verbose, quiet=quiet, log_file=log_file)


def setup_library_logging(
    level: Union[str, int] = logging.INFO, log_file: Optional[str] = None
) -> logging.Logger:
    """
    Convenience function to set up logging for library usage.

    Args:
        level: Logging level
        log_file: Optional log file path

    Returns:
        Configured logger instance
    """
    return setup_logging(cli_mode=False, level=level, log_file=log_file)


# At the moment these functions are called from logger in the logs rather than their parent
logger = get_logger(__name__)


def log_function_entry(func_name: str, *args, **kwargs) -> None:
    """Log function entry with arguments (for debugging)."""
    args_str = ", ".join(str(arg) for arg in args)
    kwargs_str = ", ".join(f"{k}={v}" for k, v in kwargs.items())
    all_args = ", ".join(filter(None, [args_str, kwargs_str]))
    logger.debug(f"Entering {func_name}({all_args})")


def log_function_exit(func_name: str, result=None) -> None:
    """Log function exit with result (for debugging)."""
    if result is not None:
        logger.debug(f"Exiting {func_name} with result: {result}")
    else:
        logger.debug(f"Exiting {func_name}")


def log_verification_step(
    step: str, status: str, details: str = "", log: Optional[logging.Logger] = None
) -> None:
    """Log a verification step with status."""
    _log = log or logger
    status_upper = status.upper()
    detail_str = f" {details}" if details else ""
    if status_upper in ["PASS", "SUCCESS", "OK"]:
        _log.info(f"✓ {step}:{detail_str} {status}")
    elif status_upper in ["FAIL", "FAILED", "ERROR"]:
        _log.error(f"! {step}:{detail_str} {status}")
    elif status_upper in ["SKIP", "SKIPPED"]:
        _log.warning(f"- {step}:{detail_str} {status}")
    else:
        _log.info(f"  {step}:{detail_str} {status}")


def log_certificate_info(
    cert_type: str, subject: str, issuer: str = "", details: str = ""
) -> None:
    """Log certificate information."""
    msg = f"{cert_type} certificate - Subject: {subject}"
    if issuer:
        msg += f", Issuer: {issuer}"
    if details:
        msg += f" - {details}"
    logger.info(msg)


def log_policy_validation(policy_name: str, status: str, details: str = "") -> None:
    """Log policy validation results."""
    log_verification_step(f"Policy '{policy_name}' validation", status, details)


def log_network_request(
    url: str, method: str = "GET", status_code: Optional[int] = None
) -> None:
    """Log network requests."""
    msg = f"{method} {url}"
    if status_code is not None:
        msg += f" - Status: {status_code}"
    logger.debug(msg)


def log_section_header(title: str) -> None:
    """Log a section header (for logging only, no console output)."""
    logger.debug(f"Section: {title}")


def log_subsection_header(title: str) -> None:
    """Log a subsection header (for logging only, no console output)."""
    logger.debug(f"Subsection: {title}")

"""Utility functions for Grandstream Home API library."""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

_LOGGER = logging.getLogger(__name__)

# Sensitive fields that should be masked in logs
SENSITIVE_FIELDS = {
    "password",
    "access_token",
    "token",
    "session_id",
    "secret",
    "key",
    "credential",
    "sid",
    "dwt",
    "jwt",
}


def format_host_url(host: str) -> str:
    """Format host URL with square brackets for IPv6 addresses.

    Args:
        host: IP address or hostname

    Returns:
        Formatted host string (IPv6 addresses wrapped in brackets)

    """
    try:
        if ipaddress.ip_address(host).version == 6:
            return f"[{host}]"
    except ValueError:
        # Not a valid IP address, return as is
        pass
    return host


def mask_sensitive_data(data: Any) -> Any:
    """Mask sensitive fields in data for safe logging.

    Args:
        data: Data to mask (dict, list, or other)

    Returns:
        Data with sensitive fields masked as ***

    """
    if isinstance(data, dict):
        return {
            k: "***"
            if k.lower() in SENSITIVE_FIELDS or k in SENSITIVE_FIELDS
            else mask_sensitive_data(v)
            for k, v in data.items()
        }
    if isinstance(data, list):
        return [mask_sensitive_data(item) for item in data]
    return data

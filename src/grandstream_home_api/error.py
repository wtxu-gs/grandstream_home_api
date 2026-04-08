"""Custom exceptions for Grandstream Home API library."""


class GrandstreamError(Exception):
    """Base exception for Grandstream Home API."""


class GrandstreamLoginError(GrandstreamError):
    """Exception raised when login fails."""


class GrandstreamAuthTokenError(GrandstreamError):
    """Exception raised when access token acquisition fails."""


class GrandstreamChallengeError(GrandstreamError):
    """Exception raised when challenge code is invalid or expired."""


class GrandstreamHAControlDisabledError(GrandstreamError):
    """Exception raised when Home Assistant control is disabled on device."""


class GrandstreamRTSPError(GrandstreamError):
    """Exception raised when RTSP operations fail."""


class GrandstreamSignatureError(GrandstreamError):
    """Exception raised when signature verification fails."""


class GrandstreamUnlockError(GrandstreamError):
    """Exception raised when door unlock operation fails."""

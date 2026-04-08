"""GDS Phone API."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from functools import wraps
import hashlib
import hmac
import json
import logging
import socket
import time
from typing import Any, TypeVar

import requests
from requests import RequestException, Session
import urllib3

from grandstream_home_api.const import (
    ACCEPT_JSON,
    ACCESS_TOKEN_TTL,
    CONTENT_TYPE_FORM,
    CONTENT_TYPE_JSON,
    DEFAULT_USERNAME,
    DEVICE_TYPE_GDS,
    DOOR_ACTION_LOCK,
    DOOR_ACTION_UNLOCK,
    GDS_TIMEOUT_CONNECT,
    GDS_TIMEOUT_READ,
    GDS_TIMEOUT_SOCKET_CHECK,
    HEADER_CONTENT_TYPE,
    HTTP_METHOD_GET,
    HTTP_METHOD_POST,
    UNLOCK_CODE_AUTH_FAILED,
    UNLOCK_CODE_CHALLENGE_INVALID,
    UNLOCK_CODE_MATERIAL_EMPTY,
    UNLOCK_CODE_PERMISSION_DENIED,
    UNLOCK_CODE_SUCCESS,
    UNLOCK_CODE_TIMESTAMP_EXPIRED,
)
from grandstream_home_api.error import (
    GrandstreamAuthTokenError,
    GrandstreamChallengeError,
    GrandstreamHAControlDisabledError,
    GrandstreamRTSPError,
    GrandstreamSignatureError,
    GrandstreamUnlockError,
)
from grandstream_home_api.utils import format_host_url, mask_sensitive_data

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_LOGGER = logging.getLogger(__name__)

T = TypeVar("T")

# API Endpoints
ENDPOINT_ACCESS = "access"
ENDPOINT_LOGIN = "dologin"
ENDPOINT_PHONE_STATUS = "api-get_phone_status"
ENDPOINT_GDS_GNS_CONFIG = "api-gds_gns_config"
ENDPOINT_SYS_OPERATION = "api-sys_operation"
ENDPOINT_GET_ACCOUNTS = "api-get_accounts"  # Get SIP accounts status

# Default Values
DEFAULT_RTSP_PORT = 554
DEFAULT_RTSP_USERNAME = "admin"
DEFAULT_HTTP_PORT = 80
DEFAULT_HTTPS_PORT = 443
DEFAULT_VERSION = "18.0.1.26"


# Response Status
RESPONSE_SUCCESS = "success"
RESPONSE_ERROR = "error"

# Session States
SESSION_EXPIRED = "session-expired"
ACCOUNT_LOCKED = "locked"

# RTSP Stream Paths
RTSP_SUB_STREAM = "/grandstream/sub_stream"

# HTTP Headers
HEADER_ORIGIN = "Origin"
HEADER_HOST = "Host"
HEADER_ACCEPT = "Accept"
HEADER_ACCEPT_ENCODING = "Accept-Encoding"
HEADER_ACCEPT_LANGUAGE = "Accept-Language"
HEADER_CONNECTION = "Connection"
HEADER_COOKIE = "Cookie"
HEADER_X_REQUESTED_WITH = "X-Requested-With"

ACCEPT_ENCODING_GZIP = "gzip, deflate"
ACCEPT_LANGUAGE_EN = "en-US,en;q=0.5"

# Connection Values
CONNECTION_KEEP_ALIVE = "keep-alive"


@dataclass
class APIResponse:
    """Standardized API response structure."""

    success: bool
    data: Any = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "response": RESPONSE_SUCCESS if self.success else RESPONSE_ERROR,
            "body": self.data if self.success else self.error,
        }


class GDSPhoneAPI:
    """GDS Phone API implementation with optimized architecture.

    Features:
    - Unified error handling
    - Request caching for performance
    - Session management with auto-retry
    - Type-safe methods with proper annotations
    - Constants-based configuration
    """

    def __init__(
        self,
        host: str | None = None,
        username: str | None = None,
        password: str | None = None,
        rtsp_username: str | None = None,
        rtsp_password: str | None = None,
        port: int = 443,
        verify_ssl: bool = False,
    ) -> None:
        """Initialize GDS Phone API.

        Args:
            host: Device IP address or hostname
            username: Device login username
            password: Device login password (plain text, also used for unlock_door)
            rtsp_username: RTSP username
            rtsp_password: RTSP password
            port: Device port (default: 443 for HTTPS)
            verify_ssl: Verify SSL certificate (default: False)

        """
        # Core attributes
        self.host = host
        self.username = username
        self.password = password
        self.device_type = DEVICE_TYPE_GDS
        self.port = port
        self.use_https = True  # GDS always uses HTTPS

        if not self.host:
            raise ValueError("Host is required")

        # Build base addresses - GDS always uses HTTPS
        host_url = format_host_url(self.host)
        if self.port == 443:
            self.base_address = f"https://{host_url}"
        else:
            self.base_address = f"https://{host_url}:{self.port}"

        # Session setup
        self.session: Session = requests.Session()
        self.session.verify = verify_ssl  # Configure SSL verification based on setting

        self.base_url: str = f"{self.base_address}/cgi-bin/"
        self.base_url_root: str = f"{self.base_address}/"

        # Runtime state
        self.session_id: str | None = None
        self.device_mac: str | None = None
        self.version: str | None = None
        self.ha_ip_address: str | None = None

        # RTSP configuration
        self.rtsp_username = rtsp_username
        self.rtsp_password = rtsp_password

        # Login failure tracking to prevent account lockout
        self._login_failed_count: int = 0
        self._last_login_attempt: float = 0
        self._account_locked: bool = False
        self._account_lock_expire_time: float = 0

        # Authentication and connection state tracking
        self._is_authenticated: bool = False
        self._is_online: bool = False

        # Home Assistant control status tracking
        self._is_ha_control_enabled: bool = True  # Default to True, will be set to False if "user is not allow" error occurs

        # Access token management for unlock_door feature
        self._access_token: str | None = None
        self._access_token_time: float | None = None
        self._access_token_ttl: int = ACCESS_TOKEN_TTL  # 55 minutes in seconds

        _LOGGER.debug(
            "GDSPhoneAPI initialized: host=%s, port=%s",
            host,
            self.port,
        )

    # ==================== Decorators ====================

    @staticmethod
    def _require_auth(func: Callable[..., T]) -> Callable[..., T]:
        """Ensure authentication before API calls."""

        @wraps(func)
        def wrapper(self: GDSPhoneAPI, *args: Any, **kwargs: Any) -> T:
            self._ensure_authenticated()
            return func(self, *args, **kwargs)

        return wrapper

    @staticmethod
    def _handle_session_retry(
        func: Callable[..., Any],
    ) -> Callable[..., Any]:
        """Handle session expiration with auto-retry.

        Works with methods that return dict or other types.
        For dict returns, checks _is_session_expired.
        For non-dict returns, wraps in try-except to handle session expiration.
        """

        @wraps(func)
        def wrapper(self: GDSPhoneAPI, *args: Any, **kwargs: Any) -> Any:
            # First attempt
            result = func(self, *args, **kwargs)

            # For dict results, check for session expiration
            if isinstance(result, dict) and self._is_session_expired(result):
                _LOGGER.info("Session expired, re-authenticating")
                self._is_authenticated = False
                if self.login():
                    _LOGGER.info("Re-authentication successful, retrying")
                    return func(self, *args, **kwargs)
                _LOGGER.error("Re-authentication failed")
                # For dict returns, return error dict
                return APIResponse(
                    success=False, error="Re-authentication failed"
                ).to_dict()

            return result

        return wrapper

    # ==================== Helper Methods ====================

    def _build_headers(
        self, content_type: str = CONTENT_TYPE_FORM, include_auth: bool = True
    ) -> dict[str, str]:
        """Build HTTP headers with optional authentication.

        Args:
            content_type: Content-Type header value
            include_auth: Include authentication Cookie

        Returns:
            Headers dictionary

        """
        if self.host is None:
            raise ValueError("Host must be set before making requests")
        headers = {
            HEADER_ORIGIN: self.base_address,
            HEADER_HOST: (
                f"{format_host_url(self.host)}:{self.port}"
                if self.port not in [DEFAULT_HTTP_PORT, DEFAULT_HTTPS_PORT]
                else f"{format_host_url(self.host)}"
            ),
            HEADER_ACCEPT: ACCEPT_JSON,
            HEADER_ACCEPT_ENCODING: ACCEPT_ENCODING_GZIP,
            HEADER_ACCEPT_LANGUAGE: ACCEPT_LANGUAGE_EN,
            HEADER_CONNECTION: CONNECTION_KEEP_ALIVE,
            HEADER_CONTENT_TYPE: content_type,
            HEADER_X_REQUESTED_WITH: "XMLHttpRequest",
        }

        if include_auth and self.session_id and self.device_mac:
            headers[HEADER_COOKIE] = (
                f"oem=0; device={self.device_mac}; "
                f"version={self.version or DEFAULT_VERSION}; "
                f"locale=en; sid={self.session_id}; "
                f"session-role={DEFAULT_USERNAME}; session-identity={self.session_id}"
            )
            _LOGGER.debug("Authentication cookie added")

        return headers

    def _generate_hmac_signature(self, key: str, message: str) -> str:
        """Generate HMAC-SHA256 signature.

        Args:
            key: Signing key (gdsha_pwd or access_token)
            message: Message to sign (fields joined with colon)

        Returns:
            64-character hexadecimal signature string

        """
        key_bytes = key.encode("utf-8")
        message_bytes = message.encode("utf-8")
        signature = hmac.new(key_bytes, message_bytes, hashlib.sha256)
        return signature.hexdigest()

    def _is_access_token_valid(self) -> bool:
        """Check if access token is valid.

        Returns:
            True if token exists and is not expired

        """
        if not self._access_token or not self._access_token_time:
            return False

        elapsed = time.time() - self._access_token_time
        return elapsed < self._access_token_ttl

    def _refresh_access_token(self) -> str:
        """Refresh access token.

        Returns:
            New access token

        """
        self._access_token = None
        self._access_token_time = None
        return self._get_access_token()

    def _check_http_401_error(self, response: dict[str, Any]) -> bool:
        """Check if response indicates HTTP 401 unauthorized error.

        Args:
            response: API response dictionary

        Returns:
            True if HTTP 401 error detected

        """
        body = response.get("body")
        return (
            response.get("response") == RESPONSE_ERROR
            and body is not None
            and "401" in str(body)
        )

    def _handle_unlock_error_code(self, code: str, operation: str) -> None:
        """Handle common unlock operation error codes.

        Args:
            code: Error code from API response
            operation: Operation name for logging (e.g., "get access token")

        Raises:
            RuntimeError: For authentication failures (code -100 in step 0)
            GrandstreamSignatureError: For signature verification failures (code -100 in steps 1-2)
            GrandstreamAuthTokenError: For token-related errors
            GrandstreamUnlockError: For unlock operation errors

        """
        if code == UNLOCK_CODE_AUTH_FAILED:
            # Code -100 has different meanings in different steps
            if operation == "access_token":
                _LOGGER.error("Authentication failed: Invalid password")
                raise RuntimeError("Invalid password for unlock_door")
            # For challenge and unlock steps, -100 means signature verification failed
            _LOGGER.warning("Signature verification failed")
            raise GrandstreamSignatureError("Signature verification failed")

        if code == UNLOCK_CODE_MATERIAL_EMPTY:
            _LOGGER.error("Material for generating token is empty")
            if operation == "access_token":
                raise GrandstreamAuthTokenError("Material is empty")
            raise GrandstreamUnlockError("Material is empty")

        if code == UNLOCK_CODE_TIMESTAMP_EXPIRED:
            _LOGGER.warning("Timestamp expired")
            if operation == "access_token":
                raise GrandstreamAuthTokenError("Timestamp expired")
            raise GrandstreamUnlockError("Timestamp expired")

        if code == UNLOCK_CODE_PERMISSION_DENIED:
            _LOGGER.error("Permission denied")
            if operation == "access_token":
                raise GrandstreamAuthTokenError("Permission denied")
            raise GrandstreamUnlockError("Permission denied")

        if code == UNLOCK_CODE_CHALLENGE_INVALID:
            _LOGGER.warning("Challenge code is invalid or expired")
            raise GrandstreamChallengeError("Challenge code is invalid")

        # Unknown error code
        _LOGGER.error("Unknown error code: %s", code)
        if operation == "access_token":
            raise GrandstreamAuthTokenError(f"Unknown error code: {code}")
        raise GrandstreamUnlockError(f"Unknown error code: {code}")

    def _make_request(
        self,
        method: str,
        endpoint: str,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        use_root_url: bool = False,
    ) -> dict[str, Any]:
        """Unified request method with standardized error handling.

        Args:
            method: HTTP method (GET/POST/PUT)
            endpoint: API endpoint
            params: Query parameters
            data: Form data
            json_data: JSON body
            headers: Custom headers
            use_root_url: Use root URL instead of cgi-bin URL

        Returns:
            Parsed JSON response or error dict

        """
        base_url = self.base_url_root if use_root_url else self.base_url
        url = f"{base_url}{endpoint}"

        # Log request details
        _LOGGER.debug(
            "Making API request: %s %s, params=%s, data=%s, json_data=%s",
            method.upper(),
            url,
            params,
            (
                {k: "***" if "password" in k.lower() else v for k, v in data.items()}
                if data
                else None
            ),
            (
                {
                    k: "***" if "password" in k.lower() else v
                    for k, v in json_data.items()
                }
                if json_data
                else None
            ),
        )

        try:
            response = self.session.request(
                method=method.upper(),
                url=url,
                params=params,
                data=data,
                json=json_data,
                headers=headers,
                timeout=(GDS_TIMEOUT_CONNECT, GDS_TIMEOUT_READ),
            )

            _LOGGER.debug(
                "Request: %s %s, Status: %s",
                method.upper(),
                endpoint,
                response.status_code,
            )

            if response.status_code == 200:
                response_json = response.json()
                # Log response details (masking sensitive data)
                _LOGGER.debug(
                    "Response from %s: %s", endpoint, mask_sensitive_data(response_json)
                )
                self._is_online = True  # Device responded successfully, mark as online

                # Check and update HA control status
                if self._check_ha_control_disabled(response_json):
                    self._handle_ha_control_disabled()
                else:
                    # Reset HA control status if no longer disabled
                    self._handle_ha_control_enabled()

                return response_json

            _LOGGER.error("HTTP error %s for %s", response.status_code, endpoint)
            return APIResponse(
                success=False, error=f"HTTP {response.status_code}"
            ).to_dict()

        except requests.exceptions.SSLError as e:
            _LOGGER.error("SSL error for %s: %s", endpoint, e)
            self._is_online = False
            return APIResponse(success=False, error=f"SSL error: {e}").to_dict()
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            _LOGGER.error("Connection/Timeout error for %s: %s", endpoint, e)
            self._is_online = False
            return APIResponse(success=False, error=f"Connection failed: {e}").to_dict()
        except (ValueError, KeyError, json.JSONDecodeError) as e:
            _LOGGER.error("JSON parse error for %s: %s", endpoint, e)
            self._is_online = True  # Device is online, but response is invalid
            return APIResponse(success=False, error=f"Invalid response: {e}").to_dict()
        except RequestException as e:
            _LOGGER.error("Request error for %s: %s", endpoint, e)
            self._is_online = False  # General request exception, assume offline
            return APIResponse(success=False, error=str(e)).to_dict()

    def _ensure_authenticated(self) -> None:
        """Ensure user is authenticated, login if necessary."""
        if not self.session_id:
            # If device is reported offline, no need to attempt login
            if not self._is_online:
                _LOGGER.warning("Device is offline, skipping authentication attempt")
                raise RuntimeError("Device is offline")

            # Check if account is locked
            if self._account_locked and time.time() < self._account_lock_expire_time:
                remaining_time = int(self._account_lock_expire_time - time.time())
                raise RuntimeError(
                    f"Account is locked. Will wait {remaining_time} seconds before retrying"
                )

            # Check login failure threshold
            if self._login_failed_count >= 2:
                # Wait at least 60 seconds before allowing retry after multiple failures
                time_since_last_attempt = time.time() - self._last_login_attempt
                if time_since_last_attempt < 300:
                    raise RuntimeError(
                        f"Too many login failures. Will wait {int(300 - time_since_last_attempt)} seconds before retrying"
                    )
                # Reset counter after waiting period
                self._login_failed_count = 0

            _LOGGER.info("Not authenticated, attempting login")
            if not self.login():
                raise RuntimeError("Authentication failed")
            _LOGGER.info("Authentication successful")

    @staticmethod
    def _is_session_expired(response: dict[str, Any]) -> bool:
        """Check if response indicates session expiration.

        Args:
            response: API response dictionary

        Returns:
            True if session expired

        """
        if not isinstance(response, dict):
            return False

        # Check for 'unauthorized' in body (string format)
        if (
            response.get("response") == RESPONSE_SUCCESS
            and response.get("body") == "unauthorized"
        ):
            return True

        # Check for session-expired in body (dict format)
        if (
            response.get("response") == RESPONSE_ERROR
            and isinstance(response.get("body"), dict)
            and response["body"].get("status") == SESSION_EXPIRED
        ):
            return True

        # Check for HTTP 401 error (unauthorized)
        if (
            response.get("response") == RESPONSE_ERROR
            and isinstance(response.get("body"), str)
            and "401" in response["body"]
        ):
            return True  # pragma: no cover

        return False

    # ==================== Authentication ====================

    def login(self) -> bool:
        """Perform GDS device login.

        Returns:
            True if login successful

        """
        _LOGGER.info("Attempting GDS device login")
        return self._perform_login()

    def _get_challenge(self) -> str:
        """Get authentication challenge token.

        Returns:
            Challenge token

        Raises:
            RuntimeError: If challenge retrieval fails

        """
        # Generate a random challenge access hass
        challenge_access_hass = hashlib.sha256(str(time.time()).encode()).hexdigest()
        data = {"access": challenge_access_hass}
        headers = self._build_headers(include_auth=False)

        _LOGGER.debug("Requesting challenge token with hass: %s", challenge_access_hass)
        response = self._make_request(
            HTTP_METHOD_POST, ENDPOINT_ACCESS, data=data, headers=headers
        )

        if response.get("response") == RESPONSE_SUCCESS:
            challenge = response.get("body")
            _LOGGER.debug("Challenge token received")
            if challenge is None:
                raise RuntimeError("Challenge token is None")
            return str(challenge)

        error_msg = f"Failed to get challenge: {response}"
        _LOGGER.error("%s", error_msg)
        raise RuntimeError(error_msg)

    def _generate_login_secret(self, challenge: str) -> str:
        """Generate SHA256 hass for login.

        Args:
            challenge: Challenge token from device

        Returns:
            SHA256 hassed password

        """
        login_string = f"{self.password}{challenge}"
        return hashlib.sha256(login_string.encode("utf-8")).hexdigest()

    def _perform_login(self) -> bool:
        """Execute login process.

        Returns:
            True if successful

        """
        try:
            # Check if account is locked
            if self._account_locked and time.time() < self._account_lock_expire_time:
                remaining_time = int(self._account_lock_expire_time - time.time())
                _LOGGER.warning(
                    "Account is locked. Will wait %d seconds before retrying",
                    remaining_time,
                )
                return False

            # Record login attempt time
            self._last_login_attempt = time.time()

            # Get challenge
            challenge = self._get_challenge()

            # Generate secret
            secret = self._generate_login_secret(challenge)

            # Perform login
            data = {"username": self.username, "password": secret}
            headers = self._build_headers(include_auth=False)

            _LOGGER.debug("Sending login request")
            response = self._make_request(
                HTTP_METHOD_POST, ENDPOINT_LOGIN, data=data, headers=headers
            )

            if response.get("response") == RESPONSE_SUCCESS:
                body = response.get("body", {})
                self.session_id = body.get("sid")
                self.device_mac = body.get("mac")
                self.version = body.get("ver")

                _LOGGER.info(
                    "Login successful: session_id=***, MAC=%s, version=%s",
                    self.device_mac,
                    self.version,
                )

                if not all([self.session_id, self.device_mac, self.version]):
                    _LOGGER.warning("Login response missing some fields: %s", body)

                # Reset failure count and set authentication/online state on success
                self._login_failed_count = 0
                self._account_locked = False
                self._is_authenticated = True
                self._is_online = True
                return True

            # Check if account is locked
            if (
                response.get("response") == RESPONSE_ERROR
                and response.get("body") == "locked"
            ):
                lock_time = response.get("lockTime", 300)
                _LOGGER.error(
                    "Login failed: Account is locked. Lock time: %d seconds "
                    "Will wait for the lock to expire before trying again",
                    lock_time,
                )
                # Mark account as locked and set expiration time
                self._account_locked = True
                self._account_lock_expire_time = time.time() + lock_time
                self._login_failed_count = 0  # Reset counter when locked
                self._is_authenticated = False
                # Device is online but account is locked
                self._is_online = True
                return False

            # Login failed - this is an authentication failure, increment count
            self._login_failed_count += 1
            _LOGGER.error(
                "Authentication failed (attempt %d/3): %s",
                self._login_failed_count,
                response,
            )

            # Warn if approaching lockout threshold
            if self._login_failed_count >= 2:
                _LOGGER.warning(
                    "Multiple authentication failures detected (%d/3) "
                    "Further failures may lock the account for 5 minutes",
                    self._login_failed_count,
                )

            self._is_authenticated = False
            # Device is online but authentication failed (wrong credentials)
            self._is_online = True
        except requests.exceptions.ConnectionError as e:
            # Connection errors should not increment login failure count
            # They indicate device is offline, not authentication failure
            _LOGGER.warning(
                "Device connection failed during login (device may be offline): %s", e
            )
            self._is_authenticated = False
            self._is_online = False
        except RuntimeError as e:
            # Check if this is a "device offline" error (not authentication failure)
            if "offline" in str(e).lower():
                _LOGGER.warning("Login skipped: %s", e)
                self._is_authenticated = False
            else:
                # This is likely an authentication failure
                self._login_failed_count += 1
                _LOGGER.error(
                    "Login failed (attempt %d/3): %s", self._login_failed_count, e
                )
                self._is_authenticated = False
        except (ValueError, KeyError, json.JSONDecodeError) as e:
            # These are likely authentication-related errors
            self._login_failed_count += 1
            _LOGGER.error("Login error (attempt %d/3): %s", self._login_failed_count, e)
            self._is_authenticated = False
        except RequestException as e:
            # Check if this is a connection-related error
            if "connection" in str(e).lower() or "timeout" in str(e).lower():
                _LOGGER.warning("Login request failed due to connection issues: %s", e)
                self._is_authenticated = False
                self._is_online = False
            else:
                # Other request errors may count as authentication failures
                self._login_failed_count += 1
                _LOGGER.error(
                    "Login error (attempt %d/3): %s", self._login_failed_count, e
                )
                self._is_authenticated = False
        return self._is_authenticated

    @property
    def is_authenticated(self) -> bool:
        """Check if device is authenticated.

        Returns:
            True if authenticated (has valid session) and not locked

        """
        return (
            self._is_authenticated
            and self.session_id is not None
            and not self._account_locked
        )

    @property
    def is_online(self) -> bool:
        """Check if device is online and reachable.

        Returns:
            True if device is online (regardless of authentication state)

        """
        return self._is_online

    @property
    def is_account_locked(self) -> bool:
        """Check if account is locked.

        Returns:
            True if account is currently locked

        """
        # Check if lock has expired
        if self._account_locked and time.time() >= self._account_lock_expire_time:
            self._account_locked = False
            _LOGGER.info("Account lock has expired, resetting lock status")
        return self._account_locked

    @property
    def is_ha_control_enabled(self) -> bool:
        """Check if Home Assistant control is enabled on device.

        Returns:
            True if HA control is enabled (user is not disabled)

        """
        return self._is_ha_control_enabled

    def _check_ha_control_disabled(self, response: dict[str, Any]) -> bool:
        """Check if response indicates HA control is disabled.

        This checks for the "user is not allow" error which indicates
        the device has disabled Home Assistant control.

        Args:
            response: API response dictionary

        Returns:
            True if HA control is disabled

        """
        if not isinstance(response, dict):
            return False

        # Check for "user is not allow" message
        if (
            response.get("response") == RESPONSE_ERROR
            and isinstance(response.get("message"), str)
            and "user is not allow" in response["message"].lower()
        ):
            return True

        return False

    def _handle_ha_control_disabled(self) -> None:
        """Handle HA control disabled state.

        Sets the internal flag and logs a warning message.

        """
        if self._is_ha_control_enabled:
            self._is_ha_control_enabled = False
            _LOGGER.warning("Home Assistant control is disabled on the device. ")
            # Raise exception to notify the caller that HA control is disabled
            raise GrandstreamHAControlDisabledError(
                "Home Assistant control is disabled on the device. "
            )

    def _handle_ha_control_enabled(self) -> None:
        """Handle HA control enabled state.

        Resets the internal flag when HA control is confirmed working.

        """
        if not self._is_ha_control_enabled:
            self._is_ha_control_enabled = True
            _LOGGER.info("Home Assistant control is now enabled on the device")

    @_require_auth
    @_handle_session_retry
    def get_phone_status(self) -> dict[str, Any]:
        """Get device status using session authentication.

        Returns:
            Status response dictionary

        """
        headers = self._build_headers()
        response = self._make_request(
            HTTP_METHOD_GET, ENDPOINT_PHONE_STATUS, headers=headers
        )

        if response.get("response") == RESPONSE_SUCCESS:
            _LOGGER.debug("Device status retrieved: %s", response)

        return response

    @_require_auth
    @_handle_session_retry
    def get_accounts(self, registered: bool | None = None) -> dict[str, Any]:
        """Get SIP accounts status including registration state.

        Args:
            registered: Optional filter - True for registered only, False for unregistered only, None for all

        Returns:
            SIP accounts status dictionary containing array of accounts:
            - sip_id: SIP account ID
            - name: Account name
            - reg: Registration status (number)
            - sip_server: SIP server address

        """
        headers = self._build_headers()
        params = {}
        if registered is not None:
            params["registered"] = "true" if registered else "false"

        response = self._make_request(
            HTTP_METHOD_GET, ENDPOINT_GET_ACCOUNTS, headers=headers, params=params
        )

        if response.get("response") == RESPONSE_SUCCESS:
            _LOGGER.debug("SIP accounts status retrieved: %s", response)

        return response

    @_require_auth
    @_handle_session_retry
    def reboot_device(self) -> dict[str, Any]:
        """Reboot the device.

        Returns:
            Reboot response dictionary

        """
        params = {"request": "REBOOT"}
        response = self._make_request(
            HTTP_METHOD_GET, ENDPOINT_SYS_OPERATION, params=params
        )
        _LOGGER.info("Reboot response: %s", response)
        return response

    def get_rtsp_url(self) -> str:
        """Get RTSP streaming URL.

        Returns:
            RTSP URL string

        Raises:
            GrandstreamRTSPError: If credentials are missing or port unreachable

        """
        if not self.rtsp_username or not self.rtsp_password:
            raise GrandstreamRTSPError(
                "RTSP credentials missing. Please configure rtsp_username and rtsp_password."
            )

        if not self.host:
            raise GrandstreamRTSPError("Host is not configured")

        rtsp_port = DEFAULT_RTSP_PORT

        # Check port reachability
        try:
            sock = socket.create_connection(
                (self.host, rtsp_port), timeout=GDS_TIMEOUT_SOCKET_CHECK
            )
            sock.close()
        except OSError:
            _LOGGER.warning(
                "RTSP port %s on %s is unreachable. Ensure RTSP is enabled",
                rtsp_port,
                self.host,
            )

        host_url = format_host_url(self.host)
        rtsp_url = (
            f"rtsp://{self.rtsp_username}:{self.rtsp_password}@"
            f"{host_url}:{rtsp_port}{RTSP_SUB_STREAM}"
        )

        _LOGGER.info(
            "RTSP URL generated: rtsp://%s:***@%s:%s%s",
            self.rtsp_username,
            host_url,
            rtsp_port,
            RTSP_SUB_STREAM,
        )
        return rtsp_url

    @_require_auth
    @_handle_session_retry
    def register_ha_urls(
        self,
        status_url: str,
        command_url: str,
        ha_instance_id: str | None = None,
        timestamp: int | None = None,
    ) -> dict[str, Any]:
        """Register Home Assistant webhook URLs.

        Args:
            status_url: Status push URL
            command_url: Command result URL
            ha_instance_id: Optional HA instance ID
            timestamp: Optional timestamp (defaults to current time)

        Returns:
            Registration response dictionary

        """
        params = {"cmd": "set", "type": "gns_ha_register"}

        payload = {
            "status_url": status_url,
            "command_url": command_url,
            "timestamp": timestamp or int(time.time()),
        }

        if ha_instance_id:
            payload["ha_instance_id"] = ha_instance_id

        headers = self._build_headers(content_type=CONTENT_TYPE_JSON)
        _LOGGER.debug("Registering HA URLs: %s", payload)

        response = self._make_request(
            HTTP_METHOD_POST,
            ENDPOINT_GDS_GNS_CONFIG,
            params=params,
            json_data=payload,
            headers=headers,
        )

        _LOGGER.info("HA URL registration response: %s", response)
        return response

    @_require_auth
    @_handle_session_retry
    def reset_all_alarms(self) -> dict[str, Any]:
        """Reset all alarms.

        Returns:
            Response dictionary

        """
        params = {"cmd": "get", "type": "reset"}
        headers = self._build_headers(content_type=CONTENT_TYPE_JSON)
        json_body = {"gdsAlarmOpt": {"opt": "reset"}}
        response = self._make_request(
            HTTP_METHOD_POST,
            "api-gds_config",
            params=params,
            json_data=json_body,
            headers=headers,
        )
        _LOGGER.info("Reset tamper alarm response: %s", response)
        return response

    # ==================== Door Unlock Feature (Three-Step Authentication) ====================

    @_require_auth
    @_handle_session_retry
    def _get_access_token_response(self) -> dict[str, Any]:
        """Get access token response (Step 0) - internal method that returns dict.

        Returns:
            Response dictionary

        Raises:
            GrandstreamAuthTokenError: If password is not set

        """
        if not self.password:
            raise GrandstreamAuthTokenError(
                "Password is required for unlock_door feature"
            )

        # At this point, password is guaranteed to be str (not None)
        password: str = self.password

        # Generate timestamp
        timestamp = str(int(time.time()))

        # Generate signature message: "password:timestamp:user"
        message = f"{password}:{timestamp}:{DEFAULT_USERNAME}"
        signature = self._generate_hmac_signature(password, message)

        # Construct request
        params = {"cmd": "0", "type": "gns_ha_action"}
        payload = {
            "user": DEFAULT_USERNAME,
            "timestamp": timestamp,
            "signature": signature,
        }

        headers = self._build_headers(content_type=CONTENT_TYPE_JSON, include_auth=True)

        _LOGGER.debug("Requesting access token")
        response = self._make_request(
            HTTP_METHOD_POST,
            ENDPOINT_GDS_GNS_CONFIG,
            params=params,
            json_data=payload,
            headers=headers,
        )

        # Debug: log response details (mask sensitive data)
        _LOGGER.debug("Access token response: %s", mask_sensitive_data(response))

        return response

    def _get_access_token(self) -> str:
        """Get access token (Step 0).

        Returns:
            36-character UUID-v4 format access token

        Raises:
            GrandstreamAuthTokenError: Token acquisition failed
            RuntimeError: Authentication failed (password error)

        """
        # Check cache
        if self._is_access_token_valid():
            _LOGGER.debug("Using cached access token")
            return self._access_token  # type: ignore[return-value]

        if not self.password:
            raise GrandstreamAuthTokenError(
                "Password is required for unlock_door feature"
            )

        # Get response using decorated method (handles session retry)
        response = self._get_access_token_response()

        # Handle response
        if response.get("response") == RESPONSE_SUCCESS:
            code = str(response.get("code", ""))

            if code == UNLOCK_CODE_SUCCESS:
                access_token = response.get("access_token")
                if not access_token:
                    raise GrandstreamAuthTokenError(
                        "Access token not found in response"
                    )

                # Cache token
                self._access_token = access_token
                self._access_token_time = time.time()

                _LOGGER.info("Access token obtained successfully")
                return access_token

            # Handle error codes using helper method
            self._handle_unlock_error_code(code, "access_token")

        raise GrandstreamAuthTokenError("Failed to get access token")

    def _get_challenge_code(self) -> tuple[str, str, str]:
        """Get challenge code and ID code (Step 1).

        Returns:
            Tuple of (challenge_code, id_code, timestamp)

        Raises:
            GrandstreamUnlockError: Challenge code acquisition failed
            GrandstreamSignatureError: Signature verification failed

        """
        # Ensure we have a valid access token
        access_token = self._get_access_token()

        # Generate signature message: "access_token:user"
        message = f"{access_token}:{DEFAULT_USERNAME}"
        signature = self._generate_hmac_signature(access_token, message)

        # Construct request
        params = {"cmd": "1", "type": "gns_ha_action"}
        payload = {
            "user": DEFAULT_USERNAME,
            "signature": signature,
        }

        headers = self._build_headers(
            content_type=CONTENT_TYPE_JSON, include_auth=False
        )

        _LOGGER.debug("Requesting challenge code")
        response = self._make_request(
            HTTP_METHOD_POST,
            ENDPOINT_GDS_GNS_CONFIG,
            params=params,
            json_data=payload,
            headers=headers,
        )

        # Check for HTTP 401 error (unauthorized - token expired/invalid)
        _LOGGER.debug("Challenge response: response=%s", response.get("response"))
        if self._check_http_401_error(response):
            _LOGGER.warning("HTTP 401 error - access token may be expired")
            raise GrandstreamSignatureError("Access token expired or invalid")

        # Handle response
        if response.get("response") == RESPONSE_SUCCESS:
            code = str(response.get("code", ""))

            if code == UNLOCK_CODE_SUCCESS:
                challenge_code = response.get("challenge_code")
                id_code = response.get("id_code")
                timestamp = response.get("timestamp")

                if not all([challenge_code, id_code, timestamp]):
                    raise GrandstreamUnlockError(
                        "Missing required fields in challenge response"
                    )

                _LOGGER.debug(
                    "Challenge code obtained: id_code=%s, timestamp=%s",
                    id_code,
                    timestamp,
                )
                # Type assertion: we've checked they're not None above
                assert challenge_code is not None
                assert id_code is not None
                return challenge_code, id_code, str(timestamp)

            # Handle error codes using helper method
            self._handle_unlock_error_code(code, "challenge")

        raise GrandstreamUnlockError("Failed to get challenge code")

    def _execute_door_action(
        self,
        access_token: str,
        challenge_code: str,
        id_code: str,
        timestamp: str,
        door_id: int,
        action_type: str,
    ) -> dict[str, Any]:
        """Execute door action operation (Step 2).

        Args:
            access_token: Access token
            challenge_code: Challenge code (32 characters)
            id_code: ID code (20 characters)
            timestamp: Timestamp
            door_id: Door ID (0=all doors, 1=door 1, 2=door 2)
            action_type: Action type ("0"=lock, "1"=unlock)

        Returns:
            Result dictionary containing success, door_id, delay_resp_time, hold_time

        Raises:
            GrandstreamUnlockError: Door action operation failed
            GrandstreamSignatureError: Signature verification failed

        """
        # Map door_id to action_obj
        action_obj = str(door_id)

        # Generate signature message: "access_token:action_obj:action_type:timestamp:id_code:challenge_code:user"
        message = (
            f"{access_token}:{action_obj}:{action_type}:"
            f"{timestamp}:{id_code}:{challenge_code}:{DEFAULT_USERNAME}"
        )
        signature = self._generate_hmac_signature(access_token, message)

        # Construct request
        params = {"cmd": "2", "type": "gns_ha_action"}
        payload = {
            "user": DEFAULT_USERNAME,
            "challenge_code": challenge_code,
            "id_code": id_code,
            "timestamp": timestamp,
            "action_type": action_type,
            "action_obj": action_obj,
            "signature": signature,
        }

        headers = self._build_headers(
            content_type=CONTENT_TYPE_JSON, include_auth=False
        )

        action_name = "unlock" if action_type == "1" else "lock"
        _LOGGER.info("Executing %s door operation: door_id=%s", action_name, door_id)
        response = self._make_request(
            HTTP_METHOD_POST,
            ENDPOINT_GDS_GNS_CONFIG,
            params=params,
            json_data=payload,
            headers=headers,
        )

        # Check for HTTP 401 error (unauthorized - token expired/invalid)
        _LOGGER.debug(
            "Door action response: response=%s, body=%s",
            response.get("response"),
            response.get("body"),
        )
        if self._check_http_401_error(response):
            _LOGGER.warning("HTTP 401 error - access token may be expired")
            raise GrandstreamSignatureError("Access token expired or invalid")

        # Handle response
        if response.get("response") == RESPONSE_SUCCESS:
            code = str(response.get("code", ""))

            if code == UNLOCK_CODE_SUCCESS and response.get("result") == "success":
                delay_resp_time = response.get("delay_resp_time")
                hold_time = response.get("hold_time")

                _LOGGER.info(
                    "Door %s successfully: door_id=%s, delay=%s, hold_time=%s",
                    action_name,
                    door_id,
                    delay_resp_time,
                    hold_time,
                )

                return {
                    "success": True,
                    "door_id": door_id,
                    "action_type": action_type,
                    "delay_resp_time": delay_resp_time,
                    "hold_time": hold_time,
                }

            # Handle error codes using helper method
            self._handle_unlock_error_code(code, "door_action")

        raise GrandstreamUnlockError(f"Failed to {action_name} door")

    def _execute_door_operation(
        self, door_id: int, action_type: str, operation_name: str
    ) -> dict[str, Any]:
        """Execute door operation (unlock/lock) with complete workflow.

        Args:
            door_id: Door ID (0=all doors, 1=door 1, 2=door 2)
            action_type: Action type (DOOR_ACTION_UNLOCK or DOOR_ACTION_LOCK)
            operation_name: Operation name for logging (e.g., "unlock", "lock")

        Returns:
            APIResponse dictionary with format:
            Success: {"response": "success", "body": {"door_id": int, "delay_resp_time": int, "hold_time": int}}
            Error: {"response": "error", "body": "error message"}

        """
        # Validate parameter
        if door_id not in [0, 1, 2]:
            return APIResponse(
                success=False,
                error=f"Invalid door_id: {door_id}. Must be 0 (all), 1, or 2",
            ).to_dict()

        max_retries = 1
        retry_count = 0

        while retry_count <= max_retries:
            try:
                # Step 0: Get access token (auto-handles caching)
                access_token = self._get_access_token()

                # Step 1: Get challenge code
                challenge_code, id_code, timestamp = self._get_challenge_code()

                # Step 2: Execute door action
                result = self._execute_door_action(
                    access_token,
                    challenge_code,
                    id_code,
                    timestamp,
                    door_id,
                    action_type,
                )

                # Convert internal result format to APIResponse format
                return APIResponse(
                    success=True,
                    data={
                        "door_id": result["door_id"],
                        "delay_resp_time": result["delay_resp_time"],
                        "hold_time": result["hold_time"],
                    },
                ).to_dict()

            except (
                GrandstreamSignatureError,
                GrandstreamAuthTokenError,
                GrandstreamChallengeError,
            ) as err:
                # Recoverable errors that can be retried:
                # - GrandstreamSignatureError: Signature verification failed (-100) → refresh token
                # - GrandstreamAuthTokenError: Material empty (-200), timestamp expired (-300), permission denied (-400) → refresh token
                # - GrandstreamChallengeError: Challenge code invalid (-500) → get new challenge (no token refresh needed)
                if retry_count < max_retries:
                    error_type = type(err).__name__

                    # Only refresh token for token-related errors
                    if isinstance(
                        err, (GrandstreamSignatureError, GrandstreamAuthTokenError)
                    ):
                        _LOGGER.warning(
                            "%s error, refreshing token and retrying: %s",
                            error_type,
                            err,
                        )
                        self._refresh_access_token()
                    else:
                        # GrandstreamChallengeError: just retry to get new challenge
                        _LOGGER.warning(
                            "%s error, retrying with new challenge: %s", error_type, err
                        )

                    retry_count += 1
                    continue

                _LOGGER.error("%s error after retry: %s", type(err).__name__, err)
                return APIResponse(
                    success=False,
                    error=f"Operation failed: {err}",
                ).to_dict()

            except RequestException as err:
                _LOGGER.error("Connection failed: %s", err)
                return APIResponse(
                    success=False,
                    error=f"Device unreachable: {err}",
                ).to_dict()

            except GrandstreamUnlockError as err:
                _LOGGER.error(
                    "%s operation failed: %s", operation_name.capitalize(), err
                )
                return APIResponse(
                    success=False,
                    error=f"Failed to {operation_name} door: {err}",
                ).to_dict()

            except RuntimeError as err:
                # Handle authentication errors (invalid password)
                _LOGGER.error("Runtime error: %s", err)
                return APIResponse(
                    success=False,
                    error=str(err),
                ).to_dict()

        # Should not reach here
        return APIResponse(
            success=False,
            error=f"{operation_name.capitalize()} operation failed after retries",
        ).to_dict()  # pragma: no cover

    def lock_door(self, door_id: int = 0) -> dict[str, Any]:
        """Execute complete door lock workflow.

        Args:
            door_id: Door ID (0=all doors, 1=door 1, 2=door 2)

        Returns:
            APIResponse dictionary with format:
            Success: {"response": "success", "body": {"door_id": int, "delay_resp_time": int, "hold_time": int}}
            Error: {"response": "error", "body": "error message"}

        """

        return self._execute_door_operation(door_id, DOOR_ACTION_LOCK, "lock")

    def unlock_door(self, door_id: int = 0) -> dict[str, Any]:
        """Execute complete door unlock workflow.

        Args:
            door_id: Door ID (0=all doors, 1=door 1, 2=door 2)

        Returns:
            APIResponse dictionary with format:
            Success: {"response": "success", "body": {"door_id": int, "delay_resp_time": int, "hold_time": int}}
            Error: {"response": "error", "body": "error message"}

        """
        return self._execute_door_operation(door_id, DOOR_ACTION_UNLOCK, "unlock")

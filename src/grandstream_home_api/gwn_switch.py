"""API for GWN Switch devices (e.g., GWN7802P)."""

from __future__ import annotations

import base64
import functools
import json
import logging
import re
from urllib.parse import unquote
from typing import Any, Callable, TypeVar

from functools import wraps

import requests
import urllib3

from grandstream_home_api.const import (
    CONTENT_TYPE_FORM,
    CONTENT_TYPE_JSON,
    DEFAULT_HTTPS_PORT,
    HEADER_AUTHORIZATION,
    HEADER_CONTENT_TYPE,
    HTTP_METHOD_GET,
    HTTP_METHOD_POST,
)
from grandstream_home_api.error import GrandstreamSessionExpiredError
from grandstream_home_api.utils import format_host_url, mask_sensitive_data

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_LOGGER = logging.getLogger(__name__)

# API response status codes
API_SUCCESS_CODE = 0

# Default settings
DEFAULT_GWN_SWITCH_PORT = 443
DEFAULT_GWN_SWITCH_USERNAME = "admin"
GWN_SWITCH_TIMEOUT = 15
# Firmware install streams progress over SSE for several minutes; use a long
# read timeout so the connection isn't dropped mid-upgrade on idle gaps.
FIRMWARE_INSTALL_TIMEOUT = 900

# API endpoint commands (GET)
CMD_SYS_CPUMEM = "sys_cpumem"
CMD_SYS_SYSINFO = "sys_sysinfo"
CMD_HOME_LOGIN_STATUS = "home_loginStatus"
CMD_HOME_LOGIN = "home_login"  # Gets RSA public key (no auth required)
CMD_PORT_PORT_INFORMATION = "port_portInformation"
CMD_PORT_PORT_DETAIL = "port_portDetail"
CMD_PORT_CNT_ALL = "port_cntAll"
CMD_POE_PORT_HISTORY = "poe_porthistory"
CMD_POE_PORT_STATUS = "poe_portStatus"
CMD_POE_STATUS = "poe_status"
CMD_MAC_DYNAMIC = "mac_dynamic"

# API endpoint commands (SET)
CMD_HOME_LOGIN_AUTH = "home_loginAuth"
CMD_SYS_REBOOT = "sys_reboot"
CMD_PORT_PORT_EDIT = "port_portEdit"
CMD_POE_PORT_EDIT = "poe_portEdit"
CMD_POE_SOFT_REBOOT = "poe_sofeReboot"
CMD_MAC_FILTER_BATCH_ADD = "mac_filterBatchAdd"
CMD_MAC_FILTER_DELETE = "mac_filterDelete"
CMD_MAC_FILTER = "mac_filter"

# Type variable for decorators
F = TypeVar("F")


def _require_auth(func: F) -> F:
    """Ensure API method is authenticated before execution."""

    @functools.wraps(func)
    def wrapper(self: GWNSwitchAPI, *args: Any, **kwargs: Any) -> Any:
        if not self._ensure_auth():
            _LOGGER.warning(
                "Cannot execute %s: authentication failed", func.__name__
            )
            return None
        return func(self, *args, **kwargs)

    return wrapper  # type: ignore[return-value]


def _model_supports_poe(model: str | None) -> bool:
    """Return True if a GWN switch model supports PoE.

    GWN's PoE switches carry a trailing "P" in the model name (e.g.
    GWN7802P, GWN7811P, GWN7821P). Non-PoE models such as GWN7801 /
    GWN7803 omit the suffix and have no PoE functionality. When the model
    is unknown we assume PoE is present so already-configured devices keep
    working until the model is resolved.
    """
    if not model:
        return True
    return model.strip().upper().endswith("P")


class GWNSwitchAPI:
    """GWN Switch API client with Token authentication.

    Supports GWN series managed switches (GWN7802P, etc.) via REST API.
    Authentication uses sha256(username:password) encrypted password.
    All requests use /cgi/get.cgi (GET) or /cgi/set.cgi (POST) endpoints.
    """

    def __init__(
        self,
        host: str,
        username: str = DEFAULT_GWN_SWITCH_USERNAME,
        password: str = "",
        port: int = DEFAULT_GWN_SWITCH_PORT,
        use_https: bool = True,
        verify_ssl: bool = False,
        model: str | None = None,
    ) -> None:
        """Initialize GWN Switch API.

        Args:
            host: Device IP address or hostname
            username: Login username (default: admin)
            password: Login password (plain text)
            port: Device HTTPS port (default: 443)
            use_https: Use HTTPS protocol (default: True)
            verify_ssl: Verify SSL certificate (default: False)
            model: Device model (e.g. GWN7802P). Used to skip PoE endpoints
                on non-PoE models (those not ending in "P").

        """
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self._use_https = use_https
        self._verify_ssl = verify_ssl
        self._model = model

        # Session
        self._session = requests.Session()
        self._session.verify = verify_ssl

        # Auth state
        self._token: str | None = None
        self._is_online: bool = False
        self._priv: int | None = None

        # Login failure tracking
        self._login_failed_count: int = 0
        self._is_locked: bool = False
        self._lock_remain_seconds: int = 0

        # PoE: some GWN78xx devices expose no per-port GET read for
        # poe_portEdit (GET with portList replies code:20). We therefore
        # POST only mode + portList and read live PoE status from
        # poe_portStatus instead.

        # Build base URL
        protocol = "https" if use_https else "http"
        host_url = format_host_url(self.host)
        self._base_url = f"{protocol}://{host_url}:{port}"

    def _get_port_edit_config(self, port_name: str) -> dict[str, Any]:
        """Get current port edit configuration by port name.

        Uses GET port_portEdit endpoint which returns all editable fields
        including jumbo (MTU) that is required for GWN781x series.

        Args:
            port_name: Port name (e.g., "1/0/1")

        Returns:
            Port edit config dict, or empty dict if not found

        """
        try:
            url = self._get_url(CMD_PORT_PORT_EDIT)
            headers = self._get_auth_headers()
            params = {"portList": port_name}
            result = self._handle_request(
                HTTP_METHOD_GET, url, f"get_port_edit_config({port_name})",
                headers=headers, params=params,
            )
            if result and isinstance(result, dict):
                return result.get("data", {})
        except (OSError, ValueError, RuntimeError):
            pass
        return {}

    def _get_url(self, cmd: str, *, is_set: bool = False) -> str:
        """Build API URL.

        Args:
            cmd: API command name
            is_set: Use set.cgi (POST) endpoint if True, get.cgi (GET) otherwise

        Returns:
            Complete API URL

        """
        cgi_path = "set.cgi" if is_set else "get.cgi"
        return f"{self._base_url}/cgi/{cgi_path}?cmd={cmd}"

    def _get_auth_headers(self, content_type: str = CONTENT_TYPE_JSON) -> dict[str, str]:
        """Get HTTP headers with authentication token.

        Args:
            content_type: Content-Type header value

        Returns:
            Headers dictionary with Authorization and Content-Type

        """
        headers = {
            HEADER_CONTENT_TYPE: content_type,
            "X-Requested-With": "XMLHttpRequest",
        }
        if self._token:
            headers[HEADER_AUTHORIZATION] = self._token
        return headers

    @staticmethod
    def _encrypt_password(username: str, password: str) -> str:
        """Return the raw password for RSA encryption.

        GWN Switch login flow (confirmed from JS analysis):
        RSA encrypt the raw password directly - NO sha256 hashing.
        The browser JS does: new JSEncrypt().setPublicKey(key).encrypt(rawPassword)

        Args:
            username: Login username (unused, kept for API compatibility)
            password: Plain text password

        Returns:
            The raw password string

        """
        return password

    def _is_session_expired(self, result: Any) -> bool:
        """Return True if the device rejected the request due to an expired session.

        The switch returns code 401 with ``data.logout == 1`` / ``errMsgs ==
        "notAuth"`` when the stored session cookie is no longer valid, even
        though ``self._token`` may still be set — ``_ensure_auth`` only checks
        the token string, so it cannot detect this.
        """
        if not isinstance(result, dict):
            return False
        if result.get("code") == 401:
            return True
        data = result.get("data")
        if isinstance(data, dict) and (
            data.get("logout") == 1 or data.get("errMsgs") == "notAuth"
        ):
            return True
        return False

    @staticmethod
    def _handle_session_retry(func: Callable[..., Any]) -> Callable[..., Any]:
        """Handle session expiration with auto-retry (mirrors gds.py).

        If the wrapped method raises ``GrandstreamSessionExpiredError`` (auth
        failure), re-log in once and retry. Works for methods returning dict or
        bool, unlike a result-inspection approach which only sees dicts.
        """

        @wraps(func)
        def wrapper(self: GWNSwitchAPI, *args: Any, **kwargs: Any) -> Any:
            try:
                return func(self, *args, **kwargs)
            except GrandstreamSessionExpiredError:
                _LOGGER.info("Session expired, re-authenticating")
                if self.login():
                    _LOGGER.info("Re-authentication successful, retrying")
                    try:
                        return func(self, *args, **kwargs)
                    except GrandstreamSessionExpiredError:
                        _LOGGER.error("Retry failed after re-authentication")
                        return None
                _LOGGER.error("Re-authentication failed")
                return None

        return wrapper

    def _handle_request(
        self,
        method: str,
        url: str,
        operation: str,
        timeout: int = GWN_SWITCH_TIMEOUT,
        return_on_error: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any] | None:
        """Unified request handler with error handling.

        On an auth failure (session expired: code 401 / ``logout:1`` /
        ``notAuth``) it raises ``GrandstreamSessionExpiredError`` so the
        ``@_handle_session_retry`` decorator can re-log in and retry, since the
        stored ``self._token`` cannot detect a server-side session invalidation.

        Args:
            method: HTTP method (GET/POST)
            url: API URL
            operation: Operation description for logging
            timeout: Request timeout in seconds
            **kwargs: Additional arguments passed to requests method

        Returns:
            API response data dict, or None if failed (non-auth)

        """
        try:
            # Log full request details for debugging
            _LOGGER.info(
                "%s request: method=%s, url=%s, kwargs_keys=%s",
                operation, method.upper(), url,
                list(kwargs.keys()),
            )
            if "data" in kwargs:
                _LOGGER.info("%s request body: %s", operation, mask_sensitive_data(kwargs["data"]))
            if "params" in kwargs:
                _LOGGER.info("%s request params: %s", operation, kwargs["params"])

            session_method = (
                self._session.get if method.upper() == HTTP_METHOD_GET
                else self._session.post
            )
            response = session_method(url, timeout=timeout, **kwargs)
            response.raise_for_status()

            result = response.json()
            _LOGGER.info("%s response: %s", operation, mask_sensitive_data(result))

            if not isinstance(result, dict):
                _LOGGER.error("Unexpected response format for %s: %s", operation, type(result))
                return None

            if result.get("code") != API_SUCCESS_CODE:
                if self._is_session_expired(result):
                    raise GrandstreamSessionExpiredError(
                        f"{operation} auth failed (code={result.get('code')}, "
                        f"msg={result.get('msg')})"
                    )
                if return_on_error:
                    _LOGGER.warning(
                        "%s returned non-zero code=%s (msg=%s); returning result "
                        "for caller to interpret",
                        operation, result.get("code"), result.get("msg"),
                    )
                    return result
                _LOGGER.error(
                    "%s failed: %s (code=%s), full_response=%s",
                    operation,
                    result.get("msg"),
                    result.get("code"),
                    mask_sensitive_data(result),
                )
                return None

            self._is_online = True
            return result

        except GrandstreamSessionExpiredError:
            raise
        except requests.exceptions.ConnectTimeout:
            _LOGGER.warning("Connection timeout during %s (device may be offline)", operation)
            self._is_online = False
        except requests.exceptions.ConnectionError:
            _LOGGER.warning("Connection failed during %s (device may be offline)", operation)
            self._is_online = False
        except requests.RequestException as err:
            _LOGGER.error("Request failed during %s: %s", operation, err)
            self._is_online = False
        except (ValueError, KeyError, json.JSONDecodeError) as err:
            _LOGGER.error("Failed to parse %s response: %s", operation, err)

        return None

    def _ensure_auth(self) -> bool:
        """Ensure authenticated, attempt login if not.

        Returns:
            True if authenticated

        """
        if not self._token:
            return self.login()
        return True

    def _fetch_public_key(self) -> str | None:
        """Fetch RSA public key from the switch (no auth required).

        Calls GET /cgi/get.cgi?cmd=home_login to get pwdPublicKey.
        Also checks lock status to detect account lockout.

        Returns:
            PEM-formatted RSA public key string, or None if failed

        """
        url = self._get_url(CMD_HOME_LOGIN)
        headers = {
            HEADER_CONTENT_TYPE: CONTENT_TYPE_JSON,
            "X-Requested-With": "XMLHttpRequest",
        }

        try:
            response = self._session.get(url, headers=headers, timeout=GWN_SWITCH_TIMEOUT)
            response.raise_for_status()
            result = response.json()
            _LOGGER.info("home_login (fetch RSA key) response: %s", mask_sensitive_data(result))

            if not isinstance(result, dict):
                _LOGGER.error("Unexpected response from home_login: %s", type(result))
                return None

            data = result.get("data", {})
            if not isinstance(data, dict):
                _LOGGER.error("Unexpected data in home_login: %s", type(data))
                return None

            # Check lock status
            lock = data.get("lock", 0)
            if lock == 1:
                remain = data.get("remainTime", 0)
                self._is_locked = True
                self._lock_remain_seconds = remain
                _LOGGER.warning(
                    "GWN Switch account is locked, remaining time: %d seconds",
                    remain,
                )
                return None

            # The public key is in data.pwdPublicKey
            public_key = data.get("pwdPublicKey")

            if public_key:
                _LOGGER.info(
                    "Got RSA public key from GWN Switch: %s...%s (len=%d)",
                    public_key[:30],
                    public_key[-30:],
                    len(public_key),
                )
            else:
                _LOGGER.warning("No pwdPublicKey in home_login response: %s", mask_sensitive_data(result))

            return public_key

        except requests.RequestException as err:
            _LOGGER.error("Failed to fetch RSA public key: %s", err)
            return None

    @staticmethod
    def port_name_to_ge(port_name: str, port_type: str = "coper") -> str:
        """Convert API port name (1/0/1) to GE/TE format for portList parameter.

        API returns port names in format "1/0/X" but set commands require
        portList in format "GE1", "GE2", etc. for copper ports and
        "TE1", "TE2", etc. for fiber (SFP+) ports.

        Args:
            port_name: Port name from API (e.g., "1/0/1", "1/0/6")
            port_type: Port type from API ("coper" for GE, "fiber"/"sfp+" for TE)

        Returns:
            GE/TE formatted port name (e.g., "GE1", "TE1")

        """
        # Extract the last number from port name like "1/0/1"
        parts = port_name.split("/")
        if len(parts) >= 3:
            try:
                port_num = int(parts[-1])
            except (ValueError, TypeError):
                return port_name
        elif port_name.startswith("GE") or port_name.startswith("TE"):
            return port_name
        else:
            return port_name

        # Fiber/SFP+ ports use TE prefix, copper ports use GE prefix
        prefix = "TE" if port_type.lower() in ("fiber", "sfp+", "sfp") else "GE"
        return f"{prefix}{port_num}"

    @staticmethod
    def parse_admin_status(admin_status: Any) -> bool:
        """Interpret a port ``adminStatus`` value as enabled/disabled.

        The device reports ``adminStatus`` from ``port_portInformation`` as a
        string such as ``"true"`` / ``"1"`` / ``"up"`` (enabled) or
        ``"false"`` / ``"down"`` / ``"0"`` (disabled). Some switches keep the
        last negotiated ``operSpeed`` after admin-down, so callers must check
        ``adminStatus`` (not just ``operSpeed``) to know whether a port is
        usable. Missing values default to enabled.

        Args:
            admin_status: Raw ``adminStatus`` from the device (str or bool).

        Returns:
            True if the port is administratively enabled.
        """
        if admin_status is None:
            return True
        if isinstance(admin_status, str):
            return admin_status.lower() in ("true", "1", "up")
        return bool(admin_status)

    @staticmethod
    def parse_sse_int(value: Any) -> int | None:
        """Coerce an SSE field to int, tolerating numeric strings.

        Firmware SSE packets sometimes carry ``state``/``process``/``code`` as
        strings (e.g. ``"3"``) rather than JSON numbers. Treat both forms as
        their integer value so progress/state checks don't silently miss
        packets. ``True``/``False`` and non-numeric values yield ``None``.
        """
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            try:
                return int(value)
            except ValueError:
                return None
        return None

    @staticmethod
    def ge_to_port_name(ge_name: str) -> str:
        """Convert a GE/TE portList (e.g. "GE1") back to the API ``1/0/X`` form.

        The ``poe_portEdit`` POST expects ``portList`` in ``1/0/X`` form; the
        frontend/entity layer holds the GE name, so it must be converted first.
        """
        match = re.match(r"^(GE|TE)(\d+)$", ge_name, re.IGNORECASE)
        if not match:
            return ge_name
        return f"1/0/{match.group(2)}"

    @staticmethod
    def _rsa_encrypt(plaintext: str, public_key_pem: str) -> str | None:
        """Encrypt plaintext using RSA public key.

        Args:
            plaintext: Text to encrypt (sha256 hash of credentials)
            public_key_pem: PEM-formatted RSA public key

        Returns:
            Base64-encoded encrypted string, or None if failed

        """
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import padding

            # Parse the PEM public key
            public_key = serialization.load_pem_public_key(public_key_pem.encode())

            # Encrypt with PKCS1v15 padding (standard for JSEncrypt)
            ciphertext = public_key.encrypt(plaintext.encode(), padding.PKCS1v15())

            # Base64 encode the result
            return base64.b64encode(ciphertext).decode()

        except (ValueError, TypeError, OSError) as err:
            _LOGGER.error("RSA encryption failed: %s", err)
            return None

    def login(self) -> bool:
        """Login to GWN Switch device.

        Login flow (confirmed from browser JS analysis):
        1. GET /cgi/get.cgi?cmd=home_login → fetch RSA public key
        2. RSA encrypt the raw password with public key → Base64 ciphertext
        3. POST /cgi/set.cgi?cmd=home_loginAuth with form-urlencoded body

        NOTE: The browser JS does NOT sha256 hash the password before RSA.
        It directly RSA-encrypts the raw password:
          new JSEncrypt().setPublicKey(publicKey).encrypt(rawPassword)
        Also, the login must use form-urlencoded (not JSON body).

        Returns:
            True if login successful

        """
        # Check if account is locked before trying
        if self._is_locked:
            _LOGGER.warning(
                "GWN Switch account is locked (%d seconds remaining), skipping login",
                self._lock_remain_seconds,
            )
            return False

        # Step 1: Fetch RSA public key
        public_key_pem = self._fetch_public_key()

        # Account may be locked after _fetch_public_key check
        if self._is_locked:
            _LOGGER.warning(
                "GWN Switch account is locked (%d seconds remaining), aborting login",
                self._lock_remain_seconds,
            )
            return False

        # Step 2: RSA encrypt the raw password (no sha256 - confirmed from JS)
        if public_key_pem:
            encrypted_pwd = self._rsa_encrypt(self.password, public_key_pem)
            if not encrypted_pwd:
                _LOGGER.warning(
                    "RSA encryption failed, falling back to plain password for %s",
                    self.host,
                )
                encrypted_pwd = self.password
        else:
            _LOGGER.warning(
                "No RSA public key available, sending plain password for %s",
                self.host,
            )
            encrypted_pwd = self.password

        # Step 3: Send login request as form-urlencoded (NOT JSON body)
        url = self._get_url(CMD_HOME_LOGIN_AUTH, is_set=True)
        headers = {
            HEADER_CONTENT_TYPE: CONTENT_TYPE_FORM,
            "X-Requested-With": "XMLHttpRequest",
        }
        data = {
            "username": self.username,
            "password": encrypted_pwd,
        }

        _LOGGER.info(
            "Attempting login to GWN Switch: %s:%d, username=%s, "
            "has_rsa_key=%s, encrypted_pwd_len=%d",
            self.host,
            self.port,
            self.username,
            public_key_pem is not None,
            len(encrypted_pwd),
        )

        try:
            response = self._session.post(
                url, headers=headers, data=data, timeout=GWN_SWITCH_TIMEOUT
            )
            response.raise_for_status()
            result = response.json()
            _LOGGER.info("Login response: %s", mask_sensitive_data(result))
        except requests.exceptions.ConnectTimeout:
            _LOGGER.warning("Connection timeout during login (device may be offline)")
            self._is_online = False
            return False
        except requests.exceptions.ConnectionError:
            _LOGGER.warning("Connection failed during login (device may be offline)")
            self._is_online = False
            return False
        except (ValueError, json.JSONDecodeError) as err:
            _LOGGER.error("Failed to parse login response: %s", err)
            return False
        except requests.RequestException as err:
            _LOGGER.error("Login request failed: %s", err)
            self._is_online = False
            return False

        if not isinstance(result, dict):
            _LOGGER.error("Unexpected login response format: %s", type(result))
            return False

        code = result.get("code")
        msg = result.get("msg", "")
        login_data = result.get("data", {})

        # Check for account lockout in the response
        if isinstance(login_data, dict):
            if login_data.get("lock") == 1:
                remain = login_data.get("remainTime", 0)
                self._is_locked = True
                self._lock_remain_seconds = remain
                _LOGGER.warning(
                    "GWN Switch account locked, remaining: %d seconds, errMsgs=%s",
                    remain,
                    login_data.get("errMsgs", ""),
                )
                return False

        if code != API_SUCCESS_CODE:
            self._login_failed_count += 1
            _LOGGER.error(
                "Login failed for GWN Switch at %s:%d, username=%s, "
                "code=%s, msg=%s, has_rsa_key=%s, encrypted_pwd_len=%d",
                self.host,
                self.port,
                self.username,
                code,
                msg,
                public_key_pem is not None,
                len(encrypted_pwd),
            )
            return False

        if not isinstance(login_data, dict) or "token" not in login_data:
            _LOGGER.error("Login response missing token data: %s", mask_sensitive_data(result))
            return False

        self._token = login_data.get("token")
        self._priv = login_data.get("priv")
        self._login_failed_count = 0
        self._is_online = True
        self._is_locked = False
        self._lock_remain_seconds = 0

        _LOGGER.info(
            "GWN Switch login successful: priv=%s, token=%s...",
            self._priv,
            self._token[:20] if self._token else "None",
        )
        return True

    @_handle_session_retry
    @_require_auth
    def get_sys_cpumem(self) -> dict[str, Any] | None:
        """Get CPU/memory usage and temperature data.

        Returns:
            Dict with keys: corenum, resList[{cpu, mem, timeStr}], cpuTemp,
            fanStatus, systemTemper, temperThreshold, consPower, remaindPower

        """
        url = self._get_url(CMD_SYS_CPUMEM)
        headers = self._get_auth_headers()
        result = self._handle_request(HTTP_METHOD_GET, url, "get_sys_cpumem", headers=headers)
        return result.get("data") if result else None

    @_handle_session_retry
    @_require_auth
    def get_sys_sysinfo(self) -> dict[str, Any] | None:
        """Get system information.

        Returns:
            Dict with keys: hostname, contact, location, sysUpTime, sysMac,
            loaderVer, fwVer, hardVer, PN, SN, adminIp, adminGw, mgmtVlan

        """
        url = self._get_url(CMD_SYS_SYSINFO)
        headers = self._get_auth_headers()
        result = self._handle_request(HTTP_METHOD_GET, url, "get_sys_sysinfo", headers=headers)
        return result.get("data") if result else None

    @_handle_session_retry
    @_require_auth
    def get_home_login_status(self) -> dict[str, Any] | None:
        """Get the raw home login-status response.

        Returns the full response dict (including ``code`` and ``data``) on a
        successful request, or ``None`` when the device is unreachable or the
        request fails. ``_handle_request`` only returns a non-``None`` result
        for ``code == 0``, so a truthy return means the device answered the
        request and is therefore online; a 401 (``notAuth`` / ``logout:1``) is
        raised as ``GrandstreamSessionExpiredError``; a connection timeout
        returns ``None``.

        The ``status`` / ``mgmtStatus`` / ``connectStatus`` fields inside
        ``data`` describe management/controller state and must NOT be used to
        decide online/offline — use the request success (code 0) instead.

        """
        url = self._get_url(CMD_HOME_LOGIN_STATUS)
        headers = self._get_auth_headers()
        return self._handle_request(
            HTTP_METHOD_GET, url, "get_home_login_status", headers=headers
        )

    @_handle_session_retry
    @_require_auth
    def get_port_information(self) -> dict[str, Any] | None:
        """Get port information for all ports.

        Returns:
            Dict with key 'ports': list of port dicts with keys: val, name,
            typeDescp, type, comboMode, autoDetect, adminSpeed, adminDuplex,
            adminStatus, operStatus, operSpeed, operDuplex, powerflag

        """
        url = self._get_url(CMD_PORT_PORT_INFORMATION)
        headers = self._get_auth_headers()
        result = self._handle_request(
            HTTP_METHOD_GET, url, "get_port_information", headers=headers
        )
        return result.get("data") if result else None

    @_handle_session_retry
    @_require_auth
    def get_port_detail(self, port_name: str, src: int = 0) -> dict[str, Any] | None:
        """Get detailed information for a specific port.

        Args:
            port_name: Port name (e.g., "1/0/1")
            src: Source parameter (default: 0)

        Returns:
            Dict with keys: basicInformation, poeInformation, statistics,
            lldpneighbor

        """
        url = self._get_url(CMD_PORT_PORT_DETAIL)
        url += f"&_src={src}"
        headers = self._get_auth_headers()
        result = self._handle_request(
            HTTP_METHOD_GET, url, f"get_port_detail({port_name})", headers=headers
        )
        return result.get("data") if result else None

    @_handle_session_retry
    @_require_auth
    def get_port_statistics(
        self, page_size: int = 100, page_num: int = 1
    ) -> dict[str, Any] | None:
        """Get port traffic statistics for all ports.

        Args:
            page_size: Number of entries per page (default: 100)
            page_num: Page number (default: 1)

        Returns:
            Dict with keys: total, ports[{val, name, operStatus, inUti,
            outUti, inOctets, inPkts, inErrs, outOctets, outPkts, outErrs,
            inRate, outRate, QueueDropPkts}]

        """
        url = self._get_url(CMD_PORT_CNT_ALL)
        url += f"&pageSize={page_size}&pageNum={page_num}"
        headers = self._get_auth_headers()
        result = self._handle_request(
            HTTP_METHOD_GET, url, "get_port_statistics", headers=headers
        )
        return result.get("data") if result else None

    @_handle_session_retry
    @_require_auth
    def get_poe_port_history(
        self, port_list: str, offset: int = 30
    ) -> dict[str, Any] | None:
        """Get PoE port power history.

        Args:
            port_list: Port name (e.g., "1/0/9"), URL-encoded
            offset: History offset interval (default: 30)

        Returns:
            Dict with keys: cnt, entrys[{num, time, ports[{descp, state,
            voltage, current, power}]}]

        """
        url = self._get_url(CMD_POE_PORT_HISTORY)
        url += f"&portList={port_list}&offset={offset}"
        headers = self._get_auth_headers()
        result = self._handle_request(
            HTTP_METHOD_GET, url, f"get_poe_port_history({port_list})", headers=headers
        )
        return result.get("data") if result else None

    @_handle_session_retry
    @_require_auth
    def get_poe_port_status(
        self, page_num: int = 1, page_size: int = 100
    ) -> dict[str, Any] | None:
        """Get live PoE status for all ports.

        This is the authoritative source for a port's current PoE on/off
        state (``powerflag``) and configured ``mode``. Unlike ``poe_portEdit``
        (which has no usable per-port GET read), ``poe_portStatus`` returns a
        list of all ports with ``descp`` (e.g. "1/0/1"), ``powerflag``
        ("on"/"off"), ``mode`` and ``state``.

        Args:
            page_num: Pagination page number
            page_size: Page size

        Returns:
            Dict with keys: total, ports[{descp, powerflag, mode, state, ...}]

        """
        url = self._get_url(CMD_POE_PORT_STATUS)
        url += f"&pageNum={page_num}&pageSize={page_size}"
        headers = self._get_auth_headers()
        result = self._handle_request(
            HTTP_METHOD_GET, url, "get_poe_port_status", headers=headers
        )
        return result.get("data") if result else None

    @_handle_session_retry
    @_require_auth
    def get_poe_status(self) -> dict[str, Any] | None:
        """Get system-wide PoE power status.

        Source: GET /cgi/get.cgi?cmd=poe_status

        Returns the total PoE power supply and real-time consumption:

        - ``PoEPowerSupply``: total PoE power budget (W)
        - ``PoERealtTimePower``: real-time PoE power consumption (W, string)
        - ``PoEUsePower``: (reported) used power
        - ``PoEReservedPower``: reserved power
        - ``PoESupportType``: e.g. "802.3 af/at"

        Returns:
            Dict with the ``data`` payload, or None on failure.

        """
        url = self._get_url(CMD_POE_STATUS)
        headers = self._get_auth_headers()
        result = self._handle_request(
            HTTP_METHOD_GET, url, "get_poe_status", headers=headers
        )
        return result.get("data") if result else None

    @_handle_session_retry
    @_require_auth
    def get_mac_dynamic(
        self, page_size: int = 100, page_num: int = 1
    ) -> dict[str, Any] | None:
        """Get MAC address table (dynamic entries).

        Args:
            page_size: Number of entries per page (default: 100)
            page_num: Page number (default: 1)

        Returns:
            Dict with keys: aging_time, total, entries[{vlan, macAddr,
            port, key}]

        """
        url = self._get_url(CMD_MAC_DYNAMIC)
        url += f"&filterPara=&pageSize={page_size}&pageNum={page_num}"
        headers = self._get_auth_headers()
        result = self._handle_request(
            HTTP_METHOD_GET, url, "get_mac_dynamic", headers=headers
        )
        return result.get("data") if result else None

    @_handle_session_retry
    @_require_auth
    def get_mac_filter(self, page_size: int = 10, page_num: int = 1) -> dict[str, Any] | None:
        """Get the MAC filter (block) list.

        Returns:
            Dict with keys: total, leftotal, entries[{vlan, macAddr, key}].
            The filter entry key format is "vlan_macAddr", e.g.
            "1_00:0B:82:10:53:21" (raw MAC with colons, not URL-encoded).

        """
        url = self._get_url(CMD_MAC_FILTER)
        url += f"&filterPara=&pageSize={page_size}&pageNum={page_num}"
        headers = self._get_auth_headers()
        result = self._handle_request(
            HTTP_METHOD_GET, url, "get_mac_filter", headers=headers
        )
        return result.get("data") if result else None

    @_handle_session_retry
    @_require_auth
    def reboot(self) -> bool:
        """Reboot the switch device.

        Returns:
            True if reboot command successful

        """
        url = self._get_url(CMD_SYS_REBOOT, is_set=True)
        headers = self._get_auth_headers(content_type=CONTENT_TYPE_FORM)
        result = self._handle_request(
            HTTP_METHOD_POST, url, "reboot", headers=headers
        )
        return result is not None

    @_handle_session_retry
    @_require_auth
    def set_port_admin_status(
        self, port_list: str, admin_status: bool, **kwargs: Any,
    ) -> bool:
        """Set port admin status (enable/disable).

        Reads current port edit config via GET, then only changes adminStatus,
        preserving all other settings (jumbo, speed, etc.) to avoid conflicts.

        Args:
            port_list: Port name (e.g., "1/0/6")
            admin_status: True to enable, False to disable
            **kwargs: Override specific port parameters

        Returns:
            True if command successful

        """
        # Get current port edit config to preserve all settings
        current = self._get_port_edit_config(port_list)

        data = {
            "portList": port_list,
            "descp": kwargs.get("descp", current.get("descp", "")),
            "adminStatus": str(admin_status).lower(),
            "adminSpeed": kwargs.get("adminSpeed", current.get("adminSpeed", "auto")),
            "adminDuplex": kwargs.get("adminDuplex", current.get("adminDuplex", "auto")),
            "adminFlowCtrl": kwargs.get("adminFlowCtrl", current.get("adminFlowCtrl", "disable")),
        }
        # jumbo (MTU) is required for GWN781x series
        if "jumbo" in current:
            data["jumbo"] = str(current["jumbo"])

        url = self._get_url(CMD_PORT_PORT_EDIT, is_set=True)
        headers = self._get_auth_headers(content_type=CONTENT_TYPE_FORM)

        result = self._handle_request(
            HTTP_METHOD_POST, url, f"set_port_admin_status({port_list})",
            headers=headers, data=data
        )
        if result and "data" in result:
            new_token = result["data"].get("token")
            if new_token:
                self._token = new_token
        return result is not None

    @_handle_session_retry
    @_require_auth
    def set_poe_port_mode(self, port_list: str, mode: str = "Automatic") -> bool:
        """Set PoE port mode.

        Sends a single POST to ``poe_portEdit`` with only ``mode`` and
        ``portList`` — those two fields are all the device needs (verified
        working request: ``mode=Automatic&portList=1/0/X`` → ``save_success``).
        GWN78xx switches do NOT expose a per-port GET read for ``poe_portEdit``
        (a GET with ``portList`` replies ``code:20 Invalid input parameter``),
        so the existing PoE settings cannot be read; we do not try to preserve
        or override them.

        Args:
            port_list: Port name in GE format (e.g., "GE1", "GE1-GE5")
            mode: PoE mode - "Automatic", "Forcepowe", or "Shutdown"

        Returns:
            True if command successful

        """
        # Only mode + portList are required by the device.
        data = {
            "portList": self.ge_to_port_name(port_list),
            "mode": mode,
        }

        url = self._get_url(CMD_POE_PORT_EDIT, is_set=True)
        headers = self._get_auth_headers(content_type=CONTENT_TYPE_FORM)

        result = self._handle_request(
            HTTP_METHOD_POST, url, f"set_poe_port_mode({port_list})",
            headers=headers, data=data
        )
        if result and "data" in result:
            new_token = result.get("data", {}).get("token")
            if new_token:
                self._token = new_token
        return result is not None

    @_handle_session_retry
    @_require_auth
    def poe_soft_reboot(self) -> bool:
        """Perform PoE soft reboot (power cycle all PoE ports).

        Returns:
            True if command successful

        """
        url = self._get_url(CMD_POE_SOFT_REBOOT, is_set=True)
        headers = self._get_auth_headers(content_type=CONTENT_TYPE_FORM)
        data = {"PoEReboot": "1"}

        result = self._handle_request(
            HTTP_METHOD_POST, url, "poe_soft_reboot", headers=headers, data=data
        )
        if result and "data" in result:
            new_token = result["data"].get("token")
            if new_token:
                self._token = new_token
        return result is not None

    @_handle_session_retry
    @_require_auth
    def mac_filter_batch_add(self, keys: list[str]) -> bool:
        """Add MAC addresses to filter (block) list.

        Args:
            keys: List of MAC filter keys (format: "000B82105321_1_15")

        Returns:
            True if command successful

        """
        url = self._get_url(CMD_MAC_FILTER_BATCH_ADD, is_set=True)
        headers = self._get_auth_headers(content_type=CONTENT_TYPE_FORM)

        # Send each key as separate form field. Decode any percent-encoding
        # first so requests form-encodes the key exactly once (a pre-encoded
        # key like "1_00%3A0B..." would otherwise be double-encoded to
        # "1_00%253A0B..." and become unmatchable).
        data = {"key": [unquote(k) for k in keys]}
        # Log the real key unmasked (mask_sensitive_data hides "key" fields)
        _LOGGER.info("mac_filter_batch_add keys=%s", keys)
        result = self._handle_request(
            HTTP_METHOD_POST, url, "mac_filter_batch_add",
            headers=headers, data=data, return_on_error=True
        )
        if result and "data" in result:
            new_token = result["data"].get("token")
            if new_token:
                self._token = new_token
        return self._mac_op_succeeded(result, "mac_filter_batch_add")

    @_handle_session_retry
    @_require_auth
    def mac_filter_delete(self, key: str) -> bool:
        """Remove MAC address from filter (block) list.

        Args:
            key: MAC filter key (format: "1_00%3A0B%3A82%3A00%3AAA%3AC0")

        Returns:
            True if command successful

        """
        url = self._get_url(CMD_MAC_FILTER_DELETE, is_set=True)
        headers = self._get_auth_headers(content_type=CONTENT_TYPE_FORM)
        # Decode any percent-encoding so requests form-encodes the key exactly
        # once (a pre-encoded key like "1_00%3A0B..." would otherwise become
        # "1_00%253A0B..." and be unmatchable -> "Delete: FAILED.").
        data = {"key": unquote(key)}

        # Log the real key unmasked (mask_sensitive_data hides "key" fields)
        _LOGGER.info("mac_filter_delete key=%s", key)
        result = self._handle_request(
            HTTP_METHOD_POST, url, f"mac_filter_delete({key})",
            headers=headers, data=data, return_on_error=True
        )
        if result and "data" in result:
            new_token = result["data"].get("token")
            if new_token:
                self._token = new_token
        return self._mac_op_succeeded(result, "mac_filter_delete")

    @staticmethod
    def _mac_op_succeeded(result: dict[str, Any] | None, operation: str) -> bool:
        """Interpret a MAC filter op result, including data-level messages.

        The device returns a non-zero ``code`` (and ``data.errMsgs``) for both
        real failures and idempotent no-ops. The desired end state is what
        matters:

        * block (``mac_filter_batch_add``): ``code=7019`` / "already exists"
          means the client is already blocked — treat as success.
        * unblock (``mac_filter_delete``): "Delete: FAILED." means the entry is
          not present (already unblocked / never blocked) — treat as success.

        Any other non-zero code (e.g. ``7018`` multicast MAC) is a real failure.
        """
        if not result:
            return False
        code = result.get("code")
        data = result.get("data")
        text = str(data).upper()

        if operation == "mac_filter_batch_add":
            if code == 0:
                return True
            if "ALREADY EXISTS" in text:
                _LOGGER.info(
                    "mac_filter_batch_add idempotent success (already blocked): %s",
                    data,
                )
                return True
            _LOGGER.error("mac_filter_batch_add failed: code=%s %s", code, data)
            return False

        if operation == "mac_filter_delete":
            if code == 0:
                return True
            if "DELETE: FAILED" in text:
                _LOGGER.info(
                    "mac_filter_delete idempotent success (not present / already "
                    "unblocked): %s",
                    data,
                )
                return True
            _LOGGER.error("mac_filter_delete failed: code=%s %s", code, data)
            return False

        # Generic fallback for other operations: success unless "FAILED" appears.
        if "FAILED" in text:
            _LOGGER.error("%s reported failure by device: %s", operation, data)
            return False
        return True

    @_handle_session_retry
    @_require_auth
    def firmware_check(self) -> str | None:
        """Check for firmware updates via SSE endpoint.

        Streams SSE packets such as::

            {"code":0,"data":{"state":1,"process":0,"code":0,"version":""}}
            {"code":0,"data":{"state":0,"process":100,"code":0,"version":"130.3.1.1"}}

        The final packet carries the result: a non-empty ``version`` means an
        update is available (``code:0``); ``code:-10`` with an empty
        ``version`` means the device is already up to date.

        Returns:
            Available firmware version string, or ``None`` when up to date or
            the check failed.

        """
        url = f"{self._base_url}/cgi-bin/httpsseupgrade.cgi?action=0"
        headers = self._get_auth_headers()
        headers["Accept"] = "text/event-stream"

        last_data: dict[str, Any] | None = None
        try:
            response = self._session.get(
                url, headers=headers, timeout=GWN_SWITCH_TIMEOUT, stream=True
            )
            response.raise_for_status()

            # The final SSE packet holds the authoritative result.
            for line in response.iter_lines(decode_unicode=True):
                if not line or not line.startswith("data:"):
                    continue
                json_str = line[len("data:"):].strip()
                try:
                    sse_data = json.loads(json_str)
                except json.JSONDecodeError:
                    continue
                if GWNSwitchAPI.parse_sse_int(sse_data.get("code")) != API_SUCCESS_CODE:
                    continue
                data = sse_data.get("data")
                if isinstance(data, dict):
                    last_data = data

        except requests.RequestException as err:
            _LOGGER.error("Firmware check failed: %s", err)
            self._is_online = False
            return None

        if last_data and last_data.get("version"):
            return last_data["version"]
        return None

    @_handle_session_retry
    @_require_auth
    def firmware_install(
        self, progress_callback: Callable[[int], None] | None = None
    ) -> bool:
        """Install firmware update via SSE endpoint.

        During the upgrade the device streams progress packets such as::

            {"code":0,"data":{"state":3,"process":1,"code":0,"version":""}}

        where ``state:3`` means upgrading and ``process`` is the percentage.
        When ``progress_callback`` is provided, each such packet is reported
        to it so the caller can surface live progress.

        Returns:
            ``True`` if the upgrade was accepted/started successfully,
            ``False`` on a device-reported failure.

        """
        url = f"{self._base_url}/cgi-bin/httpsseupgrade.cgi?action=1"
        headers = self._get_auth_headers()
        headers["Accept"] = "text/event-stream"

        try:
            response = self._session.get(
                url,
                headers=headers,
                timeout=(GWN_SWITCH_TIMEOUT, FIRMWARE_INSTALL_TIMEOUT),
                stream=True,
            )
            response.raise_for_status()

            for line in response.iter_lines(decode_unicode=True):
                if not line or not line.startswith("data:"):
                    continue
                json_str = line[len("data:"):].strip()
                try:
                    sse_data = json.loads(json_str)
                except json.JSONDecodeError:
                    continue
                if GWNSwitchAPI.parse_sse_int(sse_data.get("code")) != API_SUCCESS_CODE:
                    continue
                data = sse_data.get("data")
                if not isinstance(data, dict):
                    continue
                if GWNSwitchAPI.parse_sse_int(data.get("code")) != 0:
                    _LOGGER.error("Firmware install reported failure: %s", data)
                    return False
                if GWNSwitchAPI.parse_sse_int(data.get("state")) == 3 and progress_callback is not None:
                    process = GWNSwitchAPI.parse_sse_int(data.get("process"))
                    if process is not None:
                        progress_callback(process)

        except requests.RequestException as err:
            _LOGGER.error("Firmware install failed: %s", err)
            self._is_online = False
            return False

        return True

    def get_system_metrics(self) -> dict[str, Any]:
        """Get all system metrics in a single call.

        Aggregates data from multiple API endpoints into a unified
        dictionary suitable for HA sensor consumption.

        Returns:
            Dictionary with all system metrics data

        """
        if not self._ensure_auth():
            return self._get_unknown_metrics()

        metrics: dict[str, Any] = {
            "device_status": "online" if self._is_online else "offline",
        }

        # CPU/Memory/Temperature
        cpumem = self.get_sys_cpumem()
        if cpumem:
            res_list = cpumem.get("resList", [])
            if res_list:
                latest = res_list[0]
                metrics["cpu_usage_percent"] = latest.get("cpu")
                metrics["memory_usage_percent"] = latest.get("mem")
            metrics["cpu_temperature_c"] = cpumem.get("cpuTemp")
            metrics["system_temperature_c"] = cpumem.get("systemTemper")
            metrics["temperature_threshold"] = cpumem.get("temperThreshold")
            metrics["fan_status"] = cpumem.get("fanStatus")
        else:
            metrics.update(self._get_default_cpumem_metrics())

        # PoE system power (authoritative total consumption + remaining).
        # Source: GET /cgi/get.cgi?cmd=poe_status
        #   total consumption = PoERealtTimePower
        #   remaining         = PoEPowerSupply - PoERealtTimePower
        # Both values are rounded to 1 decimal place. Skipped entirely on
        # non-PoE models (model not ending in "P"), which have no PoE budget.
        if self.has_poe:
            poe_status = self.get_poe_status()
            if poe_status:
                try:
                    realtime = float(poe_status.get("PoERealtTimePower") or 0)
                    supply = float(poe_status.get("PoEPowerSupply") or 0)
                except (TypeError, ValueError):
                    realtime = None
                    supply = None
                if realtime is not None:
                    metrics["total_power_w"] = round(realtime, 1)
                if realtime is not None and supply is not None:
                    metrics["remaining_power_w"] = round(supply - realtime, 1)

        # System info (uptime, firmware, etc.)
        sysinfo = self.get_sys_sysinfo()
        if sysinfo:
            metrics["hostname"] = sysinfo.get("hostname")
            metrics["uptime_seconds"] = self._parse_uptime(sysinfo.get("sysUpTime", "0"))
            metrics["mac_address"] = sysinfo.get("sysMac")
            metrics["firmware_version"] = sysinfo.get("fwVer")
            metrics["hardware_version"] = sysinfo.get("hardVer")
            metrics["serial_number"] = sysinfo.get("SN")
            metrics["admin_ip"] = sysinfo.get("adminIp")
            metrics["part_number"] = sysinfo.get("PN")
        else:
            metrics.update(self._get_default_sysinfo_metrics())

        # Connection status (home_loginStatus)
        # Online/offline is decided purely by whether the request succeeded
        # (code 0). _handle_request returns None for any non-zero code / timeout
        # and raises GrandstreamSessionExpiredError on 401 (notAuth). The
        # status / mgmtStatus / connectStatus fields inside the response only
        # describe management/controller state and must NOT drive the decision.
        try:
            login_result = self.get_home_login_status()
        except GrandstreamSessionExpiredError:
            metrics["connect_status"] = "auth_failed"
            metrics["connect_manager"] = None
            metrics["connect_address"] = None
        else:
            if login_result is not None:
                metrics["connect_status"] = "online"
                data = login_result.get("data") or {}
                metrics["connect_manager"] = (
                    data.get("connectManager") or data.get("mgmtAddress")
                )
                metrics["connect_address"] = (
                    data.get("connectAddress") or data.get("mgmtAddress")
                )
            else:
                metrics["connect_status"] = "offline"
                metrics["connect_manager"] = None
                metrics["connect_address"] = None

        # Port information (primary data source for per-port sensors)
        port_info = self.get_port_information()
        if port_info:
            metrics["ports"] = port_info.get("ports", [])
        else:
            metrics["ports"] = []

        # Port statistics (merge inRate/outRate into each port entry)
        port_stats = self.get_port_statistics()
        if port_stats:
            stats_list = port_stats.get("ports", [])
            # Build lookup by port name for merging
            stats_by_name: dict[str, dict[str, Any]] = {}
            for stat in stats_list:
                if isinstance(stat, dict):
                    # port_cntAll uses GE1 format in name field
                    stats_by_name[stat.get("name", "")] = stat
            # Merge traffic data into each port entry
            for port in metrics["ports"]:
                if not isinstance(port, dict):
                    continue
                port_name = port.get("name", "")
                # Try matching by 1/0/X format, then convert to GE format
                stat_entry = stats_by_name.get(port_name)
                if not stat_entry:
                    ge_name = self.port_name_to_ge(
                        port_name, port.get("typeDescp", "coper")
                    )
                    stat_entry = stats_by_name.get(ge_name)
                if stat_entry:
                    port["inRate"] = stat_entry.get("inRate")
                    port["outRate"] = stat_entry.get("outRate")

        # PoE live status (authoritative powerflag/mode per port).
        # poe_portStatus keyed by descp ("1/0/X"), matching port "name".
        # Skipped on non-PoE models, which never report PoE ports.
        if self.has_poe:
            poe_status = self.get_poe_port_status()
            if poe_status:
                poe_by_name: dict[str, dict[str, Any]] = {}
                for p in poe_status.get("ports", []) or []:
                    if isinstance(p, dict) and p.get("descp"):
                        poe_by_name[p["descp"]] = p
                for port in metrics["ports"]:
                    if not isinstance(port, dict):
                        continue
                    poe_entry = poe_by_name.get(port.get("name", ""))
                    if not poe_entry:
                        continue
                    port["powerflag"] = poe_entry.get("powerflag", port.get("powerflag"))
                    port["mode"] = poe_entry.get("mode", port.get("mode"))
                    port["poe_state"] = poe_entry.get("state")

        # MAC address table (dynamic entries)
        mac_table = self.get_mac_dynamic()
        if mac_table:
            metrics["mac_entries"] = mac_table.get("entries", [])
        else:
            metrics["mac_entries"] = []

        # MAC filter (block) list — authoritative source for blocked state.
        # Entry key format: "vlan_macAddr" (e.g. "1_00:0B:82:10:53:21").
        mac_filter = self.get_mac_filter()
        if mac_filter:
            filter_entries = mac_filter.get("entries", [])
            metrics["blocked_entries"] = filter_entries
            metrics["blocked_macs"] = {
                e.get("macAddr", "").upper()
                for e in filter_entries
                if isinstance(e, dict) and e.get("macAddr")
            }
            metrics["filter_key_map"] = {
                e.get("macAddr", "").upper(): e.get("key", "")
                for e in filter_entries
                if isinstance(e, dict) and e.get("macAddr")
            }
        else:
            metrics["blocked_entries"] = []
            metrics["blocked_macs"] = set()
            metrics["filter_key_map"] = {}

        _LOGGER.debug(
            "Processed GWN Switch metrics: %d ports, %d MAC entries, %d blocked",
            len(metrics.get("ports", [])),
            len(metrics.get("mac_entries", [])),
            len(metrics.get("blocked_macs", set())),
        )

        return metrics

    @staticmethod
    def _parse_uptime(uptime_str: str | None) -> int | None:
        """Parse uptime string to seconds.

        Args:
            uptime_str: Uptime value from API (string, in seconds)

        Returns:
            Uptime in seconds, or None if parsing fails

        """
        if not uptime_str:
            return None
        try:
            return int(uptime_str)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _get_unknown_metrics() -> dict[str, Any]:
        """Get unknown metrics when device is offline."""
        metrics = GWNSwitchAPI._get_default_cpumem_metrics()
        metrics.update(GWNSwitchAPI._get_default_sysinfo_metrics())
        metrics.update({
            "device_status": "offline",
            "connect_status": "offline",
            "connect_manager": None,
            "connect_address": None,
            "ports": [],
            "port_statistics": [],
        })
        return metrics

    @staticmethod
    def _get_default_cpumem_metrics() -> dict[str, Any]:
        """Get default CPU/memory metric values."""
        return {
            "cpu_usage_percent": None,
            "memory_usage_percent": None,
            "cpu_temperature_c": None,
            "system_temperature_c": None,
            "temperature_threshold": None,
            "fan_status": None,
            "total_power_w": None,
            "remaining_power_w": None,
        }

    @staticmethod
    def _get_default_sysinfo_metrics() -> dict[str, Any]:
        """Get default system info metric values."""
        return {
            "hostname": None,
            "uptime_seconds": None,
            "mac_address": None,
            "firmware_version": None,
            "hardware_version": None,
            "serial_number": None,
            "admin_ip": None,
            "part_number": None,
        }

    @property
    def is_online(self) -> bool:
        """Check if device is online."""
        return self._is_online

    @staticmethod
    def model_supports_poe(model: str | None) -> bool:
        """Return True if a GWN switch model supports PoE.

        GWN's PoE switches carry a trailing "P" in the model name (e.g.
        GWN7802P, GWN7811P, GWN7821P). Non-PoE models such as GWN7801 /
        GWN7803 omit the suffix and have no PoE functionality. When the model
        is unknown we assume PoE is present so already-configured devices keep
        working until the model is resolved.
        """
        return _model_supports_poe(model)

    @property
    def has_poe(self) -> bool:
        """Whether this device supports PoE (model ends with "P")."""
        return _model_supports_poe(self._model)

    @property
    def is_locked(self) -> bool:
        """Check if account is locked due to too many failed login attempts."""
        return self._is_locked

    @property
    def lock_remain_seconds(self) -> int:
        """Get remaining lock time in seconds."""
        return self._lock_remain_seconds

    @property
    def token(self) -> str | None:
        """Get current authentication token."""
        return self._token

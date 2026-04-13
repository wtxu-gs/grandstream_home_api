"""Utility functions for Grandstream Home API library."""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from typing import TYPE_CHECKING, Any, Literal

import requests
import urllib3

from grandstream_home_api.const import (
    DEVICE_TYPE_GDS,
    DEVICE_TYPE_GNS_NAS,
)
from grandstream_home_api.error import GrandstreamHAControlDisabledError

if TYPE_CHECKING:
    from grandstream_home_api.gds import GDSPhoneAPI
    from grandstream_home_api.gns import GNSNasAPI

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

# SIP registration status mapping
SIP_STATUS_MAP = {
    0: "unregistered",
    1: "registered",
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


def process_status(status_data: str | dict) -> str:
    """Process status data and ensure it doesn't exceed maximum length.

    Args:
        status_data: Raw status data (string or dict)

    Returns:
        Processed status string

    """
    if not status_data:
        return "unknown"

    if isinstance(status_data, dict):
        status_data = status_data.get("status", str(status_data))

    if isinstance(status_data, str) and status_data.startswith("{"):
        try:
            status_dict = json.loads(status_data)
            status_data = status_dict.get("status", status_data)
        except json.JSONDecodeError:
            pass

    status_str = str(status_data).lower().strip()

    if len(status_str) > 250:
        _LOGGER.warning(
            "Status string too long (%d characters), will be truncated",
            len(status_str),
        )
        return status_str[:250] + "..."

    return status_str


def process_push_data(data: dict[str, Any] | str) -> dict[str, Any]:
    """Process push data into standardized format.

    Args:
        data: Raw push data (dict or string)

    Returns:
        Processed data dictionary

    """
    if isinstance(data, str):
        try:
            parsed_data = json.loads(data)
            data = parsed_data
        except json.JSONDecodeError:
            data = {"phone_status": data}

    if not isinstance(data, dict):
        data = {"phone_status": str(data)}

    if "phone_status" not in data:
        status = data.get("status") or data.get("state") or data.get("value")
        if status:
            data = {"phone_status": status}

    if "phone_status" in data:
        data["phone_status"] = process_status(data["phone_status"])

    return data


def build_sip_account_dict(account: dict[str, Any]) -> dict[str, Any]:
    """Build SIP account dictionary with status mapping.

    Args:
        account: Raw account data

    Returns:
        Processed account dictionary

    """
    account_id = account.get("id", "")
    sip_id = account.get("sip_id", "")
    name = account.get("name", "")
    reg_status = account.get("reg", -1)
    status_text = SIP_STATUS_MAP.get(reg_status, f"Unknown ({reg_status})")

    return {
        "id": account_id,
        "sip_id": sip_id,
        "name": name,
        "reg": reg_status,
        "status": status_text,
    }


def get_by_path(data: dict[str, Any], path: str, index: int | None = None) -> Any:
    """Resolve nested value by path like 'disks[0].temperature_c' or 'fans[0]'.

    Args:
        data: Data dictionary to traverse
        path: Path string with optional array indices
        index: Optional index to replace {index} placeholder

    Returns:
        Value at path or None if not found

    """
    if index is not None and "{index}" in path:
        path = path.replace("{index}", str(index))

    cur = data
    parts = path.split(".")
    for part in parts:
        while "[" in part and "]" in part:
            base = part[: part.index("[")]
            idx_str = part[part.index("[") + 1 : part.index("]")]
            if base:
                if isinstance(cur, dict):
                    temp = cur.get(base)
                    if temp is None:
                        return None
                    cur = temp
                else:
                    return None
            try:
                idx = int(idx_str)
            except ValueError:
                return None
            if isinstance(cur, list) and 0 <= idx < len(cur):
                cur = cur[idx]
            else:
                return None
            if part.endswith("]"):
                part = ""
            else:
                part = part[part.index("]") + 1 :]
        if part:
            if isinstance(cur, dict):
                temp = cur.get(part)
                if temp is None:
                    return None
                cur = temp
            else:
                return None
    return cur


def detect_device_type(
    host: str, timeout: float = 5.0
) -> Literal["GDS", "GNS_NAS"] | None:
    """Detect device type by probing the device.

    This function attempts to determine the device type by checking
    which API endpoints respond correctly.

    Args:
        host: Device IP address or hostname
        timeout: Connection timeout in seconds

    Returns:
        Device type string ("GDS", "GNS_NAS") or None if detection failed

    """
    formatted_host = format_host_url(host)

    # Suppress all logging during detection to avoid spam
    logging.getLogger("urllib3").setLevel(logging.CRITICAL)
    logging.getLogger("requests").setLevel(logging.CRITICAL)

    # GNS devices use /api/gs/v1.0/ prefix, ports 5001 or 443
    gns_ports = [5001, 443]

    for port in gns_ports:
        gns_url = f"https://{formatted_host}:{port}/api/gs/v1.0/login/account/public_key"
        try:
            response = requests.get(
                gns_url,
                verify=False,
                timeout=timeout,
                allow_redirects=False,
            )
            # GNS API returns JSON with 'code' and 'data' fields
            if response.status_code == 200:
                try:
                    data = response.json()
                    if "code" in data and ("data" in data or "public_key" in data):
                        return DEVICE_TYPE_GNS_NAS
                except json.JSONDecodeError:
                    pass
            # Also check for 401 (auth required) which indicates GNS API
            if response.status_code in (401, 403):
                return DEVICE_TYPE_GNS_NAS
        except (requests.RequestException, OSError):
            pass

    # GDS devices use port 443, different API structure
    gds_url = f"https://{formatted_host}:443/"
    try:
        response = requests.get(
            gds_url,
            verify=False,
            timeout=timeout,
            allow_redirects=True,
        )
        # GDS devices typically return HTML with specific patterns
        if response.status_code == 200:
            content = response.text.lower()
            if "grandstream" in content or "gds" in content or "login" in content:
                return DEVICE_TYPE_GDS
        # Try the dologin endpoint
        login_url = f"https://{formatted_host}:443/dologin"
        try:
            login_response = requests.get(
                login_url,
                verify=False,
                timeout=timeout,
                allow_redirects=False,
            )
            if login_response.status_code in (200, 401, 403):
                return DEVICE_TYPE_GDS
        except (requests.RequestException, OSError):
            pass
    except (requests.RequestException, OSError):
        pass

    return None


def determine_device_type_from_product(product_name: str) -> str:
    """Determine device type from product name.

    Args:
        product_name: Product name from device discovery or detection

    Returns:
        Device type string ("GDS" or "GNS")

    """
    if not product_name:
        return DEVICE_TYPE_GDS

    product_upper = product_name.strip().upper()

    if product_upper.startswith("GNS"):
        return DEVICE_TYPE_GNS_NAS

    # GSC and GDS both use GDS API internally
    return DEVICE_TYPE_GDS


def get_device_model_from_product(product_name: str) -> str:
    """Get device model from product name.

    This returns the actual device model (GDS, GSC, or GNS)
    unlike determine_device_type_from_product which returns the API type.

    Args:
        product_name: Product name from device discovery

    Returns:
        Device model string ("GDS", "GSC", or "GNS")

    """
    if not product_name:
        return DEVICE_TYPE_GDS

    product_upper = product_name.strip().upper()

    if product_upper.startswith("GNS"):
        return DEVICE_TYPE_GNS_NAS
    if product_upper.startswith("GSC"):
        return "GSC"

    return DEVICE_TYPE_GDS


def is_grandstream_device(product_name: str) -> bool:
    """Check if device is a Grandstream device.

    Args:
        product_name: Product name from device discovery

    Returns:
        True if device is a Grandstream device

    """
    if not product_name or not isinstance(product_name, str):
        return False

    product_upper = product_name.strip().upper()
    return any(
        product_upper.startswith(prefix)
        for prefix in ("GDS", "GSC", "GNS")
    )


def extract_port_from_txt(
    txt_properties: dict[str, Any],
    default_port: int = 443,
) -> int:
    """Extract port from TXT record properties.

    Args:
        txt_properties: TXT record properties from Zeroconf
        default_port: Default port if none found

    Returns:
        Port number

    """
    # Try HTTPS port first
    https_port = txt_properties.get("https_port")
    if https_port:
        try:
            return int(https_port)
        except (ValueError, TypeError):
            pass

    # Try HTTP port
    http_port = txt_properties.get("http_port")
    if http_port:
        try:
            return int(http_port)
        except (ValueError, TypeError):
            pass

    return default_port


def create_api_instance(
    device_type: str,
    host: str,
    username: str,
    password: str,
    port: int = 443,
    verify_ssl: bool = False,
) -> GDSPhoneAPI | GNSNasAPI:
    """Create API instance based on device type.

    Args:
        device_type: Device type ("GDS" or "GNS")
        host: Device IP or hostname
        username: Login username
        password: Login password
        port: Port number
        verify_ssl: Whether to verify SSL certificate

    Returns:
        API instance (GDSPhoneAPI or GNSNasAPI)

    """
    # Import here to avoid circular import
    from grandstream_home_api.gds import GDSPhoneAPI
    from grandstream_home_api.gns import GNSNasAPI

    if device_type == DEVICE_TYPE_GNS_NAS:
        return GNSNasAPI(
            host,
            username,
            password,
            port=port,
            verify_ssl=verify_ssl,
        )
    return GDSPhoneAPI(
        host=host,
        username=username,
        password=password,
        port=port,
        verify_ssl=verify_ssl,
    )


def attempt_login(api: GDSPhoneAPI | GNSNasAPI) -> tuple[bool, str | None]:
    """Attempt to login to device API.

    Args:
        api: API instance (GDSPhoneAPI or GNSNasAPI)

    Returns:
        Tuple of (success, error_type) where error_type is:
        - None: login successful
        - "ha_control_disabled": HA control is disabled on device
        - "account_locked": account is temporarily locked
        - "auth_failed": authentication failed
        - "offline": device is offline/unreachable

    """
    try:
        success = api.login()
    except GrandstreamHAControlDisabledError:
        return False, "ha_control_disabled"
    except (OSError, RuntimeError, ValueError):
        return False, "offline"

    if success:
        return True, None

    # Check if HA control is disabled
    if hasattr(api, "is_ha_control_enabled") and not api.is_ha_control_enabled:
        return False, "ha_control_disabled"

    # Check if account is locked
    if hasattr(api, "_account_locked") and getattr(api, "_account_locked", False):
        return False, "account_locked"

    return False, "auth_failed"


def parse_mac_from_txt(mac_value: str | None) -> str | None:
    """Parse MAC address from TXT record value.

    Handles multiple MACs separated by comma.

    Args:
        mac_value: MAC address string from TXT record

    Returns:
        First MAC address or None

    """
    if not mac_value:
        return None

    mac_str = str(mac_value).strip()
    if "," in mac_str:
        mac_str = mac_str.split(",", maxsplit=1)[0].strip()

    return mac_str if mac_str else None


def get_device_info_from_txt(
    txt_properties: dict[str, Any],
) -> dict[str, Any]:
    """Extract device information from TXT record properties.

    Args:
        txt_properties: TXT record properties from Zeroconf

    Returns:
        Dictionary with extracted device info:
        - product_model: Product model string or None
        - device_type: Device type ("GDS" or "GNS")
        - device_model: Device model ("GDS", "GSC", or "GNS")
        - mac: MAC address or None
        - hostname: Hostname string
        - version: Firmware version string

    """
    product = txt_properties.get("product")
    product_name = txt_properties.get("product_name", "")
    hostname = txt_properties.get("hostname", "")
    mac = txt_properties.get("mac")
    version = txt_properties.get("version", "")

    # Product model - prefer 'product' field over 'product_name'
    product_model = None
    if product:
        product_model = str(product).strip().upper()
    elif product_name:
        product_model = str(product_name).strip().upper()

    # Device type and model
    device_type = DEVICE_TYPE_GDS
    device_model = DEVICE_TYPE_GDS

    if product_model:
        device_type = determine_device_type_from_product(product_model)
        device_model = get_device_model_from_product(product_model)

    return {
        "product_model": product_model,
        "device_type": device_type,
        "device_model": device_model,
        "mac": parse_mac_from_txt(mac),
        "hostname": hostname,
        "version": version,
    }


def get_default_username(device_type: str) -> str:
    """Get default username based on device type.

    Args:
        device_type: Device type ("GDS" or "GNS")

    Returns:
        Default username string

    """
    from grandstream_home_api.const import DEFAULT_USERNAME, DEFAULT_USERNAME_GNS

    if device_type == DEVICE_TYPE_GNS_NAS:
        return DEFAULT_USERNAME_GNS
    return DEFAULT_USERNAME


def get_default_port(device_type: str) -> int:
    """Get default port based on device type.

    Args:
        device_type: Device type ("GDS" or "GNS")

    Returns:
        Default port number

    """
    from grandstream_home_api.const import DEFAULT_HTTPS_PORT, DEFAULT_PORT

    if device_type == DEVICE_TYPE_GNS_NAS:
        return DEFAULT_HTTPS_PORT
    return DEFAULT_PORT


def validate_ip_address(ip_str: str) -> bool:
    """Validate IP address format.

    Args:
        ip_str: IP address string to validate

    Returns:
        True if valid, False otherwise

    """
    try:
        ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False
    else:
        return True


def validate_port(port_value: str | None) -> tuple[bool, int]:
    """Validate port number.

    Args:
        port_value: Port value to validate

    Returns:
        Tuple of (is_valid, port_number)

    """
    if port_value is None:
        return False, 0
    try:
        port = int(port_value)
    except (ValueError, TypeError):
        return False, 0
    else:
        return (1 <= port <= 65535), port


def extract_mac_from_name(name: str | None) -> str | None:
    """Extract MAC address from device name.

    Device names often contain MAC address in format like:
    - GDS_EC74D79753C5
    - GNS_xxx_EC74D79753C5

    Args:
        name: Device name to extract MAC from

    Returns:
        Formatted MAC address (e.g., "ec:74:d7:97:53:c5") or None

    """
    if not name:
        return None

    # Look for 12 consecutive hex characters (MAC without colons)
    match = re.search(r"([0-9A-Fa-f]{12})(?:_|$)", name)
    if match:
        mac_hex = match.group(1).upper()
        # Format as xx:xx:xx:xx:xx:xx
        formatted_mac = ":".join(mac_hex[i : i + 2] for i in range(0, 12, 2)).lower()
        return formatted_mac

    return None


def _get_encryption_key(unique_id: str) -> bytes:
    """Generate a consistent encryption key based on unique_id.

    Args:
        unique_id: Unique identifier for key generation

    Returns:
        Base64 encoded encryption key

    """
    import base64
    import hashlib

    # Use unique_id + a fixed salt to generate key
    salt = hashlib.sha256(f"grandstream_home_{unique_id}_salt_2026".encode()).digest()
    key_material = (unique_id + "grandstream_home").encode() + salt
    key = hashlib.sha256(key_material).digest()
    return base64.urlsafe_b64encode(key)


def encrypt_password(password: str, unique_id: str) -> str:
    """Encrypt password using Fernet encryption.

    Args:
        password: Plain text password
        unique_id: Unique ID for key generation

    Returns:
        Encrypted password (base64 encoded)

    """
    import base64

    from cryptography.fernet import Fernet

    if not password:
        return ""

    try:
        key = _get_encryption_key(unique_id)
        f = Fernet(key)
        encrypted = f.encrypt(password.encode())
        return base64.b64encode(encrypted).decode()
    except (ValueError, TypeError, OSError):
        return password  # Fallback to plaintext


def decrypt_password(encrypted_password: str, unique_id: str) -> str:
    """Decrypt password using Fernet encryption.

    Args:
        encrypted_password: Encrypted password (base64 encoded)
        unique_id: Unique ID for key generation

    Returns:
        Plain text password

    """
    import base64

    from cryptography.fernet import Fernet, InvalidToken

    if not encrypted_password:
        return ""

    # Check if it looks like encrypted data (base64 + reasonable length)
    if not is_encrypted_password(encrypted_password):
        return encrypted_password  # Assume plaintext for backward compatibility

    try:
        key = _get_encryption_key(unique_id)
        f = Fernet(key)
        encrypted_bytes = base64.b64decode(encrypted_password.encode())
        decrypted = f.decrypt(encrypted_bytes)
        return decrypted.decode()
    except (ValueError, TypeError, OSError, InvalidToken):
        return encrypted_password  # Fallback to plaintext


def is_encrypted_password(password: str) -> bool:
    """Check if password appears to be encrypted.

    Args:
        password: Password string to check

    Returns:
        True if password appears encrypted

    """
    import base64

    try:
        # Try to decode as base64, if successful it might be encrypted
        base64.b64decode(password.encode())
        return len(password) > 50  # Encrypted passwords are typically longer
    except (ValueError, TypeError):
        return False


def generate_unique_id(
    device_name: str, device_type: str, host: str, port: int = 443
) -> str:
    """Generate device unique ID.

    Prioritize using device name as the basis for unique ID.
    If device name is empty, use IP address and port.

    Args:
        device_name: Device name
        device_type: Device type (e.g., "GDS", "GNS_NAS")
        host: Device IP address
        port: Device port

    Returns:
        Formatted unique ID string

    """
    # Clean device name, remove special characters
    if device_name and device_name.strip():
        # Use device name as the basis for unique ID
        clean_name = (
            device_name.strip().replace(" ", "_").replace("-", "_").replace(".", "_")
        )
        unique_id = clean_name
    else:
        # If no device name, use IP address and port
        clean_host = host.replace(".", "_").replace(":", "_")
        unique_id = f"{device_type}_{clean_host}_{port}"

    # Ensure unique ID contains no special characters and convert to lowercase
    return unique_id.replace(" ", "_").replace("-", "_").lower()


def fetch_sip_accounts(api) -> list[dict[str, Any]]:
    """Fetch SIP account status from device API.

    Args:
        api: GDSPhoneAPI instance with get_accounts method

    Returns:
        List of SIP account dictionaries with id, sip_id, name, reg, status fields

    """
    sip_accounts: list[dict[str, Any]] = []

    if not hasattr(api, "get_accounts"):
        return sip_accounts

    try:
        sip_result = api.get_accounts()
        if isinstance(sip_result, dict) and sip_result.get("response") == "success":
            sip_body = sip_result.get("body", [])
            if isinstance(sip_body, list):
                sip_accounts.extend(
                    build_sip_account_dict(account)
                    for account in sip_body
                    if isinstance(account, dict)
                )
            elif isinstance(sip_body, dict):
                sip_accounts.append(build_sip_account_dict(sip_body))
    except (RuntimeError, ValueError, OSError):
        pass

    return sip_accounts


def fetch_gds_status(api) -> dict[str, Any] | None:
    """Fetch GDS device status and SIP accounts.

    Args:
        api: GDSPhoneAPI instance

    Returns:
        Dictionary with phone_status and sip_accounts, or None if failed

    """
    if not hasattr(api, "get_phone_status"):
        return None

    try:
        result = api.get_phone_status()
        if not isinstance(result, dict) or result.get("response") != "success":
            return None

        status = result.get("body", "unknown")
        processed_status = process_status(status) + " "

        # Fetch SIP accounts
        sip_accounts = fetch_sip_accounts(api)

        return {
            "phone_status": processed_status,
            "sip_accounts": sip_accounts,
            "version": getattr(api, "version", None),
        }
    except (RuntimeError, ValueError, OSError):
        return None


def fetch_gns_metrics(api) -> dict[str, Any] | None:
    """Fetch GNS NAS device metrics.

    Args:
        api: GNSNasAPI instance

    Returns:
        Dictionary with system metrics, or None if failed

    """
    if not hasattr(api, "get_system_metrics"):
        return None

    try:
        result = api.get_system_metrics()
        if not isinstance(result, dict):
            return None

        result.setdefault("device_status", "online")
        return result
    except (RuntimeError, ValueError, OSError):
        return None

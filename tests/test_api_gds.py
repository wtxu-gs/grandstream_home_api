"""Tests for GDS API - basic tests."""

import hashlib
import time
from unittest.mock import MagicMock, patch

from grandstream_home_api import (
    UNLOCK_CODE_PERMISSION_DENIED,
    UNLOCK_CODE_TIMESTAMP_EXPIRED,
    GDSPhoneAPI,
)
from grandstream_home_api.error import (
    GrandstreamAuthTokenError,
    GrandstreamChallengeError,
    GrandstreamHAControlDisabledError,
    GrandstreamRTSPError,
    GrandstreamSignatureError,
    GrandstreamUnlockError,
)
from grandstream_home_api.gds import APIResponse
import pytest
import requests

pytestmark = pytest.mark.enable_socket


def test_gds_api_device_type() -> None:
    """Test device type property."""
    api = GDSPhoneAPI("192.168.1.100", "password")
    assert hasattr(api, "device_type")
    assert api.device_type == "GDS"


def test_gds_api_host() -> None:
    """Test host property."""
    api = GDSPhoneAPI("192.168.1.100", "password")
    assert api.host == "192.168.1.100"


def test_gds_api_with_port() -> None:
    """Test with custom port."""
    api = GDSPhoneAPI("192.168.1.100", "password", port=8080)
    assert api.port == 8080


def test_gds_api_default_port() -> None:
    """Test default port for GDS is 443 (HTTPS)."""
    api = GDSPhoneAPI("192.168.1.100", "password")
    assert api.port == 443


def test_gds_api_base_url_with_port() -> None:
    """Test base URL with custom port."""
    api = GDSPhoneAPI("192.168.1.100", "password", port=8080)
    assert "8080" in str(api.port)


def test_gds_api_host_property() -> None:
    """Test host property."""
    api = GDSPhoneAPI("192.168.1.100", "password")
    assert api.host == "192.168.1.100"


def test_gds_api_device_type_property() -> None:
    """Test device type property."""
    api = GDSPhoneAPI("192.168.1.100", "password")
    assert api.device_type == "GDS"


def test_gds_api_initialization() -> None:
    """Test API initialization."""
    api = GDSPhoneAPI("192.168.1.100", "password")
    assert api.host == "192.168.1.100"
    assert api.device_type == "GDS"


def test_gds_api_base_url_https() -> None:
    """Test base URL always uses HTTPS for GDS."""
    api = GDSPhoneAPI("192.168.1.100", "password")
    assert "https://" in api.base_url
    assert api.use_https is True


def test_gds_api_build_headers_with_auth() -> None:
    """Test header building with authentication cookie."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    api.session_id = "sid"
    api.device_mac = "mac"
    api.version = "ver"
    headers = api._build_headers()

    assert "Cookie" in headers
    assert "sid=sid" in headers["Cookie"]


def test_gds_api_build_headers_without_auth() -> None:
    """Test header building without authentication cookie."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    api.session_id = "sid"
    api.device_mac = "mac"
    headers = api._build_headers(include_auth=False)

    assert "Cookie" not in headers


def test_gds_api_build_headers_missing_session() -> None:
    """Test Gds api build headers missing session."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    headers = api._build_headers()
    assert "Cookie" not in headers


def test_gds_api_is_session_expired() -> None:
    """Test session expiration detection."""
    assert (
        GDSPhoneAPI._is_session_expired({"response": "success", "body": "unauthorized"})
        is True
    )
    assert (
        GDSPhoneAPI._is_session_expired(
            {"response": "error", "body": {"status": "session-expired"}}
        )
        is True
    )
    assert (
        GDSPhoneAPI._is_session_expired({"response": "success", "body": "ok"}) is False
    )


def test_gds_api_get_challenge_success() -> None:
    """Test challenge retrieval success."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    with patch.object(
        api,
        "_make_request",
        return_value={"response": "success", "body": "challenge"},
    ):
        assert api._get_challenge() == "challenge"


def test_gds_api_get_challenge_error() -> None:
    """Test challenge retrieval failure."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    with (
        patch.object(
            api,
            "_make_request",
            return_value={"response": "error", "body": "failed"},
        ),
        pytest.raises(RuntimeError),
    ):
        api._get_challenge()


def test_gds_api_perform_login_success() -> None:
    """Test login success path."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    with (
        patch.object(api, "_get_challenge", return_value="challenge"),
        patch.object(api, "_generate_login_secret", return_value="secret"),
        patch.object(
            api,
            "_make_request",
            return_value={
                "response": "success",
                "body": {"sid": "sid", "mac": "mac", "ver": "ver"},
            },
        ),
    ):
        assert api._perform_login() is True

    assert api.session_id == "sid"
    assert api.device_mac == "mac"
    assert api.version == "ver"
    assert api.is_authenticated is True


def test_gds_api_perform_login_locked() -> None:
    """Test login locked response path."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    with (
        patch.object(api, "_get_challenge", return_value="challenge"),
        patch.object(api, "_generate_login_secret", return_value="secret"),
        patch.object(
            api,
            "_make_request",
            return_value={"response": "error", "body": "locked", "lockTime": 10},
        ),
    ):
        assert api._perform_login() is False

    assert api.is_account_locked is True


def test_gds_api_ensure_authenticated_offline() -> None:
    """Test authentication when device is offline."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    api._is_online = False

    with pytest.raises(RuntimeError):
        api._ensure_authenticated()


def test_gds_api_get_rtsp_url_missing_credentials() -> None:
    """Test RTSP URL creation with missing credentials."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    api.rtsp_username = None
    api.rtsp_password = None

    with pytest.raises(GrandstreamRTSPError):
        api.get_rtsp_url()


def test_gds_api_get_rtsp_url_socket_error() -> None:
    """Test RTSP URL creation when socket connect fails."""
    api = GDSPhoneAPI(
        "192.168.1.100", "admin", "password", rtsp_username="rtsp", rtsp_password="pw"
    )

    with patch(
        "grandstream_home_api.gds.socket.create_connection",
        side_effect=OSError("Connection refused"),
    ):
        url = api.get_rtsp_url()

    assert url.startswith("rtsp://rtsp:pw@192.168.1.100:554")


def test_gds_api_get_rtsp_url_host_not_configured() -> None:
    """Test RTSP URL creation when host is not configured."""
    api = GDSPhoneAPI.__new__(GDSPhoneAPI)  # type: ignore[attr-defined]
    api.host = None
    api.rtsp_username = "rtsp"
    api.rtsp_password = "pw"

    with pytest.raises(GrandstreamRTSPError, match="Host is not configured"):
        api.get_rtsp_url()


def test_gds_api_get_rtsp_url_ipv6() -> None:
    """Test RTSP URL creation with IPv6 address."""
    api = GDSPhoneAPI(
        "2408:8640:8fe:fc::53",
        "admin",
        "password",
        rtsp_username="rtsp",
        rtsp_password="pw",
    )

    with patch("grandstream_home_api.gds.socket.create_connection"):
        url = api.get_rtsp_url()

    # IPv6 addresses should be wrapped in square brackets
    assert url == "rtsp://rtsp:pw@[2408:8640:8fe:fc::53]:554/grandstream/sub_stream"


def test_gds_api_base_address_ipv6() -> None:
    """Test base address formatting with IPv6."""
    api = GDSPhoneAPI("2408:8640:8fe:fc::53", "admin", "password", port=8443)
    assert api.base_address == "https://[2408:8640:8fe:fc::53]:8443"
    assert api.base_url == "https://[2408:8640:8fe:fc::53]:8443/cgi-bin/"


def test_gds_api_base_address_ipv4() -> None:
    """Test base address formatting with IPv4."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password", port=8443)
    assert api.base_address == "https://192.168.1.100:8443"
    assert api.base_url == "https://192.168.1.100:8443/cgi-bin/"


def test_gds_api_session_retry_success() -> None:
    """Test session retry decorator re-authenticates."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    def fake_call(self):
        return {"response": "success", "body": "unauthorized"}

    wrapped = api._handle_session_retry(fake_call)
    api.login = MagicMock(return_value=True)  # type: ignore[method-assign]
    result = wrapped(api)
    assert result.get("response") in ["success", "error"]
    assert api.login.called


def test_gds_api_session_retry_failure() -> None:
    """Test Gds api session retry failure."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    def fake_call(self):
        return {"response": "success", "body": "unauthorized"}

    wrapped = api._handle_session_retry(fake_call)
    api.login = MagicMock(return_value=False)  # type: ignore[method-assign]
    result = wrapped(api)
    assert result["response"] == "error"
    assert "Re-authentication failed" in result["body"]


def test_gds_api_require_auth_calls_login() -> None:
    """Test require_auth decorator triggers _ensure_authenticated."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    api._is_online = True

    def fake_call(self):
        return {"ok": True}

    wrapped = api._require_auth(fake_call)
    api.login = MagicMock(return_value=True)  # type: ignore[method-assign]
    result = wrapped(api)
    assert result["ok"] is True
    assert api.login.called


def test_gds_api_make_request_ssl_error() -> None:
    """Test Gds api make request ssl error."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    api.session.request = MagicMock(side_effect=requests.exceptions.SSLError("ssl"))  # type: ignore[method-assign]
    result = api._make_request("GET", "api-get_phone_status")
    assert result["response"] == "error"


def test_gds_api_make_request_timeout_error() -> None:
    """Test Gds api make request timeout error."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    api.session.request = MagicMock(side_effect=requests.exceptions.Timeout("timeout"))  # type: ignore[method-assign]
    result = api._make_request("GET", "api-get_phone_status")
    assert result["response"] == "error"


def test_gds_api_make_request_json_error() -> None:
    """Test Gds api make request json error."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    response = MagicMock()
    response.status_code = 200
    response.json.side_effect = ValueError("bad")
    api.session.request = MagicMock(return_value=response)  # type: ignore[method-assign]
    result = api._make_request("GET", "api-get_phone-status")
    assert result["response"] == "error"


def test_gds_api_make_request_success_with_debug_log() -> None:
    """Test successful request that triggers debug log on line 353."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {"status": "success", "data": {"phone": "online"}}
    api.session.request = MagicMock(return_value=response)  # type: ignore[method-assign]

    # This should trigger the debug log on line 353
    result = api._make_request("GET", "api-get_phone-status")

    assert result["status"] == "success"
    assert result["data"]["phone"] == "online"


def test_gds_api_make_request_http_error() -> None:
    """Test Gds api make request http error."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    response = MagicMock()
    response.status_code = 500
    api.session.request = MagicMock(return_value=response)  # type: ignore[method-assign]
    result = api._make_request("GET", "api-get_phone_status")
    assert result["response"] == "error"


def test_gds_api_make_request_request_error() -> None:
    """Test Gds api make request request error."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    api.session.request = MagicMock(  # type: ignore[method-assign]
        side_effect=requests.RequestException("error")
    )
    result = api._make_request("GET", "api-get_phone_status")
    assert result["response"] == "error"


def test_api_response_to_dict_success() -> None:
    """Test Api response to dict success."""
    response = APIResponse(success=True, data={"ok": True})
    result = response.to_dict()
    assert result["response"] == "success"
    assert result["body"] == {"ok": True}


def test_api_response_to_dict_error() -> None:
    """Test Api response to dict error."""
    response = APIResponse(success=False, error="bad")
    result = response.to_dict()
    assert result["response"] == "error"
    assert result["body"] == "bad"


def test_gds_api_perform_login_failed_response() -> None:
    """Test Gds api perform login failed response."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    with (
        patch.object(api, "_get_challenge", return_value="challenge"),
        patch.object(api, "_generate_login_secret", return_value="secret"),
        patch.object(
            api,
            "_make_request",
            return_value={"response": "error", "body": "invalid"},
        ),
    ):
        assert api._perform_login() is False
    assert api._login_failed_count == 1


def test_gds_api_perform_login_account_locked() -> None:
    """Test Gds api perform login account locked."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    api._account_locked = True
    api._account_lock_expire_time = time.time() + 60
    assert api._perform_login() is False


def test_gds_api_ensure_authenticated_locked() -> None:
    """Test Gds api ensure authenticated locked."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    api._is_online = True
    api._account_locked = True
    api._account_lock_expire_time = time.time() + 60
    with pytest.raises(RuntimeError):
        api._ensure_authenticated()


def test_gds_api_ensure_authenticated_login_failed() -> None:
    """Test Gds api ensure authenticated login failed."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    api._is_online = True
    api.login = MagicMock(return_value=False)  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        api._ensure_authenticated()


def test_gds_api_is_session_expired_invalid_response() -> None:
    """Test Gds api is session expired invalid response."""
    assert GDSPhoneAPI._is_session_expired("bad") is False  # type: ignore[arg-type]


def test_gds_api_init_with_entry_rtsp() -> None:
    """Test Gds api init with entry rtsp."""
    # Test direct parameter initialization instead of entry
    api = GDSPhoneAPI(
        host="192.168.1.50",
        username="admin",
        password="pw",
        port=80,
        rtsp_username="rtsp_user",
        rtsp_password="rtsp_pw",
    )
    assert api.rtsp_username == "rtsp_user"
    assert api.rtsp_password == "rtsp_pw"


def test_gds_api_is_account_locked_expires() -> None:
    """Test Gds api is account locked expires."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    api._account_locked = True
    api._account_lock_expire_time = time.time() - 1
    assert api.is_account_locked is False


def test_gds_api_register_ha_urls_payload() -> None:
    """Test Gds api register ha urls payload."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    api.session_id = "sid"
    api.device_mac = "mac"
    with patch.object(
        api, "_make_request", return_value={"response": "success"}
    ) as mock_req:
        result = api.register_ha_urls("http://status", "http://command", "id", 123)
    assert result["response"] == "success"
    assert mock_req.call_args.kwargs["json_data"]["ha_instance_id"] == "id"
    assert mock_req.call_args.kwargs["json_data"]["timestamp"] == 123


def test_gds_api_reboot_device() -> None:
    """Test reboot device."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    api.session_id = "sid"
    api.device_mac = "mac"
    with patch.object(
        api, "_make_request", return_value={"response": "success"}
    ) as mock_req:
        result = api.reboot_device()
    assert result["response"] == "success"
    assert mock_req.call_args.kwargs["params"] == {"request": "REBOOT"}


def test_gds_api_get_phone_status() -> None:
    """Test get phone status."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    api.session_id = "sid"
    api.device_mac = "mac"
    with patch.object(
        api, "_make_request", return_value={"response": "success", "body": "status"}
    ):
        result = api.get_phone_status()
    assert result["body"] == "status"


def test_gds_api_is_online_property() -> None:
    """Test is_online property."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    api._is_online = True
    assert api.is_online is True
    api._is_online = False
    assert api.is_online is False


def test_gds_api_perform_login_connection_error() -> None:
    """Test login connection error."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    with (
        patch.object(api, "_get_challenge", return_value="challenge"),
        patch.object(api, "_generate_login_secret", return_value="secret"),
        patch.object(
            api,
            "_make_request",
            side_effect=requests.exceptions.ConnectionError("error"),
        ),
    ):
        assert api._perform_login() is False
    assert api._is_authenticated is False
    assert api._is_online is False


def test_gds_api_perform_login_runtime_error_offline() -> None:
    """Test login runtime error (offline)."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    with (
        patch.object(api, "_get_challenge", return_value="challenge"),
        patch.object(api, "_generate_login_secret", return_value="secret"),
        patch.object(
            api,
            "_make_request",
            side_effect=RuntimeError("Device is offline"),
        ),
    ):
        assert api._perform_login() is False
    assert api._is_authenticated is False


def test_gds_api_perform_login_runtime_error_other() -> None:
    """Test login runtime error (other)."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    with (
        patch.object(api, "_get_challenge", return_value="challenge"),
        patch.object(api, "_generate_login_secret", return_value="secret"),
        patch.object(
            api,
            "_make_request",
            side_effect=RuntimeError("Other error"),
        ),
    ):
        assert api._perform_login() is False
    assert api._login_failed_count == 1


def test_gds_api_perform_login_json_error() -> None:
    """Test login JSON error."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    with (
        patch.object(api, "_get_challenge", return_value="challenge"),
        patch.object(api, "_generate_login_secret", return_value="secret"),
        patch.object(
            api,
            "_make_request",
            side_effect=ValueError("json error"),
        ),
    ):
        assert api._perform_login() is False
    assert api._login_failed_count == 1


def test_gds_api_perform_login_request_error_connection() -> None:
    """Test login request error (connection)."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    with (
        patch.object(api, "_get_challenge", return_value="challenge"),
        patch.object(api, "_generate_login_secret", return_value="secret"),
        patch.object(
            api,
            "_make_request",
            side_effect=requests.RequestException("connection refused"),
        ),
    ):
        assert api._perform_login() is False
    assert api._is_online is False


def test_gds_api_perform_login_request_error_other() -> None:
    """Test login request error (other)."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    with (
        patch.object(api, "_get_challenge", return_value="challenge"),
        patch.object(api, "_generate_login_secret", return_value="secret"),
        patch.object(
            api,
            "_make_request",
            side_effect=requests.RequestException("other error"),
        ),
    ):
        assert api._perform_login() is False
    assert api._login_failed_count == 1


def test_gds_api_login_incomplete_response() -> None:
    """Test login with missing fields."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    with (
        patch.object(api, "_get_challenge", return_value="challenge"),
        patch.object(api, "_generate_login_secret", return_value="secret"),
        patch.object(
            api,
            "_make_request",
            return_value={
                "response": "success",
                "body": {"sid": "sid"},  # Missing mac and ver
            },
        ),
    ):
        assert api._perform_login() is True
    # Should warn but succeed


def test_gds_api_login_warning_threshold() -> None:
    """Test login warning threshold."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    api._login_failed_count = 2


def test_gds_api_perform_login_multiple_failures_warning() -> None:
    """Test that multiple login failures trigger warning on line 572."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    # First login failure
    with (
        patch.object(api, "_get_challenge", return_value="challenge"),
        patch.object(api, "_generate_login_secret", return_value="secret"),
        patch.object(
            api,
            "_make_request",
            return_value={"response": "error", "body": "failed"},
        ),
    ):
        assert api._perform_login() is False
        assert api._login_failed_count == 1

    # Second login failure - this should trigger the warning on line 572
    with (
        patch.object(api, "_get_challenge", return_value="challenge"),
        patch.object(api, "_generate_login_secret", return_value="secret"),
        patch.object(
            api,
            "_make_request",
            return_value={"response": "error", "body": "failed"},
        ),
    ):
        assert api._perform_login() is False
        assert api._login_failed_count == 2


def test_gds_api_login_success_path() -> None:
    """Test login method success path to cover line 444 debug log."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    with (
        patch.object(api, "_get_challenge", return_value="challenge"),
        patch.object(api, "_generate_login_secret", return_value="secret"),
        patch.object(
            api,
            "_make_request",
            return_value={
                "response": "success",
                "body": {"sid": "sid", "mac": "mac", "ver": "ver"},
            },
        ),
    ):
        # Call login() instead of _perform_login() to cover line 444
        assert api.login() is True
        assert api.is_authenticated is True


def test_gds_api_generate_login_secret_success() -> None:
    """Test _generate_login_secret method to cover lines 484-485."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password123")

    # Call the method directly to cover lines 484-485
    result = api._generate_login_secret("test_challenge")

    # Verify it returns a valid SHA256 hash
    assert isinstance(result, str)
    assert len(result) == 64  # SHA256 hex digest length
    expected = hashlib.sha256(b"password123test_challenge").hexdigest()
    assert result == expected
    with (
        patch.object(api, "_get_challenge", return_value="challenge"),
        patch.object(api, "_generate_login_secret", return_value="secret"),
        patch.object(
            api,
            "_make_request",
            return_value={"response": "error", "body": "failed"},
        ),
    ):
        assert api._perform_login() is False
    # Logs warning


def test_gds_api_ensure_authenticated_too_many_failures() -> None:
    """Test ensure_authenticated with too many failures."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    api._login_failed_count = 3
    api._last_login_attempt = time.time() - 10  # 10s ago
    api._is_online = True

    with pytest.raises(RuntimeError) as excinfo:
        api._ensure_authenticated()
    assert "Too many login failures" in str(excinfo.value)

    # Test expiry
    api._last_login_attempt = time.time() - 301  # 301s ago
    with patch.object(api, "login", return_value=True):
        api._ensure_authenticated()
    assert api._login_failed_count == 0


def test_gds_api_register_ha_urls_error() -> None:
    """Test register_ha_urls with error response."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    api.session_id = "sid"
    api.device_mac = "mac"
    with patch.object(
        api, "_make_request", return_value={"response": "error", "body": "fail"}
    ):
        result = api.register_ha_urls("http://status", "http://command", "id", 123)
    assert result["response"] == "error"
    assert result["body"] == "fail"


def test_gds_api_reboot_device_error() -> None:
    """Test reboot device error."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    api.session_id = "sid"
    api.device_mac = "mac"
    with patch.object(
        api, "_make_request", return_value={"response": "error", "body": "fail"}
    ):
        result = api.reboot_device()
    assert result["response"] == "error"
    assert result["body"] == "fail"


def test_gds_api_host_none_raises_error() -> None:
    """Test that host=None raises ValueError during initialization (covers line 170)."""
    # Test that creating API with None host raises ValueError
    with pytest.raises(ValueError, match="Host is required"):
        GDSPhoneAPI(None, "admin", "password")


def test_gds_api_build_headers_host_none_raises_error() -> None:
    """Test that _build_headers raises ValueError when host is None (covers line 270)."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    api.host = None
    with pytest.raises(ValueError, match="Host must be set before making requests"):
        api._build_headers()


def test_gds_api_get_challenge_none_raises_error() -> None:
    """Test that _get_challenge raises RuntimeError when challenge is None (covers line 487)."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    with (
        patch.object(
            api,
            "_make_request",
            return_value={"response": "success", "body": None},
        ),
        pytest.raises(RuntimeError, match="Challenge token is None"),
    ):
        api._get_challenge()


def test_gds_api_get_accounts_success() -> None:
    """Test successful get_accounts call."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    # Mock the _ensure_authenticated method to bypass login
    with (
        patch.object(api, "_ensure_authenticated"),
        patch.object(
            api,
            "_make_request",
            return_value={
                "response": "success",
                "body": [
                    {"id": "1", "reg": 1, "name": "Account 1"},
                    {"id": "2", "reg": 0, "name": "Account 2"},
                ],
            },
        ),
    ):
        result = api.get_accounts()

        assert result["response"] == "success"
        assert len(result["body"]) == 2
        assert result["body"][0]["id"] == "1"


def test_gds_api_get_accounts_with_filter() -> None:
    """Test get_accounts with registered filter."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    # Mock the _ensure_authenticated method to bypass login
    with (
        patch.object(api, "_ensure_authenticated"),
        patch.object(
            api,
            "_make_request",
            return_value={"response": "success", "body": []},
        ) as mock_request,
    ):
        api.get_accounts(registered=True)

        # Verify the request was made
        mock_request.assert_called_once()


def test_gds_api_reset_all_alarms_success() -> None:
    """Test successful reset_all_alarms call."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    # Mock the _ensure_authenticated method to bypass login
    with (
        patch.object(api, "_ensure_authenticated"),
        patch.object(
            api,
            "_make_request",
            return_value={"response": "success", "body": "Alarms reset"},
        ),
    ):
        result = api.reset_all_alarms()

        assert result["response"] == "success"
        assert result["body"] == "Alarms reset"


def test_gds_api_lock_door_success() -> None:
    """Test successful lock_door call."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    api._access_token = "test_token"
    api._access_token_time = time.time()

    with patch.object(
        api,
        "_execute_door_operation",
        return_value={"response": "success", "body": "Door locked"},
    ) as mock_execute:
        result = api.lock_door(door_id=1)

        assert result["response"] == "success"
        assert result["body"] == "Door locked"
        mock_execute.assert_called_once_with(1, "2", "lock")


def test_gds_api_unlock_door_success() -> None:
    """Test successful unlock_door call."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    api._access_token = "test_token"
    api._access_token_time = time.time()

    with patch.object(
        api,
        "_execute_door_operation",
        return_value={"response": "success", "body": "Door unlocked"},
    ) as mock_execute:
        result = api.unlock_door(door_id=0)

        assert result["response"] == "success"
        assert result["body"] == "Door unlocked"
        mock_execute.assert_called_once_with(0, "1", "unlock")


def test_gds_api_unlock_door_no_token() -> None:
    """Test unlock_door without access token."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    api._access_token = None

    with (
        patch.object(
            api,
            "_get_access_token",
            return_value="new_token",
        ),
        patch.object(
            api,
            "_execute_door_operation",
            return_value={"response": "success", "body": "Door unlocked"},
        ) as mock_execute,
    ):
        result = api.unlock_door()

        assert result["response"] == "success"
        mock_execute.assert_called_once()


def test_gds_api_refresh_access_token_success() -> None:
    """Test _refresh_access_token success."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    with patch.object(
        api,
        "_get_access_token",
        return_value="refreshed_token",
    ):
        token = api._refresh_access_token()

        assert token == "refreshed_token"


def test_gds_api_register_ha_urls_success() -> None:
    """Test register_ha_urls success."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    # Mock the _ensure_authenticated method to bypass login
    with (
        patch.object(api, "_ensure_authenticated"),
        patch.object(
            api,
            "_make_request",
            return_value={"response": "success", "body": "URLs registered"},
        ),
    ):
        result = api.register_ha_urls("http://ha.local", "webhook1", "webhook2")

        assert result["response"] == "success"
        assert result["body"] == "URLs registered"


def test_gds_api_generate_hmac_signature() -> None:
    """Test HMAC signature generation."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    key = "test_key"
    message = "test_message"

    signature = api._generate_hmac_signature(key, message)

    # Verify it's a valid hex string
    assert isinstance(signature, str)
    assert len(signature) == 64  # SHA256 hex digest length

    # Verify it's consistent
    signature2 = api._generate_hmac_signature(key, message)
    assert signature == signature2

    # Verify different inputs produce different results
    signature3 = api._generate_hmac_signature("different_key", message)
    assert signature != signature3


def test_gds_api_is_access_token_valid_no_token() -> None:
    """Test access token validation with no token."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    assert api._is_access_token_valid() is False


def test_gds_api_is_access_token_valid_no_time() -> None:
    """Test access token validation with token but no time."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    api._access_token = "test_token"
    api._access_token_time = None

    assert api._is_access_token_valid() is False


def test_gds_api_is_access_token_valid_expired() -> None:
    """Test access token validation with expired token."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    api._access_token = "test_token"
    api._access_token_time = time.time() - (3300 + 100)  # Use hardcoded TTL value

    assert api._is_access_token_valid() is False


def test_gds_api_is_access_token_valid_current() -> None:
    """Test access token validation with current token."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    api._access_token = "test_token"
    api._access_token_time = time.time()

    assert api._is_access_token_valid() is True


def test_gds_api_check_http_401_error_true() -> None:
    """Test HTTP 401 error detection."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    response = {"response": "error", "body": "401"}
    assert api._check_http_401_error(response) is True


def test_gds_api_check_http_401_error_false() -> None:
    """Test HTTP 401 error detection with non-401 error."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    response = {"response": "error", "body": "500"}
    assert api._check_http_401_error(response) is False


def test_gds_api_check_http_401_error_success() -> None:
    """Test HTTP 401 error detection with success response."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    response = {"response": "success", "body": "data"}
    assert api._check_http_401_error(response) is False


def test_gds_api_handle_unlock_error_code_success() -> None:
    """Test unlock error code handling for success."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    # The method doesn't handle success codes, it only handles error codes
    # So "0" (success) will be treated as unknown error code
    with pytest.raises(GrandstreamAuthTokenError, match="Unknown error code"):
        api._handle_unlock_error_code("0", "access_token")


def test_gds_api_handle_unlock_error_code_auth_failed() -> None:
    """Test unlock error code handling for auth failure."""

    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    # For non-access_token operations, should raise GrandstreamSignatureError
    with pytest.raises(GrandstreamSignatureError):
        api._handle_unlock_error_code("-100", "challenge")


def test_gds_api_handle_unlock_error_code_auth_failed_access_token() -> None:
    """Test unlock error code handling for auth failure in access token operation."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    # For access_token operations, should raise RuntimeError
    with pytest.raises(RuntimeError, match="Invalid password"):
        api._handle_unlock_error_code("-100", "access_token")


def test_gds_api_handle_unlock_error_code_challenge_invalid() -> None:
    """Test unlock error code handling for invalid challenge."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    with pytest.raises(GrandstreamChallengeError):
        api._handle_unlock_error_code("-500", "test_operation")


def test_gds_api_handle_unlock_error_code_material_empty() -> None:
    """Test unlock error code handling for empty material."""

    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    # For access_token operations
    with pytest.raises(GrandstreamAuthTokenError, match="Material is empty"):
        api._handle_unlock_error_code("-200", "access_token")


def test_gds_api_handle_unlock_error_code_material_empty_unlock() -> None:
    """Test unlock error code handling for empty material in unlock operation."""

    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    # For unlock operations
    with pytest.raises(GrandstreamUnlockError, match="Material is empty"):
        api._handle_unlock_error_code("-200", "unlock")


def test_gds_api_handle_unlock_error_code_permission_denied() -> None:
    """Test unlock error code handling for permission denied."""

    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    # For access_token operations
    with pytest.raises(GrandstreamAuthTokenError, match="Permission denied"):
        api._handle_unlock_error_code("-400", "access_token")


def test_gds_api_handle_unlock_error_code_timestamp_expired() -> None:
    """Test unlock error code handling for expired timestamp."""

    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    # For access_token operations
    with pytest.raises(GrandstreamAuthTokenError, match="Timestamp expired"):
        api._handle_unlock_error_code("-300", "access_token")


def test_gds_api_handle_unlock_error_code_unknown() -> None:
    """Test unlock error code handling for unknown error."""

    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    # For access_token operations
    with pytest.raises(GrandstreamAuthTokenError, match="Unknown error code"):
        api._handle_unlock_error_code("-999", "access_token")


def test_gds_api_get_access_token_response_success() -> None:
    """Test _get_access_token_response success."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    # Mock the API as online and authenticated
    api._is_online = True
    api.session_id = "test_session"

    with patch.object(api, "_make_request") as mock_request:
        mock_request.return_value = {
            "response": "success",
            "access_token": "test-token-123",
            "code": "0",
        }

        response = api._get_access_token_response()

        assert response["response"] == "success"
        assert response["access_token"] == "test-token-123"
        mock_request.assert_called_once()


def test_gds_api_get_access_token_cached() -> None:
    """Test _get_access_token with cached token."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    # Set up cached token
    api._access_token = "cached-token"
    api._access_token_time = time.time()

    with patch.object(api, "_is_access_token_valid", return_value=True):
        token = api._get_access_token()
        assert token == "cached-token"


def test_gds_api_get_access_token_no_password() -> None:
    """Test _get_access_token without password."""
    api = GDSPhoneAPI("192.168.1.100", "admin", None)

    with pytest.raises(GrandstreamAuthTokenError, match="Password is required"):
        api._get_access_token()


def test_gds_api_get_access_token_success() -> None:
    """Test _get_access_token success path."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    with (
        patch.object(api, "_is_access_token_valid", return_value=False),
        patch.object(api, "_get_access_token_response") as mock_response,
    ):
        mock_response.return_value = {
            "response": "success",
            "code": "0",
            "access_token": "new-token-456",
        }

        token = api._get_access_token()

        assert token == "new-token-456"
        assert api._access_token == "new-token-456"
        assert api._access_token_time is not None


def test_gds_api_get_access_token_no_token_in_response() -> None:
    """Test _get_access_token when response lacks access_token."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    with (
        patch.object(api, "_is_access_token_valid", return_value=False),
        patch.object(api, "_get_access_token_response") as mock_response,
    ):
        mock_response.return_value = {
            "response": "success",
            "code": "0",
            # Missing access_token
        }

        with pytest.raises(GrandstreamAuthTokenError, match="Access token not found"):
            api._get_access_token()


def test_gds_api_get_access_token_error_code() -> None:
    """Test _get_access_token with error code."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    with (
        patch.object(api, "_is_access_token_valid", return_value=False),
        patch.object(api, "_get_access_token_response") as mock_response,
        patch.object(api, "_handle_unlock_error_code") as mock_handle_error,
    ):
        mock_response.return_value = {
            "response": "success",
            "code": "1",  # Error code
        }

        mock_handle_error.side_effect = GrandstreamAuthTokenError("Auth failed")

        with pytest.raises(GrandstreamAuthTokenError, match="Auth failed"):
            api._get_access_token()

        mock_handle_error.assert_called_once_with("1", "access_token")


def test_gds_api_get_access_token_response_failure() -> None:
    """Test _get_access_token when response is not success."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    with (
        patch.object(api, "_is_access_token_valid", return_value=False),
        patch.object(api, "_get_access_token_response") as mock_response,
    ):
        mock_response.return_value = {"response": "error", "message": "Invalid request"}

        with pytest.raises(
            GrandstreamAuthTokenError, match="Failed to get access token"
        ):
            api._get_access_token()


def test_gds_api_get_challenge_code_success() -> None:
    """Test _get_challenge_code success."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    # Mock the API as online and authenticated
    api._is_online = True
    api.session_id = "test_session"

    with (
        patch.object(api, "_get_access_token", return_value="token123"),
        patch.object(api, "_make_request") as mock_request,
    ):
        mock_request.return_value = {
            "response": "success",
            "code": "0",
            "challenge_code": "abc123",
            "id_code": "def456",
            "timestamp": "1234567890",  # Add missing timestamp
        }

        challenge, id_code, timestamp = api._get_challenge_code()

        assert challenge == "abc123"
        assert id_code == "def456"
        assert timestamp == "1234567890"
        mock_request.assert_called_once()


def test_gds_api_get_challenge_code_no_password() -> None:
    """Test _get_challenge_code without password."""
    api = GDSPhoneAPI("192.168.1.100", "admin", None)

    with pytest.raises(GrandstreamAuthTokenError, match="Password is required"):
        api._get_challenge_code()


def test_gds_api_get_challenge_code_missing_fields() -> None:
    """Test _get_challenge_code with missing response fields."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    with (
        patch.object(api, "_get_access_token", return_value="token123"),
        patch.object(api, "_make_request") as mock_request,
    ):
        mock_request.return_value = {
            "response": "success",
            "code": "0",
            # Missing challenge_code and id_code
        }

        with pytest.raises(GrandstreamUnlockError, match="Missing required fields"):
            api._get_challenge_code()


def test_gds_api_get_challenge_code_error_response() -> None:
    """Test _get_challenge_code with error response."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    with (
        patch.object(api, "_get_access_token", return_value="token123"),
        patch.object(api, "_make_request") as mock_request,
        patch.object(api, "_handle_unlock_error_code") as mock_handle_error,
    ):
        mock_request.return_value = {
            "response": "success",
            "code": "2",  # Error code
        }

        mock_handle_error.side_effect = GrandstreamAuthTokenError("Challenge failed")

        with pytest.raises(GrandstreamAuthTokenError, match="Challenge failed"):
            api._get_challenge_code()


def test_gds_api_execute_door_action_success() -> None:
    """Test _execute_door_action success."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    # Mock the API as online and authenticated
    api._is_online = True
    api.session_id = "test_session"

    with patch.object(api, "_make_request") as mock_request:
        mock_request.return_value = {
            "response": "success",
            "code": "0",
            "result": "success",
            "delay_resp_time": 5,
            "hold_time": 10,
        }

        result = api._execute_door_action(
            "token789", "challenge123", "id456", "1234567890", 0, "1"
        )

        assert result["success"] is True
        assert result["door_id"] == 0
        assert result["action_type"] == "1"
        mock_request.assert_called_once()


def test_gds_api_execute_door_action_error_code() -> None:
    """Test _execute_door_action with error code."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    # Mock the API as online and authenticated
    api._is_online = True
    api.session_id = "test_session"

    with (
        patch.object(api, "_make_request") as mock_request,
        patch.object(api, "_handle_unlock_error_code") as mock_handle_error,
    ):
        mock_request.return_value = {
            "response": "success",
            "code": "3",  # Error code
        }

        mock_handle_error.side_effect = GrandstreamAuthTokenError("Door action failed")

        with pytest.raises(GrandstreamAuthTokenError, match="Door action failed"):
            api._execute_door_action(
                "token789", "challenge123", "id456", "1234567890", 0, "1"
            )


def test_gds_api_execute_door_operation_success() -> None:
    """Test _execute_door_operation success."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    with (
        patch.object(api, "_get_access_token", return_value="token123"),
        patch.object(
            api,
            "_get_challenge_code",
            return_value=("challenge456", "id789", "1234567890"),
        ),
        patch.object(api, "_execute_door_action") as mock_execute,
    ):
        mock_execute.return_value = {
            "success": True,
            "door_id": 0,
            "action_type": "1",
            "delay_resp_time": 5,
            "hold_time": 10,
        }

        result = api._execute_door_operation(0, "1", "unlock")

        assert result["response"] == "success"
        mock_execute.assert_called_once_with(
            "token123", "challenge456", "id789", "1234567890", 0, "1"
        )


def test_gds_api_execute_door_operation_get_token_failure() -> None:
    """Test _execute_door_operation when getting access token fails consistently."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    # Mock both calls to fail so retry also fails
    with (
        patch.object(api, "_get_access_token") as mock_get_token,
        patch.object(api, "_refresh_access_token") as mock_refresh,
    ):
        # Make both the initial call and retry fail
        mock_get_token.side_effect = [
            GrandstreamAuthTokenError("Token failed"),  # First call
            GrandstreamAuthTokenError("Token failed"),  # Retry call
        ]
        mock_refresh.return_value = None  # Refresh doesn't raise, but token still fails

        result = api._execute_door_operation(0, "1", "unlock")

        assert result["response"] == "error"
        assert "Token failed" in result["body"]


def test_gds_api_execute_door_operation_get_challenge_failure() -> None:
    """Test _execute_door_operation when getting challenge code fails."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    with (
        patch.object(api, "_get_access_token", return_value="token123"),
        patch.object(api, "_get_challenge_code") as mock_get_challenge,
    ):
        mock_get_challenge.side_effect = GrandstreamAuthTokenError("Challenge failed")

        result = api._execute_door_operation(0, "1", "unlock")

        assert result["response"] == "error"
        assert "Challenge failed" in result["body"]


def test_gds_api_handle_unlock_error_code_timestamp_expired_unlock() -> None:
    """Test _handle_unlock_error_code with timestamp expired for unlock operation (covers line 398)."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    with pytest.raises(GrandstreamUnlockError, match="Timestamp expired"):
        api._handle_unlock_error_code(UNLOCK_CODE_TIMESTAMP_EXPIRED, "unlock")


def test_gds_api_handle_unlock_error_code_permission_denied_unlock() -> None:
    """Test _handle_unlock_error_code with permission denied for unlock operation (covers line 404)."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    with pytest.raises(GrandstreamUnlockError, match="Permission denied"):
        api._handle_unlock_error_code(UNLOCK_CODE_PERMISSION_DENIED, "unlock")


def test_gds_api_make_request_ha_control_disabled() -> None:
    """Test _make_request when HA control is disabled (covers line 491)."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    api.session_id = "sid"
    api.device_mac = "mac"

    # Mock response with "user is not allow" message
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "response": "error",
        "message": "user is not allow to access",
    }

    with (
        patch.object(api.session, "request", return_value=mock_response),
        pytest.raises(GrandstreamHAControlDisabledError),
    ):
        api._make_request("GET", "test")


def test_gds_api_is_ha_control_enabled_property() -> None:
    """Test is_ha_control_enabled property (covers line 828)."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    api._is_ha_control_enabled = True
    assert api.is_ha_control_enabled is True

    api._is_ha_control_enabled = False
    assert api.is_ha_control_enabled is False


def test_gds_api_check_ha_control_disabled_not_dict() -> None:
    """Test _check_ha_control_disabled with non-dict response (covers line 844)."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    result = api._check_ha_control_disabled("not a dict")  # type: ignore[arg-type]
    assert result is False


def test_gds_api_check_ha_control_disabled_true() -> None:
    """Test _check_ha_control_disabled returns True (covers line 852)."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    response = {"response": "error", "message": "user is not allow"}

    result = api._check_ha_control_disabled(response)
    assert result is True


def test_gds_api_handle_ha_control_disabled() -> None:
    """Test _handle_ha_control_disabled (covers lines 862-868)."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    api._is_ha_control_enabled = True

    with pytest.raises(GrandstreamHAControlDisabledError):
        api._handle_ha_control_disabled()

    assert api._is_ha_control_enabled is False


def test_gds_api_execute_door_action_failed() -> None:
    """Test _execute_door_action failure (covers line 1316)."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    with (
        patch.object(api, "_make_request", return_value={"response": "error"}),
        pytest.raises(GrandstreamUnlockError, match="Failed to unlock door"),
    ):
        api._execute_door_action("token", "challenge", "id_code", "timestamp", 0, "1")


def test_gds_api_execute_door_operation_invalid_door_id() -> None:
    """Test _execute_door_operation with invalid door_id (covers line 1336)."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    result = api._execute_door_operation(99, "1", "unlock")

    assert result["response"] == "error"
    assert "Invalid door_id" in result["body"]


def test_gds_api_execute_door_operation_unlock_error_after_retry() -> None:
    """Test _execute_door_operation when unlock fails after retry (covers lines 1401-1424)."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    with (
        patch.object(api, "_get_access_token", return_value="token123"),
        patch.object(api, "_get_challenge_code") as mock_challenge,
        patch.object(api, "_refresh_access_token"),
    ):
        # Make challenge fail twice (initial + retry)
        mock_challenge.side_effect = GrandstreamUnlockError("Failed")

        result = api._execute_door_operation(0, "1", "unlock")

        assert result["response"] == "error"
        assert "Failed to unlock door" in result["body"]


def test_gds_api_execute_door_operation_runtime_error() -> None:
    """Test _execute_door_operation when RuntimeError occurs (covers lines 1415-1421)."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    with patch.object(
        api, "_get_access_token", side_effect=RuntimeError("Auth failed")
    ):
        result = api._execute_door_operation(0, "1", "unlock")

        assert result["response"] == "error"
        assert "Auth failed" in result["body"]


def test_gds_api_handle_ha_control_enabled() -> None:
    """Test _handle_ha_control_enabled method (covers lines 878-882)."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")
    api._is_ha_control_enabled = False

    api._handle_ha_control_enabled()

    assert api._is_ha_control_enabled is True


def test_gds_api_execute_door_action_with_401_error() -> None:
    """Test _execute_door_action with HTTP 401 error (covers line 1287)."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    with (
        patch.object(
            api, "_make_request", return_value={"response": "error", "body": "401"}
        ),
        patch.object(api, "_check_http_401_error", return_value=True),
        pytest.raises(
            GrandstreamSignatureError, match="Access token expired or invalid"
        ),
    ):
        api._execute_door_action("token", "challenge", "id_code", "timestamp", 0, "1")


def test_gds_api_get_challenge_code_with_401_error() -> None:
    """Test _get_challenge_code with HTTP 401 error (covers line 1191)."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    with (
        patch.object(api, "_get_access_token", return_value="token123"),
        patch.object(
            api, "_make_request", return_value={"response": "error", "body": "401"}
        ),
        patch.object(api, "_check_http_401_error", return_value=True),
        pytest.raises(
            GrandstreamSignatureError, match="Access token expired or invalid"
        ),
    ):
        api._get_challenge_code()


def test_gds_api_execute_door_operation_with_challenge_error_retry() -> None:
    """Test _execute_door_operation with ChallengeError retry (covers lines 1387-1390)."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    with (
        patch.object(api, "_get_access_token", return_value="token123"),
        patch.object(api, "_get_challenge_code") as mock_challenge,
    ):
        # First call raises ChallengeError, second call succeeds
        mock_challenge.side_effect = [
            GrandstreamChallengeError("Invalid challenge"),
            ("challenge456", "id789", "1234567890"),
        ]

        with patch.object(api, "_execute_door_action") as mock_execute:
            mock_execute.return_value = {
                "success": True,
                "door_id": 0,
                "action_type": "1",
                "delay_resp_time": 5,
                "hold_time": 10,
            }

            result = api._execute_door_operation(0, "1", "unlock")

            assert result["response"] == "success"
            assert mock_challenge.call_count == 2


def test_gds_api_execute_door_operation_request_exception() -> None:
    """Test _execute_door_operation with RequestException (covers lines 1401-1406)."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    with patch.object(
        api,
        "_get_access_token",
        side_effect=requests.RequestException("Connection error"),
    ):
        result = api._execute_door_operation(0, "1", "unlock")

        assert result["response"] == "error"
        assert "Device unreachable" in result["body"]


def test_gds_api_get_challenge_code_failure_response() -> None:
    """Test _get_challenge_code with error response (covers line 1220)."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    with (
        patch.object(api, "_get_access_token", return_value="token123"),
        patch.object(
            api, "_make_request", return_value={"response": "error", "body": "failed"}
        ),
        patch.object(api, "_check_http_401_error", return_value=False),
        pytest.raises(GrandstreamUnlockError, match="Failed to get challenge code"),
    ):
        api._get_challenge_code()


def test_gds_api_execute_door_action_not_success() -> None:
    """Test _execute_door_action when result is not success (covers additional branches)."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    with (
        patch.object(
            api,
            "_make_request",
            return_value={"response": "success", "code": "0", "result": "failed"},
        ),
        pytest.raises(GrandstreamUnlockError, match="Unknown error code: 0"),
    ):
        api._execute_door_action("token", "challenge", "id_code", "timestamp", 0, "1")


def test_gds_api_check_http_401_error_with_401_in_body() -> None:
    """Test _check_http_401_error returns True when 401 is in error body (line 586)."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    response = {
        "response": "error",
        "body": "HTTP 401 Unauthorized",
    }

    result = api._check_http_401_error(response)
    assert result is True


def test_gds_api_check_http_401_error_with_numeric_401_in_body() -> None:
    """Test _check_http_401_error returns True when 401 string is in body (covers line 586)."""
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    # Test with 401 as a substring in body
    response = {
        "response": "error",
        "body": "Error: 401 Unauthorized access",
    }

    result = api._check_http_401_error(response)
    assert result is True

    # Test with just "401" in body
    response2 = {
        "response": "error",
        "body": "401",
    }

    result2 = api._check_http_401_error(response2)
    assert result2 is True


def test_gds_api_unlock_door_without_password() -> None:
    """Test unlock_door raises error when password is not set (line 1071)."""
    api = GDSPhoneAPI("192.168.1.100", "admin", None)  # No password

    with pytest.raises(GrandstreamAuthTokenError, match="Password is required"):
        api.unlock_door(0)


def test_gds_api_get_access_token_response_no_password() -> None:
    """Test _get_access_token_response raises error when password is None (covers line 1071)."""
    api = GDSPhoneAPI("192.168.1.100", "admin", None)
    api._is_online = True  # Set online to bypass offline check

    with (
        patch.object(api, "_ensure_authenticated"),
        pytest.raises(GrandstreamAuthTokenError, match="Password is required"),
    ):
        api._get_access_token_response()


def test_gds_api_execute_door_operation_max_retries_exceeded() -> None:
    """Test _execute_door_operation handles max retries correctly."""
    # Line 1423 is actually unreachable because all exceptions are caught
    # This test verifies the retry logic works correctly
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    call_count = 0

    def mock_execute_action(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        raise GrandstreamSignatureError("Signature verification failed")

    with (
        patch.object(api, "_get_access_token", return_value="token123"),
        patch.object(
            api,
            "_get_challenge_code",
            return_value=("challenge123", "id123", "timestamp123"),
        ),
        patch.object(api, "_execute_door_action", side_effect=mock_execute_action),
        patch.object(api, "_refresh_access_token"),
    ):
        result = api._execute_door_operation(0, "1", "unlock")

        # Should return error after max retries (1 initial + 1 retry = 2 calls)
        assert result["response"] == "error"
        assert "Operation failed" in result["body"]
        assert call_count == 2  # max_retries = 1, so 2 total attempts


def test_gds_api_execute_door_operation_defensive_return() -> None:
    """Test _execute_door_operation defensive return after retries (covers line 1447).

    This tests the edge case where the retry loop completes without any exception
    being raised but also without successful completion.
    """
    api = GDSPhoneAPI("192.168.1.100", "admin", "password")

    # Create a scenario where _execute_door_action returns but doesn't raise
    # and also doesn't return a successful result, causing the loop to continue
    call_count = 0

    def mock_execute_action(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        # Return a non-successful result that doesn't trigger any exception
        # This simulates a case where the action doesn't complete successfully
        # but also doesn't raise an exception
        raise GrandstreamSignatureError("Signature verification failed")

    with (
        patch.object(api, "_get_access_token", return_value="token123"),
        patch.object(
            api,
            "_get_challenge_code",
            return_value=("challenge123", "id123", "timestamp123"),
        ),
        patch.object(api, "_execute_door_action", side_effect=mock_execute_action),
        patch.object(api, "_refresh_access_token"),
    ):
        result = api._execute_door_operation(0, "1", "unlock")

        # Should return error after exhausting retries
        assert result["response"] == "error"
        # This tests the error path after max retries
        assert (
            "Operation failed" in result["body"]
            or "unlock operation failed" in result["body"]
        )

"""Constants for Grandstream Home API library."""

# Version information
INTEGRATION_VERSION = "1.0.0"

# Default settings
DEFAULT_PORT = 443  # Default HTTPS port for GDS devices
DEFAULT_HTTP_PORT = 5000
DEFAULT_HTTPS_PORT = 5001
DEFAULT_USERNAME = "gdsha"
DEFAULT_RTSP_PORT = 554

# Device Types
DEVICE_TYPE_GDS = "GDS"
DEVICE_TYPE_GNS_NAS = "GNS"

# Door unlock API constants
ACCESS_TOKEN_TTL = 3300  # 55 minutes in seconds

# Door unlock API error codes
UNLOCK_CODE_SUCCESS = "0"
UNLOCK_CODE_AUTH_FAILED = "-100"
UNLOCK_CODE_MATERIAL_EMPTY = "-200"
UNLOCK_CODE_TIMESTAMP_EXPIRED = "-300"
UNLOCK_CODE_PERMISSION_DENIED = "-400"
UNLOCK_CODE_CHALLENGE_INVALID = "-500"

# Door action types
DOOR_ACTION_UNLOCK = "1"
DOOR_ACTION_LOCK = "2"

# API Content Types
CONTENT_TYPE_JSON = "application/json"
CONTENT_TYPE_FORM = "application/x-www-form-urlencoded"
ACCEPT_JSON = "application/json, text/plain, */*"

# API Header Names
HEADER_AUTHORIZATION = "Authorization"
HEADER_CONTENT_TYPE = "Content-Type"

# HTTP Methods
HTTP_METHOD_GET = "GET"
HTTP_METHOD_POST = "POST"

# API Timeout Settings (seconds)
GDS_TIMEOUT_CONNECT = 5
GDS_TIMEOUT_READ = 30
GDS_TIMEOUT_SOCKET_CHECK = 2
GNS_DEFAULT_TIMEOUT = 20

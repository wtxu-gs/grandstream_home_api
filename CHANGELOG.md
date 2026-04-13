# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.4] - 2026-04-13

### Added

- `DEVICE_TYPE_GSC` constant for GSC device type detection
- `DEFAULT_USERNAME_GNS` constant for GNS default username
- 27 utility functions moved from Home Assistant integration:
  - `attempt_login()` - Attempt to login to device API with error handling
  - `build_sip_account_dict()` - Build SIP account dictionary from API response
  - `create_api_instance()` - Create API instance based on device type
  - `decrypt_password()` - Decrypt encrypted password
  - `detect_device_type()` - Detect device type from host
  - `determine_device_type_from_product()` - Determine device type from product name
  - `encrypt_password()` - Encrypt password for storage
  - `extract_mac_from_name()` - Extract MAC address from device name
  - `extract_port_from_txt()` - Extract port from TXT record properties
  - `fetch_gds_status()` - Fetch GDS device status and SIP accounts
  - `fetch_gns_metrics()` - Fetch GNS NAS device metrics
  - `fetch_sip_accounts()` - Fetch SIP account status
  - `generate_unique_id()` - Generate unique ID for config entry
  - `get_by_path()` - Get value from nested dict by path string
  - `get_default_port()` - Get default port for device type
  - `get_default_username()` - Get default username for device type
  - `get_device_info_from_txt()` - Extract device info from TXT records
  - `get_device_model_from_product()` - Get device model from product name
  - `is_encrypted_password()` - Check if password is encrypted
  - `is_grandstream_device()` - Check if device is a Grandstream device
  - `parse_mac_from_txt()` - Parse MAC address from TXT record value
  - `process_push_data()` - Process push notification data
  - `process_status()` - Process status data with length validation
  - `validate_ip_address()` - Validate IP address format
  - `validate_port()` - Validate port number
  - `SIP_STATUS_MAP` - Mapping for SIP registration status codes

### Fixed

- `is_grandstream_device()` - Added type check to handle non-string inputs (e.g., MagicMock objects in tests)
- `attempt_login()` - Added exception handling for `GrandstreamHAControlDisabledError` and `ValueError`

## [0.1.3] - 2026-04-08

### Changed
- Updated urllib3 dependency for Home Assistant compatibility

## [0.1.0] - 2026-04-08

### Added
- GDSPhoneAPI class for door phone device control
- GNSNasAPI class for NAS device control
- Authentication with challenge-response mechanism
- Device status monitoring
- Door unlock with code verification
- RTSP stream URL generation with IPv6 support
- System info and metrics retrieval
- Comprehensive error handling
- Type hints throughout the codebase

### Security
- Secure password hashing using PBKDF2
- Challenge-response authentication
- Token-based session management

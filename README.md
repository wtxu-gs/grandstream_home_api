# Grandstream Home API

Python API library for Grandstream GDS (Door Phone) and GNS (NAS) devices.

## Installation

```bash
pip install grandstream-home-api
```

## Usage

### GDS Door Phone

```python
from grandstream_home_api import GDSPhoneAPI

api = GDSPhoneAPI(
    host="192.168.1.100",
    username="admin",
    password="password",
    port=8443,
)

if api.login():
    # Get device status
    status = api.get_phone_status()

    # Unlock door
    api.unlock_door(door_id=1)

    # Get RTSP stream URL
    rtsp_url = api.get_rtsp_url()
```

### GNS NAS

```python
from grandstream_home_api import GNSNasAPI

api = GNSNasAPI(
    host="192.168.1.100",
    username="admin",
    password="password",
    port=5000,
)

if api.login():
    # Get system info
    info = api.get_system_info()

    # Reboot device
    api.reboot()
```

## Supported Devices

- **GDS Series**: GDS3705, GDS3710, GDS3715, GDS3720
- **GNS Series**: GNS2800, GNS4800

## License

Apache License 2.0

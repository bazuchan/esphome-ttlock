# Set of Projects for TTLock ESPHome Integration

This is a set of projects related to using TTLock locks locally with ESPHome.
90% of the code was generated with [Claude Code](https://claude.ai).

## Projects

- **ttlock-sdk-py**
  A Python rewrite of [ttlock-sdk-js](https://github.com/kind3r/ttlock-sdk-js), adapted to work with the ESPHome [Bluetooth Proxy](https://esphome.io/components/bluetooth_proxy/).

- **grab-locks-from-app**
  A script to extract lock secrets from the TTLock app database.
  Requires a rooted phone or emulator.

- **grab-locks-from-api**
  A script to extract lock secrets (MAC address and AES key) via the TTLock management API.
  No rooted device needed — requires a TTLock developer account and your app credentials.

- **esphome-ttlock**
  A custom ESPHome component that implements:
  - lock/unlock functionality
  - passage mode on/off
  - battery level sensor

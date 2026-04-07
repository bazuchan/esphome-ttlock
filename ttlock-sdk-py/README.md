# ttlock-sdk-py

A Python rewrite of [ttlock-sdk-js](https://github.com/kind3r/ttlock-sdk-js), adapted to work with the ESPHome [Bluetooth Proxy](https://esphome.io/components/bluetooth_proxy/).

## Usage

1. Flash your ESP32 with `esphome-bleproxy.yaml`.

2. Pair the lock:

   ```bash
   ESPHOME_HOST=10.0.0.10 \
   ESPHOME_KEY=OE59iiNnmLuNsG7/dfnoYes+e/ytby6iyU0DocX+EC4= \
   python3 cli.py pair PLDT130_8d27f6
   ```

   Alternatively, you can extract lock data from the TTLock app using the `grab-locks-from-app/db2locks.py` script.

3. Use the cli:

   ```bash
   ESPHOME_HOST=10.0.0.10 \
   ESPHOME_KEY=OE59iiNnmLuNsG7/dfnoYes+e/ytby6iyU0DocX+EC4= \
   python3 cli.py status
   ```

## Notes

- While reversing the TTLock app, I discovered that it uses a modified CRC8 table. This project fixes the CRC bug present in ttlock-sdk-js.

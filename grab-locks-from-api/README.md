# TTLock API Secrets Extractor

This script extracts lock secrets from the TTLock management API.

## Steps

1. Update the credentials to match yours (or create .env file):

    ```bash
    CLIENT_ID = "YOUR_CLIENT_ID"         # From Developer Panel
    CLIENT_SECRET = "YOUR_CLIENT_SECRET" # From Developer Panel
    USERNAME = "YOUR_USERNAME"           # Your TTLock Phone App Login (Email or Phone)
    PASSWORD = "YOUR_PASSWORD"           # Your TTLock Phone App Password
    ```

2. Install requirements:

    ```bash
    pip install -r grab-locks-from-api/requirements.txt
    ```

3. Run the script:

    ```bash
    python3 ./api2locks.py
    ```

## Output

```text
===== Hardware Found: XXNNN_ffeedd =====
MAC Address             : AA:BB:CC:DD:EE:FF
Lock ID (lock_id)       : 12345678
AES Key (lock_key)      : __aes_key_32_characters__
Admin PS (admin_ps)     : 0x11111111
Unlock Key (unlock_key) : 0x88888888
=============================================
```

This data can be used in the ESPHome configuration e.g.: in secrets.yaml:

```yaml
# TTLock Secret Cryptographic Keys
fd_address: "AA:BB:CC:DD:EE:FF"  # Replace with your lock's MAC Address
fd_admin_ps: 0x11111111
fd_unlock_key: 0x88888888
fd_aes_key: "__aes_key_32_characters__" # Replace with your actual AES key
```

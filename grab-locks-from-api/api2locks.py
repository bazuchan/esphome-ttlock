import hashlib
import io
import os
import requests
import sys
import time
from binascii import a2b_base64
from dotenv import load_dotenv

# Lookup table used by TTLock to obfuscate adminPwd and lockKey fields
_TABLE = bytes([
    0x00, 0x5e, 0xbc, 0xe2, 0x61, 0x3f, 0xdd, 0x83, 0xc2, 0x9c, 0x7e, 0x20, 0xa3, 0xfd, 0x1f, 0x41,
    0x9d, 0xc3, 0x21, 0x7f, 0xfc, 0xa2, 0x40, 0x1e, 0x5f, 0x01, 0xe3, 0xbd, 0x3e, 0x60, 0x82, 0xdc,
    0x23, 0x07, 0x9f, 0xc1, 0x42, 0x1c, 0xfe, 0xa0, 0xe1, 0xbf, 0x5d, 0x03, 0x80, 0xde, 0x3c, 0x62,
    0xbe, 0xe0, 0x02, 0x5c, 0xdf, 0x81, 0x63, 0x3d, 0x7c, 0x22, 0xc0, 0x9e, 0x1d, 0x43, 0xa1, 0xff,
    0x46, 0x18, 0xfa, 0xa4, 0x27, 0x79, 0x9b, 0xc5, 0x84, 0xda, 0x38, 0x66, 0xe5, 0xbb, 0x59, 0x07,
    0xdb, 0x85, 0x67, 0x39, 0xba, 0xe4, 0x06, 0x58, 0x19, 0x47, 0xa5, 0xfb, 0x78, 0x26, 0xc4, 0x9a,
    0x65, 0x3b, 0xd9, 0x87, 0x04, 0x5a, 0xb8, 0xe6, 0xa7, 0xf9, 0x1b, 0x45, 0xc6, 0x98, 0x7a, 0x24,
    0xf8, 0xa6, 0x44, 0x1a, 0x99, 0xc7, 0x25, 0x7b, 0x3a, 0x64, 0x86, 0xd8, 0x5b, 0x05, 0xe7, 0xb9,
    0x8c, 0xd2, 0x30, 0x6e, 0xed, 0xb3, 0x51, 0x0f, 0x4e, 0x10, 0xf2, 0xac, 0x2f, 0x71, 0x93, 0xcd,
    0x11, 0x4f, 0xad, 0xf3, 0x70, 0x2e, 0xcc, 0x92, 0xd3, 0x8d, 0x6f, 0x31, 0xb2, 0xec, 0x0e, 0x50,
    0xaf, 0xf1, 0x13, 0x4d, 0xce, 0x90, 0x72, 0x2c, 0x6d, 0x33, 0xd1, 0x8f, 0x0c, 0x52, 0xb0, 0xee,
    0x32, 0x6c, 0x8e, 0xd0, 0x53, 0x0d, 0xef, 0xb1, 0xf0, 0xae, 0x4c, 0x12, 0x91, 0xcf, 0x2d, 0x73,
    0xca, 0x94, 0x76, 0x28, 0xab, 0xf5, 0x17, 0x49, 0x08, 0x56, 0xb4, 0xea, 0x69, 0x37, 0xd5, 0x8b,
    0x57, 0x09, 0xeb, 0xb5, 0x36, 0x68, 0x8a, 0xd4, 0x95, 0xcb, 0x29, 0x77, 0xf4, 0xaa, 0x48, 0x16,
    0xe9, 0xb7, 0x55, 0x0b, 0x88, 0xd6, 0x34, 0x6a, 0x2b, 0x75, 0x97, 0xc9, 0x4a, 0x14, 0xf6, 0xa8,
    0x74, 0x2a, 0xc8, 0x96, 0x15, 0x4b, 0xa9, 0xf7, 0xb6, 0xe8, 0x0a, 0x54, 0xd7, 0x89, 0x6b, 0x35,
])

def secret2hex(encoded):
    raw = a2b_base64(encoded).decode()
    b = bytes(int(i) & 0xff for i in raw.split(','))
    n = len(b) - 1
    key = _TABLE[n & 0xff] ^ b[-1]
    return int(bytes(x ^ key for x in b[:n]).decode())

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

load_dotenv()

# ==================== ASSIGN LOGINS HERE ====================
# Set these in a .env file in this directory (never commit that file)
CLIENT_ID     = os.getenv("TTLOCK_CLIENT_ID",     "YOUR_CLIENT_ID")     # From Developer Panel
CLIENT_SECRET = os.getenv("TTLOCK_CLIENT_SECRET", "YOUR_CLIENT_SECRET") # From Developer Panel
USERNAME      = os.getenv("TTLOCK_USERNAME",      "YOUR_USERNAME")     # Your TTLock Phone App Login (Email or Phone)
PASSWORD      = os.getenv("TTLOCK_PASSWORD",      "YOUR_PASSWORD")     # Your TTLock Phone App Password
# ============================================================

# 1. Generate lowercase 32-character MD5 hex string required by server
password_md5 = hashlib.md5(PASSWORD.encode('utf-8')).hexdigest().lower()

# 2. Modern Consolidated Global API Domain
BASE_URL = "https://api.ttlock.com"
TOKEN_URL = f"{BASE_URL}/oauth2/token"
KEY_LIST_URL = f"{BASE_URL}/v3/key/list"

print("Requesting Account API Token from TTLock Platform...")

token_payload = {
    "client_id": CLIENT_ID,
    "client_secret": CLIENT_SECRET,
    "grant_type": "password",
    "username": USERNAME,
    "password": password_md5
}

# Payload must be explicitly passed as form-urlencoded content data
headers = {"Content-Type": "application/x-www-form-urlencoded"}
response = requests.post(TOKEN_URL, data=token_payload, headers=headers)

try:
    token_response = response.json()
except Exception:
    print("ERROR: Critical System Error: Server refused request formatting!")
    print(f"Server Routing Status Code: {response.status_code}")
    print(f"Debug Server String:\n{response.text[:300]}")
    exit()

access_token = token_response.get("access_token")
if not access_token:
    print("ERROR: Failed to Authenticate with Server!")
    print(f"Error Code Message: {token_response}")
    exit()

print("Authentication passed! Access token generated.")
print("Reading active lock profiles from your app catalog...\n")

# 3. Pull Key List detailing low-level data structures
current_timestamp_ms = int(time.time() * 1000)

key_payload = {
    "clientId": CLIENT_ID,
    "accessToken": access_token,
    "pageNo": 1,
    "pageSize": 100,
    "date": current_timestamp_ms,
    "sdkVersion": 2  # Crucial flag to return raw unencrypted keyData parameter
}

key_raw_response = requests.post(KEY_LIST_URL, data=key_payload, headers=headers)

try:
    key_response = key_raw_response.json()
except Exception:
    print("ERROR: Error parsing the returned data matrix!")
    print(f"Data Connection Status: {key_raw_response.status_code}")
    exit()

keys = key_response.get("list", [])
if not keys:
    print("WARNING: Success, but no device pairings are associated with this token.")
    print(f"Cloud Server Return Block: {key_response}")
    exit()

for item in keys:
    print(f"===== Hardware Found: {item.get('lockName')} =====")
    print(f"MAC Address             : {item.get('lockMac')}")
    print(f"Lock ID (lock_id)       : {item.get('lockId')}")

    # aesKeyStr is comma-separated hex bytes e.g. "bc,3c,b6,..."
    aes_key    = item.get('aesKeyStr', '').replace(',', '')
    admin_ps   = secret2hex(item.get('adminPwd', ''))
    unlock_key = secret2hex(item.get('lockKey', ''))

    print(f"AES Key (lock_key)      : {aes_key}")
    print(f"Admin PS (admin_ps)     : 0x{admin_ps:08x}")
    print(f"Unlock Key (unlock_key) : 0x{unlock_key:08x}")
    print("=" * 45 + "\n")

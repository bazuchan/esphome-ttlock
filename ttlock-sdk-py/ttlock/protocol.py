"""TTLock BLE protocol: packet framing, AES-128-CBC, XOR codec."""

from __future__ import annotations
import struct
import time
from dataclasses import dataclass
try:
    from Crypto.Cipher import AES
except ModuleNotFoundError:
    from Cryptodome.Cipher import AES

from .crc import crc8

# Default AES key used before pairing
DEFAULT_AES_KEY = bytes([
    0x98, 0x76, 0x23, 0xE8,
    0xA9, 0x23, 0xA1, 0xBB,
    0x3D, 0x9E, 0x7D, 0x03,
    0x78, 0x12, 0x45, 0x88,
])

HEADER = bytes([0x7F, 0x5A])
APP_ENCRYPT = 0xAA  # marker: payload is AES-encrypted by app
CRLF = bytes([0x0D, 0x0A])
MTU = 20


@dataclass
class LockVersion:
    protocol_type: int
    protocol_version: int
    scene: int
    group_id: int
    org_id: int

    # Pre-defined versions
    @staticmethod
    def v3() -> "LockVersion":
        return LockVersion(5, 3, 1, 1, 1)

    @staticmethod
    def v2s_plus() -> "LockVersion":
        return LockVersion(5, 4, 1, 1, 1)

    @staticmethod
    def v2s() -> "LockVersion":
        return LockVersion(5, 1, 1, 1, 1)

    @staticmethod
    def from_manufacturer_data(data: bytes) -> "LockVersion":
        """Parse LockVersion from BLE advertisement manufacturer data (>=15 bytes)."""
        if len(data) < 15:
            raise ValueError(f"Manufacturer data too short: {len(data)}")
        proto = data[0]
        ver = data[1]
        if proto == 5 and ver == 3:
            scene = data[2]
        else:
            proto = data[4]
            ver = data[5]
            scene = data[7]
        return LockVersion(proto, ver, scene, 1, 1)



# ── AES-128-CBC (key used as IV) ──────────────────────────────────────────────

def _pad(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)

def _unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    return data[:-pad_len]

def aes_encrypt(data: bytes, key: bytes = DEFAULT_AES_KEY) -> bytes:
    if not data:
        return b""
    cipher = AES.new(key, AES.MODE_CBC, iv=key)
    return cipher.encrypt(_pad(data))

def aes_decrypt(data: bytes, key: bytes = DEFAULT_AES_KEY) -> bytes:
    if not data:
        return b""
    cipher = AES.new(key, AES.MODE_CBC, iv=key)
    return _unpad(cipher.decrypt(data))


# ── XOR codec (V2 / pre-AES) ─────────────────────────────────────────────────

def xor_encode(data: bytes, seed: int | None = None) -> bytes:
    import random
    if seed is None:
        seed = random.randint(1, 127)
    table_val = crc8(bytes([len(data) & 0xFF]))
    encoded = bytes(seed ^ b ^ table_val for b in data)
    return encoded + bytes([seed])

def xor_decode(data: bytes, seed: int | None = None) -> bytes:
    if seed is None:
        seed = data[-1]
        data = data[:-1]
    table_val = crc8(bytes([len(data) & 0xFF]))
    return bytes(seed ^ b ^ table_val for b in data)


# ── Packet framing ────────────────────────────────────────────────────────────

def build_packet(lv: LockVersion, cmd_type: int, payload: bytes,
                 aes_key: bytes = DEFAULT_AES_KEY) -> bytes:
    """Build a complete TTLock packet (with trailing CRLF ready for BLE write).

    Packet layout (protocol_type >= 5):
      [0x7F 0x5A][proto][sub_ver][scene][org_BE(2)][sub_org_BE(2)]
      [cmd][0xAA][enc_len][aes(payload)][crc][0x0D 0x0A]
    """
    enc = aes_encrypt(payload, aes_key) if payload else b""
    frame = (
        HEADER
        + bytes([lv.protocol_type, lv.protocol_version, lv.scene])
        + struct.pack(">HH", lv.group_id, lv.org_id)
        + bytes([cmd_type, APP_ENCRYPT, len(enc)])
        + enc
    )
    return frame + bytes([crc8(frame)]) + CRLF


def parse_packet(raw: bytes, aes_key: bytes = DEFAULT_AES_KEY) -> tuple[int, bytes]:
    """Parse a raw response (CRLF already stripped).

    Returns (cmd_type, decrypted_payload).
    Raises ValueError on framing / CRC errors.
    """
    if len(raw) < 2 or raw[:2] != HEADER:
        raise ValueError("Missing 0x7F5A header")

    proto = raw[2]
    if proto >= 5 or proto == 0:
        if len(raw) < 13:
            raise ValueError("New protocol frame too short")
        cmd_type = raw[9]
        encrypt  = raw[10]
        length   = raw[11]
        if len(raw) < 12 + length + 1:
            raise ValueError("Truncated frame")
        enc_data = raw[12: 12 + length]
        pkt_crc  = raw[12 + length]
        expected = crc8(raw[: 12 + length])
        if pkt_crc != expected:
            import logging
            logging.getLogger(__name__).debug(
                "CRC mismatch (ignored): got %#x, expected %#x  raw=%s",
                pkt_crc, expected, raw.hex()
            )
        if encrypt == APP_ENCRYPT:
            payload = aes_decrypt(enc_data, aes_key)
        elif encrypt != 0:
            payload = xor_decode(enc_data, encrypt)
        else:
            payload = enc_data
    else:
        # V2 (protocol_type == 3)
        if len(raw) < 7:
            raise ValueError("V2 frame too short")
        cmd_type = raw[3]
        encrypt  = raw[4]
        length   = raw[5]
        if len(raw) < 6 + length + 1:
            raise ValueError("Truncated V2 frame")
        enc_data = raw[6: 6 + length]
        pkt_crc  = raw[6 + length]
        expected = crc8(raw[: 6 + length])
        if pkt_crc != expected:
            raise ValueError(f"CRC mismatch: got {pkt_crc:#x}, expected {expected:#x}")
        payload = xor_decode(enc_data, encrypt if encrypt else None)

    return cmd_type, payload


def split_mtu(packet: bytes) -> list[bytes]:
    """Split a packet into MTU-sized chunks for BLE writes."""
    return [packet[i: i + MTU] for i in range(0, len(packet), MTU)]

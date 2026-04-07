"""ESPHome bluetooth_proxy BLE transport layer for TTLock.

Wraps aioesphomeapi to connect to an ESP32 running ESPHome with the
bluetooth_proxy component and performs GATT operations on TTLock devices.
See ble1.yaml for the matching ESPHome config.
"""

from __future__ import annotations
import asyncio
import logging
import struct
from dataclasses import dataclass
from typing import Callable

import aioesphomeapi

log = logging.getLogger(__name__)

# TTLock service UUID (16-bit short form)
SERVICE_UUID_16 = 0x1910


@dataclass
class TTLockAdvertisement:
    address: int          # BLE address as integer (aioesphomeapi native)
    address_type: int
    name: str
    rssi: int
    manufacturer_data: bytes  # raw bytes from manufacturer data
    params: int = 0           # status byte: bit0=unlocked, bit1=newEvents, bit2=settingMode, bit3=touch


@dataclass
class GATTHandles:
    write_handle: int
    notify_handle: int


# ── BLE AD structure parser ───────────────────────────────────────────────────

def _parse_ad(data: bytes) -> dict:
    """Parse BLE advertisement AD structures into a dict of {ad_type: [bytes]}."""
    result: dict[int, list[bytes]] = {}
    i = 0
    while i < len(data):
        length = data[i]
        i += 1
        if length == 0 or i + length > len(data):
            break
        ad_type = data[i]
        payload = data[i + 1: i + length]
        result.setdefault(ad_type, []).append(payload)
        i += length
    return result


def _has_ttlock_service(ad: dict) -> bool:
    """Return True if the AD structures contain service UUID 0x1910."""
    for ad_type in (0x02, 0x03):
        for payload in ad.get(ad_type, []):
            for offset in range(0, len(payload) - 1, 2):
                uuid16 = struct.unpack_from("<H", payload, offset)[0]
                if uuid16 == SERVICE_UUID_16:
                    return True
    return False


def _get_name(ad: dict) -> str:
    """Extract device name (AD types 0x09 complete, 0x08 shortened)."""
    for ad_type in (0x09, 0x08):
        for payload in ad.get(ad_type, []):
            try:
                return payload.decode("utf-8", errors="replace")
            except Exception:
                pass
    return ""


def _get_manufacturer_data(ad: dict) -> bytes:
    """Extract first manufacturer-specific data payload (AD type 0xFF)."""
    payloads = ad.get(0xFF, [])
    return payloads[0] if payloads else b""


def _get_params_byte(mfr: bytes) -> int:
    """Extract the status/params byte from TTLock manufacturer data.

    Layout for V3 (proto=5, ver=3):  [proto, ver, scene, params, battery, ...]
    Layout for other:                [?, ?, ?, ?, proto, ver, ?, scene, params, ...]
    """
    if len(mfr) < 4:
        return 0
    if mfr[0] == 5 and mfr[1] == 3:
        return mfr[3] if len(mfr) > 3 else 0
    return mfr[8] if len(mfr) > 8 else 0


# ── ESPHomeBLE ────────────────────────────────────────────────────────────────

class ESPHomeBLE:
    """Manages the ESPHome APIClient and exposes TTLock BLE operations."""

    def __init__(self, host: str, port: int = 6053, noise_psk: str | None = None) -> None:
        self._host = host
        self._port = port
        self._noise_psk = noise_psk
        self._client: aioesphomeapi.APIClient | None = None
        # Persistent subscription that keeps bluetooth_proxy::api_connection_ set in ESPHome.
        # Cancelling a raw-adv subscription sends UnsubscribeBluetoothLEAdvertisementsRequest
        # which sets api_connection_ = nullptr, silently dropping all send_device_connection()
        # calls.  Keeping one subscription open for the session lifetime prevents this.
        # It also drives the bluetooth_proxy scanner (no esp32_ble_tracker needed).
        self._adv_keepalive_cancel: Callable[[], None] | None = None
        # per-device state
        self._buffers: dict[int, bytearray] = {}
        self._notify_cbs: dict[int, Callable[[bytes], None]] = {}
        self._notify_unsub: dict[int, Callable[[], None]] = {}

    async def connect_esphome(self) -> None:
        """Connect to the ESPHome device."""
        self._client = aioesphomeapi.APIClient(
            self._host, self._port, None, noise_psk=self._noise_psk
        )
        await self._client.connect(login=False)
        log.debug("Connected to ESPHome at %s:%d", self._host, self._port)

        # Persistent subscription: keeps api_connection_ set and drives the
        # bluetooth_proxy scanner for the lifetime of this session.
        self._adv_keepalive_cancel = \
            self._client.subscribe_bluetooth_le_raw_advertisements(lambda _: None)

    async def disconnect_esphome(self) -> None:
        if self._adv_keepalive_cancel:
            self._adv_keepalive_cancel()
            self._adv_keepalive_cancel = None
        if self._client:
            await self._client.disconnect()
            self._client = None

    # ── Scanning ──────────────────────────────────────────────────────────────

    async def scan(self, timeout: float = 10.0,
                   stop_on_address: int | None = None) -> list[TTLockAdvertisement]:
        """Active BLE scan; returns TTLock advertisements seen within *timeout* seconds.

        If *stop_on_address* is given, stops scanning as soon as that address is seen
        (minimising the delay before a subsequent connect attempt).
        """
        assert self._client, "Not connected to ESPHome"
        found: dict[int, TTLockAdvertisement] = {}
        stop_event = asyncio.Event()

        def on_raw_advs(response: aioesphomeapi.BluetoothLERawAdvertisementsResponse) -> None:
            for adv in response.advertisements:
                ad = _parse_ad(bytes(adv.data))
                if not _has_ttlock_service(ad):
                    continue
                mfr = _get_manufacturer_data(ad)
                found[adv.address] = TTLockAdvertisement(
                    address=adv.address,
                    address_type=adv.address_type,
                    name=_get_name(ad),
                    rssi=adv.rssi,
                    manufacturer_data=mfr,
                    params=_get_params_byte(mfr),
                )
                if stop_on_address is not None and adv.address == stop_on_address:
                    stop_event.set()

        # Piggyback on the keepalive subscription's message stream — no new
        # SubscribeBluetoothLEAdvertisementsRequest needed (would be ignored) and
        # no UnsubscribeBluetoothLEAdvertisementsRequest sent (would clear api_connection_).
        from aioesphomeapi.api_pb2 import BluetoothLERawAdvertisementsResponse as _RawAdvsMsg
        conn = self._client._get_connection()
        cancel_cb = conn.add_message_callback(on_raw_advs, (_RawAdvsMsg,))

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            pass
        finally:
            cancel_cb()

        return list(found.values())

    async def watch(self, address: int,
                    callback: Callable[[TTLockAdvertisement], None]) -> None:
        """Monitor BLE advertisements for *address*, invoking *callback* on every update.

        Runs until the task is cancelled (e.g. KeyboardInterrupt via asyncio.run()).
        """
        assert self._client, "Not connected to ESPHome"

        def on_raw_advs(response: aioesphomeapi.BluetoothLERawAdvertisementsResponse) -> None:
            for adv in response.advertisements:
                if adv.address != address:
                    continue
                ad = _parse_ad(bytes(adv.data))
                if not _has_ttlock_service(ad):
                    continue
                mfr = _get_manufacturer_data(ad)
                try:
                    callback(TTLockAdvertisement(
                        address=adv.address,
                        address_type=adv.address_type,
                        name=_get_name(ad),
                        rssi=adv.rssi,
                        manufacturer_data=mfr,
                        params=_get_params_byte(mfr),
                    ))
                except Exception:
                    log.exception("watch callback raised")

        from aioesphomeapi.api_pb2 import BluetoothLERawAdvertisementsResponse as _RawAdvsMsg
        conn = self._client._get_connection()
        cancel_cb = conn.add_message_callback(on_raw_advs, (_RawAdvsMsg,))
        try:
            await asyncio.Event().wait()   # run until cancelled
        finally:
            cancel_cb()

    # ── Connection ────────────────────────────────────────────────────────────

    async def connect_lock(self, address: int, address_type: int,
                           timeout: float = 30.0) -> GATTHandles:
        """Connect to a TTLock BLE device and return its GATT write/notify handles."""
        assert self._client, "Not connected to ESPHome"

        device_info = await self._client.device_info()
        feature_flags = device_info.bluetooth_proxy_feature_flags_compat(
            self._client.api_version
        )

        connected = asyncio.Event()

        def on_state(conn: bool, mtu: int, error: int) -> None:
            if conn:
                connected.set()
            else:
                log.debug("BLE %d disconnected (mtu=%d error=%d)", address, mtu, error)

        disconnect_cb = await self._client.bluetooth_device_connect(
            address,
            on_bluetooth_connection_state=on_state,
            timeout=timeout,
            disconnect_timeout=5.0,
            feature_flags=feature_flags,
            address_type=address_type,
        )

        if not connected.is_set():
            disconnect_cb()
            raise RuntimeError(f"BLE connect failed for {address} (no connected event)")

        services = await self._client.bluetooth_gatt_get_services(address)
        write_handle = notify_handle = None
        for svc in services.services:
            if "1910" not in svc.uuid.lower():
                continue
            for char in svc.characteristics:
                cu = char.uuid.lower()
                if "fff2" in cu:
                    write_handle = char.handle
                elif "fff4" in cu:
                    notify_handle = char.handle

        if write_handle is None or notify_handle is None:
            disconnect_cb()
            raise RuntimeError(
                f"TTLock characteristics not found on device {address}; "
                f"write={write_handle}, notify={notify_handle}"
            )

        self._buffers[address] = bytearray()
        self._notify_unsub[address] = disconnect_cb
        log.debug("GATT handles: write=%d notify=%d", write_handle, notify_handle)
        return GATTHandles(write_handle=write_handle, notify_handle=notify_handle)

    async def disconnect_lock(self, address: int) -> None:
        assert self._client, "Not connected to ESPHome"
        self._buffers.pop(address, None)
        self._notify_cbs.pop(address, None)
        unsub = self._notify_unsub.pop(address, None)
        if unsub:
            unsub()
        await self._client.bluetooth_device_disconnect(address)

    # ── GATT operations ───────────────────────────────────────────────────────

    async def start_notify(self, address: int, handle: int,
                           callback: Callable[[bytes], None]) -> None:
        """Subscribe to notifications; *callback* is invoked with complete frames."""
        assert self._client, "Not connected to ESPHome"
        self._notify_cbs[address] = callback

        def on_notify(h: int, data: bytearray) -> None:
            buf = self._buffers.get(address)
            if buf is None:
                return
            buf.extend(data)
            while len(buf) >= 2:
                idx = buf.find(b"\r\n")
                if idx == -1:
                    break
                frame = bytes(buf[:idx])
                del buf[: idx + 2]
                cb = self._notify_cbs.get(address)
                if cb and frame:
                    try:
                        cb(frame)
                    except Exception:
                        log.exception("Notify callback raised")

        await self._client.bluetooth_gatt_start_notify(address, handle, on_notify)

    async def stop_notify(self, address: int, handle: int) -> None:
        if self._client:
            self._client.bluetooth_gatt_stop_notify(address, handle)

    async def write(self, address: int, handle: int, data: bytes) -> None:
        """Write *data* to *handle*, chunked at MTU=20 bytes, appending CRLF."""
        assert self._client, "Not connected to ESPHome"
        from .protocol import MTU, CRLF
        packet = data + CRLF
        for i in range(0, len(packet), MTU):
            chunk = packet[i: i + MTU]
            await self._client.bluetooth_gatt_write(
                address, handle, chunk, response=True
            )

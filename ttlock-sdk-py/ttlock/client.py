"""TTLockClient: top-level entry point.

Usage example:

    import asyncio
    from client import TTLockClient

    async def main():
        async with TTLockClient("192.168.1.100", noise_psk="base64key==") as client:
            devices = await client.scan(timeout=8)
            for d in devices:
                print(d.name, d.address)

            async with client.session(devices[0].address, devices[0].lock_version) as sess:
                aes_key = await sess.get_aes_key()
                await sess.calibrate_time()
                await sess.unlock(admin_ps=0x12345678, unlock_key=0xABCDEF00)

    asyncio.run(main())
"""

from __future__ import annotations
import asyncio
import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator, Callable

from .protocol import LockVersion, DEFAULT_AES_KEY
from .ble import ESPHomeBLE, TTLockAdvertisement
from .lock import TTLockSession

log = logging.getLogger(__name__)


class TTLockClient:
    """Manages a single ESPHome connection and spawns TTLockSession objects."""

    def __init__(
        self,
        esphome_host: str,
        esphome_port: int = 6053,
        noise_psk: str | None = None,
    ) -> None:
        self._ble = ESPHomeBLE(esphome_host, esphome_port, noise_psk=noise_psk)

    async def __aenter__(self) -> "TTLockClient":
        await self._ble.connect_esphome()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self._ble.disconnect_esphome()

    async def scan(self, timeout: float = 10.0,
                   stop_on_address: int | None = None) -> list[TTLockAdvertisement]:
        """Scan for nearby TTLock BLE advertisements.

        Returns a list of :class:`TTLockAdvertisement`.  Each has:
          - ``address`` (int)  — BLE address usable with :meth:`session`
          - ``name``    (str)
          - ``rssi``    (int)
          - ``manufacturer_data`` (bytes) — parse with LockVersion.from_manufacturer_data()

        If *stop_on_address* is set, scanning stops as soon as that address is seen.
        """
        return await self._ble.scan(timeout=timeout, stop_on_address=stop_on_address)

    async def watch(self, address: int,
                    callback: Callable[[TTLockAdvertisement], None]) -> None:
        """Watch BLE advertisements for *address*, calling *callback* on each update.

        Runs until the task is cancelled (KeyboardInterrupt via asyncio.run()).
        """
        await self._ble.watch(address, callback)

    @asynccontextmanager
    async def session(
        self,
        address: int,
        address_type: int = 0,
        lock_version: LockVersion | None = None,
        aes_key: bytes = DEFAULT_AES_KEY,
    ) -> AsyncIterator[TTLockSession]:
        """Context manager that connects to a TTLock device and yields a session.

        *address* and *address_type* come from a :class:`TTLockAdvertisement`::

            async with client.session(adv.address, adv.address_type, lv) as sess:
                ...

        *lock_version* can be obtained from advertisement manufacturer data::

            lv = LockVersion.from_manufacturer_data(adv.manufacturer_data)

        If omitted, defaults to V3.
        """
        lv = lock_version or LockVersion.v3()
        sess = TTLockSession(self._ble, address, address_type, lv, aes_key)
        await sess.connect()
        try:
            yield sess
        finally:
            await sess.disconnect()

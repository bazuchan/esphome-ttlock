"""TTLockSession: high-level lock operations over ESPHomeBLE transport."""

from __future__ import annotations
import asyncio
import logging

from .protocol import (
    LockVersion, DEFAULT_AES_KEY,
    build_packet, parse_packet,
)
from . import commands as cmd
from .ble import ESPHomeBLE, GATTHandles

log = logging.getLogger(__name__)

RESPONSE_TIMEOUT = 10.0  # seconds


class TTLockSession:
    """Represents an active connection to one TTLock device.

    Typical pairing flow (new lock):
        aes_key = await session.get_aes_key()
        await session.calibrate_time()
        await session.add_admin(admin_ps, unlock_key)

    Typical unlock flow (paired lock):
        ps = await session.check_admin(admin_ps, lock_flag_pos, uid)
        result = await session.unlock(admin_ps, unlock_key)
    """

    def __init__(
        self,
        ble: ESPHomeBLE,
        address: int,
        address_type: int,
        lock_version: LockVersion,
        aes_key: bytes = DEFAULT_AES_KEY,
    ) -> None:
        self._ble = ble
        self._address = address
        self._address_type = address_type
        self._lv = lock_version
        self._aes_key = aes_key
        self._handles: GATTHandles | None = None
        self._pending: asyncio.Future | None = None
        self._expected_cmd: int | None = None   # cmd_type we're waiting for

    async def connect(self) -> None:
        self._handles = await self._ble.connect_lock(self._address, self._address_type)
        await self._ble.start_notify(
            self._address, self._handles.notify_handle, self._on_notify
        )

    async def disconnect(self) -> None:
        if self._handles:
            await self._ble.stop_notify(self._address, self._handles.notify_handle)
        await self._ble.disconnect_lock(self._address)
        self._handles = None

    def set_aes_key(self, key: bytes) -> None:
        self._aes_key = key

    # ── Internal send/receive ─────────────────────────────────────────────────

    @staticmethod
    def _peek_cmd(raw: bytes) -> int | None:
        """Extract cmd_type from a raw frame without full parsing."""
        if len(raw) < 2 or raw[0] != 0x7F or raw[1] != 0x5A:
            return None
        proto = raw[2] if len(raw) > 2 else 0
        if proto >= 5 or proto == 0:
            return raw[9] if len(raw) > 9 else None
        else:
            return raw[3] if len(raw) > 3 else None

    def _on_notify(self, raw: bytes) -> None:
        """Called by ESPHomeBLE when a complete frame arrives (CRLF stripped)."""
        if self._pending and not self._pending.done():
            cmd = self._peek_cmd(raw)
            if self._expected_cmd is not None and cmd != self._expected_cmd:
                # cmd=0x54 is the lock's generic response wrapper for ALL commands.
                if cmd == 0x54 and len(raw) >= 13:
                    pass  # accept 0x54 wrapper for any command
                else:
                    log.debug("Unsolicited frame (cmd=%s, waiting for %#x): %s",
                              f"{cmd:#x}" if cmd is not None else "?",
                              self._expected_cmd, raw.hex())
                    return
            self._pending.set_result(raw)
        else:
            log.debug("Unsolicited frame: %s", raw.hex())

    async def _send_command(
        self, cmd_type: int, payload: bytes, timeout: float = RESPONSE_TIMEOUT
    ) -> tuple[int, bytes]:
        """Send a command and await the response.  Returns (resp_cmd_type, resp_payload)."""
        assert self._handles, "Not connected"

        loop = asyncio.get_event_loop()
        self._pending = loop.create_future()
        self._expected_cmd = cmd_type
        try:
            packet = build_packet(self._lv, cmd_type, payload, self._aes_key)
            # build_packet includes CRLF; ble.write() would add another — strip it
            packet_no_crlf = packet[:-2]
            log.debug("TX  cmd=%#04x  plain=%-32s  enc=%s",
                      cmd_type, payload.hex(), packet_no_crlf.hex())
            await self._ble.write(self._address, self._handles.write_handle, packet_no_crlf)
            raw = await asyncio.wait_for(self._pending, timeout=timeout)
        finally:
            self._pending = None
            self._expected_cmd = None

        resp_type, resp_payload = parse_packet(raw, self._aes_key)
        log.debug("RX  cmd=%#04x  plain=%-32s  enc=%s",
                  resp_type, resp_payload.hex(), raw.hex())
        return resp_type, resp_payload

    # ── High-level commands ───────────────────────────────────────────────────

    async def init(self) -> None:
        """Send INITIALIZATION command (cmd=0x45) — call first during pairing."""
        await self._send_command(cmd.CMD_INITIALIZATION, b"")
        log.debug("Init sent")

    async def operate_finished(self) -> None:
        """Send OPERATE_FINISHED (cmd=0x57) — required to commit pairing data."""
        await self._send_command(cmd.CMD_OPERATE_FINISHED, b"")
        log.info("Operate finished — pairing committed")

    async def get_aes_key(self) -> bytes:
        """Exchange AES key with the lock (call before any encrypted command)."""
        _, payload = await self._send_command(cmd.CMD_GET_AES_KEY, cmd.build_get_aes_key())
        result = cmd.parse_get_aes_key(payload)
        self._aes_key = result.aes_key
        log.info("Got AES key: %s", result.aes_key.hex())
        return result.aes_key

    async def calibrate_time(self) -> None:
        """Sync the lock's clock to the current system time."""
        await self._send_command(cmd.CMD_TIME_CALIBRATE, cmd.build_calibrate_time())
        log.info("Time calibrated")

    async def add_admin(self, admin_ps: int, unlock_key: int) -> None:
        """Register this app as administrator on a factory-fresh lock."""
        _, payload = await self._send_command(
            cmd.CMD_ADD_ADMIN, cmd.build_add_admin(admin_ps, unlock_key)
        )
        data = payload[2:]
        if data[:7] != b"SCIENER":
            raise RuntimeError(f"ADD_ADMIN rejected, response data: {payload.hex()}")
        log.info("Admin added successfully")

    async def check_admin(self, admin_ps: int, lock_flag_pos: int, uid: int) -> int:
        """Verify admin credentials; returns psFromLock (needed for unlock sum)."""
        _, payload = await self._send_command(
            cmd.CMD_CHECK_ADMIN,
            cmd.build_check_admin(admin_ps, lock_flag_pos, uid),
        )
        result = cmd.parse_check_admin(payload)
        log.debug("psFromLock = %d", result.ps_from_lock)
        return result.ps_from_lock

    async def check_random(self, ps_from_lock: int, unlock_key: int) -> None:
        """Verify admin token (required before reset_lock)."""
        _, payload = await self._send_command(
            cmd.CMD_CHECK_RANDOM, cmd.build_check_random(ps_from_lock, unlock_key)
        )
        if len(payload) >= 2 and payload[1] != cmd.RESP_SUCCESS:
            raise RuntimeError(f"CHECK_RANDOM failed: {payload[1]:#x}")

    async def reset_lock(self) -> None:
        """Factory-reset the lock (erases admin and all credentials)."""
        await self._send_command(cmd.CMD_RESET_LOCK, cmd.build_reset_lock())
        log.info("Lock reset")

    async def check_user_time(self) -> int:
        """Send CHECK_USER_TIME and return ps_from_lock (needed for unlock sum).

        Uses a wide-open date range so the admin always passes the time check.
        """
        _, payload = await self._send_command(
            cmd.CMD_CHECK_USER_TIME, cmd.build_check_user_time()
        )
        result = cmd.parse_check_user_time(payload)
        log.debug("ps_from_lock = %d", result.ps_from_lock)
        return result.ps_from_lock

    async def unlock(self, ps_from_lock: int, unlock_key: int) -> cmd.UnlockResponse:
        """Unlock the door.  *ps_from_lock* from check_user_time(); *unlock_key* from pairing."""
        _, payload = await self._send_command(
            cmd.CMD_UNLOCK, cmd.build_unlock(ps_from_lock, unlock_key)
        )
        result = cmd.parse_unlock(payload)
        log.info("Unlocked — battery=%d%%", result.battery)
        return result

    async def lock(self, ps_from_lock: int, unlock_key: int) -> cmd.LockResponse:
        """Lock the door.  *ps_from_lock* from check_user_time()."""
        _, payload = await self._send_command(
            cmd.CMD_LOCK, cmd.build_lock(ps_from_lock, unlock_key)
        )
        result = cmd.parse_lock(payload)
        log.info("Locked — battery=%d%%", result.battery)
        return result

    async def get_logs(self, sequence: int = 0xFFFF) -> cmd.LogResponse:
        """Fetch operation log records starting from *sequence* (0xFFFF = all)."""
        _, payload = await self._send_command(
            cmd.CMD_GET_OPERATE_LOG, cmd.build_get_log(sequence)
        )
        result = cmd.parse_get_log(payload)
        log.info("Got %d log records (total=%d)", len(result.records), result.total_len)
        return result

    async def add_passcode(
        self,
        pwd: str,
        start: tuple[int, int, int, int, int] | None = None,
        end: tuple[int, int, int, int, int] | None = None,
    ) -> None:
        """Add a keyboard passcode.  *start*/*end* are (year, month, day, hour, minute)."""
        await self._send_command(
            cmd.CMD_MANAGE_KBD_PASSWORD,
            cmd.build_add_passcode(pwd, start, end),
        )
        log.info("Passcode %s added", pwd)

    async def configure_passage_mode(self, enable: bool) -> None:
        """Enable or disable passage mode (lock stays open while enabled)."""
        payload = cmd.build_passage_mode_on() if enable else cmd.build_passage_mode_off()
        _, resp = await self._send_command(cmd.CMD_CONFIGURE_PASSAGE_MODE, payload)
        if len(resp) >= 2 and resp[1] != cmd.RESP_SUCCESS:
            raise RuntimeError(f"CONFIGURE_PASSAGE_MODE failed: {resp[1]:#x}")
        log.info("Passage mode %s", "enabled" if enable else "disabled")

    async def _wait_notification(self, timeout: float = RESPONSE_TIMEOUT) -> tuple[int, bytes]:
        """Wait for the next unsolicited notification frame (no TX)."""
        loop = asyncio.get_event_loop()
        self._pending = loop.create_future()
        self._expected_cmd = None   # accept any cmd
        try:
            raw = await asyncio.wait_for(self._pending, timeout=timeout)
        finally:
            self._pending = None
            self._expected_cmd = None
        resp_type, resp_payload = parse_packet(raw, self._aes_key)
        log.debug("RX (notify)  cmd=%#04x  plain=%-32s  enc=%s",
                  resp_type, resp_payload.hex(), raw.hex())
        return resp_type, resp_payload

    # ── Status ────────────────────────────────────────────────────────────────

    async def get_status(self) -> cmd.StatusResponse:
        """Query locked/unlocked status."""
        _, payload = await self._send_command(cmd.CMD_SEARCH_STATUS, cmd.build_status())
        return cmd.parse_status(payload)

    # ── Autolock ──────────────────────────────────────────────────────────────

    async def get_autolock(self) -> cmd.AutolockResponse:
        """Get the current autolock delay (seconds)."""
        _, payload = await self._send_command(cmd.CMD_AUTO_LOCK_MANAGE, cmd.build_autolock_get())
        return cmd.parse_autolock(payload)

    async def set_autolock(self, seconds: int) -> cmd.AutolockResponse:
        """Set the autolock delay in seconds (0 = disabled)."""
        _, payload = await self._send_command(cmd.CMD_AUTO_LOCK_MANAGE,
                                              cmd.build_autolock_set(seconds))
        return cmd.parse_autolock(payload)

    # ── Audio ─────────────────────────────────────────────────────────────────

    async def get_audio(self) -> cmd.AudioResponse:
        """Query lock-sound on/off state."""
        _, payload = await self._send_command(cmd.CMD_AUDIO_MANAGE, cmd.build_audio_get())
        return cmd.parse_audio(payload)

    async def set_audio(self, on: bool) -> None:
        """Enable or disable the lock sound."""
        await self._send_command(cmd.CMD_AUDIO_MANAGE, cmd.build_audio_set(on))
        log.info("Audio %s", "on" if on else "off")

    # ── Switch state (reset button / tamper alert / …) ───────────────────────

    async def get_switch_state(self, config_item: int) -> cmd.SwitchResponse:
        """Query a switch-type config item (SWITCH_RESET_BUTTON, SWITCH_TAMPER_ALERT, …)."""
        _, payload = await self._send_command(cmd.CMD_SWITCH, cmd.build_switch_get())
        return cmd.parse_switch(payload, config_item)

    async def set_switch_state(self, config_item: int, enable: bool) -> None:
        """Enable or disable a switch-type config item."""
        await self._send_command(cmd.CMD_SWITCH,
                                 cmd.build_switch_set(config_item, enable))
        log.info("Switch %#x %s", config_item, "enabled" if enable else "disabled")

    # ── IC cards ──────────────────────────────────────────────────────────────

    async def list_ic_cards(self) -> list[cmd.ICCard]:
        """Return all registered IC cards (paginates automatically)."""
        cards: list[cmd.ICCard] = []
        sequence = 0
        while True:
            _, payload = await self._send_command(cmd.CMD_IC_MANAGE,
                                                  cmd.build_ic_list(sequence))
            resp = cmd.parse_ic_list(payload)
            cards.extend(resp.cards)
            if resp.sequence < 0:
                break
            sequence = resp.sequence
        return cards

    async def start_add_ic_card(self) -> None:
        """Enter IC-card add mode; the lock waits for a card to be presented."""
        _, payload = await self._send_command(cmd.CMD_IC_MANAGE, cmd.build_ic_add_start())
        resp = cmd.parse_ic_add_response(payload)
        if resp.status != cmd.IC_STATUS_ENTER_MODE:
            raise RuntimeError(f"IC add: unexpected status {resp.status:#x}")

    async def wait_ic_card(self, timeout: float = 30.0) -> str:
        """Wait for the lock to report a scanned card; returns card number string."""
        _, payload = await self._wait_notification(timeout=timeout)
        resp = cmd.parse_ic_add_response(payload)
        if resp.status != cmd.IC_STATUS_SUCCESS:
            raise RuntimeError(f"IC add: unexpected status {resp.status:#x}")
        return resp.number

    async def clear_ic_cards(self) -> None:
        """Remove all registered IC cards."""
        await self._send_command(cmd.CMD_IC_MANAGE, cmd.build_ic_clear())
        log.info("IC cards cleared")

    # ── Fingerprints ──────────────────────────────────────────────────────────

    async def list_fingerprints(self) -> list[cmd.Fingerprint]:
        """Return all registered fingerprints (paginates automatically)."""
        fps: list[cmd.Fingerprint] = []
        sequence = 0
        while True:
            _, payload = await self._send_command(cmd.CMD_FR_MANAGE,
                                                  cmd.build_fr_list(sequence))
            resp = cmd.parse_fr_list(payload)
            fps.extend(resp.fingerprints)
            if resp.sequence < 0:
                break
            sequence = resp.sequence
        return fps

    async def start_add_fingerprint(self) -> None:
        """Enter fingerprint add mode."""
        _, payload = await self._send_command(cmd.CMD_FR_MANAGE, cmd.build_fr_add_start())
        resp = cmd.parse_fr_add_response(payload)
        if resp.status != cmd.IC_STATUS_ENTER_MODE:
            raise RuntimeError(f"FR add: unexpected status {resp.status:#x}")

    async def wait_fingerprint(self, timeout: float = 30.0,
                               progress_cb=None) -> str:
        """Wait for fingerprint scanning to complete; returns fingerprint number string.

        *progress_cb* is called with no arguments on each progress notification.
        """
        while True:
            _, payload = await self._wait_notification(timeout=timeout)
            resp = cmd.parse_fr_add_response(payload)
            if resp.status == cmd.IC_STATUS_FR_PROGRESS:
                if progress_cb:
                    progress_cb()
                continue
            if resp.status == cmd.IC_STATUS_SUCCESS:
                return resp.number
            raise RuntimeError(f"FR add: unexpected status {resp.status:#x}")

    async def clear_fingerprints(self) -> None:
        """Remove all registered fingerprints."""
        await self._send_command(cmd.CMD_FR_MANAGE, cmd.build_fr_clear())
        log.info("Fingerprints cleared")

    # ── Passcode list / clear ─────────────────────────────────────────────────

    async def list_passcodes(self) -> list[cmd.Passcode]:
        """Return all registered keyboard passcodes (paginates automatically)."""
        codes: list[cmd.Passcode] = []
        sequence = 0
        while True:
            _, payload = await self._send_command(cmd.CMD_PWD_LIST,
                                                  cmd.build_passcode_list(sequence))
            resp = cmd.parse_passcode_list(payload)
            codes.extend(resp.passcodes)
            if resp.sequence < 0:
                break
            sequence = resp.sequence
        return codes

    async def clear_passcodes(self) -> None:
        """Remove all keyboard passcodes."""
        await self._send_command(cmd.CMD_MANAGE_KBD_PASSWORD, cmd.build_passcode_clear())
        log.info("Passcodes cleared")

    # ── Passage mode list ─────────────────────────────────────────────────────

    async def list_passage_mode(self) -> list[cmd.PassageModeEntry]:
        """Return all configured passage mode intervals (paginates automatically)."""
        entries: list[cmd.PassageModeEntry] = []
        sequence = 0
        while True:
            _, payload = await self._send_command(cmd.CMD_CONFIGURE_PASSAGE_MODE,
                                                  cmd.build_passage_mode_list(sequence))
            resp = cmd.parse_passage_mode_list(payload)
            entries.extend(resp.entries)
            if resp.sequence < 0:
                break
            sequence = resp.sequence
        return entries

    async def delete_passcode(self, pwd: str) -> None:
        await self._send_command(
            cmd.CMD_MANAGE_KBD_PASSWORD,
            cmd.build_delete_passcode(pwd),
        )
        log.info("Passcode %s deleted", pwd)

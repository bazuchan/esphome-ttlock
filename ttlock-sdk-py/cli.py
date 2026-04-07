#!/usr/bin/env python3
"""TTLock management CLI.

Usage:
  cli.py pair [address|MAC|bt-name|any] [lock-name]
  cli.py unlock [lock-name]
  cli.py lock   [lock-name]
  cli.py reset  [lock-name]
"""

import argparse
import asyncio
import json
import logging
import os
import random
import shutil
import sys

from ttlock import TTLockClient, LockVersion, TTLockAdvertisement

ESPHOME_HOST      = os.environ.get("ESPHOME_HOST")
DATA_FILE         = "locks.json"
SCAN_TIMEOUT_PAIR = 60.0
SCAN_TIMEOUT      = 15.0


# ── Data file helpers ─────────────────────────────────────────────────────────

def _load_locks() -> dict:
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE) as f:
            return json.load(f)
    return {}


def _save_locks(locks: dict) -> None:
    if os.path.exists(DATA_FILE):
        shutil.copy2(DATA_FILE, DATA_FILE + ".bak")
    with open(DATA_FILE, "w") as f:
        json.dump(locks, f, indent=2)
        f.write("\n")


def _get_lock(name: str | None) -> tuple[str, dict]:
    locks = _load_locks()
    if not locks:
        raise SystemExit("No locks in locks.json.")
    if name is None:
        if len(locks) != 1:
            raise SystemExit(f"Multiple locks — specify a name: {', '.join(locks)}")
        name = next(iter(locks))
    elif name not in locks:
        raise SystemExit(f"Lock {name!r} not found. Available: {', '.join(locks)}")
    return name, locks[name]


def _lock_version(d: dict) -> LockVersion:
    return LockVersion(
        protocol_type    = d["protocol_type"],
        protocol_version = d["protocol_version"],
        scene            = d["scene"],
        group_id         = d["group_id"],
        org_id           = d["org_id"],
    )


def _mac_to_int(mac: str) -> int:
    return int(mac.replace(":", ""), 16)


def _int_to_mac(n: int) -> str:
    return ":".join(f"{(n >> (40 - i * 8)) & 0xFF:02X}" for i in range(6))


# ── Commands ──────────────────────────────────────────────────────────────────

async def cmd_pair(target: str, lock_name: str | None) -> None:
    locks = _load_locks()

    async with TTLockClient(ESPHOME_HOST, noise_psk=os.environ.get("ESPHOME_KEY")) as cl:
        print("Scanning …")
        devices = await cl.scan(timeout=SCAN_TIMEOUT_PAIR)

        if not devices:
            raise SystemExit("No TTLock devices found.")

        # Filter by target
        def matches(adv: TTLockAdvertisement) -> bool:
            if target == "any":
                return True
            try:
                return adv.address == int(target)
            except ValueError:
                pass
            if ":" in target:
                try:
                    return adv.address == _mac_to_int(target)
                except ValueError:
                    pass
            return adv.name == target

        candidates = [d for d in devices if matches(d)]

        # For "any" exclude already-known addresses
        if target == "any":
            known = {v["address"] for v in locks.values()}
            candidates = [d for d in candidates if d.address not in known]

        if not candidates:
            raise SystemExit(f"No matching unpaired TTLock found for {target!r}.")

        dev = candidates[0]
        if len(candidates) > 1:
            print(f"Multiple matches — using first: {dev.name!r} ({dev.address})")

        name = lock_name or dev.name or str(dev.address)
        print(f"Pairing '{name}'  addr={dev.address}  rssi={dev.rssi} dBm")

        try:
            lv = LockVersion.from_manufacturer_data(dev.manufacturer_data)
        except Exception as exc:
            print(f"Warning: cannot parse LockVersion ({exc}), defaulting to V3")
            lv = LockVersion.v3()

        admin_ps   = random.randint(0x00010000, 0x7FFFFFFF)
        unlock_key = random.randint(0x00010000, 0x7FFFFFFF)

        async with cl.session(dev.address, 0, lv) as sess:
            await sess.init()
            aes_key = await sess.get_aes_key()
            await sess.add_admin(admin_ps, unlock_key)
            await sess.calibrate_time()
            await sess.operate_finished()

    locks[name] = {
        "address":          _int_to_mac(dev.address),
        "protocol_type":    lv.protocol_type,
        "protocol_version": lv.protocol_version,
        "scene":            lv.scene,
        "group_id":         lv.group_id,
        "org_id":           lv.org_id,
        "aes_key":          aes_key.hex(),
        "admin_ps":         f"{admin_ps:08x}",
        "unlock_key":       f"{unlock_key:08x}",
    }
    _save_locks(locks)
    print(f"Paired and saved as '{name}'.")


async def cmd_unlock(lock_name: str | None) -> None:
    name, d = _get_lock(lock_name)
    aes_key    = bytes.fromhex(d["aes_key"])
    unlock_key = int(d["unlock_key"], 16)

    print(f"Unlocking '{name}' …")
    async with TTLockClient(ESPHOME_HOST, noise_psk=os.environ.get("ESPHOME_KEY")) as cl:
        async with cl.session(_mac_to_int(d["address"]), 0, _lock_version(d),
                              aes_key=aes_key) as sess:
            ps = await sess.check_user_time()
            result = await sess.unlock(ps, unlock_key)
    print(f"Unlocked!  battery={result.battery}%")


async def cmd_lock(lock_name: str | None) -> None:
    name, d = _get_lock(lock_name)
    aes_key    = bytes.fromhex(d["aes_key"])
    unlock_key = int(d["unlock_key"], 16)

    print(f"Locking '{name}' …")
    async with TTLockClient(ESPHOME_HOST, noise_psk=os.environ.get("ESPHOME_KEY")) as cl:
        async with cl.session(_mac_to_int(d["address"]), 0, _lock_version(d),
                              aes_key=aes_key) as sess:
            ps = await sess.check_user_time()
            result = await sess.lock(ps, unlock_key)
    print(f"Locked!  battery={result.battery}%")


async def cmd_pass(lock_name: str | None, enable: bool) -> None:
    name, d = _get_lock(lock_name)
    aes_key    = bytes.fromhex(d["aes_key"])
    admin_ps   = int(d["admin_ps"],   16)
    unlock_key = int(d["unlock_key"], 16)

    state = "on" if enable else "off"
    print(f"Setting passage mode {state} for '{name}' …")
    async with TTLockClient(ESPHOME_HOST, noise_psk=os.environ.get("ESPHOME_KEY")) as cl:
        async with cl.session(_mac_to_int(d["address"]), 0, _lock_version(d),
                              aes_key=aes_key) as sess:
            ps = await sess.check_admin(admin_ps, 0, 0)
            await sess.check_random(ps, unlock_key)
            await sess.configure_passage_mode(enable)
            if enable:
                ps = await sess.check_user_time()
                result = await sess.unlock(ps, unlock_key)
                print(f"Passage mode on — unlocked.  battery={result.battery}%")
            else:
                print("Passage mode off.")


async def cmd_status(lock_name: str | None) -> None:
    name, d = _get_lock(lock_name)
    aes_key = bytes.fromhex(d["aes_key"])
    async with TTLockClient(ESPHOME_HOST, noise_psk=os.environ.get("ESPHOME_KEY")) as cl:
        async with cl.session(_mac_to_int(d["address"]), 0, _lock_version(d),
                              aes_key=aes_key) as sess:
            result = await sess.get_status()
    state = "LOCKED" if result.locked else "UNLOCKED"
    print(f"{name}: {state}  battery={result.battery}%")


async def cmd_autolock(lock_name: str | None, seconds: int | None) -> None:
    name, d = _get_lock(lock_name)
    aes_key = bytes.fromhex(d["aes_key"])
    async with TTLockClient(ESPHOME_HOST, noise_psk=os.environ.get("ESPHOME_KEY")) as cl:
        async with cl.session(_mac_to_int(d["address"]), 0, _lock_version(d),
                              aes_key=aes_key) as sess:
            if seconds is None:
                result = await sess.get_autolock()
                print(f"Autolock: {result.seconds}s  battery={result.battery}%")
            else:
                result = await sess.set_autolock(seconds)
                print(f"Autolock set to {result.seconds}s  battery={result.battery}%")


async def cmd_sound(lock_name: str | None, enable: bool) -> None:
    name, d = _get_lock(lock_name)
    aes_key = bytes.fromhex(d["aes_key"])
    state = "on" if enable else "off"
    print(f"Setting sound {state} for '{name}' …")
    async with TTLockClient(ESPHOME_HOST, noise_psk=os.environ.get("ESPHOME_KEY")) as cl:
        async with cl.session(_mac_to_int(d["address"]), 0, _lock_version(d),
                              aes_key=aes_key) as sess:
            await sess.set_audio(enable)
    print(f"Sound {state}.")


async def cmd_get_passage(lock_name: str | None) -> None:
    name, d = _get_lock(lock_name)
    aes_key   = bytes.fromhex(d["aes_key"])
    admin_ps  = int(d["admin_ps"],  16)
    unlock_key = int(d["unlock_key"], 16)
    async with TTLockClient(ESPHOME_HOST, noise_psk=os.environ.get("ESPHOME_KEY")) as cl:
        async with cl.session(_mac_to_int(d["address"]), 0, _lock_version(d),
                              aes_key=aes_key) as sess:
            ps = await sess.check_admin(admin_ps, 0, 0)
            await sess.check_random(ps, unlock_key)
            entries = await sess.list_passage_mode()
    if not entries:
        print("No passage mode entries.")
        return
    day_names = ["Every day", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    for e in entries:
        typ  = "weekly" if e.type == 1 else "monthly"
        day  = day_names[e.week_or_day] if e.type == 1 and e.week_or_day < len(day_names) \
               else str(e.week_or_day)
        hrs  = "all day" if e.start == "00:00" and e.end == "00:00" \
               else f"{e.start}–{e.end}"
        print(f"  {typ}  {day}  {hrs}")


async def cmd_add_card(lock_name: str | None) -> None:
    name, d = _get_lock(lock_name)
    aes_key    = bytes.fromhex(d["aes_key"])
    admin_ps   = int(d["admin_ps"],   16)
    unlock_key = int(d["unlock_key"], 16)
    async with TTLockClient(ESPHOME_HOST, noise_psk=os.environ.get("ESPHOME_KEY")) as cl:
        async with cl.session(_mac_to_int(d["address"]), 0, _lock_version(d),
                              aes_key=aes_key) as sess:
            ps = await sess.check_admin(admin_ps, 0, 0)
            await sess.check_random(ps, unlock_key)
            await sess.start_add_ic_card()
            print("Scan an IC card …")
            card_number = await sess.wait_ic_card(timeout=30.0)
    print(f"Card added: {card_number}")


async def cmd_get_cards(lock_name: str | None) -> None:
    name, d = _get_lock(lock_name)
    aes_key    = bytes.fromhex(d["aes_key"])
    admin_ps   = int(d["admin_ps"],   16)
    unlock_key = int(d["unlock_key"], 16)
    async with TTLockClient(ESPHOME_HOST, noise_psk=os.environ.get("ESPHOME_KEY")) as cl:
        async with cl.session(_mac_to_int(d["address"]), 0, _lock_version(d),
                              aes_key=aes_key) as sess:
            ps = await sess.check_admin(admin_ps, 0, 0)
            await sess.check_random(ps, unlock_key)
            cards = await sess.list_ic_cards()
    if not cards:
        print("No IC cards registered.")
        return
    for c in cards:
        print(f"  {c.number}  {c.start} – {c.end}")


async def cmd_clear_cards(lock_name: str | None) -> None:
    name, d = _get_lock(lock_name)
    aes_key    = bytes.fromhex(d["aes_key"])
    admin_ps   = int(d["admin_ps"],   16)
    unlock_key = int(d["unlock_key"], 16)
    async with TTLockClient(ESPHOME_HOST, noise_psk=os.environ.get("ESPHOME_KEY")) as cl:
        async with cl.session(_mac_to_int(d["address"]), 0, _lock_version(d),
                              aes_key=aes_key) as sess:
            ps = await sess.check_admin(admin_ps, 0, 0)
            await sess.check_random(ps, unlock_key)
            await sess.clear_ic_cards()
    print("All IC cards removed.")


async def cmd_add_fingerprint(lock_name: str | None) -> None:
    name, d = _get_lock(lock_name)
    aes_key    = bytes.fromhex(d["aes_key"])
    admin_ps   = int(d["admin_ps"],   16)
    unlock_key = int(d["unlock_key"], 16)
    async with TTLockClient(ESPHOME_HOST, noise_psk=os.environ.get("ESPHOME_KEY")) as cl:
        async with cl.session(_mac_to_int(d["address"]), 0, _lock_version(d),
                              aes_key=aes_key) as sess:
            ps = await sess.check_admin(admin_ps, 0, 0)
            await sess.check_random(ps, unlock_key)
            await sess.start_add_fingerprint()
            print("Place finger on sensor …")
            scans = 0
            def on_progress():
                nonlocal scans
                scans += 1
                print(f"  scan {scans} recorded, keep going …")
            fp_number = await sess.wait_fingerprint(timeout=30.0, progress_cb=on_progress)
    print(f"Fingerprint added: {fp_number}")


async def cmd_get_fingerprints(lock_name: str | None) -> None:
    name, d = _get_lock(lock_name)
    aes_key    = bytes.fromhex(d["aes_key"])
    admin_ps   = int(d["admin_ps"],   16)
    unlock_key = int(d["unlock_key"], 16)
    async with TTLockClient(ESPHOME_HOST, noise_psk=os.environ.get("ESPHOME_KEY")) as cl:
        async with cl.session(_mac_to_int(d["address"]), 0, _lock_version(d),
                              aes_key=aes_key) as sess:
            ps = await sess.check_admin(admin_ps, 0, 0)
            await sess.check_random(ps, unlock_key)
            fps = await sess.list_fingerprints()
    if not fps:
        print("No fingerprints registered.")
        return
    for f in fps:
        print(f"  {f.number}  {f.start} – {f.end}")


async def cmd_clear_fingerprints(lock_name: str | None) -> None:
    name, d = _get_lock(lock_name)
    aes_key    = bytes.fromhex(d["aes_key"])
    admin_ps   = int(d["admin_ps"],   16)
    unlock_key = int(d["unlock_key"], 16)
    async with TTLockClient(ESPHOME_HOST, noise_psk=os.environ.get("ESPHOME_KEY")) as cl:
        async with cl.session(_mac_to_int(d["address"]), 0, _lock_version(d),
                              aes_key=aes_key) as sess:
            ps = await sess.check_admin(admin_ps, 0, 0)
            await sess.check_random(ps, unlock_key)
            await sess.clear_fingerprints()
    print("All fingerprints removed.")


async def cmd_get_passcodes(lock_name: str | None) -> None:
    name, d = _get_lock(lock_name)
    aes_key    = bytes.fromhex(d["aes_key"])
    admin_ps   = int(d["admin_ps"],   16)
    unlock_key = int(d["unlock_key"], 16)
    async with TTLockClient(ESPHOME_HOST, noise_psk=os.environ.get("ESPHOME_KEY")) as cl:
        async with cl.session(_mac_to_int(d["address"]), 0, _lock_version(d),
                              aes_key=aes_key) as sess:
            ps = await sess.check_admin(admin_ps, 0, 0)
            await sess.check_random(ps, unlock_key)
            codes = await sess.list_passcodes()
    if not codes:
        print("No passcodes registered.")
        return
    PWD_TYPE_NAMES = {1: "permanent", 2: "count-limited", 3: "time-limited", 4: "cyclic"}
    for c in codes:
        typ = PWD_TYPE_NAMES.get(c.pwd_type, str(c.pwd_type))
        end = f" – {c.end}" if c.end else ""
        print(f"  {c.passcode}  [{typ}]  from {c.start}{end}")


async def cmd_clear_passcodes(lock_name: str | None) -> None:
    name, d = _get_lock(lock_name)
    aes_key    = bytes.fromhex(d["aes_key"])
    admin_ps   = int(d["admin_ps"],   16)
    unlock_key = int(d["unlock_key"], 16)
    async with TTLockClient(ESPHOME_HOST, noise_psk=os.environ.get("ESPHOME_KEY")) as cl:
        async with cl.session(_mac_to_int(d["address"]), 0, _lock_version(d),
                              aes_key=aes_key) as sess:
            ps = await sess.check_admin(admin_ps, 0, 0)
            await sess.check_random(ps, unlock_key)
            await sess.clear_passcodes()
    print("All passcodes removed.")


_LOG_TYPE_NAMES = {
    1: "BT unlock", 4: "PIN unlock", 5: "PIN changed", 6: "PIN deleted",
    7: "Wrong PIN", 8: "All PINs deleted", 9: "PIN kicked", 10: "Delete-PIN used",
    11: "PIN expired", 12: "Storage full", 13: "PIN blacklisted",
    14: "Power-on reboot", 15: "IC card added", 16: "IC cards cleared",
    17: "IC unlock", 18: "IC card deleted", 19: "Bong unlock",
    20: "Fingerprint unlock", 21: "Fingerprint added", 22: "Fingerprint failed",
    23: "Fingerprint deleted", 24: "Fingerprints cleared", 25: "IC card expired",
    26: "BT lock", 27: "Mechanical key unlock", 28: "Gateway unlock",
    29: "Illegal unlock", 30: "Door sensor closed", 31: "Door sensor opened",
    32: "Exit", 33: "Fingerprint lock", 34: "PIN lock", 35: "IC lock",
    36: "Mechanical key lock", 37: "Remote key", 38: "PIN unlock failed (locked)",
    39: "IC unlock failed (locked)", 40: "Fingerprint unlock failed (locked)",
    41: "App unlock failed (locked)", 55: "Wireless key fob", 56: "Wireless keypad",
}


async def cmd_get_log(lock_name: str | None) -> None:
    name, d = _get_lock(lock_name)
    aes_key = bytes.fromhex(d["aes_key"])
    async with TTLockClient(ESPHOME_HOST, noise_psk=os.environ.get("ESPHOME_KEY")) as cl:
        async with cl.session(_mac_to_int(d["address"]), 0, _lock_version(d),
                              aes_key=aes_key) as sess:
            result = await sess.get_logs()
    if not result.records:
        print("No log entries.")
        return
    for rec in result.records:
        dt = rec.date
        if len(dt) == 6:
            ts = f"20{dt[0]:02d}-{dt[1]:02d}-{dt[2]:02d} {dt[3]:02d}:{dt[4]:02d}:{dt[5]:02d}"
        else:
            ts = rec.date.hex()
        typ = _LOG_TYPE_NAMES.get(rec.record_type, f"type={rec.record_type}")
        print(f"  {ts}  {typ}  battery={rec.battery}%")


async def cmd_listen(lock_name: str | None) -> None:
    _, d = _get_lock(lock_name)
    address = _mac_to_int(d["address"])
    prev_params: int | None = None

    def on_adv(adv) -> None:
        nonlocal prev_params
        if adv.params == prev_params:
            return
        prev_params = adv.params
        p = adv.params
        state  = "UNLOCKED" if (p & 0x01) else "LOCKED"
        flags  = []
        if p & 0x02: flags.append("new-events")
        if p & 0x04: flags.append("setting-mode")
        if p & 0x08: flags.append("touch")
        extra = ("  " + " ".join(flags)) if flags else ""
        print(f"{state}  rssi={adv.rssi} dBm{extra}")

    print("Listening … (Ctrl+C to stop)")
    async with TTLockClient(ESPHOME_HOST, noise_psk=os.environ.get("ESPHOME_KEY")) as cl:
        await cl.watch(address, on_adv)


async def cmd_reset_button(lock_name: str | None, enable: bool | None) -> None:
    from ttlock.commands import SWITCH_RESET_BUTTON
    name, d = _get_lock(lock_name)
    aes_key    = bytes.fromhex(d["aes_key"])
    admin_ps   = int(d["admin_ps"],   16)
    unlock_key = int(d["unlock_key"], 16)
    async with TTLockClient(ESPHOME_HOST, noise_psk=os.environ.get("ESPHOME_KEY")) as cl:
        async with cl.session(_mac_to_int(d["address"]), 0, _lock_version(d),
                              aes_key=aes_key) as sess:
            ps = await sess.check_admin(admin_ps, 0, 0)
            await sess.check_random(ps, unlock_key)
            if enable is None:
                result = await sess.get_switch_state(SWITCH_RESET_BUTTON)
                state = "enabled" if result.enabled else "disabled"
                print(f"Reset button: {state}  battery={result.battery}%")
            else:
                await sess.set_switch_state(SWITCH_RESET_BUTTON, enable)
                state = "enabled" if enable else "disabled"
                print(f"Reset button {state}.")


async def cmd_reset(lock_name: str | None) -> None:
    name, d = _get_lock(lock_name)
    aes_key    = bytes.fromhex(d["aes_key"])
    admin_ps   = int(d["admin_ps"],   16)
    unlock_key = int(d["unlock_key"], 16)

    print(f"Resetting '{name}' — WARNING: this will erase all credentials!")
    async with TTLockClient(ESPHOME_HOST, noise_psk=os.environ.get("ESPHOME_KEY")) as cl:
        async with cl.session(_mac_to_int(d["address"]), 0, _lock_version(d),
                              aes_key=aes_key) as sess:
            ps = await sess.check_admin(admin_ps, 0, 0)
            await sess.check_random(ps, unlock_key)
            await sess.reset_lock()
    print("Lock reset — it is now in factory state.")


# ── Argument parsing ──────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(prog="cli.py",
                                     description="TTLock management CLI")
    parser.add_argument("-d", "--debug", action="store_true",
                        help="dump all TX/RX payloads (encrypted + decrypted)")
    sub = parser.add_subparsers(dest="command", metavar="command")
    sub.required = True

    p = sub.add_parser("pair", help="Pair a new lock")
    p.add_argument("target", nargs="?", default="any",
                   help="address, MAC (AA:BB:CC:DD:EE:FF), BT name, or 'any' (default)")
    p.add_argument("lock_name", nargs="?", default=None,
                   help="name to save in locks.json (default: BT device name)")

    for name in ("unlock", "lock", "reset", "status", "get-cards", "clear-cards",
                 "get-fingerprints", "clear-fingerprints", "get-passcodes",
                 "clear-passcodes", "get-passage", "get-log", "listen", "add-card",
                 "add-fingerprint"):
        p = sub.add_parser(name, help=f"{name.replace('-', ' ').capitalize()}")
        p.add_argument("lock_name", nargs="?", default=None,
                       help="lock name from locks.json (default: the only lock)")

    p = sub.add_parser("set-passage", help="Enable/disable passage mode (lock stays open)")
    p.add_argument("lock_name", nargs="?", default=None,
                   help="lock name from locks.json (default: the only lock)")
    p.add_argument("state", choices=["on", "off"], help="on = always open, off = normal")

    p = sub.add_parser("autolock", help="Get or set autolock delay")
    p.add_argument("lock_name", nargs="?", default=None,
                   help="lock name from locks.json (default: the only lock)")
    p.add_argument("seconds", nargs="?", type=int, default=None,
                   help="autolock delay in seconds (omit to query)")

    p = sub.add_parser("sound", help="Enable or disable lock sound")
    p.add_argument("lock_name", nargs="?", default=None,
                   help="lock name from locks.json (default: the only lock)")
    p.add_argument("state", choices=["on", "off"], help="on = sound enabled, off = silent")

    p = sub.add_parser("reset-button",
                       help="Get or set hardware reset-button enable/disable")
    p.add_argument("lock_name", nargs="?", default=None,
                   help="lock name from locks.json (default: the only lock)")
    p.add_argument("state", nargs="?", choices=["on", "off"], default=None,
                   help="on = button enabled, off = disabled (omit to query)")

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG,
                            format="%(name)s %(levelname)s %(message)s")

    match args.command:
        case "pair":
            asyncio.run(cmd_pair(args.target, args.lock_name))
        case "unlock":
            asyncio.run(cmd_unlock(args.lock_name))
        case "lock":
            asyncio.run(cmd_lock(args.lock_name))
        case "status":
            asyncio.run(cmd_status(args.lock_name))
        case "autolock":
            asyncio.run(cmd_autolock(args.lock_name, args.seconds))
        case "sound":
            asyncio.run(cmd_sound(args.lock_name, args.state == "on"))
        case "reset-button":
            enable = None if args.state is None else (args.state == "on")
            asyncio.run(cmd_reset_button(args.lock_name, enable))
        case "set-passage":
            asyncio.run(cmd_pass(args.lock_name, args.state == "on"))
        case "get-passage":
            asyncio.run(cmd_get_passage(args.lock_name))
        case "add-card":
            asyncio.run(cmd_add_card(args.lock_name))
        case "get-cards":
            asyncio.run(cmd_get_cards(args.lock_name))
        case "clear-cards":
            asyncio.run(cmd_clear_cards(args.lock_name))
        case "add-fingerprint":
            asyncio.run(cmd_add_fingerprint(args.lock_name))
        case "get-fingerprints":
            asyncio.run(cmd_get_fingerprints(args.lock_name))
        case "clear-fingerprints":
            asyncio.run(cmd_clear_fingerprints(args.lock_name))
        case "get-passcodes":
            asyncio.run(cmd_get_passcodes(args.lock_name))
        case "clear-passcodes":
            asyncio.run(cmd_clear_passcodes(args.lock_name))
        case "get-log":
            asyncio.run(cmd_get_log(args.lock_name))
        case "listen":
            try:
                asyncio.run(cmd_listen(args.lock_name))
            except KeyboardInterrupt:
                print("\nStopped.")
        case "reset":
            asyncio.run(cmd_reset(args.lock_name))


if __name__ == "__main__":
    main()

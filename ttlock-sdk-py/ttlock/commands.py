"""TTLock command payload builders and response parsers.

Each builder returns raw bytes to pass as *payload* to protocol.build_packet().
Each parser takes decrypted *payload* bytes from protocol.parse_packet().
"""

from __future__ import annotations
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

# ── Command type codes ────────────────────────────────────────────────────────

CMD_INITIALIZATION         = 0x45
CMD_GET_AES_KEY            = 0x19
CMD_ADD_ADMIN              = 0x56
CMD_CHECK_ADMIN            = 0x41
CMD_SET_ADMIN_KBD_PWD      = 0x53
CMD_UNLOCK                 = 0x47
CMD_LOCK                   = 0x4C
CMD_TIME_CALIBRATE         = 0x43
CMD_MANAGE_KBD_PASSWORD    = 0x03
CMD_GET_VALID_KBD_PASSWORD = 0x04
CMD_GET_OPERATE_LOG        = 0x25
CMD_CHECK_RANDOM           = 0x30
CMD_INIT_PASSWORDS         = 0x31
CMD_RESET_LOCK             = 0x52
CMD_SEARCH_DEVICE_FEATURE  = 0x01
CMD_IC_MANAGE              = 0x05
CMD_FR_MANAGE              = 0x06
CMD_PWD_LIST               = 0x07
CMD_SEARCH_STATUS          = 0x14
CMD_AUTO_LOCK_MANAGE       = 0x36
CMD_CONTROL_REMOTE_UNLOCK  = 0x37
CMD_READ_DEVICE_INFO       = 0x90
CMD_FUNCTION_LOCK          = 0x58
CMD_AUDIO_MANAGE           = 0x62
CMD_CONFIGURE_PASSAGE_MODE = 0x66
CMD_SWITCH                 = 0x68
CMD_OPERATE_FINISHED       = 0x57
CMD_CHECK_USER_TIME        = 0x55

# Password operation types (match JS SDK PwdOperateType)
PWD_OP_CLEAR  = 1
PWD_OP_ADD    = 2
PWD_OP_DELETE = 3
PWD_OP_MODIFY = 5

# Password types
PWD_TYPE_KEYBOARD = 1

# IC card / fingerprint operation types
IC_OP_SEARCH = 1
IC_OP_ADD    = 2
IC_OP_DELETE = 3
IC_OP_CLEAR  = 4
IC_OP_MODIFY = 5
FR_OP_SEARCH = 6

IC_STATUS_SUCCESS     = 1  # card/fp added successfully
IC_STATUS_ENTER_MODE  = 2  # entered add mode, waiting for scan
IC_STATUS_FR_PROGRESS = 3  # fingerprint scan in progress

# Audio manage operation types
AUDIO_QUERY  = 1
AUDIO_MODIFY = 2
AUDIO_OFF    = 0
AUDIO_ON     = 1

# Autolock operation types
AUTOLOCK_SEARCH = 1
AUTOLOCK_MODIFY = 2

# Switch operation types and config item constants (TTLockConfigType)
SWITCH_GET = 1
SWITCH_SET = 2
SWITCH_TAMPER_ALERT               = 1
SWITCH_RESET_BUTTON               = 2
SWITCH_PRIVACY_LOCK               = 4
SWITCH_LOCK_AND_UNLOCK            = 16
SWITCH_PASSAGE_MODE_AUTO_UNLOCK   = 32


# ── Response code ─────────────────────────────────────────────────────────────

RESP_SUCCESS = 0x01


def _check_response(payload: bytes, name: str) -> bytes:
    """Assert response code == 0x01 and return command-specific data."""
    if len(payload) < 2:
        raise ValueError(f"{name}: response too short ({len(payload)} bytes)")
    if payload[1] != RESP_SUCCESS:
        raise ValueError(f"{name}: lock returned error code {payload[1]:#x}")
    return payload[2:]


# ── Init / AES key exchange ───────────────────────────────────────────────────

def build_init() -> bytes:
    return b""


def build_get_aes_key() -> bytes:
    return b"SCIENER"


@dataclass
class AESKeyResponse:
    aes_key: bytes  # 16 bytes


def parse_get_aes_key(payload: bytes) -> AESKeyResponse:
    data = _check_response(payload, "GET_AES_KEY")
    if len(data) < 16:
        raise ValueError(f"AES key too short: {len(data)}")
    return AESKeyResponse(aes_key=bytes(data[:16]))


# ── Admin management ──────────────────────────────────────────────────────────

def build_add_admin(admin_ps: int, unlock_key: int) -> bytes:
    # adminPs(4B BE) + unlockKey(4B BE) + "SCIENER"
    return struct.pack(">II", admin_ps, unlock_key) + b"SCIENER"


def build_check_admin(admin_ps: int, lock_flag_pos: int, uid: int) -> bytes:
    # 11-byte overlapping layout (mirrors JS SDK write order):
    #   lockFlagPos written first at [3:7], then adminPs at [0:4] overwrites [3]
    #   so adminPs is fully preserved and lockFlagPos[1:4] occupy bytes [4:7].
    buf = bytearray(11)
    struct.pack_into(">I", buf, 3, lock_flag_pos)  # write first so adminPs wins at [3]
    struct.pack_into(">I", buf, 0, admin_ps)        # overwrites buf[3] with adminPs[3]
    struct.pack_into(">I", buf, 7, uid)
    return bytes(buf)


@dataclass
class CheckAdminResponse:
    ps_from_lock: int


def parse_check_admin(payload: bytes) -> CheckAdminResponse:
    data = _check_response(payload, "CHECK_ADMIN")
    if len(data) < 4:
        raise ValueError("CHECK_ADMIN response data too short")
    ps_from_lock = struct.unpack_from(">I", data, 0)[0]
    return CheckAdminResponse(ps_from_lock=ps_from_lock)


def build_check_random(ps_from_lock: int, unlock_key: int) -> bytes:
    return struct.pack(">I", ps_from_lock + unlock_key)


def build_reset_lock() -> bytes:
    return b""


# ── Passage mode ──────────────────────────────────────────────────────────────

_PASSAGE_OP_ADD   = 2
_PASSAGE_OP_CLEAR = 4
_PASSAGE_TYPE_WEEKLY = 1


def build_passage_mode_on() -> bytes:
    """Add an all-day every-day passage mode entry (lock stays open)."""
    # op=ADD, type=WEEKLY, weekOrDay=0(every day), month=0,
    # startHH=0, startMM=0, endHH=0, endMM=0  (0:0 means all day per SDK)
    return bytes([_PASSAGE_OP_ADD, _PASSAGE_TYPE_WEEKLY, 0, 0, 0, 0, 0, 0])


def build_passage_mode_off() -> bytes:
    """Clear all passage mode entries (normal autolock behaviour restored)."""
    return bytes([_PASSAGE_OP_CLEAR])


# ── User time check (gets ps_from_lock for unlock sum) ───────────────────────

def build_check_user_time() -> bytes:
    """17-byte payload: startDate(5) + endDate(5, overlapping) + lockFlagPos(4) + uid(4).

    Uses wide-open date range [Jan-31-2000 … Nov-30-2099] with uid=lockFlagPos=0
    (same defaults as the JS reference SDK).
    """
    data = bytearray(17)
    start = bytes([0, 1, 31, 14, 0])   # '0001311400' Jan-31-2000 14:00
    end   = bytes([99, 11, 30, 14, 0]) # '9911301400' Nov-30-2099 14:00
    # Mirror JS build order so the overlap is identical
    data[0:5] = start
    struct.pack_into(">I", data, 9, 0)  # lockFlagPos=0 (written before endDate)
    data[5:10] = end                    # endDate[4] overwrites lockFlagPos[0]
    struct.pack_into(">I", data, 13, 0) # uid=0
    return bytes(data)


@dataclass
class CheckUserTimeResponse:
    ps_from_lock: int


def parse_check_user_time(payload: bytes) -> CheckUserTimeResponse:
    data = _check_response(payload, "CHECK_USER_TIME")
    if len(data) < 4:
        raise ValueError("CHECK_USER_TIME response too short")
    ps_from_lock = struct.unpack_from(">I", data, 0)[0]
    return CheckUserTimeResponse(ps_from_lock=ps_from_lock)


# ── Unlock / Lock ─────────────────────────────────────────────────────────────

def build_unlock(ps_from_lock: int, unlock_key: int) -> bytes:
    """Build UNLOCK payload.  *ps_from_lock* comes from check_user_time()."""
    total = (ps_from_lock + unlock_key) & 0xFFFFFFFF
    ts = int(time.time()) & 0xFFFFFFFF
    return struct.pack(">II", total, ts)


@dataclass
class UnlockResponse:
    battery: int
    uid: int
    unique_id: int
    datetime: bytes  # 6 bytes: YY MM DD HH mm ss


def parse_unlock(payload: bytes) -> UnlockResponse:
    data = _check_response(payload, "UNLOCK")
    if len(data) < 15:
        raise ValueError(f"UNLOCK response too short: {len(data)}")
    battery   = data[0]
    uid       = struct.unpack_from(">I", data, 1)[0]
    unique_id = struct.unpack_from(">I", data, 5)[0]
    dt        = bytes(data[9:15])
    return UnlockResponse(battery=battery, uid=uid, unique_id=unique_id, datetime=dt)


def build_lock(admin_ps: int, unlock_key: int) -> bytes:
    return build_unlock(admin_ps, unlock_key)  # same layout


@dataclass
class LockResponse:
    battery: int
    uid: int
    unique_id: int
    datetime: bytes


def parse_lock(payload: bytes) -> LockResponse:
    r = parse_unlock(payload)
    return LockResponse(battery=r.battery, uid=r.uid, unique_id=r.unique_id, datetime=r.datetime)


# ── Time calibration ──────────────────────────────────────────────────────────

def build_calibrate_time() -> bytes:
    t = time.localtime()
    yy = t.tm_year % 100
    return bytes([yy, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec])


# ── Operation log ─────────────────────────────────────────────────────────────

def build_get_log(sequence: int = 0xFFFF) -> bytes:
    return struct.pack(">H", sequence)


@dataclass
class LogRecord:
    record_type: int
    date: bytes       # 6 bytes: YY MM DD HH mm ss
    battery: int
    data: bytes       # type-specific remaining bytes


@dataclass
class LogResponse:
    total_len: int
    sequence: int
    records: list[LogRecord]


def parse_get_log(payload: bytes) -> LogResponse:
    data = _check_response(payload, "GET_OPERATE_LOG")
    if len(data) < 4:
        raise ValueError("Log response too short")
    total_len = struct.unpack_from(">H", data, 0)[0]
    sequence  = struct.unpack_from(">H", data, 2)[0]
    records: list[LogRecord] = []
    idx = 4
    while idx < len(data):
        if idx >= len(data):
            break
        rec_len = data[idx]
        idx += 1
        if rec_len == 0 or idx + rec_len > len(data):
            break
        rec = data[idx: idx + rec_len]
        idx += rec_len
        if len(rec) < 8:
            continue
        record_type = rec[0]
        date        = bytes(rec[1:7])
        battery     = rec[7]
        extra       = bytes(rec[8:])
        records.append(LogRecord(record_type=record_type, date=date,
                                 battery=battery, data=extra))
    return LogResponse(total_len=total_len, sequence=sequence, records=records)


# ── Passcode management ───────────────────────────────────────────────────────

def _encode_date5(year: int, month: int, day: int, hour: int, minute: int) -> bytes:
    return bytes([year % 100, month, day, hour, minute])


def build_add_passcode(pwd: str, start: tuple | None = None,
                       end: tuple | None = None,
                       pwd_type: int = PWD_TYPE_KEYBOARD) -> bytes:
    pwd_bytes = pwd.encode()
    buf = bytes([PWD_OP_ADD, pwd_type, len(pwd_bytes)]) + pwd_bytes
    if start:
        buf += _encode_date5(*start)
    if end:
        buf += _encode_date5(*end)
    return buf


def build_delete_passcode(pwd: str, pwd_type: int = PWD_TYPE_KEYBOARD) -> bytes:
    pwd_bytes = pwd.encode()
    return bytes([PWD_OP_DELETE, pwd_type, len(pwd_bytes)]) + pwd_bytes


def build_modify_passcode(old_pwd: str, new_pwd: str,
                          start: tuple | None = None,
                          end: tuple | None = None,
                          pwd_type: int = PWD_TYPE_KEYBOARD) -> bytes:
    old_b = old_pwd.encode()
    new_b = new_pwd.encode()
    buf = bytes([PWD_OP_MODIFY, pwd_type, len(old_b)]) + old_b + bytes([len(new_b)]) + new_b
    if start:
        buf += _encode_date5(*start)
    if end:
        buf += _encode_date5(*end)
    return buf


def build_passcode_clear() -> bytes:
    return bytes([PWD_OP_CLEAR])


# ── Status ────────────────────────────────────────────────────────────────────

def build_status() -> bytes:
    return b"SCIENER"


@dataclass
class StatusResponse:
    locked: bool   # True = locked, False = unlocked
    battery: int


def parse_status(payload: bytes) -> StatusResponse:
    data = _check_response(payload, "SEARCH_STATUS")
    if len(data) < 2:
        raise ValueError("SEARCH_STATUS response too short")
    battery     = data[0]
    lock_status = data[1]   # 0 = locked, 1 = unlocked
    return StatusResponse(locked=(lock_status == 0), battery=battery)


# ── Autolock ──────────────────────────────────────────────────────────────────

def build_autolock_get() -> bytes:
    return bytes([AUTOLOCK_SEARCH])


def build_autolock_set(seconds: int) -> bytes:
    return bytes([AUTOLOCK_MODIFY, seconds >> 8, seconds & 0xFF])


@dataclass
class AutolockResponse:
    seconds: int
    battery: int


def parse_autolock(payload: bytes) -> AutolockResponse:
    data = _check_response(payload, "AUTO_LOCK")
    if len(data) < 4:
        raise ValueError("AUTO_LOCK response too short")
    battery = data[0]
    seconds = struct.unpack_from(">H", data, 2)[0]
    return AutolockResponse(seconds=seconds, battery=battery)


# ── Audio ─────────────────────────────────────────────────────────────────────

def build_audio_get() -> bytes:
    return bytes([AUDIO_QUERY])


def build_audio_set(on: bool) -> bytes:
    return bytes([AUDIO_MODIFY, AUDIO_ON if on else AUDIO_OFF])


@dataclass
class AudioResponse:
    on: bool
    battery: int


def parse_audio(payload: bytes) -> AudioResponse:
    data = _check_response(payload, "AUDIO_MANAGE")
    if len(data) < 2:
        raise ValueError("AUDIO_MANAGE response too short")
    battery = data[0]
    on      = (data[2] == AUDIO_ON) if len(data) > 2 else False
    return AudioResponse(on=on, battery=battery)


# ── Switch state (reset button, tamper alert, privacy lock, …) ───────────────

def build_switch_get() -> bytes:
    return bytes([SWITCH_GET])


def build_switch_set(config_item: int, enable: bool) -> bytes:
    """9-byte payload: [SET(1B), configItem(4B BE), enabled(4B BE)]."""
    return struct.pack(">BII", SWITCH_SET, config_item, 1 if enable else 0)


@dataclass
class SwitchResponse:
    enabled: bool
    battery: int


def parse_switch(payload: bytes, config_item: int) -> SwitchResponse:
    """Parse COMM_SWITCH response.  *config_item* is the SWITCH_* constant queried."""
    data = _check_response(payload, "COMM_SWITCH")
    if len(data) < 6:
        raise ValueError(f"COMM_SWITCH response too short ({len(data)} bytes)")
    battery      = data[0]
    switch_value = struct.unpack_from(">I", data, 2)[0]
    enabled      = bool(switch_value & config_item)
    return SwitchResponse(enabled=enabled, battery=battery)


# ── IC card management ────────────────────────────────────────────────────────

def build_ic_list(sequence: int = 0) -> bytes:
    return bytes([IC_OP_SEARCH, sequence >> 8, sequence & 0xFF])


def build_ic_add_start() -> bytes:
    return bytes([IC_OP_ADD])


def build_ic_clear() -> bytes:
    return bytes([IC_OP_CLEAR])


def _decode_date5(data: bytes, offset: int) -> str:
    yy, mm, dd, hh, mi = data[offset: offset + 5]
    return f"20{yy:02d}-{mm:02d}-{dd:02d} {hh:02d}:{mi:02d}"


@dataclass
class ICCard:
    number: str
    start: str
    end: str


@dataclass
class ICListResponse:
    sequence: int   # -1 = last page
    battery: int
    cards: list


def parse_ic_list(payload: bytes) -> ICListResponse:
    data = _check_response(payload, "IC_LIST")
    if len(data) < 4:
        raise ValueError("IC_LIST response too short")
    battery  = data[0]
    sequence = struct.unpack_from(">h", data, 2)[0]  # signed int16
    cards: list[ICCard] = []
    idx = 4
    while idx < len(data):
        remaining = len(data) - idx
        # 8-byte card if remaining bytes leave room; JS heuristic: length==24 → 8-byte
        if len(data) == 24 or remaining == 18:
            if idx + 18 > len(data):
                break
            number = str(struct.unpack_from(">Q", data, idx)[0])
            idx += 8
        else:
            if idx + 14 > len(data):
                break
            number = str(struct.unpack_from(">I", data, idx)[0])
            idx += 4
        start = _decode_date5(data, idx); idx += 5
        end   = _decode_date5(data, idx); idx += 5
        cards.append(ICCard(number=number, start=start, end=end))
    return ICListResponse(sequence=sequence, battery=battery, cards=cards)


@dataclass
class ICAddResponse:
    status: int     # IC_STATUS_ENTER_MODE or IC_STATUS_SUCCESS
    number: str     # populated on IC_STATUS_SUCCESS
    battery: int


def parse_ic_add_response(payload: bytes) -> ICAddResponse:
    data = _check_response(payload, "IC_ADD")
    if len(data) < 3:
        raise ValueError("IC_ADD response too short")
    battery = data[0]
    status  = data[2]
    number  = ""
    if status == IC_STATUS_SUCCESS:
        tail = len(data) - 3
        if tail == 8:
            number = str(struct.unpack_from(">Q", data, 3)[0])
        elif tail >= 4:
            number = str(struct.unpack_from(">I", data, 3)[0])
    return ICAddResponse(status=status, number=number, battery=battery)


# ── Fingerprint management ────────────────────────────────────────────────────

def build_fr_list(sequence: int = 0) -> bytes:
    return bytes([FR_OP_SEARCH, sequence >> 8, sequence & 0xFF])


def build_fr_add_start() -> bytes:
    return bytes([IC_OP_ADD])


def build_fr_clear() -> bytes:
    return bytes([IC_OP_CLEAR])


@dataclass
class Fingerprint:
    number: str
    start: str
    end: str


@dataclass
class FRListResponse:
    sequence: int
    battery: int
    fingerprints: list


def parse_fr_list(payload: bytes) -> FRListResponse:
    data = _check_response(payload, "FR_LIST")
    if len(data) < 4:
        raise ValueError("FR_LIST response too short")
    battery  = data[0]
    sequence = struct.unpack_from(">h", data, 2)[0]
    fps: list[Fingerprint] = []
    idx = 4
    while idx + 16 <= len(data):
        fp_bytes = b'\x00\x00' + bytes(data[idx: idx + 6])
        number = str(struct.unpack(">q", fp_bytes)[0])
        idx += 6
        start = _decode_date5(data, idx); idx += 5
        end   = _decode_date5(data, idx); idx += 5
        fps.append(Fingerprint(number=number, start=start, end=end))
    return FRListResponse(sequence=sequence, battery=battery, fingerprints=fps)


@dataclass
class FRAddResponse:
    status: int     # IC_STATUS_ENTER_MODE, IC_STATUS_FR_PROGRESS, or IC_STATUS_SUCCESS
    number: str     # populated on IC_STATUS_SUCCESS
    battery: int


def parse_fr_add_response(payload: bytes) -> FRAddResponse:
    data = _check_response(payload, "FR_ADD")
    if len(data) < 3:
        raise ValueError("FR_ADD response too short")
    battery = data[0]
    status  = data[2]
    number  = ""
    if status == IC_STATUS_SUCCESS and len(data) >= 9:
        fp_bytes = b'\x00\x00' + bytes(data[3:9])
        number = str(struct.unpack(">q", fp_bytes)[0])
    return FRAddResponse(status=status, number=number, battery=battery)


# ── Passcode list ─────────────────────────────────────────────────────────────

def build_passcode_list(sequence: int = 0) -> bytes:
    return struct.pack(">H", sequence)


@dataclass
class Passcode:
    pwd_type: int
    passcode: str
    new_passcode: str
    start: str
    end: str


@dataclass
class PasscodeListResponse:
    sequence: int
    passcodes: list


def parse_passcode_list(payload: bytes) -> PasscodeListResponse:
    data = _check_response(payload, "PWD_LIST")
    if len(data) < 2:
        raise ValueError("PWD_LIST response too short")
    total_len = struct.unpack_from(">H", data, 0)[0]
    if total_len == 0:
        return PasscodeListResponse(sequence=-1, passcodes=[])
    sequence  = struct.unpack_from(">h", data, 2)[0]
    passcodes: list[Passcode] = []
    idx = 4
    while idx < len(data):
        entry_len = data[idx]; idx += 1
        entry_end = idx + entry_len - 1  # -1 because entry_len counts from the type byte
        if idx >= len(data):
            break
        pwd_type = data[idx]; idx += 1
        new_len  = data[idx]; idx += 1
        new_pwd  = data[idx: idx + new_len].decode(errors="replace"); idx += new_len
        pwd_len  = data[idx]; idx += 1
        pwd      = data[idx: idx + pwd_len].decode(errors="replace"); idx += pwd_len
        start    = _decode_date5(data, idx); idx += 5
        end      = ""
        # Limited-time types have an end date
        if idx + 5 <= len(data) and idx < entry_end:
            end = _decode_date5(data, idx); idx += 5
        passcodes.append(Passcode(pwd_type=pwd_type, passcode=pwd, new_passcode=new_pwd,
                                  start=start, end=end))
    return PasscodeListResponse(sequence=sequence, passcodes=passcodes)


# ── Passage mode list ─────────────────────────────────────────────────────────

_PASSAGE_OP_QUERY = 1


def build_passage_mode_list(sequence: int = 0) -> bytes:
    return bytes([_PASSAGE_OP_QUERY, sequence])


@dataclass
class PassageModeEntry:
    type: int         # 1=weekly, 2=monthly
    week_or_day: int  # 0=every day, 1-7=Mon-Sun (weekly) or day-of-month (monthly)
    month: int
    start: str        # "HH:MM"
    end: str          # "HH:MM"


@dataclass
class PassageModeListResponse:
    sequence: int     # -1 or 255 = last page
    battery: int
    entries: list


def parse_passage_mode_list(payload: bytes) -> PassageModeListResponse:
    data = _check_response(payload, "PASSAGE_MODE_LIST")
    if len(data) < 3:
        return PassageModeListResponse(sequence=-1, battery=0, entries=[])
    battery  = data[0]
    sequence = struct.unpack_from("b", data, 2)[0]  # signed int8; -1 = last page
    entries: list[PassageModeEntry] = []
    idx = 3
    while idx + 7 <= len(data):
        entries.append(PassageModeEntry(
            type        = data[idx],
            week_or_day = data[idx + 1],
            month       = data[idx + 2],
            start       = f"{data[idx + 3]:02d}:{data[idx + 4]:02d}",
            end         = f"{data[idx + 5]:02d}:{data[idx + 6]:02d}",
        ))
        idx += 7
    return PassageModeListResponse(sequence=sequence, battery=battery, entries=entries)

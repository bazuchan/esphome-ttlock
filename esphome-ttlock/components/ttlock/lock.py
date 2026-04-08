"""ESPHome TTLock lock platform."""
import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.components import esp32_ble_client, esp32_ble_tracker, lock, sensor, switch
from esphome.components.ttlock import ttlock_ns
from esphome.const import (
    CONF_ID,
    PLATFORM_ESP32,
    UNIT_PERCENT,
    DEVICE_CLASS_BATTERY,
    STATE_CLASS_MEASUREMENT,
    ENTITY_CATEGORY_DIAGNOSTIC,
)

CODEOWNERS = ["@you"]
DEPENDENCIES = ["esp32_ble_tracker"]
AUTO_LOAD = ["esp32_ble_client", "sensor", "switch"]
ESP_PLATFORMS = [PLATFORM_ESP32]

TTLockLock = ttlock_ns.class_(
    "TTLockLock", lock.Lock, esp32_ble_client.BLEClientBase
)
TTLockPassageSwitch = ttlock_ns.class_(
    "TTLockPassageSwitch", switch.Switch, cg.Component
)

CONF_ADDRESS    = "address"
CONF_ADMIN_PS    = "admin_ps"
CONF_UNLOCK_KEY  = "unlock_key"
CONF_AES_KEY     = "aes_key"
CONF_PROTO_TYPE  = "protocol_type"
CONF_PROTO_VER   = "protocol_version"
CONF_SCENE       = "scene"
CONF_GROUP_ID    = "group_id"
CONF_ORG_ID      = "org_id"
CONF_BATTERY     = "battery_level"
CONF_PASSAGE     = "passage_mode"
CONF_POLLING     = "polling"


def _validate_aes_key(value):
    """Accept a 32-hex-char string (16 bytes), optionally space-separated."""
    value = cv.string(value).replace(" ", "").lower()
    if len(value) != 32:
        raise cv.Invalid("aes_key must be exactly 32 hex characters (16 bytes)")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise cv.Invalid(f"aes_key is not valid hex: {exc}") from exc
    return value


CONFIG_SCHEMA = cv.All(
    cv.Schema(
        {
            cv.GenerateID(): cv.declare_id(TTLockLock),

            # ── BLE address (replaces ble_client_id) ─────────────────────────
            cv.Required(CONF_ADDRESS): cv.mac_address,

            # ── Credentials (required) ────────────────────────────────────────
            cv.Required(CONF_ADMIN_PS):   cv.int_range(min=1, max=0x7FFFFFFF),
            cv.Required(CONF_UNLOCK_KEY): cv.int_range(min=1, max=0x7FFFFFFF),
            cv.Required(CONF_AES_KEY):    _validate_aes_key,

            # ── Protocol version ──────────────────────────────────────────────
            cv.Optional(CONF_PROTO_TYPE, default=0x05): cv.hex_uint8_t,
            cv.Optional(CONF_PROTO_VER,  default=0x03): cv.hex_uint8_t,
            cv.Optional(CONF_SCENE,      default=0x02): cv.hex_uint8_t,
            cv.Optional(CONF_GROUP_ID,   default=0x0000): cv.uint16_t,
            cv.Optional(CONF_ORG_ID,     default=0x0000): cv.uint16_t,

            # ── Polling ───────────────────────────────────────────────────────
            cv.Optional(CONF_POLLING, default=True): cv.boolean,

            # ── Optional sensors / switches ───────────────────────────────────
            cv.Optional(CONF_BATTERY): sensor.sensor_schema(
                unit_of_measurement=UNIT_PERCENT,
                device_class=DEVICE_CLASS_BATTERY,
                state_class=STATE_CLASS_MEASUREMENT,
                entity_category=ENTITY_CATEGORY_DIAGNOSTIC,
                accuracy_decimals=0,
            ),
            cv.Optional(CONF_PASSAGE): switch.switch_schema(
                TTLockPassageSwitch,
            ),
        }
    )
    .extend(cv.ENTITY_BASE_SCHEMA)
    .extend(esp32_ble_tracker.ESP_BLE_DEVICE_SCHEMA)
    .extend(cv.COMPONENT_SCHEMA),
)


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    await lock.register_lock(var, config)
    await esp32_ble_tracker.register_client(var, config)

    cg.add(var.set_address(config[CONF_ADDRESS].as_hex))
    cg.add(var.set_admin_ps(config[CONF_ADMIN_PS]))
    cg.add(var.set_unlock_key(config[CONF_UNLOCK_KEY]))
    cg.add(var.set_aes_key(list(bytes.fromhex(config[CONF_AES_KEY]))))

    cg.add(var.set_polling(config[CONF_POLLING]))
    cg.add(var.set_proto_type(config[CONF_PROTO_TYPE]))
    cg.add(var.set_proto_ver(config[CONF_PROTO_VER]))
    cg.add(var.set_scene(config[CONF_SCENE]))
    cg.add(var.set_group_id(config[CONF_GROUP_ID]))
    cg.add(var.set_org_id(config[CONF_ORG_ID]))

    if CONF_BATTERY in config:
        bat = await sensor.new_sensor(config[CONF_BATTERY])
        cg.add(var.set_battery_sensor(bat))

    if CONF_PASSAGE in config:
        sw = await switch.new_switch(config[CONF_PASSAGE])
        await cg.register_component(sw, config[CONF_PASSAGE])
        cg.add(sw.set_lock(var))
        cg.add(var.set_passage_switch(sw))

#pragma once

#include "esphome/core/component.h"
#include "esphome/components/esp32_ble_client/ble_client_base.h"
#include "esphome/components/lock/lock.h"
#include "esphome/components/sensor/sensor.h"
#include "esphome/components/switch/switch.h"

#include <esp_gattc_api.h>
#include <esp_gap_ble_api.h>

#include <cstdint>
#include <string>
#include <vector>

namespace esphome {
namespace ttlock {

namespace espbt = esphome::esp32_ble_tracker;
namespace ble_client = esphome::esp32_ble_client;

// ── BLE UUIDs ──────────────────────────────────────────────────────────────
static constexpr uint16_t SERVICE_UUID  = 0x1910;
static constexpr uint16_t WRITE_UUID    = 0xFFF2;  // App → Lock
static constexpr uint16_t NOTIFY_UUID   = 0xFFF4;  // Lock → App

// ── Transport constants ─────────────────────────────────────────────────────
static constexpr uint16_t MTU_SIZE = 20;  // max bytes per BLE write chunk

// ── Packet layout (proto_type >= 5 / V3) ───────────────────────────────────
// [0x7F][0x5A][proto_type][proto_ver][scene][group_hi][group_lo][org_hi][org_lo]
// [cmd][0xAA][enc_len][enc_data…][crc8] ++ [0x0D][0x0A]
static constexpr uint8_t PKT_HDR0     = 0x7F;
static constexpr uint8_t PKT_HDR1     = 0x5A;
static constexpr uint8_t PKT_APP_ENC  = 0xAA;
static constexpr uint8_t PKT_CRLF0    = 0x0D;
static constexpr uint8_t PKT_CRLF1    = 0x0A;
static constexpr size_t  PKT_OVERHEAD  = 13;  // header through enc_len field + CRC

// ── Command types ───────────────────────────────────────────────────────────
static constexpr uint8_t CMD_GET_STATUS          = 0x14;  // query current locked state
static constexpr uint8_t CMD_CHECK_ADMIN         = 0x41;  // 'A'
static constexpr uint8_t CMD_CHECK_RANDOM        = 0x30;
static constexpr uint8_t CMD_UNLOCK              = 0x47;  // COMM_UNLOCK
static constexpr uint8_t CMD_LOCK                = 0x58;  // COMM_FUNCTION_LOCK
static constexpr uint8_t CMD_CONFIGURE_PASSAGE   = 0x66;  // COMM_CONFIGURE_PASSAGE_MODE

// ── Lock version (from YAML config) ─────────────────────────────────────────
struct LockVersion {
    uint8_t  proto_type{0x05};
    uint8_t  proto_ver {0x03};
    uint8_t  scene     {0x02};
    uint16_t group_id  {0x0000};
    uint16_t org_id    {0x0000};
};

// ─────────────────────────────────────────────────────────────────────────────

// Passage mode switch: turns the lock into an always-open (passage) mode.
// ON  → lock is unlocked and stays unlocked until switched off.
// OFF → lock is locked.
class TTLockPassageSwitch : public switch_::Switch, public Component {
 public:
  void set_lock(class TTLockLock *lock) { lock_ = lock; }
  float get_setup_priority() const override { return setup_priority::DATA; }
 protected:
  void write_state(bool state) override;
  TTLockLock *lock_{nullptr};
};

class TTLockLock : public lock::Lock,
                   public ble_client::BLEClientBase {
 public:
  // ── ESPHome Component ──────────────────────────────────────────────────
  void setup() override;
  void dump_config() override;
  float get_setup_priority() const override { return setup_priority::DATA; }

  // ── BLEClientBase ──────────────────────────────────────────────────────
  bool gattc_event_handler(esp_gattc_cb_event_t event,
                           esp_gatt_if_t        gattc_if,
                           esp_ble_gattc_cb_param_t *param) override;

  // ── ESPBTDeviceListener ────────────────────────────────────────────────
  bool parse_device(const espbt::ESPBTDevice &device) override;

  // ── lock::Lock ─────────────────────────────────────────────────────────
  void control(const lock::LockCall &call) override;

  // ── Configuration setters (called from Python to_code) ─────────────────
  void set_admin_ps(uint32_t v)   { admin_ps_   = v; }
  void set_unlock_key(uint32_t v) { unlock_key_ = v; }
  void set_aes_key(const std::vector<uint8_t> &key) {
    memcpy(aes_key_, key.data(), 16);
  }
  void set_proto_type(uint8_t v)  { lv_.proto_type = v; }
  void set_proto_ver(uint8_t v)   { lv_.proto_ver  = v; }
  void set_scene(uint8_t v)       { lv_.scene      = v; }
  void set_group_id(uint16_t v)   { lv_.group_id   = v; }
  void set_org_id(uint16_t v)     { lv_.org_id     = v; }
  void set_battery_sensor(sensor::Sensor *s) { battery_sensor_ = s; }
  void set_passage_switch(TTLockPassageSwitch *s) { passage_switch_ = s; }

  // Called by TTLockPassageSwitch
  void set_passage_mode(bool enable);

  // Trigger a status + passage mode update. Safe to call from a lambda.
  void request_update();

 protected:
  // ── State machine ──────────────────────────────────────────────────────
  enum class OpState : uint8_t {
    IDLE,
    QUERY_STATUS,        // querying lock state on connect
    CHECK_ADMIN,
    CHECK_RANDOM,
    QUERY_PASSAGE_CMD,   // 0x66 QUERY → read passage mode from lock
    PASSAGE_CLEAR_CMD,   // 0x66 CLEAR
    PASSAGE_ON_CMD,      // 0x66 ADD all-day schedule → then UNLOCK
    PASSAGE_OFF_CMD,     // 0x66 CLEAR → then LOCK
    UNLOCK_CMD,
    LOCK_CMD,
  };

  // ── BLE characteristic handles ─────────────────────────────────────────
  uint16_t write_handle_  {0};
  uint16_t notify_handle_ {0};

  // ── Credentials (from YAML) ────────────────────────────────────────────
  uint32_t    admin_ps_   {0};
  uint32_t    unlock_key_ {0};
  uint8_t     aes_key_[16]{};
  LockVersion lv_;

  // ── Operation state ────────────────────────────────────────────────────
  OpState  op_state_             {OpState::IDLE};
  bool     pending_unlock_       {false};
  bool     pending_lock_         {false};
  bool     pending_passage_on_   {false};
  bool     pending_passage_off_  {false};
  bool     passage_mode_         {false};
  bool     last_status_unlocked_ {false};
  uint8_t  last_adv_params_      {0xFF};  // cached advertisement params; 0xFF = never seen
  uint32_t ps_from_lock_         {0};

  // ── RX buffer (reassembly across MTU chunks) ───────────────────────────
  std::vector<uint8_t> rx_buf_;

  // ── Optional sensors / switches ────────────────────────────────────────
  sensor::Sensor       *battery_sensor_{nullptr};
  TTLockPassageSwitch  *passage_switch_{nullptr};

  // ── Protocol helpers ───────────────────────────────────────────────────
  static uint8_t crc8_(const uint8_t *data, size_t len);
  static size_t  aes_encrypt_(const uint8_t *in,  size_t in_len,
                               const uint8_t *key, uint8_t *out);
  static size_t  aes_decrypt_(const uint8_t *in,  size_t in_len,
                               const uint8_t *key, uint8_t *out);
  void           send_cmd_(uint8_t cmd, const uint8_t *payload, size_t payload_len);
  bool           parse_pkt_(const uint8_t *raw, size_t len,
                             uint8_t &cmd_out, std::vector<uint8_t> &data_out);

  // ── Data flow ──────────────────────────────────────────────────────────
  void on_ble_data_(const uint8_t *data, uint16_t len);
  void handle_response_(uint8_t cmd, const std::vector<uint8_t> &payload);

  // ── Lock/unlock sequence ───────────────────────────────────────────────
  void start_pending_();
  void do_query_status_();
  void do_check_admin_();
  void do_check_random_();
  void do_query_passage_();
  void do_passage_clear_();
  void do_passage_on_();
  void do_passage_off_();
  void do_unlock_();
  void do_lock_();
};

}  // namespace ttlock
}  // namespace esphome

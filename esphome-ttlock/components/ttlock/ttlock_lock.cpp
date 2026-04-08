#include "ttlock_lock.h"
#include "esphome/core/log.h"
#include "esphome/core/application.h"

#include "esp_system.h"
#include "esp_gattc_api.h"
#include "aes/esp_aes.h"

#include <cstring>
#include <ctime>
#include <algorithm>

namespace esphome {
namespace ttlock {

static const char *const TAG = "ttlock";

// ── CRC-8 Dallas / Maxim ────────────────────────────────────────────────────

static const uint8_t DSCRC[256] = {
      0,  94, 188, 226,  97,  63, 221, 131, 194, 156, 126,  32, 163, 253,  31,  65,
    157, 195,  33, 127, 252, 162,  64,  30,  95,   1, 227, 189,  62,  96, 130, 220,
     35,   7, 159, 193,  66,  28, 254, 160, 225, 191,  93,   3, 128, 222,  60,  98,
    190, 224,   2,  92, 223, 129,  99,  61, 124,  34, 192, 158,  29,  67, 161, 255,
     70,  24, 250, 164,  39, 121, 155, 197, 132, 218,  56, 102, 229, 187,  89,   7,
    219, 133, 103,  57, 186, 228,   6,  88,  25,  71, 165, 251, 120,  38, 196, 154,
    101,  59, 217, 135,   4,  90, 184, 230, 167, 249,  27,  69, 198, 152, 122,  36,
    248, 166,  68,  26, 153, 199,  37, 123,  58, 100, 134, 216,  91,   5, 231, 185,
    140, 210,  48, 110, 237, 179,  81,  15,  78,  16, 242, 172,  47, 113, 147, 205,
     17,  79, 173, 243, 112,  46, 204, 146, 211, 141, 111,  49, 178, 236,  14,  80,
    175, 241,  19,  77, 206, 144, 114,  44, 109,  51, 209, 143,  12,  82, 176, 238,
     50, 108, 142, 208,  83,  13, 239, 177, 240, 174,  76,  18, 145, 207,  45, 115,
    202, 148, 118,  40, 171, 245,  23,  73,   8,  86, 180, 234, 105,  55, 213, 139,
     87,   9, 235, 181,  54, 104, 138, 212, 149, 203,  41, 119, 244, 170,  72,  22,
    233, 183,  85,  11, 136, 214,  52, 106,  43, 117, 151, 201,  74,  20, 246, 168,
    116,  42, 200, 150,  21,  75, 169, 247, 182, 232,  10,  84, 215, 137, 107,  53,
};

uint8_t TTLockLock::crc8_(const uint8_t *data, size_t len) {
  uint8_t crc = 0;
  for (size_t i = 0; i < len; i++)
    crc = DSCRC[crc ^ data[i]];
  return crc;
}

// ── AES-128-CBC  (IV == key, PKCS7 padding) ─────────────────────────────────

size_t TTLockLock::aes_encrypt_(const uint8_t *in, size_t in_len,
                                  const uint8_t *key, uint8_t *out) {
  if (in_len == 0) return 0;

  // PKCS7: pad to next 16-byte boundary (always 1–16 bytes of padding)
  uint8_t pad   = 16 - (in_len % 16);
  size_t  total = in_len + pad;

  uint8_t buf[total];
  memcpy(buf, in, in_len);
  memset(buf + in_len, pad, pad);

  // IV == key (TTLock protocol)
  uint8_t iv[16];
  memcpy(iv, key, 16);

  esp_aes_context ctx;
  esp_aes_init(&ctx);
  esp_aes_setkey(&ctx, key, 128);
  esp_aes_crypt_cbc(&ctx, ESP_AES_ENCRYPT, total, iv, buf, out);
  esp_aes_free(&ctx);

  return total;
}

size_t TTLockLock::aes_decrypt_(const uint8_t *in, size_t in_len,
                                  const uint8_t *key, uint8_t *out) {
  if (in_len == 0 || (in_len % 16) != 0) return 0;

  // IV == key (TTLock protocol)
  uint8_t iv[16];
  memcpy(iv, key, 16);

  esp_aes_context ctx;
  esp_aes_init(&ctx);
  esp_aes_setkey(&ctx, key, 128);
  esp_aes_crypt_cbc(&ctx, ESP_AES_DECRYPT, in_len, iv, in, out);
  esp_aes_free(&ctx);

  // Strip PKCS7 padding
  uint8_t p = out[in_len - 1];
  if (p == 0 || p > 16) return in_len;
  return in_len - p;
}

// ── Packet builder ───────────────────────────────────────────────────────────

void TTLockLock::send_cmd_(uint8_t cmd, const uint8_t *payload, size_t payload_len) {
  // Encrypt payload  (max plaintext we ever send is ~15 bytes → 16 bytes cipher)
  uint8_t enc[128];
  size_t  enc_len = 0;
  if (payload_len > 0) {
    enc_len = aes_encrypt_(payload, payload_len, aes_key_, enc);
  }

  // Build packet:
  // [7F][5A][pt][pv][sc][ghi][glo][ohi][olo][cmd][AA][len][…enc…][crc][0D][0A]
  uint8_t pkt[256];
  size_t  n = 0;
  pkt[n++] = PKT_HDR0;
  pkt[n++] = PKT_HDR1;
  pkt[n++] = lv_.proto_type;
  pkt[n++] = lv_.proto_ver;
  pkt[n++] = lv_.scene;
  pkt[n++] = (lv_.group_id >> 8) & 0xFF;
  pkt[n++] = lv_.group_id & 0xFF;
  pkt[n++] = (lv_.org_id >> 8) & 0xFF;
  pkt[n++] = lv_.org_id & 0xFF;
  pkt[n++] = cmd;
  pkt[n++] = PKT_APP_ENC;
  pkt[n++] = (uint8_t) enc_len;
  memcpy(pkt + n, enc, enc_len);
  n += enc_len;
  pkt[n++] = crc8_(pkt, n);   // CRC of everything up to here
  pkt[n++] = PKT_CRLF0;
  pkt[n++] = PKT_CRLF1;

  ESP_LOGV(TAG, "TX cmd=0x%02X total=%d enc=%d", cmd, n, enc_len);

  // Write in MTU_SIZE chunks with response confirmation
  for (size_t off = 0; off < n; off += MTU_SIZE) {
    size_t chunk = std::min((size_t) MTU_SIZE, n - off);
    esp_err_t err = esp_ble_gattc_write_char(
        this->get_gattc_if(),
        this->get_conn_id(),
        write_handle_,
        (uint16_t) chunk,
        pkt + off,
        ESP_GATT_WRITE_TYPE_RSP,
        ESP_GATT_AUTH_REQ_NONE);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "gattc_write_char failed: %s", esp_err_to_name(err));
      return;
    }
  }
}

// ── Packet parser ─────────────────────────────────────────────────────────────

bool TTLockLock::parse_pkt_(const uint8_t *raw, size_t len,
                              uint8_t &cmd_out, std::vector<uint8_t> &data_out) {
  if (len < PKT_OVERHEAD) {
    ESP_LOGW(TAG, "Packet too short: %d", len);
    return false;
  }
  if (raw[0] != PKT_HDR0 || raw[1] != PKT_HDR1) {
    ESP_LOGW(TAG, "Bad header: %02X %02X", raw[0], raw[1]);
    return false;
  }

  cmd_out = raw[9];
  uint8_t enc_len = raw[11];

  if (len < (size_t)(PKT_OVERHEAD + enc_len)) {
    ESP_LOGW(TAG, "Truncated packet: need %d got %d", PKT_OVERHEAD + enc_len, len);
    return false;
  }

  // Verify CRC (covers bytes 0 … 11+enc_len, i.e. up to but not including CRC byte)
  // NOTE: TTLock firmware frequently sends intentionally wrong CRC values in
  // responses (confirmed by JS SDK analysis – it retries and accepts bad CRC if
  // consistent). We log the mismatch but continue processing the packet.
  size_t  body_end = 12 + enc_len;
  uint8_t expected = crc8_(raw, body_end);
  if (raw[body_end] != expected) {
    ESP_LOGW(TAG, "CRC mismatch: got 0x%02X expected 0x%02X (continuing – TTLock quirk)",
             raw[body_end], expected);
  }

  // Decrypt payload
  if (enc_len > 0) {
    uint8_t dec[enc_len + 16];
    size_t  dec_len = aes_decrypt_(raw + 12, enc_len, aes_key_, dec);
    data_out.assign(dec, dec + dec_len);
  }

  return true;
}

// ── BLE event handler ────────────────────────────────────────────────────────

bool TTLockLock::gattc_event_handler(esp_gattc_cb_event_t     event,
                                      esp_gatt_if_t            gattc_if,
                                      esp_ble_gattc_cb_param_t *param) {
  // Chain to BLEClientBase first: it handles app_id/gattc_if filtering,
  // stores gattc_if_/conn_id_, manages state transitions, service discovery,
  // and CCCD descriptor writes.  Returns false if the event is not ours.
  if (!ble_client::BLEClientBase::gattc_event_handler(event, gattc_if, param))
    return false;

  switch (event) {

    // ── App registration: base stored gattc_if_; schedule connect ───────────
    case ESP_GATTC_REG_EVT:
      if (param->reg.status != ESP_GATT_OK) break;  // base already logged
      ESP_LOGI(TAG, "GATTC registered (if=%d), scheduling connect", this->get_gattc_if());
      this->run_later([this]() { this->connect(); });
      break;

    // ── Service discovery complete: look up characteristic handles ───────────
    case ESP_GATTC_SEARCH_CMPL_EVT: {
      if (param->search_cmpl.status != ESP_GATT_OK) {
        ESP_LOGE(TAG, "Service search failed: %d", param->search_cmpl.status);
        this->disconnect();
        break;
      }
      auto *chr_write  = this->get_characteristic(SERVICE_UUID, WRITE_UUID);
      auto *chr_notify = this->get_characteristic(SERVICE_UUID, NOTIFY_UUID);
      if (!chr_write || !chr_notify) {
        ESP_LOGE(TAG, "TTLock service/characteristics missing – is this a TTLock?");
        this->disconnect();
        break;
      }
      write_handle_  = chr_write->handle;
      notify_handle_ = chr_notify->handle;
      ESP_LOGD(TAG, "Handles write=0x%04X notify=0x%04X", write_handle_, notify_handle_);
      // Register for notifications on FFF4; base will write CCCD descriptor.
      esp_err_t err = esp_ble_gattc_register_for_notify(
          this->get_gattc_if(), this->get_remote_bda(), notify_handle_);
      if (err != ESP_OK)
        ESP_LOGE(TAG, "register_for_notify failed: %s", esp_err_to_name(err));
      break;
    }

    // ── Notify subscription confirmed: start protocol ────────────────────────
    case ESP_GATTC_REG_FOR_NOTIFY_EVT:
      if (param->reg_for_notify.status == ESP_GATT_OK) {
        ESP_LOGI(TAG, "BLE ready");
        start_pending_();
      } else {
        ESP_LOGE(TAG, "register_for_notify status=%d", param->reg_for_notify.status);
        this->disconnect();
      }
      break;

    // ── Incoming notification: feed to protocol parser ───────────────────────
    case ESP_GATTC_NOTIFY_EVT:
      if (param->notify.handle == notify_handle_)
        on_ble_data_(param->notify.value, param->notify.value_len);
      break;

    // ── Connection failed: OPEN_EVT with error status ────────────────────────
    // Base already called set_idle_(); CLOSE_EVT will NOT follow in this case.
    case ESP_GATTC_OPEN_EVT:
      if (param->open.status != ESP_GATT_OK && param->open.status != ESP_GATT_ALREADY_OPEN)
        schedule_reconnect_();
      break;

    // ── Disconnected: reset protocol state; wait for CLOSE_EVT to reconnect ──
    case ESP_GATTC_DISCONNECT_EVT:
      // Do NOT publish UNKNOWN – keep the last known state (LOCKED/UNLOCKED).
      // The lock disconnects after each operation; showing UNKNOWN on every
      // disconnect causes confusing state flicker in HA.
      write_handle_  = 0;
      notify_handle_ = 0;
      op_state_      = OpState::IDLE;
      auto_unlock_   = false;
      rx_buf_.clear();
      break;

    // ── Connection fully closed: schedule fast reconnect ────────────────────
    case ESP_GATTC_CLOSE_EVT:
      schedule_reconnect_();
      break;

    default:
      break;
  }
  return true;
}

void TTLockLock::schedule_reconnect_() {
  if (!polling_) {
    bool has_work = pending_unlock_ || pending_lock_ ||
                    pending_passage_on_ || pending_passage_off_ ||
                    pending_status_query_;
    if (!has_work) {
      ESP_LOGD(TAG, "Polling disabled, no pending work – not reconnecting");
      return;
    }
  }
  // Short delay before reconnect so the lock has time to close its side.
  ESP_LOGD(TAG, "Scheduling reconnect in 500 ms");
  this->set_timeout("reconnect", 500, [this]() {
    auto st = espbt::ESPBTClient::state();
    ESP_LOGD(TAG, "Reconnect timeout fired, state=%d", (int) st);
    if (st == espbt::ClientState::IDLE)
      this->connect();
  });
}

// ── Data reception  (reassemble MTU chunks → complete frame) ─────────────────

void TTLockLock::on_ble_data_(const uint8_t *data, uint16_t len) {
  rx_buf_.insert(rx_buf_.end(), data, data + len);

  // Use length-based framing: the enc_len field (byte 11) determines the total
  // packet size. Do NOT search for CRLF as a delimiter — 0x0D 0x0A can appear
  // inside the ciphertext, causing false splits (confirmed from TTLock JS SDK).
  for (;;) {
    // Skip bytes until we find the 0x7F 0x5A header
    while (rx_buf_.size() >= 2 &&
           (rx_buf_[0] != PKT_HDR0 || rx_buf_[1] != PKT_HDR1)) {
      rx_buf_.erase(rx_buf_.begin());
    }
    if (rx_buf_.size() < PKT_OVERHEAD) break;  // need at least 13 bytes to read enc_len

    uint8_t enc_len = rx_buf_[11];
    // total = 12 header bytes + enc_len encrypted bytes + 1 CRC byte + 2 CRLF
    size_t total = 12 + enc_len + 1 + 2;
    if (rx_buf_.size() < total) break;

    // Parse the frame: pass byte count up to and including the CRC byte
    uint8_t cmd;
    std::vector<uint8_t> payload;
    if (parse_pkt_(rx_buf_.data(), 12 + (size_t)enc_len + 1, cmd, payload))
      handle_response_(cmd, payload);

    rx_buf_.erase(rx_buf_.begin(), rx_buf_.begin() + total);
  }

  // Guard against runaway buffer growth (e.g. lock sends garbage)
  if (rx_buf_.size() > 512) {
    ESP_LOGW(TAG, "RX buffer overflow, clearing");
    rx_buf_.clear();
  }
}

// ── Response dispatcher ──────────────────────────────────────────────────────

void TTLockLock::handle_response_(uint8_t raw_cmd, const std::vector<uint8_t> &data) {
  // TTLock responses use COMM_RESPONSE (0x54) as the packet header cmd byte.
  // The actual command type is data[0]; response status is data[1]; payload starts at data[2].
  // (JS SDK: commandFromData reads commandType = decryptedData[0])
  uint8_t cmd    = data.size() >= 1 ? data[0] : raw_cmd;
  uint8_t status = data.size() >= 2 ? data[1] : 0xFF;

  ESP_LOGD(TAG, "RX cmd=0x%02X status=0x%02X len=%d op=%d",
           cmd, status, data.size(), (int) op_state_);

  switch (op_state_) {

    // ── Status query (idle reconnect) ─────────────────────────────────────

    case OpState::QUERY_STATUS:
      if (cmd == CMD_GET_STATUS && data.size() >= 4) {
        // data[3] = LockedStatus: 0 = LOCKED, 1 = UNLOCKED (JS SDK convention)
        last_status_unlocked_ = (data[3] == 1);
        if (last_status_unlocked_) {
          ESP_LOGI(TAG, "Lock status: UNLOCKED");
          this->publish_state(lock::LOCK_STATE_UNLOCKED);
        } else {
          ESP_LOGI(TAG, "Lock status: LOCKED");
          this->publish_state(lock::LOCK_STATE_LOCKED);
        }
        // Always follow with a passage mode query so passage_mode_ stays in sync.
        do_check_admin_();
      }
      break;

    // ── Normal lock/unlock states ─────────────────────────────────────────

    case OpState::CHECK_ADMIN:
      if (cmd == CMD_CHECK_ADMIN && data.size() >= 6) {
        // psFromLock is at data[2..5] (after cmd type byte + status byte)
        ps_from_lock_ = ((uint32_t) data[2] << 24) | ((uint32_t) data[3] << 16) |
                        ((uint32_t) data[4] <<  8) |  (uint32_t) data[5];
        ESP_LOGD(TAG, "CHECK_ADMIN: got token from lock");
        op_state_ = OpState::CHECK_RANDOM;
        do_check_random_();
      } else {
        ESP_LOGE(TAG, "CHECK_ADMIN failed (cmd=0x%02X status=0x%02X len=%d)",
                 cmd, status, data.size());
        op_state_            = OpState::IDLE;
        pending_unlock_      = pending_lock_ = false;
        pending_passage_on_  = pending_passage_off_ = false;
        this->publish_state(lock::LOCK_STATE_JAMMED);
      }
      break;

    case OpState::CHECK_RANDOM:
      if (cmd == CMD_CHECK_RANDOM) {
        if (pending_passage_on_) {
          op_state_ = OpState::PASSAGE_ON_CMD;
          do_passage_on_();
        } else if (pending_passage_off_) {
          op_state_ = OpState::PASSAGE_OFF_CMD;
          do_passage_off_();
        } else if (pending_unlock_) {
          op_state_ = OpState::UNLOCK_CMD;
          do_unlock_();
        } else if (pending_lock_) {
          op_state_ = OpState::LOCK_CMD;
          do_lock_();
        } else {
          do_query_passage_();
        }
      } else {
        ESP_LOGE(TAG, "CHECK_RANDOM failed (cmd=0x%02X status=0x%02X)", cmd, status);
        op_state_            = OpState::IDLE;
        pending_unlock_      = pending_lock_ = false;
        pending_passage_on_  = pending_passage_off_ = false;
        this->publish_state(lock::LOCK_STATE_JAMMED);
      }
      break;

    case OpState::QUERY_PASSAGE_CMD:
      if (cmd == CMD_CONFIGURE_PASSAGE) {
        // Response header: [cmd=0x66, status, battery, unknown, seq]  = 5 bytes
        // Each schedule entry is 7 bytes: [type, weekOrDay, month, startH, startM, endH, endM]
        // has_entries when total decoded data >= 5 + 7 = 12 bytes
        bool has_entries = (data.size() >= 12);
        passage_mode_ = has_entries;
        if (passage_switch_)
          passage_switch_->publish_state(passage_mode_);
        ESP_LOGI(TAG, "Passage mode: %s", passage_mode_ ? "ACTIVE" : "INACTIVE");
        // Re-unlock if passage mode is active but the lock reported LOCKED.
        // Actually this should never happen, need to check it on more locks
        if (passage_mode_ && !last_status_unlocked_) {
          ESP_LOGI(TAG, "Passage mode active but locked – re-unlocking");
          auto_unlock_    = true;  // marks this as automatic, not user-initiated
          pending_unlock_ = true;
          op_state_       = OpState::UNLOCK_CMD;
          do_unlock_();
        } else {
          op_state_ = OpState::IDLE;
        }
      } else {
        ESP_LOGW(TAG, "Unexpected response in QUERY_PASSAGE_CMD (cmd=0x%02X)", cmd);
        op_state_ = OpState::IDLE;
      }
      break;

    case OpState::PASSAGE_ON_CMD:
      if (cmd == CMD_CONFIGURE_PASSAGE) {
        pending_passage_on_ = false;
        passage_mode_       = true;
        if (status == 0x01) {
          ESP_LOGI(TAG, "Passage mode ADD acknowledged, unlocking");
        } else {
          // Lock did not confirm ADD but we still track passage mode in memory
          // and proceed to unlock; the lock will be re-unlocked on every reconnect.
          ESP_LOGW(TAG, "Passage mode ADD status=0x%02X (proceeding anyway)", status);
        }
        pending_unlock_ = true;
        op_state_       = OpState::UNLOCK_CMD;
        do_unlock_();
      }
      break;

    case OpState::PASSAGE_OFF_CMD:
      if (cmd == CMD_CONFIGURE_PASSAGE) {
        if (status == 0x01) {
          pending_passage_off_ = false;
          passage_mode_        = false;
          // Passage mode cleared; now explicitly lock the door.
          // Set op_state_ = LOCK_CMD BEFORE calling do_lock_() so the
          // LOCK response is processed by the correct handler.
          ESP_LOGI(TAG, "Passage mode cleared, locking");
          pending_lock_ = true;
          op_state_     = OpState::LOCK_CMD;
          do_lock_();
        } else {
          ESP_LOGE(TAG, "Passage mode disable failed (status=0x%02X)", status);
          pending_passage_off_ = false;
          op_state_            = OpState::IDLE;
          this->publish_state(lock::LOCK_STATE_JAMMED);
        }
      }
      break;

    case OpState::UNLOCK_CMD:
      if (cmd == CMD_UNLOCK) {
        op_state_ = OpState::IDLE;
        if (status == 0x01) {
          pending_unlock_ = false;
          if (!polling_ && !auto_unlock_)
            pending_status_query_ = true;  // schedule one status+passage query after disconnect
          auto_unlock_ = false;
          // Battery is only valid in the full success response (≥3 bytes, status=0x01)
          if (data.size() >= 3) {
            uint8_t battery = data[2];
            ESP_LOGI(TAG, "Unlocked  battery=%d%%", battery);
            if (battery_sensor_)
              battery_sensor_->publish_state((float) battery);
          } else {
            ESP_LOGI(TAG, "Unlocked");
          }
          this->publish_state(lock::LOCK_STATE_UNLOCKED);
          if (passage_switch_)
            passage_switch_->publish_state(passage_mode_);
        } else {
          // Lock rejected the command (status=0x00 = still locked).
          // Keep pending_unlock_ set so we retry automatically on the next reconnect.
          ESP_LOGW(TAG, "Unlock rejected (status=0x%02X) – will retry", status);
          this->publish_state(lock::LOCK_STATE_LOCKED);
        }
      }
      break;

    case OpState::LOCK_CMD:
      if (cmd == CMD_LOCK) {
        op_state_ = OpState::IDLE;
        if (status == 0x01) {
          pending_lock_ = false;
          passage_mode_ = false;  // locking always exits passage mode
          if (!polling_)
            pending_status_query_ = true;  // schedule one status+passage query after disconnect
          // Battery is only valid in the full success response (≥3 bytes, status=0x01)
          if (data.size() >= 3) {
            uint8_t battery = data[2];
            ESP_LOGI(TAG, "Locked  battery=%d%%", battery);
            if (battery_sensor_)
              battery_sensor_->publish_state((float) battery);
          } else {
            ESP_LOGI(TAG, "Locked");
          }
          this->publish_state(lock::LOCK_STATE_LOCKED);
          if (passage_switch_)
            passage_switch_->publish_state(false);
        } else {
          // Lock rejected the command – keep pending_lock_ set for retry.
          ESP_LOGW(TAG, "Lock rejected (status=0x%02X) – will retry", status);
          this->publish_state(lock::LOCK_STATE_UNLOCKED);
        }
      }
      break;

    case OpState::IDLE:
      // Unsolicited status notification from the lock (e.g. auto-relock event).
      if (cmd == CMD_GET_STATUS && data.size() >= 4) {
        bool is_unlocked = (data[3] == 1);
        if (is_unlocked) {
          ESP_LOGI(TAG, "Unsolicited status: UNLOCKED");
          this->publish_state(lock::LOCK_STATE_UNLOCKED);
          if (passage_switch_)
            passage_switch_->publish_state(passage_mode_);
        } else {
          ESP_LOGI(TAG, "Unsolicited status: LOCKED");
          this->publish_state(lock::LOCK_STATE_LOCKED);
          if (passage_switch_)
            passage_switch_->publish_state(passage_mode_);
          if (passage_mode_) {
            ESP_LOGI(TAG, "Passage mode active, re-unlocking after unsolicited lock");
            pending_unlock_ = true;
            do_check_admin_();
          }
        }
      }
      break;

    default:
      break;
  }
}

// ── Normal operation sequence ─────────────────────────────────────────────────

void TTLockLock::start_pending_() {
  if (pending_passage_on_ || pending_passage_off_ || pending_unlock_ || pending_lock_) {
    do_check_admin_();
  } else {
    pending_status_query_ = false;  // consuming this request
    do_query_status_();
  }
}

void TTLockLock::do_query_status_() {
  // COMM_SEARCH_BICYCLE_STATUS (0x14) with payload "SCIENER" queries the current
  // locked/unlocked state. Response: data[3] = 0 (LOCKED) / 1 (UNLOCKED).
  static const uint8_t payload[] = {'S','C','I','E','N','E','R'};
  op_state_ = OpState::QUERY_STATUS;
  ESP_LOGD(TAG, "→ QUERY_STATUS");
  send_cmd_(CMD_GET_STATUS, payload, sizeof(payload));
}

void TTLockLock::do_check_admin_() {
  // Payload: adminPs (4 B BE) at offset 0, lockFlagPos (0) at offset 3 (overlaps),
  // uid (0) at offset 7 → effectively adminPs + 7 zero bytes = 11 bytes total.
  // Matches JS SDK CheckAdminCommand.build() with lockFlagPos=0, uid=0.
  uint8_t data[11] = {};
  data[0] = (admin_ps_ >> 24) & 0xFF;
  data[1] = (admin_ps_ >> 16) & 0xFF;
  data[2] = (admin_ps_ >>  8) & 0xFF;
  data[3] =  admin_ps_        & 0xFF;
  // bytes 4-10 remain zero
  op_state_ = OpState::CHECK_ADMIN;
  ESP_LOGD(TAG, "→ CHECK_ADMIN");
  send_cmd_(CMD_CHECK_ADMIN, data, sizeof(data));
}

void TTLockLock::do_check_random_() {
  uint32_t sum = ps_from_lock_ + unlock_key_;
  uint8_t data[4];
  data[0] = (sum >> 24) & 0xFF;
  data[1] = (sum >> 16) & 0xFF;
  data[2] = (sum >>  8) & 0xFF;
  data[3] =  sum        & 0xFF;
  ESP_LOGD(TAG, "→ CHECK_RANDOM");
  send_cmd_(CMD_CHECK_RANDOM, data, sizeof(data));
}

void TTLockLock::do_unlock_() {
  uint32_t sum = ps_from_lock_ + unlock_key_;
  uint32_t ts  = (uint32_t) time(nullptr);
  uint8_t data[8];
  data[0] = (sum >> 24) & 0xFF;
  data[1] = (sum >> 16) & 0xFF;
  data[2] = (sum >>  8) & 0xFF;
  data[3] =  sum        & 0xFF;
  data[4] = (ts  >> 24) & 0xFF;
  data[5] = (ts  >> 16) & 0xFF;
  data[6] = (ts  >>  8) & 0xFF;
  data[7] =  ts         & 0xFF;
  ESP_LOGD(TAG, "→ UNLOCK");
  send_cmd_(CMD_UNLOCK, data, sizeof(data));
}

void TTLockLock::do_lock_() {
  uint32_t sum = ps_from_lock_ + unlock_key_;
  uint32_t ts  = (uint32_t) time(nullptr);
  uint8_t data[8];
  data[0] = (sum >> 24) & 0xFF;
  data[1] = (sum >> 16) & 0xFF;
  data[2] = (sum >>  8) & 0xFF;
  data[3] =  sum        & 0xFF;
  data[4] = (ts  >> 24) & 0xFF;
  data[5] = (ts  >> 16) & 0xFF;
  data[6] = (ts  >>  8) & 0xFF;
  data[7] =  ts         & 0xFF;
  ESP_LOGD(TAG, "→ LOCK");
  send_cmd_(CMD_LOCK, data, sizeof(data));
}

void TTLockLock::do_query_passage_() {
  // 0x66 QUERY: op=1, seq=0 (request first page of schedule entries)
  static const uint8_t payload[] = {0x01, 0x00};
  op_state_ = OpState::QUERY_PASSAGE_CMD;
  ESP_LOGD(TAG, "→ QUERY_PASSAGE");
  send_cmd_(CMD_CONFIGURE_PASSAGE, payload, sizeof(payload));
}

void TTLockLock::do_passage_clear_() {
  // COMM_CONFIGURE_PASSAGE_MODE CLEAR: remove all passage mode entries.
  // Only reached when QUERY found stale entries (passage-ON) or for passage-OFF.
  static const uint8_t payload[] = {0x04};
  ESP_LOGD(TAG, "→ PASSAGE_CLEAR");
  send_cmd_(CMD_CONFIGURE_PASSAGE, payload, sizeof(payload));
}

void TTLockLock::do_passage_on_() {
  // COMM_CONFIGURE_PASSAGE_MODE ADD: all-day, every day (weekly).
  // Called after PASSAGE_CLEAR_CMD completes (CLEAR→ADD sequence is idempotent).
  // Payload: [op=ADD(2), type=WEEKLY(1), seq=0, weekOrDay=0x7f(all dayes), startH=0, startM=0, endH=23, endM=59]
  static const uint8_t payload[] = {0x02, 0x01, 0x00, 0x7F, 0x00, 0x00, 0x17, 0x3B};
  op_state_ = OpState::PASSAGE_ON_CMD;
  ESP_LOGD(TAG, "→ PASSAGE_ON (add)");
  send_cmd_(CMD_CONFIGURE_PASSAGE, payload, sizeof(payload));
}

void TTLockLock::do_passage_off_() {
  // Send 0x66 CLEAR then LOCK. passage_mode_ will be cleared in PASSAGE_OFF_CMD handler.
  op_state_ = OpState::PASSAGE_OFF_CMD;
  ESP_LOGD(TAG, "→ PASSAGE_CLEAR (off)");
  do_passage_clear_();
}

// ── Passage mode ──────────────────────────────────────────────────────────────

void TTLockPassageSwitch::write_state(bool state) {
  publish_state(state);
  lock_->set_passage_mode(state);
}

void TTLockLock::request_update() {
  pending_status_query_ = true;
  auto ble_st = espbt::ESPBTClient::state();
  if (ble_st == espbt::ClientState::ESTABLISHED && op_state_ == OpState::IDLE)
    start_pending_();
  else if (ble_st == espbt::ClientState::IDLE)
    this->connect();
}

void TTLockLock::set_passage_mode(bool enable) {
  ESP_LOGI(TAG, "Passage mode %s", enable ? "ON" : "OFF");
  passage_mode_ = enable;
  pending_passage_on_  = enable;
  pending_passage_off_ = !enable;
  pending_unlock_      = false;
  pending_lock_        = false;
  if (enable) {
    this->publish_state(lock::LOCK_STATE_UNLOCKING);
  } else {
    this->publish_state(lock::LOCK_STATE_LOCKING);
  }
  auto ble_st = espbt::ESPBTClient::state();
  if (ble_st == espbt::ClientState::ESTABLISHED && op_state_ == OpState::IDLE)
    start_pending_();
  else if (ble_st == espbt::ClientState::IDLE)
    this->connect();
}

// ── lock::Lock interface ─────────────────────────────────────────────────────

void TTLockLock::control(const lock::LockCall &call) {
  auto state = call.get_state();
  if (!state.has_value()) return;

  if (*state == lock::LOCK_STATE_UNLOCKED) {
    pending_unlock_      = true;
    pending_lock_        = false;
    pending_passage_on_  = false;
    pending_passage_off_ = false;
    this->publish_state(lock::LOCK_STATE_UNLOCKING);
    ESP_LOGD(TAG, "Unlock queued, BLE state=%d", (int) espbt::ESPBTClient::state());
    {
      auto ble_st = espbt::ESPBTClient::state();
      if (ble_st == espbt::ClientState::ESTABLISHED && op_state_ == OpState::IDLE)
        start_pending_();
      else if (ble_st == espbt::ClientState::IDLE)
        this->connect();
    }

  } else if (*state == lock::LOCK_STATE_LOCKED) {
    if (passage_mode_) {
      // Must clear passage mode in firmware before locking.
      set_passage_mode(false);
    } else {
      pending_lock_        = true;
      pending_unlock_      = false;
      pending_passage_on_  = false;
      pending_passage_off_ = false;
      this->publish_state(lock::LOCK_STATE_LOCKING);
      auto ble_st = espbt::ESPBTClient::state();
      if (ble_st == espbt::ClientState::ESTABLISHED && op_state_ == OpState::IDLE)
        start_pending_();
      else if (ble_st == espbt::ClientState::IDLE)
        this->connect();
    }
  }
}

// ── Component lifecycle ──────────────────────────────────────────────────────

void TTLockLock::setup() {
  // BLEClientBase::setup() assigns the connection_index_.
  // GATTC app registration happens lazily in loop() once BLE is active.
  ble_client::BLEClientBase::setup();
  this->publish_state(lock::LOCK_STATE_NONE);
  ESP_LOGI(TAG, "TTLock setup: app_id=%d addr=%s", this->app_id, this->address_str());
}

void TTLockLock::loop() {
  ble_client::BLEClientBase::loop();
}

void TTLockLock::dump_config() {
  LOG_LOCK("", "TTLock", this);
  ESP_LOGCONFIG(TAG, "  Address: %s", this->address_str());
  ESP_LOGCONFIG(TAG, "  Protocol: type=0x%02X  ver=0x%02X  scene=0x%02X  group=0x%04X  org=0x%04X",
                lv_.proto_type, lv_.proto_ver, lv_.scene, lv_.group_id, lv_.org_id);
  ESP_LOGCONFIG(TAG, "  Credentials: configured");
}

}  // namespace ttlock
}  // namespace esphome

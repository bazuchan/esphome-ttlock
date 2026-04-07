#include "ttlock_lock.h"
#include "esphome/core/log.h"
#include "esphome/core/application.h"

#include "esp_system.h"
#include "esp_gattc_api.h"

#include <cstring>
#include <ctime>
#include <algorithm>

// ── Self-contained AES-128-CBC ────────────────────────────────────────────────
// Standard FIPS-197 AES-128.  Replaces mbedTLS to avoid linker dependencies.
namespace {

// Forward S-box
static const uint8_t FSBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

// Inverse S-box
static const uint8_t RSBOX[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
};

// Round constants (Rcon[1..10], index 0 unused)
static const uint8_t RCON[11] = {0,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

// GF(2^8) multiply: used only in InvMixColumns
static uint8_t gfmul(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    while (b) {
        if (b & 1) r ^= a;
        bool hi = (a & 0x80) != 0;
        a = (uint8_t)(a << 1);
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return r;
}

// GF(2^8) multiply by 2 (xtime), used in MixColumns
static inline uint8_t xt(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x >> 7) ? 0x1b : 0x00));
}

// Key expansion: produce 11 × 16 = 176 byte round-key schedule
static void key_expand(const uint8_t key[16], uint8_t rk[176]) {
    memcpy(rk, key, 16);
    for (int i = 16; i < 176; i += 4) {
        uint8_t t0 = rk[i-4], t1 = rk[i-3], t2 = rk[i-2], t3 = rk[i-1];
        if ((i & 15) == 0) {
            // RotWord then SubWord then XOR Rcon
            uint8_t tmp = t0;
            t0 = FSBOX[t1] ^ RCON[i >> 4];
            t1 = FSBOX[t2];
            t2 = FSBOX[t3];
            t3 = FSBOX[tmp];
        }
        rk[i]   = rk[i-16] ^ t0;
        rk[i+1] = rk[i-15] ^ t1;
        rk[i+2] = rk[i-14] ^ t2;
        rk[i+3] = rk[i-13] ^ t3;
    }
}

// State is a flat 16-byte array in column-major order:
//   byte index = col*4 + row  (col 0..3, row 0..3)

static void add_round_key(uint8_t s[16], const uint8_t *rk) {
    for (int i = 0; i < 16; i++) s[i] ^= rk[i];
}

static void sub_bytes(uint8_t s[16], const uint8_t *box) {
    for (int i = 0; i < 16; i++) s[i] = box[s[i]];
}

static void shift_rows(uint8_t s[16]) {
    uint8_t t;
    // Row 1: left-shift by 1
    t=s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=t;
    // Row 2: left-shift by 2
    t=s[2]; s[2]=s[10]; s[10]=t;  t=s[6]; s[6]=s[14]; s[14]=t;
    // Row 3: left-shift by 3 (= right-shift by 1)
    t=s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=s[3]; s[3]=t;
}

static void inv_shift_rows(uint8_t s[16]) {
    uint8_t t;
    // Row 1: right-shift by 1
    t=s[13]; s[13]=s[9]; s[9]=s[5]; s[5]=s[1]; s[1]=t;
    // Row 2: right-shift by 2
    t=s[2]; s[2]=s[10]; s[10]=t;  t=s[6]; s[6]=s[14]; s[14]=t;
    // Row 3: right-shift by 3 (= left-shift by 1)
    t=s[3]; s[3]=s[7]; s[7]=s[11]; s[11]=s[15]; s[15]=t;
}

static void mix_columns(uint8_t s[16]) {
    for (int c = 0; c < 4; c++) {
        uint8_t a0=s[c*4], a1=s[c*4+1], a2=s[c*4+2], a3=s[c*4+3];
        uint8_t tmp = a0^a1^a2^a3;
        s[c*4  ] = a0 ^ tmp ^ xt(a0^a1);
        s[c*4+1] = a1 ^ tmp ^ xt(a1^a2);
        s[c*4+2] = a2 ^ tmp ^ xt(a2^a3);
        s[c*4+3] = a3 ^ tmp ^ xt(a3^a0);
    }
}

static void inv_mix_columns(uint8_t s[16]) {
    for (int c = 0; c < 4; c++) {
        uint8_t a0=s[c*4], a1=s[c*4+1], a2=s[c*4+2], a3=s[c*4+3];
        s[c*4  ] = gfmul(0x0e,a0)^gfmul(0x0b,a1)^gfmul(0x0d,a2)^gfmul(0x09,a3);
        s[c*4+1] = gfmul(0x09,a0)^gfmul(0x0e,a1)^gfmul(0x0b,a2)^gfmul(0x0d,a3);
        s[c*4+2] = gfmul(0x0d,a0)^gfmul(0x09,a1)^gfmul(0x0e,a2)^gfmul(0x0b,a3);
        s[c*4+3] = gfmul(0x0b,a0)^gfmul(0x0d,a1)^gfmul(0x09,a2)^gfmul(0x0e,a3);
    }
}

static void aes128_block_encrypt(uint8_t s[16], const uint8_t rk[176]) {
    add_round_key(s, rk);
    for (int r = 1; r < 10; r++) {
        sub_bytes(s, FSBOX);
        shift_rows(s);
        mix_columns(s);
        add_round_key(s, rk + 16*r);
    }
    sub_bytes(s, FSBOX);
    shift_rows(s);
    add_round_key(s, rk + 160);
}

static void aes128_block_decrypt(uint8_t s[16], const uint8_t rk[176]) {
    add_round_key(s, rk + 160);
    for (int r = 9; r > 0; r--) {
        inv_shift_rows(s);
        sub_bytes(s, RSBOX);
        add_round_key(s, rk + 16*r);
        inv_mix_columns(s);
    }
    inv_shift_rows(s);
    sub_bytes(s, RSBOX);
    add_round_key(s, rk);
}

} // anonymous namespace

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

  uint8_t rk[176];
  key_expand(key, rk);

  // CBC mode: IV == key (TTLock protocol)
  uint8_t iv[16];
  memcpy(iv, key, 16);

  for (size_t i = 0; i < total; i += 16) {
    for (int j = 0; j < 16; j++) buf[i + j] ^= iv[j];
    aes128_block_encrypt(buf + i, rk);
    memcpy(iv, buf + i, 16);
  }

  memcpy(out, buf, total);
  return total;
}

size_t TTLockLock::aes_decrypt_(const uint8_t *in, size_t in_len,
                                  const uint8_t *key, uint8_t *out) {
  if (in_len == 0 || (in_len % 16) != 0) return 0;

  uint8_t rk[176];
  key_expand(key, rk);

  // CBC mode: IV == key (TTLock protocol)
  uint8_t iv[16];
  memcpy(iv, key, 16);

  for (size_t i = 0; i < in_len; i += 16) {
    uint8_t block[16];
    memcpy(block, in + i, 16);
    aes128_block_decrypt(block, rk);
    for (int j = 0; j < 16; j++) block[j] ^= iv[j];
    memcpy(iv, in + i, 16);
    memcpy(out + i, block, 16);
  }

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
  bool has_pending = pending_passage_on_ || pending_passage_off_ ||
                     pending_unlock_     || pending_lock_;
  // In passage mode with nothing pending, schedule a periodic status check so
  // we can re-unlock if the lock auto-relocked while passage mode was active.
  if (passage_mode_ && !has_pending) {
    ESP_LOGD(TAG, "Passage mode idle, status check in %u ms", PASSAGE_CHECK_MS);
    this->set_timeout("reconnect", PASSAGE_CHECK_MS, [this]() {
      if (espbt::ESPBTClient::state() == espbt::ClientState::IDLE)
        this->connect();
    });
    return;
  }
  // Short delay before reconnect so the lock has time to close its side.
  ESP_LOGD(TAG, "Scheduling reconnect in 500 ms");
  this->set_timeout("reconnect", 500, [this]() {
    auto st = espbt::ESPBTClient::state();
    ESP_LOGD(TAG, "Reconnect timeout fired, state=%d", (int) st);
    // Only connect from IDLE — calling connect() while DISCONNECTING causes the
    // ESP-IDF stack to queue esp_ble_gattc_open(), which bounces back as
    // ESP_GATTC_OPEN_EVT status=133 in DISCONNECTING state.
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
        bool is_unlocked = (data[3] == 1);
        op_state_ = OpState::IDLE;
        if (is_unlocked) {
          ESP_LOGI(TAG, "Lock status: UNLOCKED");
          this->publish_state(lock::LOCK_STATE_UNLOCKED);
          if (passage_switch_)
            passage_switch_->publish_state(passage_mode_);
        } else {
          ESP_LOGI(TAG, "Lock status: LOCKED");
          this->publish_state(lock::LOCK_STATE_LOCKED);
          if (passage_switch_)
            passage_switch_->publish_state(passage_mode_);
          // Passage mode is active but the lock auto-relocked – verify passage
          // mode state on the lock before re-unlocking.
          if (passage_mode_) {
            ESP_LOGI(TAG, "Passage mode active but lock is LOCKED – querying passage then re-unlocking");
            pending_passage_on_ = true;
            do_check_admin_();
          }
        }
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
          // Query current passage mode first: if empty → ADD directly;
          // if entries present → already active; if wrong → CLEAR then reconnect.
          op_state_ = OpState::QUERY_PASSAGE_CMD;
          do_query_passage_();
        } else if (pending_passage_off_) {
          op_state_ = OpState::PASSAGE_OFF_CMD;
          do_passage_off_();
        } else if (pending_unlock_) {
          op_state_ = OpState::UNLOCK_CMD;
          do_unlock_();
        } else if (pending_lock_) {
          op_state_ = OpState::LOCK_CMD;
          do_lock_();
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
      // Response layout: data[] = [cmd, status, op, seq, type, weekOrDay, month, sH, sM, eH, eM, ...]
      // One 7-byte entry needs 4 header bytes + 7 = 11 total. TS SDK checks commandData.length >= 10
      // (commandData omits the leading cmd byte), which translates to data.size() >= 11 here.
      if (cmd == CMD_CONFIGURE_PASSAGE) {
        if (data.size() >= 11) {
          // Entries present → passage mode already active in firmware; just unlock.
          ESP_LOGI(TAG, "Passage mode already active, unlocking");
          pending_passage_on_ = false;
          passage_mode_       = true;
          pending_unlock_     = true;
          op_state_           = OpState::UNLOCK_CMD;
          do_unlock_();
        } else {
          // No entries → safe to ADD directly (either fresh or post-CLEAR session).
          ESP_LOGD(TAG, "Passage mode not set, adding");
          op_state_ = OpState::PASSAGE_ON_CMD;
          do_passage_on_();
        }
      }
      break;

    case OpState::PASSAGE_CLEAR_CMD:
      // CLEAR response (only reached when QUERY found wrong/stale entries).
      // ADD in the same session as CLEAR always fails (firmware bug), so return to
      // IDLE; the lock will disconnect naturally (reason 0x13). On the next session
      // QUERY returns empty → ADD proceeds without another CLEAR.
      if (cmd == CMD_CONFIGURE_PASSAGE) {
        ESP_LOGD(TAG, "PASSAGE_CLEAR done, ADD will follow on next connect");
        op_state_ = OpState::IDLE;
        // pending_passage_on_ remains true for the reconnect
      }
      break;

    case OpState::PASSAGE_ON_CMD:
      if (cmd == CMD_CONFIGURE_PASSAGE) {
        if (status == 0x01) {
          pending_passage_on_ = false;
          passage_mode_       = true;
          ESP_LOGI(TAG, "Passage mode enabled in firmware, unlocking");
          pending_unlock_ = true;
          op_state_       = OpState::UNLOCK_CMD;
          do_unlock_();
        } else {
          // ADD failed — reset and retry from scratch next time.
          ESP_LOGE(TAG, "Passage mode ADD failed (status=0x%02X), will retry", status);
          pending_passage_on_ = false;
          passage_mode_       = false;
          op_state_           = OpState::IDLE;
          if (passage_switch_) passage_switch_->publish_state(false);
          this->publish_state(lock::LOCK_STATE_LOCKED);
        }
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
            ESP_LOGI(TAG, "Passage mode active, querying passage then re-unlocking after unsolicited lock");
            pending_passage_on_ = true;
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
    // No pending operation – query the physical lock state so HA stays in sync.
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
  // COMM_CONFIGURE_PASSAGE_MODE QUERY (op=0x01, type=Weekly).
  // Response payload: empty → not configured; 7 bytes/entry → active entries.
  static const uint8_t payload[] = {0x01, 0x01};  // QUERY, Week type
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
  // Payload: [op=ADD(2), type=WEEKLY(1), weekOrDay=0, month=0, startH=0, startM=0, endH=0, endM=0]
  static const uint8_t payload[] = {0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  ESP_LOGD(TAG, "→ PASSAGE_ON (add)");
  send_cmd_(CMD_CONFIGURE_PASSAGE, payload, sizeof(payload));
}

void TTLockLock::do_passage_off_() {
  // COMM_CONFIGURE_PASSAGE_MODE CLEAR: remove all passage mode entries, then lock.
  op_state_ = OpState::PASSAGE_OFF_CMD;
  do_passage_clear_();
}

// ── Passage mode ──────────────────────────────────────────────────────────────

void TTLockPassageSwitch::write_state(bool state) {
  publish_state(state);
  lock_->set_passage_mode(state);
}

void TTLockLock::set_passage_mode(bool enable) {
  ESP_LOGI(TAG, "Passage mode %s", enable ? "ON" : "OFF");
  if (enable) {
    pending_passage_on_  = true;
    pending_passage_off_ = false;
    pending_unlock_      = false;
    pending_lock_        = false;
    this->publish_state(lock::LOCK_STATE_UNLOCKING);
  } else {
    pending_passage_off_ = true;
    pending_passage_on_  = false;
    pending_unlock_      = false;
    pending_lock_        = false;
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

/*
 * CAALC audio transmitter, ESP32 A.
 * INMP441 I2S -> authenticated CAALC/Ascon frames -> Bluetooth Classic SPP -> ESP32 B.
 * Key and session are provisioned by the laptop over trusted USB for every boot.
 * Configuration: CFG SENDER <32-hex-key> <16-hex-session> <BT-MAC> <CAALC|ASCON>
 * Runtime control: STOP\n over USB stops the microphone stream.
 */
#include <Arduino.h>
#include <BluetoothSerial.h>
#include <driver/i2s.h>
#include "caalc_core.h"
extern "C" {
#include "src/ascon/crypto_aead.h"
}
#if !defined(CONFIG_BT_ENABLED) || !defined(CONFIG_BLUEDROID_ENABLED) || !defined(CONFIG_BT_SPP_ENABLED)
#error "Bluetooth Classic SPP requires the original ESP32 with Bluetooth enabled."
#endif

BluetoothSerial SerialBT;
// 40 ms frames halve Bluetooth/Wi-Fi packet frequency compared with the
// original 20 ms framing while remaining below the Wi-Fi MTU.
static constexpr unsigned FRAME_MS = 40;
static constexpr unsigned FRAME_SAMPLES = 320;
static constexpr unsigned PCM_BYTES = FRAME_SAMPLES * 2;
static constexpr unsigned PACKET_BYTES = 28 + PCM_BYTES + 16;
static constexpr unsigned FRAMED_BYTES = 6 + PACKET_BYTES;
static uint8_t keyBytes[16], sessionId[8], pcm[PCM_BYTES], packet[PACKET_BYTES], btAddress[6];
static int32_t stereoSamples[FRAME_SAMPLES * 2];
static uint64_t sequence = 0, cryptoTotalUs = 0;
static uint32_t frameCount = 0, lostFrames = 0, cryptoMaxUs = 0;
static uint32_t micReadErrors = 0, micPeak = 0, micSampleCount = 0;
static uint64_t micSquareTotal = 0;
static int32_t micDc = 0;
static int micActiveSlot = 0;
static bool micDcReady = false;
static bool configured = false, running = false;
static uint32_t sentFrames = 0;
static uint8_t algorithmId = 0;
static char configLine[160];
static size_t configLen = 0;
static const char *FW_VERSION = "sender-20261122.2";

static bool hexParse(const char *s, uint8_t *out, size_t n) {
  if (strlen(s) != 2 * n) return false;
  for (size_t i = 0; i < n; ++i) {
    unsigned v = 0;
    for (unsigned j = 0; j < 2; ++j) {
      char c = s[2 * i + j]; unsigned d;
      if (c >= '0' && c <= '9') d = c - '0';
      else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
      else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
      else return false;
      v = (v << 4) | d;
    }
    out[i] = (uint8_t)v;
  }
  return true;
}

static bool parseMac(const char *s, uint8_t out[6]) {
  unsigned v[6];
  if (sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) return false;
  for (int i = 0; i < 6; ++i) { if (v[i] > 255) return false; out[i] = (uint8_t)v[i]; }
  return true;
}

static void halt(const char *msg) {
  Serial.printf("FATAL %s\n", msg); configured = false; running = false;
  char command[8] = {}; size_t n = 0;
  while (true) {
    while (Serial.available()) {
      char c = (char)Serial.read();
      if (c == '\n') {
        command[n] = 0;
        if (!strcmp(command, "RESET")) { Serial.println("RESETTING role=sender"); Serial.flush(); delay(100); ESP.restart(); }
        n = 0;
      } else if (c != '\r' && n < sizeof(command)-1) command[n++] = c;
    }
    delay(50);
  }
}

static size_t readStereoFrames(size_t requestedFrames) {
  size_t got = 0;
  esp_err_t result = i2s_read(I2S_NUM_0, stereoSamples,
      requestedFrames * 2 * sizeof(int32_t), &got, pdMS_TO_TICKS(250));
  if (result != ESP_OK || !got || got % (2 * sizeof(int32_t))) {
    ++micReadErrors;
    Serial.printf("ERR_I2S_READ code=%d bytes=%u frames=%u total_errors=%lu\n",
      (int)result, (unsigned)got, (unsigned)requestedFrames,
      (unsigned long)micReadErrors);
    return 0;
  }
  return got / (2 * sizeof(int32_t));
}

static int detectActiveMicSlot() {
  uint64_t activity[2] = {0, 0};
  int32_t previous[2] = {0, 0};
  bool havePrevious = false;
  for (int block = 0; block < 10; ++block) {
    size_t frames = readStereoFrames(FRAME_SAMPLES);
    for (size_t frame = 0; frame < frames; ++frame) {
      for (int slot = 0; slot < 2; ++slot) {
        int32_t value = stereoSamples[frame * 2 + slot];
        if (havePrevious) {
          int64_t difference = (int64_t)value - previous[slot];
          if (difference < 0) difference = -difference;
          activity[slot] += (uint64_t)difference;
        }
        previous[slot] = value;
      }
      havePrevious = true;
    }
  }
  int selected = activity[1] > activity[0] ? 1 : 0;
  Serial.printf("MIC_CHANNEL_DETECT slot0_activity=%llu slot1_activity=%llu selected=%d\n",
    (unsigned long long)activity[0], (unsigned long long)activity[1], selected);
  return selected;
}

static int16_t microphonePcm16(int32_t rawWord) {
  // INMP441 sends signed 24-bit data left-aligned in its 32-bit I2S slot.
  int32_t sample24 = rawWord >> 8;
  if (!micDcReady) { micDc = sample24; micDcReady = true; }
  // Slow IIR estimate removes DC/very-low-frequency drift. Dividing the
  // centered 24-bit value by 64 gives 4x the normal 24-to-16 conversion.
  micDc += (sample24 - micDc) >> 8;
  int32_t amplified = (sample24 - micDc) >> 6;
  if (amplified > 32767) amplified = 32767;
  if (amplified < -32768) amplified = -32768;
  int32_t magnitude = amplified < 0 ? -amplified : amplified;
  if ((uint32_t)magnitude > micPeak) micPeak = (uint32_t)magnitude;
  micSquareTotal += (uint64_t)((int64_t)amplified * amplified);
  ++micSampleCount;
  return (int16_t)amplified;
}

static void startMic() {
  i2s_config_t c = {};
  c.mode = (i2s_mode_t)(I2S_MODE_MASTER | I2S_MODE_RX);
  c.sample_rate = 8000; c.bits_per_sample = I2S_BITS_PER_SAMPLE_32BIT;
  c.channel_format = I2S_CHANNEL_FMT_RIGHT_LEFT; c.communication_format = I2S_COMM_FORMAT_STAND_I2S;
  c.intr_alloc_flags = 0; c.dma_buf_count = 8; c.dma_buf_len = FRAME_SAMPLES; c.use_apll = false;
  i2s_pin_config_t pins = {};
  pins.bck_io_num = 14; pins.ws_io_num = 15; pins.data_out_num = I2S_PIN_NO_CHANGE;
  pins.data_in_num = 32; pins.mck_io_num = I2S_PIN_NO_CHANGE;
  esp_err_t result = i2s_driver_install(I2S_NUM_0, &c, 0, NULL);
  if (result != ESP_OK) { Serial.printf("ERR_I2S_DRIVER code=%d\n", (int)result); halt("I2S driver install"); }
  result = i2s_set_pin(I2S_NUM_0, &pins);
  if (result != ESP_OK) { Serial.printf("ERR_I2S_PINS code=%d\n", (int)result); halt("I2S pin setup"); }
  i2s_zero_dma_buffer(I2S_NUM_0);
  delay(350);
  for (int i = 0; i < 4; ++i) readStereoFrames(FRAME_SAMPLES);
  micActiveSlot = detectActiveMicSlot();
  micDcReady = false; micPeak = 0; micSquareTotal = 0; micSampleCount = 0;
  Serial.printf("I2S_READY rate=8000 frame_ms=%u bits=32 channel=stereo active_slot=%d pins_bclk=14 ws=15 data=32\n", FRAME_MS, micActiveSlot);
}

static bool ensureBluetooth() {
  if (SerialBT.connected()) return true;
  for (int attempt = 0; attempt < 12; ++attempt) {
    Serial.printf("BT_CONNECT attempt=%d/12 target=%02X:%02X:%02X:%02X:%02X:%02X\n", attempt + 1,
      btAddress[0], btAddress[1], btAddress[2], btAddress[3], btAddress[4], btAddress[5]);
    if (SerialBT.connect(btAddress)) {
      Serial.println("BT_CONNECTED");
      return true;
    }
    delay(1000);
  }
  return false;
}

static void provision() {
  char kh[33], sh[17], mac[18], suite[8];
  int fields = sscanf(configLine, "CFG SENDER %32s %16s %17s %7s", kh, sh, mac, suite);
  if (fields != 4) { Serial.printf("ERR_CFG_SENDER_FIELDS parsed=%d line_bytes=%u\n", fields, (unsigned)strlen(configLine)); return; }
  if (strlen(kh) != 32) { Serial.printf("ERR_CFG_SENDER_KEY_LENGTH chars=%u\n", (unsigned)strlen(kh)); return; }
  if (!hexParse(kh, keyBytes, 16)) { Serial.println("ERR_CFG_SENDER_KEY_HEX"); return; }
  if (strlen(sh) != 16) { Serial.printf("ERR_CFG_SENDER_SESSION_LENGTH chars=%u\n", (unsigned)strlen(sh)); return; }
  if (!hexParse(sh, sessionId, 8)) { Serial.println("ERR_CFG_SENDER_SESSION_HEX"); return; }
  if (!parseMac(mac, btAddress)) { Serial.println("ERR_CFG_SENDER_BT_MAC"); return; }
  if (strcmp(suite, "CAALC") && strcmp(suite, "ASCON")) { Serial.printf("ERR_CFG_SENDER_SUITE value=%s\n", suite); return; }
  algorithmId = !strcmp(suite, "ASCON") ? 1 : 0;
  Serial.printf("CFG_SENDER_OK suite=%s bt_mac=%s key_and_session_redacted=1\n", suite, mac);
  Serial.println("BT_MASTER_BEGIN");
  if (!SerialBT.begin("CAALC-ESP32-A", true)) halt("ERR Bluetooth master init");
  memset(kh, 0, sizeof(kh)); memset(sh, 0, sizeof(sh));
  if (!ensureBluetooth()) halt("ERR Bluetooth peer connection");
  memset(configLine, 0, sizeof(configLine)); configLen = 0;
  startMic(); sequence = 0; configured = true; running = true;
  // The fresh traffic key stays in RAM for this boot/session only.
  Serial.printf("READY SENDER suite=%s rate=8000 frame_ms=%u mic_slot=%d\n", suite, FRAME_MS, micActiveSlot);
}

static bool writeAllBt(const uint8_t *data, size_t length) {
  size_t offset = 0; uint32_t start = millis();
  while (offset < length && millis() - start < 1500) {
    if (!SerialBT.connected()) return false;
    size_t n = SerialBT.write(data + offset, length - offset);
    offset += n;
    if (!n) delay(1);
  }
  return offset == length;
}

static void sendFrame() {
  if (sequence >= 0x100000000ULL) halt("ERR session exhausted; use fresh key/session after reboot");
  memcpy(packet, "CAP1", 4); packet[4] = 1; packet[5] = algorithmId;
  memcpy(packet + 6, sessionId, 8); caalc::store64(packet + 14, sequence);
  packet[22] = 0x40; packet[23] = 0x1f;
  packet[24] = (uint8_t)FRAME_MS; packet[25] = 0;
  packet[26] = (uint8_t)PCM_BYTES; packet[27] = (uint8_t)(PCM_BYTES >> 8);
  uint8_t nonce[16]; memcpy(nonce, sessionId, 8); caalc::store64(nonce + 8, sequence);
  uint32_t begin = micros();
  if (algorithmId == 0) {
    // The tag follows the ciphertext. Keep this derived from PCM_BYTES so a
    // frame-duration change cannot silently leave the tag at an old offset.
    if (!caalc::crypt(keyBytes, nonce, pcm, sizeof(pcm), packet, 28,
                      packet + 28, packet + 28 + PCM_BYTES))
      halt("ERR CAALC encryption");
  } else {
    unsigned long long clen = 0;
    if (crypto_aead_encrypt(packet + 28, &clen, pcm, sizeof(pcm), packet, 28, NULL, nonce, keyBytes) != 0 || clen != PCM_BYTES + 16)
      halt("ERR Ascon encryption");
  }
  uint32_t elapsed = micros() - begin;
  cryptoTotalUs += elapsed; if (elapsed > cryptoMaxUs) cryptoMaxUs = elapsed;

  uint8_t framed[FRAMED_BYTES] = {'C','B','T','1',
    (uint8_t)PACKET_BYTES, (uint8_t)(PACKET_BYTES >> 8)};
  memcpy(framed + 6, packet, sizeof(packet));
  if (!writeAllBt(framed, sizeof(framed))) {
    ++lostFrames; ++sequence;
    if (lostFrames == 1 || lostFrames % 10 == 0) Serial.printf("BT_FRAME_WRITE_FAILED lost=%lu\n", (unsigned long)lostFrames);
    return;
  }
  ++sequence; ++frameCount;
  ++sentFrames;
  if (frameCount % 100 == 0) {
    uint32_t micRms = micSampleCount ? (uint32_t)sqrt((double)micSquareTotal / micSampleCount) : 0;
    Serial.printf("STAT frames=%lu lost=%lu enc_mean_us=%lu enc_max_us=%lu mic_slot=%d mic_peak=%lu mic_rms=%lu i2s_errors=%lu heap=%lu\n",
      (unsigned long)frameCount, (unsigned long)lostFrames,
      (unsigned long)(cryptoTotalUs / frameCount), (unsigned long)cryptoMaxUs,
      micActiveSlot, (unsigned long)micPeak, (unsigned long)micRms,
      (unsigned long)micReadErrors,
      (unsigned long)ESP.getFreeHeap());
    micPeak = 0; micSquareTotal = 0; micSampleCount = 0;
  }
}

static void checkStop() {
  static char cmd[16]; static size_t n = 0;
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\n') {
      cmd[n] = 0;
      if (!strcmp(cmd, "STOP")) {
        running = false; i2s_driver_uninstall(I2S_NUM_0);
        memset(keyBytes, 0, sizeof(keyBytes)); memset(sessionId, 0, sizeof(sessionId));
        Serial.printf("STOPPED frames=%lu lost=%lu\n", (unsigned long)frameCount, (unsigned long)lostFrames);
      } else if (!strcmp(cmd, "STATUS")) {
        Serial.printf("SENDER_STATUS sent_frames=%lu lost_frames=%lu enc_mean_us=%lu mic_peak=%lu mic_rms=%lu i2s_errors=%lu\n",
          (unsigned long)sentFrames, (unsigned long)lostFrames,
          (unsigned long)(frameCount ? cryptoTotalUs / frameCount : 0),
          (unsigned long)micPeak,
          (unsigned long)(micSampleCount ? sqrt((double)micSquareTotal / micSampleCount) : 0),
          (unsigned long)micReadErrors);
      } else if (!strcmp(cmd, "RESET")) {
        Serial.println("RESETTING role=sender"); Serial.flush(); delay(100); ESP.restart();
      }
      n = 0;
    } else if (c != '\r' && n < sizeof(cmd) - 1) cmd[n++] = c;
  }
}

void setup() {
  Serial.begin(115200); Serial.setTimeout(100); delay(500);
  Serial.printf("BOOT role=sender fw=%s baud=115200 chip=%s free_heap=%lu\n",
    FW_VERSION, ESP.getChipModel(), (unsigned long)ESP.getFreeHeap());
  Serial.println("CAALC_SELFTEST_BEGIN");
  uint32_t s[12] = {}, z[12] = {}; caalc::perm(s); caalc::perm(s, true);
  if (memcmp(s, z, sizeof(s))) halt("ERR CAALC inverse selftest");
  Serial.println("CAALC_SELFTEST_PASS");
  Serial.println("CAALC ESP32 A ready; waiting for trusted USB configuration and fresh session");
}

void loop() {
  if (!configured) {
    while (Serial.available()) {
      char c = (char)Serial.read();
      if (c == '\n') {
        configLine[configLen] = 0;
        if (!strcmp(configLine, "RESET")) {
          Serial.println("RESETTING role=sender"); Serial.flush(); delay(100); ESP.restart();
        }
        Serial.printf("SERIAL_CONFIG_RECEIVED bytes=%u role=sender\n", (unsigned)configLen);
        provision(); configLen = 0; break;
      }
      if (c != '\r') { if (configLen >= sizeof(configLine) - 1) { configLen = 0; Serial.println("ERR_CFG_SENDER_LINE_TOO_LONG"); } else configLine[configLen++] = c; }
    }
    delay(1); return;
  }
  checkStop();
  if (!running) { delay(10); return; }
  if (!ensureBluetooth()) halt("ERR Bluetooth reconnect");
  size_t frames = readStereoFrames(FRAME_SAMPLES);
  if (frames != FRAME_SAMPLES) return;
  for (unsigned i = 0; i < FRAME_SAMPLES; ++i) {
    int16_t value = microphonePcm16(stereoSamples[2 * i + micActiveSlot]);
    pcm[2 * i] = (uint8_t)value; pcm[2 * i + 1] = (uint8_t)((uint16_t)value >> 8);
  }
  sendFrame();
}

/*
 * INMP441 USB recorder for ESP32 DevKit V1.
 *
 * Wiring:
 *   SCK/BCLK -> GPIO14
 *   WS/LRCL  -> GPIO15
 *   SD/DOUT  -> GPIO32
 *   L/R      -> GND
 *   VDD      -> 3V3
 *   GND      -> GND
 *
 * USB protocol at 921600 baud:
 *   RECORD <milliseconds>\n
 *   AUDIO_BEGIN <rate> <sample_count> 4 <active_slot>\n
 *   <sample_count little-endian signed int32 I2S words>
 *   \nAUDIO_END samples=<n> read_errors=<n>\n
 *
 * The laptop performs DC removal, gain and WAV conversion. Sending the
 * original 32-bit I2S word avoids throwing away quiet microphone data.
 */
#include <Arduino.h>
#include <driver/i2s.h>

namespace {

constexpr i2s_port_t kMicPort = I2S_NUM_0;
constexpr int kSampleRate = 16000;
constexpr int kBclkPin = 14;
constexpr int kWsPin = 15;
constexpr int kDataPin = 32;
constexpr size_t kFramesPerBlock = 256;
constexpr uint32_t kReadTimeoutMs = 1000;
constexpr uint32_t kMaxConsecutiveReadFailures = 4;
constexpr uint32_t kSerialWriteTimeoutMs = 2000;

int32_t g_stereoWords[kFramesPerBlock * 2];
int32_t g_monoWords[kFramesPerBlock];
int g_activeSlot = 0;
uint32_t g_totalReadErrors = 0;

void fatal(const char *stage, const esp_err_t error) {
  Serial.printf("FATAL stage=%s esp_err=%d name=%s\n", stage, (int)error,
                esp_err_to_name(error));
  while (true) delay(1000);
}

size_t readStereoFrames(const size_t requestedFrames) {
  size_t bytesRead = 0;
  const esp_err_t error = i2s_read(
      kMicPort, g_stereoWords, requestedFrames * 2 * sizeof(int32_t),
      &bytesRead, pdMS_TO_TICKS(kReadTimeoutMs));

  if (error != ESP_OK || bytesRead == 0 ||
      (bytesRead % (2 * sizeof(int32_t))) != 0) {
    ++g_totalReadErrors;
    return 0;
  }
  return bytesRead / (2 * sizeof(int32_t));
}

void startMicrophone() {
  i2s_config_t config = {};
  config.mode = static_cast<i2s_mode_t>(I2S_MODE_MASTER | I2S_MODE_RX);
  config.sample_rate = kSampleRate;
  config.bits_per_sample = I2S_BITS_PER_SAMPLE_32BIT;
  config.channel_format = I2S_CHANNEL_FMT_RIGHT_LEFT;
  config.communication_format = I2S_COMM_FORMAT_STAND_I2S;
  config.intr_alloc_flags = ESP_INTR_FLAG_LEVEL1;
  config.dma_buf_count = 8;
  config.dma_buf_len = 256;
  config.use_apll = false;
  config.tx_desc_auto_clear = false;
  config.fixed_mclk = 0;

  i2s_pin_config_t pins = {};
  pins.bck_io_num = kBclkPin;
  pins.ws_io_num = kWsPin;
  pins.data_out_num = I2S_PIN_NO_CHANGE;
  pins.data_in_num = kDataPin;
  pins.mck_io_num = I2S_PIN_NO_CHANGE;

  esp_err_t error = i2s_driver_install(kMicPort, &config, 0, nullptr);
  if (error != ESP_OK) fatal("driver_install", error);
  error = i2s_set_pin(kMicPort, &pins);
  if (error != ESP_OK) fatal("set_pin", error);
  error = i2s_zero_dma_buffer(kMicPort);
  if (error != ESP_OK) fatal("zero_dma", error);

  // INMP441 startup data is not valid until it has received enough clocks.
  delay(350);
  for (int i = 0; i < 4; ++i) readStereoFrames(kFramesPerBlock);
}

int detectActiveSlot() {
  uint64_t activity[2] = {0, 0};
  int32_t previous[2] = {0, 0};
  bool havePrevious = false;

  for (int block = 0; block < 8; ++block) {
    const size_t frames = readStereoFrames(kFramesPerBlock);
    for (size_t frame = 0; frame < frames; ++frame) {
      for (int slot = 0; slot < 2; ++slot) {
        const int32_t value = g_stereoWords[frame * 2 + slot];
        if (havePrevious) {
          int64_t difference = static_cast<int64_t>(value) - previous[slot];
          if (difference < 0) difference = -difference;
          activity[slot] += static_cast<uint64_t>(difference);
        }
        previous[slot] = value;
      }
      havePrevious = true;
    }
  }

  const int selected = activity[1] > activity[0] ? 1 : 0;
  Serial.printf("CHANNEL_DETECT slot0_activity=%llu slot1_activity=%llu selected=%d\n",
                (unsigned long long)activity[0],
                (unsigned long long)activity[1], selected);
  return selected;
}

bool writeAll(const uint8_t *data, const size_t length) {
  size_t sent = 0;
  const uint32_t startedMs = millis();
  while (sent < length) {
    const size_t written = Serial.write(data + sent, length - sent);
    if (written == 0) {
      if (millis() - startedMs >= kSerialWriteTimeoutMs) return false;
      delay(1);
      continue;
    }
    sent += written;
  }
  return true;
}

void recordAudio(uint32_t milliseconds) {
  milliseconds = constrain(milliseconds, 500U, 10000U);
  const uint32_t totalSamples =
      (static_cast<uint32_t>(kSampleRate) * milliseconds) / 1000U;
  const uint32_t errorsBefore = g_totalReadErrors;
  const uint32_t startedMs = millis();

  Serial.printf("AUDIO_BEGIN %d %lu 4 %d\n", kSampleRate,
                (unsigned long)totalSamples, g_activeSlot);
  Serial.flush();

  uint32_t sentSamples = 0;
  uint32_t consecutiveReadFailures = 0;
  while (sentSamples < totalSamples) {
    const size_t requested =
        min(static_cast<uint32_t>(kFramesPerBlock), totalSamples - sentSamples);
    const size_t frames = readStereoFrames(requested);
    if (frames == 0) {
      if (++consecutiveReadFailures >= kMaxConsecutiveReadFailures) {
        Serial.printf("\nAUDIO_ERROR reason=i2s_read samples=%lu read_errors=%lu\n",
                      (unsigned long)sentSamples,
                      (unsigned long)(g_totalReadErrors - errorsBefore));
        return;
      }
      continue;
    }
    consecutiveReadFailures = 0;

    for (size_t frame = 0; frame < frames; ++frame) {
      g_monoWords[frame] = g_stereoWords[frame * 2 + g_activeSlot];
    }
    if (!writeAll(reinterpret_cast<const uint8_t *>(g_monoWords),
                  frames * sizeof(int32_t))) {
      Serial.printf("\nAUDIO_ERROR reason=serial_write samples=%lu\n",
                    (unsigned long)sentSamples);
      return;
    }
    sentSamples += frames;
  }

  Serial.printf("\nAUDIO_END samples=%lu read_errors=%lu elapsed_ms=%lu\n",
                (unsigned long)sentSamples,
                (unsigned long)(g_totalReadErrors - errorsBefore),
                (unsigned long)(millis() - startedMs));
  Serial.flush();
}

void printLevel() {
  const size_t frames = readStereoFrames(kFramesPerBlock);
  if (frames == 0) {
    Serial.printf("LEVEL read_error total=%lu\n",
                  (unsigned long)g_totalReadErrors);
    return;
  }

  int32_t minimum = INT32_MAX;
  int32_t maximum = INT32_MIN;
  for (size_t frame = 0; frame < frames; ++frame) {
    const int32_t sample24 =
        g_stereoWords[frame * 2 + g_activeSlot] >> 8;
    minimum = min(minimum, sample24);
    maximum = max(maximum, sample24);
  }
  Serial.printf("LEVEL slot=%d span24=%ld read_errors=%lu\n", g_activeSlot,
                (long)(maximum - minimum),
                (unsigned long)g_totalReadErrors);
}

}  // namespace

void setup() {
  Serial.begin(921600);
  Serial.setTimeout(100);
  delay(600);

  Serial.println();
  Serial.println("MIC_RECORDER_BOOT");
  startMicrophone();
  g_activeSlot = detectActiveSlot();
  Serial.printf(
      "MIC_TEST_READY rate=%d bclk=%d ws=%d data=%d active_slot=%d "
      "sample_bytes=4 baud=921600\n",
      kSampleRate, kBclkPin, kWsPin, kDataPin, g_activeSlot);
}

void loop() {
  if (Serial.available()) {
    String command = Serial.readStringUntil('\n');
    command.trim();
    command.toUpperCase();
    if (command.startsWith("RECORD ")) {
      recordAudio(static_cast<uint32_t>(command.substring(7).toInt()));
      return;
    }
    if (command == "STATUS") {
      Serial.printf("STATUS active_slot=%d read_errors=%lu\n", g_activeSlot,
                    (unsigned long)g_totalReadErrors);
      return;
    }
    if (command.length() != 0) {
      Serial.printf("UNKNOWN_COMMAND value=%s\n", command.c_str());
    }
  }

  static uint32_t lastLevelMs = 0;
  const uint32_t now = millis();
  if (now - lastLevelMs >= 500) {
    printLevel();
    lastLevelMs = now;
  } else {
    // Keep draining I2S so the next level/recording starts with fresh samples.
    readStereoFrames(kFramesPerBlock);
  }
}

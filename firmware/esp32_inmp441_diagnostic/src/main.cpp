/*
 * Standalone INMP441 diagnostic for an ESP32 DevKit V1.
 *
 * Wiring:
 *   INMP441 SCK/BCLK -> GPIO14
 *   INMP441 WS/LRCL  -> GPIO15
 *   INMP441 SD/DOUT  -> GPIO32
 *   INMP441 L/R      -> GND (left channel)
 *   INMP441 VDD      -> 3V3
 *   INMP441 GND      -> GND
 *
 * This firmware deliberately avoids WAV conversion, Bluetooth, Wi-Fi and
 * encryption. It reads the microphone's native 32-bit I2S slots, reports
 * raw and signed-24-bit statistics, and can emit throttled plot samples.
 */
#include <Arduino.h>
#include <driver/i2s.h>
#include <math.h>

namespace {

constexpr i2s_port_t kI2sPort = I2S_NUM_0;
constexpr int kSampleRate = 16000;
constexpr int kBclkPin = 14;
constexpr int kWsPin = 15;
constexpr int kDataPin = 32;
constexpr size_t kFramesPerBlock = 512;
constexpr size_t kWordsPerBlock = kFramesPerBlock * 2;
constexpr uint32_t kReadTimeoutMs = 1000;
constexpr uint32_t kReportIntervalMs = 500;

int32_t g_samples[kWordsPerBlock];
bool g_plotMode = false;
uint32_t g_readErrors = 0;
uint32_t g_shortReads = 0;
uint32_t g_blocks = 0;

void haltWithError(const char *stage, esp_err_t error) {
  Serial.printf("FATAL stage=%s esp_err=%d name=%s\n", stage, (int)error,
                esp_err_to_name(error));
  while (true) {
    delay(1000);
  }
}

void startMicrophone() {
  i2s_config_t config = {};
  config.mode = static_cast<i2s_mode_t>(I2S_MODE_MASTER | I2S_MODE_RX);
  config.sample_rate = kSampleRate;
  config.bits_per_sample = I2S_BITS_PER_SAMPLE_32BIT;
  // Read both slots. This makes a wrong/floating L/R connection visible
  // instead of silently diagnosing the unused slot as a dead microphone.
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

  esp_err_t error = i2s_driver_install(kI2sPort, &config, 0, nullptr);
  if (error != ESP_OK) haltWithError("driver_install", error);

  error = i2s_set_pin(kI2sPort, &pins);
  if (error != ESP_OK) haltWithError("set_pin", error);

  error = i2s_zero_dma_buffer(kI2sPort);
  if (error != ESP_OK) haltWithError("zero_dma", error);

  // Discard startup data after allowing the microphone clocks to stabilize.
  delay(50);
  size_t ignored = 0;
  i2s_read(kI2sPort, g_samples, sizeof(g_samples), &ignored,
           pdMS_TO_TICKS(kReadTimeoutMs));
}

bool readSamples(size_t &samplesRead) {
  size_t bytesRead = 0;
  const esp_err_t error =
      i2s_read(kI2sPort, g_samples, sizeof(g_samples), &bytesRead,
               pdMS_TO_TICKS(kReadTimeoutMs));

  if (error != ESP_OK) {
    ++g_readErrors;
    Serial.printf("I2S_READ_ERROR esp_err=%d name=%s total=%lu\n", (int)error,
                  esp_err_to_name(error), (unsigned long)g_readErrors);
    samplesRead = 0;
    return false;
  }

  if (bytesRead == 0 || (bytesRead % sizeof(int32_t)) != 0) {
    ++g_shortReads;
    Serial.printf("I2S_BAD_LENGTH bytes=%u total=%lu\n", (unsigned)bytesRead,
                  (unsigned long)g_shortReads);
    samplesRead = 0;
    return false;
  }

  samplesRead = bytesRead / sizeof(int32_t);
  if (samplesRead != kWordsPerBlock) ++g_shortReads;
  ++g_blocks;
  return true;
}

void printSlotStatistics(const size_t count, const size_t slot) {
  int32_t rawMin = INT32_MAX;
  int32_t rawMax = INT32_MIN;
  int32_t sample24Min = INT32_MAX;
  int32_t sample24Max = INT32_MIN;
  int64_t sum = 0;
  long double sumSquares = 0.0;
  uint32_t zeroSamples = 0;
  uint32_t changedSamples = 0;
  uint32_t lowByteNonzero = 0;

  const size_t frames = count / 2;
  int32_t previous = g_samples[slot];
  for (size_t frame = 0; frame < frames; ++frame) {
    const size_t i = frame * 2 + slot;
    const int32_t raw = g_samples[i];
    // INMP441 data is signed 24-bit, MSB first, in a 32-bit I2S slot.
    const int32_t sample24 = raw >> 8;

    rawMin = min(rawMin, raw);
    rawMax = max(rawMax, raw);
    sample24Min = min(sample24Min, sample24);
    sample24Max = max(sample24Max, sample24);
    sum += sample24;
    sumSquares += static_cast<long double>(sample24) * sample24;
    if (raw == 0) ++zeroSamples;
    if (frame != 0 && raw != previous) ++changedSamples;
    if ((static_cast<uint32_t>(raw) & 0xFFU) != 0) ++lowByteNonzero;
    previous = raw;
  }

  const double mean = static_cast<double>(sum) / frames;
  const double rms = sqrt(static_cast<double>(sumSquares / frames));
  double variance = static_cast<double>(sumSquares / frames) - mean * mean;
  if (variance < 0.0) variance = 0.0;
  const double acRms = sqrt(variance);
  const double acPeak = max(fabs(static_cast<double>(sample24Min) - mean),
                            fabs(static_cast<double>(sample24Max) - mean));
  const int64_t span24 = static_cast<int64_t>(sample24Max) - sample24Min;
  const char *state = "RESPONDING";
  if (zeroSamples == frames) {
    state = "ALL_ZERO";
  } else if (changedSamples < frames / 20) {
    state = "STUCK_OR_WEAK";
  }

  Serial.printf(
      "SLOT slot=%u state=%s frames=%u raw_min=%ld raw_max=%ld "
      "sample24_min=%ld "
      "sample24_max=%ld span24=%lld mean=%.1f rms=%.1f ac_rms=%.1f "
      "ac_peak=%.1f zeros=%lu "
      "changes=%lu low8_nonzero=%lu blocks=%lu read_errors=%lu "
      "short_reads=%lu first_hex=%08lx\n",
      (unsigned)slot, state, (unsigned)frames, (long)rawMin, (long)rawMax,
      (long)sample24Min, (long)sample24Max, (long long)span24, mean, rms,
      acRms, acPeak,
      (unsigned long)zeroSamples, (unsigned long)changedSamples,
      (unsigned long)lowByteNonzero, (unsigned long)g_blocks,
      (unsigned long)g_readErrors, (unsigned long)g_shortReads,
      (unsigned long)static_cast<uint32_t>(g_samples[slot]));
}

void printStatistics(const size_t count) {
  printSlotStatistics(count, 0);
  printSlotStatistics(count, 1);
}

void processSerialCommand() {
  if (!Serial.available()) return;

  String command = Serial.readStringUntil('\n');
  command.trim();
  command.toUpperCase();

  if (command == "PLOT") {
    g_plotMode = true;
    Serial.println("MODE PLOT; send DIAG to return to statistics");
  } else if (command == "DIAG") {
    g_plotMode = false;
    Serial.println("MODE DIAG");
  } else if (command == "HELP") {
    Serial.println("COMMANDS: PLOT, DIAG, HELP");
  } else if (command.length() != 0) {
    Serial.printf("UNKNOWN_COMMAND value=%s\n", command.c_str());
  }
}

}  // namespace

void setup() {
  Serial.begin(115200);
  Serial.setTimeout(50);
  delay(500);

  Serial.println();
  Serial.println("INMP441_DIAGNOSTIC_BOOT");
  Serial.printf(
      "CONFIG rate=%d bits=32 format=I2S channel=BOTH bclk=%d ws=%d data=%d "
      "lr_pin=GND baud=115200\n",
      kSampleRate, kBclkPin, kWsPin, kDataPin);

  startMicrophone();
  Serial.println("INMP441_DIAGNOSTIC_READY; clap or whistle near the microphone");
  Serial.println("COMMANDS: PLOT, DIAG, HELP");
}

void loop() {
  processSerialCommand();

  size_t samplesRead = 0;
  if (!readSamples(samplesRead)) return;

  if (g_plotMode) {
    // Throttle to 1/16 of the 16 kHz stream so 115200-baud serial cannot
    // starve I2S DMA. The label works with common serial plotters.
    for (size_t frame = 0; frame < samplesRead / 2; frame += 32) {
      const size_t i = frame * 2;
      Serial.printf("slot0:%ld,slot1:%ld\n", (long)(g_samples[i] >> 8),
                    (long)(g_samples[i + 1] >> 8));
    }
    return;
  }

  static uint32_t lastReportMs = 0;
  const uint32_t now = millis();
  if (now - lastReportMs >= kReportIntervalMs) {
    printStatistics(samplesRead);
    lastReportMs = now;
  }
}

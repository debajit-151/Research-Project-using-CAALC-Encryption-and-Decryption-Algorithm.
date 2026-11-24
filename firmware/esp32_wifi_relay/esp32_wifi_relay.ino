/*
 * CAALC audio relay, ESP32 B.
 * Receives length-delimited authenticated packets over Bluetooth Classic SPP and forwards
 * them unchanged over Wi-Fi UDP to the laptop. It never receives the session key and cannot
 * decrypt or release audio. Configuration: CFG RELAY <ssid-hex> <password-hex-or-> <laptop-ip> <udp-port>
 */
#include <Arduino.h>
#include <BluetoothSerial.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <esp_mac.h>
#include <freertos/stream_buffer.h>
#if !defined(CONFIG_BT_ENABLED) || !defined(CONFIG_BLUEDROID_ENABLED) || !defined(CONFIG_BT_SPP_ENABLED)
#error "Bluetooth Classic SPP requires the original ESP32 with Bluetooth enabled."
#endif

BluetoothSerial SerialBT;
WiFiUDP udp;
static char configLine[320]; static size_t configLen = 0;
static char ssid[33], password[64];
static IPAddress laptop; static uint16_t laptopPort = 5005;
static uint8_t rx[4096]; static size_t rxLen = 0;
static constexpr size_t BT_STREAM_BYTES = 16384;
static StreamBufferHandle_t btStream = nullptr;
static volatile uint32_t btOverflowBytes = 0;
static uint32_t forwarded = 0, invalidFrames = 0, udpErrors = 0, lastBtByteAt = 0;
static bool ready = false;
static const char *FW_VERSION = "relay-20261122.2";

static void receiveBluetoothData(const uint8_t *data, size_t length) {
  if (!btStream || !length) return;
  size_t written = xStreamBufferSend(btStream, data, length, 0);
  if (written < length) btOverflowBytes += (uint32_t)(length - written);
}

static void halt(const char *msg) {
  Serial.printf("FATAL %s\n", msg); ready = false;
  char command[8] = {}; size_t n = 0;
  while (true) {
    while (Serial.available()) {
      char c = (char)Serial.read();
      if (c == '\n') {
        command[n] = 0;
        if (!strcmp(command, "RESET")) { Serial.println("RESETTING role=relay"); Serial.flush(); delay(100); ESP.restart(); }
        n = 0;
      } else if (c != '\r' && n < sizeof(command)-1) command[n++] = c;
    }
    delay(50);
  }
}

static bool hexText(const char *src, char *dst, size_t cap, bool allowEmpty) {
  if (!strcmp(src, "-")) { if (!allowEmpty) return false; dst[0] = 0; return true; }
  size_t n = strlen(src); if ((n & 1) || n / 2 >= cap) return false;
  for (size_t i = 0; i < n / 2; ++i) {
    auto digit = [](char c)->int { if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; };
    int a = digit(src[2*i]), b = digit(src[2*i+1]); if (a < 0 || b < 0) return false;
    dst[i] = (char)((a << 4) | b);
  }
  dst[n / 2] = 0; return true;
}

static bool validPacket(const uint8_t *p, uint16_t n) {
  if (n < 44 || memcmp(p, "CAP1", 4) || p[4] != 1 || p[5] > 1) return false;
  uint16_t rate = (uint16_t)p[22] | ((uint16_t)p[23] << 8);
  uint16_t ms = (uint16_t)p[24] | ((uint16_t)p[25] << 8);
  uint16_t payload = (uint16_t)p[26] | ((uint16_t)p[27] << 8);
  return rate == 8000 && ms == 40 && payload == 640 && n == (uint16_t)(44 + payload);
}

static void provision() {
  char ssidHex[66], passHex[130], host[32]; unsigned port;
  int fields = sscanf(configLine, "CFG RELAY %65s %129s %31s %u", ssidHex, passHex, host, &port);
  if (fields != 4) { Serial.printf("ERR_CFG_RELAY_FIELDS parsed=%d line_bytes=%u\n", fields, (unsigned)strlen(configLine)); return; }
  if (!hexText(ssidHex, ssid, sizeof(ssid), false)) { Serial.println("ERR_CFG_RELAY_SSID_ENCODING"); return; }
  if (!hexText(passHex, password, sizeof(password), true)) { Serial.println("ERR_CFG_RELAY_PASSWORD_ENCODING"); return; }
  if (strlen(ssid) > 32 || strlen(password) > 63) { Serial.println("ERR_CFG_RELAY_CREDENTIAL_LENGTH"); return; }
  if (port < 1 || port > 65535) { Serial.printf("ERR_CFG_RELAY_UDP_PORT value=%u\n", port); return; }
  if (!laptop.fromString(host)) { Serial.println("ERR_CFG_RELAY_LAPTOP_IP"); return; }
  laptopPort = (uint16_t)port;
  Serial.printf("CFG_RELAY_OK ssid_bytes=%u password_present=%u laptop_ip=%s udp_port=%u\n",
    (unsigned)strlen(ssid), password[0] ? 1 : 0, laptop.toString().c_str(), laptopPort);
  WiFi.mode(WIFI_STA);
  // ESP32 Classic Bluetooth and Wi-Fi share one 2.4 GHz radio. Arduino-ESP32
  // 2.0.17/IDF 4.4 aborts in coex_core_enable when Bluetooth is enabled after
  // WIFI_PS_NONE. Keep MIN_MODEM enabled so the coexistence scheduler can
  // safely time-slice both links.
  WiFi.setSleep(true);
  Serial.printf("WIFI_COEX_POWER_SAVE mode=%d\n", (int)WiFi.getSleep());
  Serial.println("WIFI_BEGIN");
  WiFi.begin(ssid, password);
  uint32_t started = millis();
  uint32_t lastLog = 0;
  while (WiFi.status() != WL_CONNECTED && millis() - started < 30000) {
    if (millis() - lastLog >= 3000) {
      Serial.printf("WIFI_WAIT status=%d elapsed_ms=%lu\n", (int)WiFi.status(), (unsigned long)(millis() - started));
      lastLog = millis();
    }
    delay(100);
  }
  if (WiFi.status() != WL_CONNECTED) {
    Serial.printf("WIFI_FAILED status=%d elapsed_ms=%lu\n", (int)WiFi.status(), (unsigned long)(millis() - started));
    halt("ERR Wi-Fi connection; check 2.4 GHz network/password");
  }
  Serial.printf("WIFI_CONNECTED ip=%s rssi=%d\n", WiFi.localIP().toString().c_str(), WiFi.RSSI());
  Serial.println("BT_SPP_BEGIN");
  btStream = xStreamBufferCreate(BT_STREAM_BYTES, 1);
  if (!btStream) halt("ERR Bluetooth receive buffer allocation");
  // BluetoothSerial's built-in RX queue is only 512 bytes, smaller than one
  // 690-byte authenticated audio frame. The data callback bypasses that queue
  // and absorbs radio/coexistence bursts in a 16 KiB stream buffer.
  SerialBT.onData(receiveBluetoothData);
  if (!SerialBT.begin("CAALC-ESP32-B", false)) halt("ERR Bluetooth SPP server init");
  Serial.println("BT_SPP_READY");
  uint8_t mac[6]; if (esp_read_mac(mac, ESP_MAC_BT) != ESP_OK) halt("ERR Bluetooth MAC read");
  memset(password, 0, sizeof(password)); memset(passHex, 0, sizeof(passHex));
  memset(configLine, 0, sizeof(configLine)); configLen = 0;
  ready = true;
  Serial.printf("READY RELAY IP=%s BT_MAC=%02X:%02X:%02X:%02X:%02X:%02X UDP=%u\n",
    WiFi.localIP().toString().c_str(), mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], laptopPort);
}

static int findMagic() {
  for (size_t i = 0; i + 4 <= rxLen; ++i)
    if (rx[i]=='C' && rx[i+1]=='B' && rx[i+2]=='T' && rx[i+3]=='1') return (int)i;
  return -1;
}

static void parseFrames() {
  while (true) {
    int at = findMagic();
    if (at < 0) { if (rxLen > 3) { memmove(rx, rx + rxLen - 3, 3); rxLen = 3; } return; }
    if (at > 0) { memmove(rx, rx + at, rxLen - at); rxLen -= (size_t)at; }
    if (rxLen < 6) return;
    uint16_t n = (uint16_t)rx[4] | ((uint16_t)rx[5] << 8);
    if (n < 44 || n > 1324) { memmove(rx, rx + 1, --rxLen); ++invalidFrames; continue; }
    if (rxLen < (size_t)(6 + n)) return;
    if (!validPacket(rx + 6, n)) {
      memmove(rx, rx + 6 + n, rxLen - 6 - n); rxLen -= 6 + n; ++invalidFrames; continue;
    }
    if (!udp.beginPacket(laptop, laptopPort) || udp.write(rx + 6, n) != n || !udp.endPacket()) ++udpErrors;
    else ++forwarded;
    memmove(rx, rx + 6 + n, rxLen - 6 - n); rxLen -= 6 + n;
    if (forwarded && forwarded % 100 == 0)
      Serial.printf("RELAY_STAT forwarded=%lu invalid=%lu udp_errors=%lu bt_dropped_bytes=%lu rssi=%d heap=%lu\n",
        (unsigned long)forwarded, (unsigned long)invalidFrames, (unsigned long)udpErrors,
        (unsigned long)btOverflowBytes,
        WiFi.RSSI(), (unsigned long)ESP.getFreeHeap());
  }
}

void setup() {
  Serial.begin(115200); Serial.setTimeout(100); delay(500);
  Serial.printf("BOOT role=relay fw=%s baud=115200 chip=%s free_heap=%lu\n",
    FW_VERSION, ESP.getChipModel(), (unsigned long)ESP.getFreeHeap());
  Serial.println("CAALC ESP32 B relay ready; waiting for laptop Wi-Fi configuration");
}

void loop() {
  while (Serial.available()) {
    char c = (char)Serial.read();
    if (c == '\n') {
      configLine[configLen] = 0;
      if (!strcmp(configLine, "RESET")) {
        Serial.println("RESETTING role=relay"); Serial.flush(); delay(100); ESP.restart();
      }
      if (!ready) {
        Serial.printf("SERIAL_CONFIG_RECEIVED bytes=%u role=relay\n", (unsigned)configLen);
        provision();
      } else if (!strcmp(configLine, "STATUS")) {
        Serial.printf("RELAY_STATUS forwarded=%lu invalid=%lu udp_errors=%lu bt_dropped_bytes=%lu bt_buffered=%u rssi=%d rx_buffered=%u heap=%lu\n",
          (unsigned long)forwarded, (unsigned long)invalidFrames,
          (unsigned long)udpErrors, (unsigned long)btOverflowBytes,
          btStream ? (unsigned)xStreamBufferBytesAvailable(btStream) : 0,
          WiFi.RSSI(), (unsigned)rxLen,
          (unsigned long)ESP.getFreeHeap());
      } else if (configLen) {
        Serial.printf("ERR_RELAY_COMMAND_UNSUPPORTED bytes=%u\n", (unsigned)configLen);
      }
      configLen = 0; break;
    }
    if (c != '\r') {
      if (configLen >= sizeof(configLine)-1) { configLen = 0; Serial.println("ERR_CFG_RELAY_LINE_TOO_LONG"); }
      else configLine[configLen++] = c;
    }
  }
  if (!ready) { delay(1); return; }
  while (btStream && xStreamBufferBytesAvailable(btStream)) {
    if (rxLen == sizeof(rx)) {
      parseFrames();
      if (rxLen == sizeof(rx)) {
        Serial.println("BT_RX_BUFFER_FULL drop=1");
        rxLen = 0; ++invalidFrames;
      }
    }
    size_t room = sizeof(rx) - rxLen;
    size_t available = xStreamBufferBytesAvailable(btStream);
    size_t take = available < room ? available : room;
    if (take > 1024) take = 1024;
    size_t got = xStreamBufferReceive(btStream, rx + rxLen, take, 0);
    rxLen += got;
    if (got) lastBtByteAt = millis();
    if (!got) break;
    // Parse between chunks so a continuous Bluetooth producer cannot fill the
    // staging buffer before complete packets are forwarded.
    parseFrames();
  }
  if (rxLen && lastBtByteAt && millis() - lastBtByteAt > 500) { Serial.printf("BT_PARTIAL_FRAME_DROP bytes=%u\n", (unsigned)rxLen); rxLen = 0; ++invalidFrames; }
  parseFrames();
  delay(1);
}

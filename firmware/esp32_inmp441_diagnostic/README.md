# ESP32 DevKit V1 + INMP441 diagnostic

This standalone firmware tests the microphone before Bluetooth, Wi-Fi,
encryption, WAV conversion, or the dashboard are involved.

## Wiring

| INMP441 | ESP32 DevKit V1 |
| --- | --- |
| VDD | 3V3 |
| GND | GND |
| SCK / BCLK | GPIO14 |
| WS / LRCL | GPIO15 |
| SD / DOUT | GPIO32 |
| L/R | GND |

## PlatformIO

Open this directory as the PlatformIO project, or run:

```bash
cd /Users/yuvrajmehta/Documents/deb/firmware/esp32_inmp441_diagnostic
/Users/yuvrajmehta/.platformio/penv/bin/pio run -e esp32dev
/Users/yuvrajmehta/.platformio/penv/bin/pio run -e esp32dev -t upload --upload-port /dev/cu.usbserial-0001
/Users/yuvrajmehta/.platformio/penv/bin/pio device monitor --port /dev/cu.usbserial-0001 --baud 115200
```

Close every other serial monitor before uploading or monitoring.

## Reading the result

- `slot=0 state=RESPONDING`: the wired microphone channel is producing data.
- `slot=1 state=ALL_ZERO` or `STUCK_OR_WEAK`: expected with L/R connected to
  GND because only one I2S slot is driven.
- `read_errors=0 short_reads=0`: the ESP32 I2S/DMA reads are healthy.
- `ac_rms` and `ac_peak` should increase when you clap or whistle close to the
  microphone's acoustic port.
- Both slots showing only zero or one indicates that SD is not delivering
  microphone data; recheck VDD, GND, SD and L/R.

Type `PLOT` in a monitor that can send input to emit throttled plot samples.
Type `DIAG` to return to statistics, or `HELP` to list commands.

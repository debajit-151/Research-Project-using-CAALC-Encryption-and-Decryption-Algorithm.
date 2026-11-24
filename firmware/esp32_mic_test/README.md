# INMP441 USB recording test

This test follows the record-on-ESP32, save-WAV-on-laptop workflow of
[mmajjedi/usb-mic Stage 1](https://github.com/mmajjedi/usb-mic/tree/main/tools).
Its original sketch targets Arduino-ESP32 3.x. This project targets the
installed PlatformIO Arduino-ESP32 2.0.17 toolchain, reads both 32-bit I2S
slots, and selects the active microphone slot. It streams raw samples to the
laptop so `microphone_capture.py` can remove DC offset and create a WAV.

Wiring on the ESP32 DevKit V1: INMP441 SCK to GPIO14, WS to GPIO15,
SD to GPIO32, L/R to GND, VDD to 3V3, GND to GND.

To build without uploading:

```bash
cd /Users/yuvrajmehta/Documents/deb/firmware/esp32_mic_test
/Users/yuvrajmehta/.platformio/penv/bin/pio run -e esp32dev
```

When you are ready to upload, close the dashboard and any serial monitor
first. Upload only to the confirmed ESP32 serial port. After uploading,
run the browser recorder from the project root:

```bash
cd /Users/yuvrajmehta/Documents/deb
.venv/bin/python -m streamlit run microphone_test_dashboard.py --server.port 8502
```

Open `http://localhost:8502`, choose the ESP32 port, select five seconds,
then press **Record audio**. The page saves and plays the WAV. The selected
duration counts microphone samples; ESP32 reboot and USB transfer add time.
The report's `esp32_record_and_transfer_seconds` field measures the device
recording and transfer phase separately.

This test replaces the diagnostic firmware *only after you upload it*.

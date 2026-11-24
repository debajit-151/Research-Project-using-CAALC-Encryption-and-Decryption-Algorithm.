# Professor demo runbook

This runbook gives a repeatable software demonstration and the revised two-board live hardware extension. Show the Ascon path as the standardized AEAD comparison and label CAALC as an experimental research candidate.

## 1. Prepare the laptop

Run these commands from the project folder. Python 3.11 or newer and a C/C++ compiler are needed.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt -r requirements-dashboard.txt
python build_native.py
python -m pytest tests -q
```

Expected evidence: both native libraries compile and the tests pass. Record the actual test count and environment from that run; do not use an older verification count as a new result.

## 2. Show audio encryption and exact recovery

Create a reproducible sample and launch the dashboard:

```bash
python main.py demo
python main.py dashboard
```

Upload `results/original.wav`. Select **Ascon-AEAD128 (standardized)**, encrypt, inspect the ciphertext bytes, and download the encrypted container. Decrypt it and play the recovered WAV. The expected recovery metrics are 100% exact samples and MSE 0. Then repeat with **CAALC-128 (experimental)**. The ciphertext is binary data and is intentionally not presented as playable audio.

The dashboard also has a **Post-quantum authenticated session demo** panel. Run it once for each suite and show successful ML-KEM-512 agreement, ML-DSA-44 signature checks, key confirmation, audio round-trip and tamper rejection.

## 3. Show the session-to-packet handoff in software

Create a fresh authenticated demo session file, then use its key and session ID with the laptop packet receiver. The automated tests exercise this path for both ciphers. The file contains a cleartext key, is created only when requested, is owner-only on POSIX and is excluded from Git.

```bash
python -m pq_session --suite ascon --write-session results/ascon-demo.session.json
```

Expected evidence: both signatures verified, key confirmation verified, audio round-trip true, tampered audio rejected, and `key_material_written` true. The report deliberately does not print the traffic key. Keep the file private and generate a new one for each hardware boot/session.

## 4. Demonstrate the two-ESP32 live audio path

Flash the Bluetooth sender to ESP32 A and the Wi-Fi relay to ESP32 B as described in [HARDWARE.md](HARDWARE.md). Wire the INMP441 to A, place B and the laptop on the same 2.4 GHz Wi-Fi network, connect both USB cables to the laptop, and close both Serial Monitors. Start the dashboard:

```bash
python prepare_bluetooth.py
python -m streamlit run hardware_dashboard.py
```

Choose A's and B's serial ports, enter the Wi-Fi details and laptop IP, and start a short Ascon capture first. Speak into the microphone. Confirm A prints `MIC_CHANNEL_DETECT`, an active slot, nonzero `mic_peak`/`mic_rms`, and zero I2S errors. Show the dashboard's pipeline stages, authenticated/rejected frames, packet-loss estimate (available from the sender status counter), waveform, spectrogram, recovered audio player, local tamper check, network counters and downloadable report. Each successful capture is saved in `results/hardware_runs.json` for the CAALC vs Ascon comparison table and CSV/JSON exports. The dashboard saves both the authenticated raw PCM WAV and a conditioned playback WAV. Repeat with CAALC and clearly label it experimental. The laptop provisions a fresh session to A; B receives and forwards only ciphertext. Physical RF performance remains unverified until the actual two-radio run is recorded.

## 5. Explain the security boundary accurately

- CAALC is an experimental custom cipher. Correctness, KATs, statistical screening and tamper tests do not prove security.
- Ascon-AEAD128 is the standardized comparison implementation. Do not imply CAALC outperforms it unless the measured result supports that.
- The ML-KEM/ML-DSA handshake roles run in one laptop process for a repeatable academic demo. ESP32 A receives the selected key over trusted USB; it does not run the handshake or authenticate a remote network peer. ESP32 B is a ciphertext relay and never receives the key.
- Host benchmarks are not ESP32 performance measurements. Do not claim physical audio, microphone, Wi-Fi, timing, power or memory results until recorded from the board.

For the project scope, methodology, limitations and viva questions, use [ACADEMIC_REPORT.md](ACADEMIC_REPORT.md). For exact wiring, compile steps and acceptance criteria, use [HARDWARE.md](HARDWARE.md).

# CAALC-128: authenticated IoT audio research prototype

**Design and Implementation of a Lightweight Cellular Automata-Based Authenticated Cipher for Post-Quantum-Oriented Secure IoT Audio Communication**

Python 3.11+ • Windows/Linux/macOS laptop • 2 × ESP32 DevKit V1 (original ESP32) • INMP441 microphone • audio only.

This project contains an experimental custom Feistel/duplex cipher, an independently tested portable C++ implementation, lossless authenticated WAV containers, a Streamlit demonstration, ML-KEM-512/HKDF key establishment, the Ascon authors' final-standard reference implementation, and an ESP32 sender/receiver workflow. **CAALC has no proven 128-bit or post-quantum security.** Use the separate Ascon option when established AEAD is required, together with an authenticated key-management protocol.

Read `results/VERIFICATION.md` for the actual executed/unexecuted checks. Host timings and synthetic test audio are supplied; no physical device measurements are claimed.

## Quick start (no hardware)

Extract the ZIP and open a terminal in `CAALC128_Project`.

Windows PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If PowerShell prevents activation, use `.\.venv\Scripts\python.exe` instead of `python`; activation is optional. A newer installed Python can be used in place of `py -3.11`.

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

For the Ascon comparison and C++ cross-checks install GCC/G++ (Linux), Xcode command-line tools (macOS, providing gcc/g++ aliases), or MSYS2 UCRT64 GCC (Windows). Put the compiler's bin directory on PATH. The Python-only CAALC cipher/audio modes do not need a compiler. Prebuilt libraries from the test machine are not distributed; build locally:

```bash
python build_native.py
python main.py test
python main.py demo
python main.py mlkem
python main.py dashboard
```

Open the local URL shown by Streamlit, usually `http://localhost:8501`. The default dashboard is one page: upload audio, encrypt it, inspect ciphertext bytes, then decrypt and listen to the authenticated recovered audio. It supports experimental CAALC and standardized Ascon-AEAD128. Keys are generated automatically; save the key from the optional session details if you need to decrypt later. See `DASHBOARD_UPDATE.md` for updating an existing installation.

The previous seven-screen research dashboard remains available with `python -m streamlit run main.py -- --advanced-dashboard`. Its ML-KEM button creates a new key file; it does not silently replace the dashboard key. The simple dashboard uses locally generated random keys, not an ML-KEM exchange.

`demo` generates a two-second **synthetic chirp**, encrypts it to `results/encrypted.caf`, reconstructs `results/recovered.wav`, and writes waveform/spectrogram and loss-simulation results. `results/demo.key` is a disposable demonstration key, not a secret suitable for deployment. Do not share recordings and their real key together.

## Nine requested execution modes

| Mode | Command |
|---|---|
| 1. Correctness, KATs, cross-language checks | `python main.py test` |
| 2. Encrypt WAV | `python main.py encrypt input.wav audio.caf --key results/session.key` |
| 3. Decrypt and verify | `python main.py decrypt audio.caf recovered.wav --key results/session.key` |
| 4. Audio quality | `python main.py analyze input.wav recovered.wav` |
| 5. Security screening | `python main.py experiments` |
| 6. Native Ascon comparison | `python main.py benchmark input.wav --trials 200` |
| 7. ML-KEM-512 + HKDF | `python main.py mlkem` |
| 8. Dashboard | `python main.py dashboard` |
| 9. Receiver | `python main.py receiver --key session.key --sid YOUR_16_HEX_SESSION_ID --seconds 15 --play` |

Additional commands:

```bash
python main.py keygen
python main.py encrypt input.wav audio.caf --key results/session.key --frame-ms 40
python main.py encrypt input.wav standard.caf --key results/session.key --algorithm ascon
python main.py simulate input.wav --key results/session.key --loss 0.1 --jitter-ms 15
python main.py play recovered.wav
```

## Authenticated post-quantum session demonstration

The repository includes a two-role software demonstration using ML-KEM-512 for ephemeral key establishment and ML-DSA-44 signatures for pinned identity authentication. Both logical endpoints run locally for this reproducible demonstration; the selected traffic key can then be provisioned to the ESP32 over trusted USB. This does not mean CAALC itself is proven post-quantum secure.

After building the native libraries, run:

```bash
python -m pq_session --suite caalc
python -m pq_session --suite ascon
python -m pytest tests/test_pq_session.py -q
```

The commands report identity fingerprints, transcript hash, peer signature and key confirmation status, an authenticated audio round trip, and tamper rejection. By default they do not write session keys. To create a one-session key package for the trusted-USB hardware path, explicitly use `--write-session`:

```bash
python -m pq_session --suite ascon --write-session results/ascon-demo.session.json
python hardware_session.py --serial /dev/cu.usbserial-XXXX --mode USB --session-file results/ascon-demo.session.json --wav results/original.wav --seconds 4 --out results/pq_usb_received.wav
```

The session file contains the traffic key in cleartext, is written with owner-only permissions, and is ignored by Git. Keep it private and use it only for this demo session. The handshake roles still run locally on the laptop; this is not a remote PQ handshake. See [docs/PQ_SESSION.md](docs/PQ_SESSION.md) for the protocol and its limits.

Use separate traffic keys for real Ascon and CAALC sessions. The decryption container selects its authenticated algorithm ID automatically. Acceptable WAV: uncompressed signed PCM16, mono, 8 or 16 kHz. Optional external conversion:

```bash
ffmpeg -i recording.mp3 -ac 1 -ar 8000 -c:a pcm_s16le input.wav
```

Empty audio encrypts correctly, but MSE/PSNR/SNR require at least one sample. Mismatched lengths/rates are rejected rather than silently aligned or resampled. For exact recovery, MSE=0 and PSNR/SNR=∞; JSON represents non-finite values as strings. Silent originals with nonzero reconstruction error have SNR=−∞. Encrypted bytes are not playable WAV audio.

## Two-ESP32 Bluetooth-to-Wi-Fi audio demonstration

The physical path is INMP441 microphone → ESP32 A authenticated audio sender → Bluetooth Classic SPP → ESP32 B ciphertext relay → Wi-Fi UDP → laptop dashboard authentication/decryption/playback. ESP32 A reads both I2S slots, selects the active microphone slot and reports microphone peak/RMS values. The dashboard keeps the authenticated raw WAV and produces a DC-removed, level-adjusted playback WAV only after authentication. See [hardware instructions](docs/HARDWARE.md) for wiring and the exact flashing steps. Use two original ESP32 DevKit V1/WROOM-32 boards. The laptop dashboard provisions a fresh traffic key to A over trusted USB; B only relays ciphertext.

Prepare and build the two firmware packages:

```bash
python prepare_bluetooth.py
pio run -d firmware/esp32_wifi_relay
pio run -d firmware/esp32_bt_sender
```

Upload each firmware to its matching board through PlatformIO. Then connect both boards to the laptop, close Serial Monitor windows, activate the project virtual environment, and start the hardware dashboard:

```bash
python -m streamlit run hardware_dashboard.py
```

Choose the serial ports, the shared 2.4 GHz Wi-Fi network, laptop Wi-Fi IP address, cipher and capture length in the page. The dashboard authenticates frames before playback, reports rejected/lost frames, and saves the recovered WAV and a key-free JSON report under `results/`. `python main.py dashboard` remains the offline file-encryption demo. The older one-board USB/Wi-Fi firmware and `hardware_session.py` remain available for diagnostics, but do not represent the professor's two-board Bluetooth + Wi-Fi topology.

Use **Ascon-AEAD128** for the standardized comparison and **CAALC-128** as an experimental candidate. CAALC has no proof or independent cryptanalysis establishing 128-bit or post-quantum security.

## Source map

For a short reproducible professor walkthrough, start with [docs/DEMO_GUIDE.md](docs/DEMO_GUIDE.md).

- `main.py`: Python reference, audio/file/wire format, metrics, statistical experiments, native wrappers, receiver, dashboard, CLI.
- `firmware/esp32_bt_sender/esp32_bt_sender.ino`: ESP32 A microphone capture, authenticated audio frames and Bluetooth SPP transmission.
- `firmware/esp32_wifi_relay/esp32_wifi_relay.ino`: ESP32 B Bluetooth-to-Wi-Fi ciphertext relay.
- `hardware_dashboard.py`: two-board provisioning, live UDP verification, recovered audio and session report.
- `firmware/include/`: shared CAALC headers used by the host C++ build and ESP32.
- `native/native.cpp`: portable C++ cipher wrapper used by the host tests.
- `hardware_session.py`: fresh key/session provisioning and capture without code edits.
- `firmware/benchmark/esp32_benchmark.ino`: optional same-device native CAALC/Ascon benchmark.
- `platformio.ini`, nested firmware PlatformIO files, `build_native.py`, `prepare_arduino.py`, `prepare_bluetooth.py`, `prepare_hardware_benchmark.py`: reproducible build preparation.
- `tests/`, `test_vectors/`: functional/transport/UI tests and public known-answer values.
- `vendor/ascon/`: upstream final-standard reference source, with licensing and provenance in `vendor/PROVENANCE.md`.
- `docs/SPECIFICATION.md`: exact mathematical, AEAD, nonce and protocol specification.
- `docs/ACADEMIC_REPORT.md`: abstract, methodology, discussion, presentation outline and viva.
- `results/`: measured host results, plots, logs and verification status.

## Operational limits and limitations

Fresh key per hardware capture/boot is mandatory; do not reuse key+session after reset. Receiver replay state is session-local and does not survive restart; start a new session after either ESP32 or dashboard restarts. Start reception before sending. Firmware capture is fixed at 8 kHz, 20 ms; Python file modes support 8/16 kHz and 10/20/40 ms. The two-board capture ends in the laptop browser audio player; it does not require a speaker module or PortAudio.

This is a research demonstration, not a hardened network service. CAALC security, authenticated endpoint identity, physical real-time performance, energy, side-channel leakage, hardware audio quality and ₹500 local procurement remain to be validated. Memory/code figures are compiler/implementation-specific. The supplied Ascon source is portable reference code, not necessarily the fastest available ESP32 implementation.

## Sources

- NIST SP 800-232 (final): https://csrc.nist.gov/pubs/sp/800/232/final
- NIST FIPS 203: https://csrc.nist.gov/pubs/fips/203/final
- Ascon authors' source and KATs: https://github.com/ascon/ascon-c
- pqcrypto Python bindings: https://github.com/backbone-hq/pqcrypto
- Espressif I2S legacy API: https://docs.espressif.com/projects/esp-idf/en/v4.4.5/esp32/api-reference/peripherals/i2s.html

The attached presentation and handwritten note informed scope. Changes from the slides are explicitly listed in the academic report. Bibliographic claims in the earlier slides have not been treated as independently verified evidence of a research gap.

## Reproduce the supplied evaluation

```bash
python reproduce.py
python reproduce.py --summary-only --large
```

The first command rebuilds the two native libraries and reruns offline demonstrations, ML-KEM, screening, benchmarks and pytest. The second reruns the slower 1 MiB CAALC audio check and refreshes the summary. Keep the dated original verification log when comparing a later environment. To reproduce native object/stack measurements on GCC:

```bash
g++ -O2 -std=c++11 -fstack-usage -Ifirmware/include -c native/native.cpp -o build/caalc.o
gcc -O2 -fstack-usage -Ivendor/ascon -c vendor/ascon/aead.c -o build/ascon.o
size build/caalc.o build/ascon.o
```

The release archive excludes temporary build products and the transient ML-KEM session key. Run the build and ML-KEM commands locally. `results/demo.key` accompanies only the public synthetic example so its encrypted CAF file can be inspected immediately.

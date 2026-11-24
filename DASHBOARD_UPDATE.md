# Simple audio dashboard update

## Update your working Windows installation

1. Stop Streamlit in PowerShell with Ctrl+C.
2. Extract this ZIP elsewhere. Copy `main.py`, `simple_dashboard.py`, and `requirements-dashboard.txt` into your existing project folder, replacing main.py. Keep your existing other files and build folder.
3. In your existing project folder run:

```powershell
python -m pip install -r requirements-dashboard.txt
python main.py dashboard
```

No native library rebuild is required for this UI update.

## Demonstrate it

Upload a short voice recording (up to 60 seconds / 20 MB). Supported uploads: WAV, MP3, M4A, FLAC, OGG. Compatible mono PCM16 WAV at 8 or 16 kHz stays unchanged. Other inputs are converted locally to mono PCM16 at 8 kHz using the packaged FFmpeg executable supplied by imageio-ffmpeg.

Listen to the prepared original, click **Encrypt audio**, listen to the **Encrypted audio** preview, then click **Decrypt audio** and listen to the recovered WAV. Successful decryption displays authentication verification, exact sample recovery, MSE and PSNR. The three players stay together on one page. Use a short clip initially; Python encryption can take time for longer files.

The encrypted preview interprets actual ciphertext bytes as PCM16 at reduced amplitude. It sounds like noise. It is only a listening representation; the downloadable CAF container is the real authenticated encrypted file. Decryption uses that container and verifies authentication before releasing audio. Converted uploads are compared with their prepared PCM, not their original compressed encoding.

A fresh random key is generated for each encryption; there is no manual key entry. Download the key under session details if keeping the CAF. Closing the session, selecting another upload, or encrypting again can discard the previous key from the page. Keep saved keys separate from ciphertext.

## Future extension

The UI lives in `simple_dashboard.py` and calls the existing `main.py` cipher and container functions. The cipher, constants, packet format and firmware are unchanged. Research screens remain accessible using:

```powershell
python -m streamlit run main.py -- --advanced-dashboard
```

This simple page uses random session keys; it does not perform ML-KEM. Existing ML-KEM and Ascon modes remain separate. CAALC remains experimental with no proven security level.

## Validation of this update

Eight targeted automated tests passed: existing CAALC vectors, actual ciphertext preview and exact recovery, tamper/wrong-key rejection, stereo WAV and MP3 conversion, invalid inputs and malformed preview containers, UI Encrypt/Decrypt/reset flow, UI authentication rejection, and initial empty screen. Syntax checks passed. Logs: `results/simple_dashboard_tests.txt`.

Run these checks with `python -m pytest tests/test_simple_dashboard.py -q`. This update was tested on the Linux host; Windows execution and physical ESP32 deployment were not tested here. Earlier full-project checks in results remain historical and were not rerun as part of this UI update.

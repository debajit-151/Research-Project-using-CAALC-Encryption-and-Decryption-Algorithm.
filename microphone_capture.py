"""Capture INMP441 audio from the standalone ESP32 USB recorder."""
from __future__ import annotations

import argparse
import array
import io
import json
import math
import re
import struct
import sys
import time
import wave
from pathlib import Path
from typing import Callable

BAUD = 921600
DEFAULT_PORT = "COM5" if sys.platform == "win32" else "/dev/cu.usbserial-0001"
ProgressCallback = Callable[[str, float], None]


def available_ports() -> list[str]:
    from serial.tools import list_ports

    return [port.device for port in list_ports.comports() if port.vid is not None]


def make_wav(pcm16: bytes, rate: int) -> bytes:
    output = io.BytesIO()
    with wave.open(output, "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(rate)
        wav.writeframes(pcm16)
    return output.getvalue()


def _condition_pcm32(raw_pcm: bytes, rate: int) -> tuple[bytes, dict]:
    if len(raw_pcm) % 4:
        raise RuntimeError("ESP32 returned a misaligned 32-bit audio payload.")

    raw_words = array.array("i")
    raw_words.frombytes(raw_pcm)
    if raw_words.itemsize != 4:
        raise RuntimeError("This Python build does not use 32-bit signed integers.")
    if sys.byteorder != "little":
        raw_words.byteswap()
    if not raw_words:
        raise RuntimeError("ESP32 returned an empty audio payload.")

    # The signed 24-bit microphone sample is left-aligned in the 32-bit word.
    samples24 = [word >> 8 for word in raw_words]

    # Remove DC drift without removing speech frequencies.
    cutoff_hz = 40.0
    alpha = math.exp(-2.0 * math.pi * cutoff_hz / rate)
    previous_x = float(samples24[0])
    previous_y = 0.0
    filtered: list[float] = []
    for value in samples24:
        x = float(value)
        y = alpha * (previous_y + x - previous_x)
        filtered.append(y)
        previous_x = x
        previous_y = y

    raw_peak = max(abs(value) for value in filtered)
    raw_rms = math.sqrt(sum(value * value for value in filtered) / len(filtered))
    changing_samples = sum(
        samples24[index] != samples24[index - 1]
        for index in range(1, len(samples24))
    )
    if raw_peak < 1.0:
        raise RuntimeError(
            "The active I2S slot contained no usable microphone signal. "
            "Recheck VDD, GND, SD and L/R."
        )

    # Limit amplification to 128x relative to normal 24-to-16 conversion.
    target_peak = 28000.0
    scale = min(0.5, target_peak / raw_peak)
    pcm_values: list[int] = []
    for value in filtered:
        sample = int(round(value * scale))
        pcm_values.append(max(-32768, min(32767, sample)))

    pcm = struct.pack(f"<{len(pcm_values)}h", *pcm_values)
    output_peak = max(abs(value) for value in pcm_values)
    output_rms = math.sqrt(
        sum(value * value for value in pcm_values) / len(pcm_values)
    )
    verdict = (
        "Microphone signal detected"
        if changing_samples > len(samples24) // 20 and raw_peak >= 128
        else "Signal captured, but it is very weak or nearly constant"
    )
    return pcm, {
        "verdict": verdict,
        "raw_24bit_ac_peak": round(raw_peak, 1),
        "raw_24bit_ac_rms": round(raw_rms, 1),
        "changing_samples": changing_samples,
        "software_gain_x": round(scale * 256.0, 2),
        "wav_peak": output_peak,
        "wav_rms": round(output_rms, 1),
    }


def capture(
    port: str,
    seconds: int,
    progress: ProgressCallback | None = None,
) -> tuple[bytes, dict]:
    import serial

    if not 1 <= seconds <= 10:
        raise ValueError("Recording duration must be between 1 and 10 seconds.")

    def update(phase: str, fraction: float) -> None:
        if progress is not None:
            progress(phase, max(0.0, min(1.0, fraction)))

    link = serial.Serial()
    link.port = port
    link.baudrate = BAUD
    link.timeout = 0.25
    link.write_timeout = 2
    link.exclusive = True
    link.dtr = False
    link.rts = False

    recent_lines: list[str] = []
    try:
        update("Opening ESP32 USB port", 0.0)
        link.open()
        link.reset_input_buffer()

        # CP2102 may reset the board when the port opens. This setup time is
        # separate from the selected audio duration.
        ready_deadline = time.monotonic() + 8.0
        ready = False
        while time.monotonic() < ready_deadline:
            line = link.readline()
            if not line:
                continue
            text = line.decode("utf-8", "replace").strip()
            if text:
                recent_lines.append(text)
                recent_lines = recent_lines[-5:]
            if line.startswith(b"MIC_TEST_READY "):
                ready = True
                break
            update("Waiting for recorder firmware", 0.0)
        if not ready:
            detail = " | ".join(recent_lines) or "no serial response"
            raise RuntimeError(
                "ESP32 recorder firmware did not become ready at 921600 baud. "
                f"Recent output: {detail}"
            )

        link.reset_input_buffer()
        link.write(f"RECORD {seconds * 1000}\n".encode("ascii"))
        link.flush()
        update("Starting recording", 0.0)

        header_deadline = time.monotonic() + 3.0
        header = b""
        while time.monotonic() < header_deadline:
            line = link.readline()
            if line.startswith(b"AUDIO_BEGIN "):
                header = line
                break
        if not header:
            raise RuntimeError("ESP32 accepted the port but did not start recording.")

        parts = header.decode("ascii").strip().split()
        if len(parts) != 5:
            raise RuntimeError(f"Unexpected recorder header: {header!r}")
        rate = int(parts[1])
        sample_count = int(parts[2])
        sample_bytes = int(parts[3])
        active_slot = int(parts[4])
        if sample_bytes != 4:
            raise RuntimeError(f"Unsupported ESP32 sample width: {sample_bytes}")

        expected_samples = rate * seconds
        if sample_count != expected_samples:
            raise RuntimeError(
                f"ESP32 announced {sample_count} samples; expected {expected_samples}."
            )

        needed = sample_count * sample_bytes
        payload = bytearray()
        transfer_deadline = time.monotonic() + seconds + 5.0
        while len(payload) < needed and time.monotonic() < transfer_deadline:
            chunk = link.read(min(4096, needed - len(payload)))
            if chunk:
                payload.extend(chunk)
                update("Recording audio", len(payload) / needed)
        if len(payload) != needed:
            raise RuntimeError(
                f"USB audio was incomplete: received {len(payload)} of {needed} bytes."
            )

        trailer = ""
        trailer_deadline = time.monotonic() + 2.0
        while time.monotonic() < trailer_deadline:
            line = link.readline()
            if line.startswith(b"AUDIO_END "):
                trailer = line.decode("ascii", "replace").strip()
                break
        if not trailer:
            raise RuntimeError("Audio arrived, but the ESP32 completion marker was missing.")

        match = re.search(r"read_errors=(\d+)", trailer)
        read_errors = int(match.group(1)) if match else -1
        elapsed_match = re.search(r"elapsed_ms=(\d+)", trailer)
        esp32_elapsed_seconds = (
            int(elapsed_match.group(1)) / 1000.0 if elapsed_match else None
        )
        update("Creating WAV on laptop", 1.0)
    finally:
        if link.is_open:
            link.close()

    pcm16, metrics = _condition_pcm32(bytes(payload), rate)
    wav = make_wav(pcm16, rate)
    report = {
        **metrics,
        "sample_rate_hz": rate,
        "duration_seconds": sample_count / rate,
        "total_samples": sample_count,
        "active_i2s_slot": active_slot,
        "esp32_read_errors": read_errors,
        "esp32_record_and_transfer_seconds": esp32_elapsed_seconds,
        "wav_bytes": len(wav),
    }
    return wav, report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", default=DEFAULT_PORT)
    parser.add_argument("--seconds", type=int, default=5, choices=range(1, 11))
    parser.add_argument("--out", type=Path, default=Path("results/inmp441_test.wav"))
    args = parser.parse_args()

    def show_progress(phase: str, fraction: float) -> None:
        print(f"{phase}: {fraction * 100:.0f}%", flush=True)

    wav, report = capture(args.port, args.seconds, show_progress)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(wav)
    print(json.dumps({**report, "saved_to": str(args.out.resolve())}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

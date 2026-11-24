"""Browser dashboard for the standalone ESP32 + INMP441 recorder."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

import streamlit as st

from microphone_capture import DEFAULT_PORT, available_ports, capture

st.set_page_config(page_title="INMP441 Sensor Test", page_icon="🎙️")
st.title("INMP441 microphone recorder")
st.caption("ESP32 wiring: SCK 14 · WS 15 · SD 32 · L/R GND · VDD 3V3")

ports = available_ports()
if not ports:
    st.error("No USB ESP32 detected.")
    st.stop()

port = st.selectbox(
    "ESP32 USB port",
    ports,
    index=ports.index(DEFAULT_PORT) if DEFAULT_PORT in ports else 0,
)
seconds = st.slider("Audio duration (seconds)", 2, 10, 5)
st.info(
    "Speak during the selected audio duration. ESP32 boot and USB setup can "
    "add about one second before recording begins."
)

if st.button("Record audio", type="primary", use_container_width=True):
    progress_bar = st.progress(0.0)
    phase_text = st.empty()

    def show_progress(phase: str, fraction: float) -> None:
        phase_text.write(phase)
        progress_bar.progress(fraction)

    try:
        wav, report = capture(port, seconds, show_progress)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = Path("results") / f"inmp441_{timestamp}.wav"
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(wav)
        report["saved_to"] = str(output.resolve())

        progress_bar.progress(1.0)
        phase_text.write("Recording complete")
        if report["verdict"] == "Microphone signal detected":
            st.success(report["verdict"])
        else:
            st.warning(report["verdict"])
        st.json(report)
        st.audio(wav, format="audio/wav")
        st.download_button(
            "Download WAV",
            wav,
            output.name,
            "audio/wav",
            use_container_width=True,
        )
    except Exception as exc:
        progress_bar.empty()
        phase_text.empty()
        st.error(str(exc))

"""Live microphone demo: ESP32 A -> Bluetooth -> ESP32 B -> Wi-Fi -> laptop."""
from __future__ import annotations

import array
import csv
import io
import json
import math
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import threading
import time
from collections import deque
from datetime import datetime

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import main as core
DEFAULT_OUT = ROOT / 'results' / 'live_received.wav'
DEFAULT_RAW_OUT = ROOT / 'results' / 'live_received_authenticated_raw.wav'
RUN_HISTORY = ROOT / 'results' / 'hardware_runs.json'

BOARD_CRASH_MARKERS = (
    'abort() was called',
    'Guru Meditation Error',
    'assert failed:',
    'CORRUPT HEAP:',
)


def board_crash_line(text: str) -> bool:
    """Recognize fatal ESP32 output that otherwise ends as a READY timeout."""
    return any(marker in text for marker in BOARD_CRASH_MARKERS)


def audio_statistics(pcm: bytes) -> dict:
    if len(pcm) % 2:
        raise ValueError('Audio PCM must contain complete 16-bit samples.')
    samples = array.array('h')
    samples.frombytes(pcm)
    if sys.byteorder != 'little':
        samples.byteswap()
    if not samples:
        return {'samples': 0, 'peak': 0, 'rms': 0.0, 'clipped_percent': 0.0}
    peak = max(abs(value) for value in samples)
    rms = math.sqrt(sum(value * value for value in samples) / len(samples))
    clipped = sum(abs(value) >= 32760 for value in samples) * 100 / len(samples)
    return {'samples': len(samples), 'peak': peak, 'rms': round(rms, 2),
            'clipped_percent': round(clipped, 4)}


def tamper_check(key: bytes, sid: bytes, algorithm: str) -> dict:
    """Alter one locally generated packet and confirm authentication rejects it."""
    pcm = struct.pack('<160h', *([1234, -987] * 80))
    packet = bytearray(core.make_packet(key, sid, 0, 8000, 20, pcm, algorithm))
    packet[-1] ^= 0x01
    try:
        core.open_packet(key, bytes(packet), sid, algorithm)
    except core.AuthenticationError:
        return {'tampered_packet_rejected': True,
                'audio_released': False,
                'scope': 'Local self-test; live capture was not modified.'}
    return {'tampered_packet_rejected': False, 'audio_released': True,
            'scope': 'Local self-test; live capture was not modified.'}


def spectrogram_image(pcm: bytes, rate: int):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np

    samples = np.frombuffer(pcm, dtype='<i2').astype(np.float32)
    fig, ax = plt.subplots(figsize=(10, 3.2))
    if samples.size >= 256:
        ax.specgram(samples, NFFT=256, Fs=rate, noverlap=192,
                    cmap='magma', scale='dB')
    ax.set(title='Authenticated received audio', xlabel='Time (s)', ylabel='Frequency (Hz)')
    fig.tight_layout()
    return fig


def audio_plot_pcm(audio_wav: bytes) -> tuple[bytes, int]:
    rate, pcm = core.wav_read(audio_wav)
    return pcm, rate


def load_run_history() -> list[dict]:
    try:
        data = json.loads(RUN_HISTORY.read_text())
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def save_run_history(report: dict) -> list[dict]:
    history = load_run_history()
    history.append(report)
    history = history[-100:]
    RUN_HISTORY.parent.mkdir(parents=True, exist_ok=True)
    RUN_HISTORY.write_text(json.dumps(history, indent=2))
    return history


def history_csv(history: list[dict]) -> str:
    fields = ('timestamp', 'algorithm', 'capture_seconds', 'authenticated_frames',
              'rejected_packets', 'concealed_missing_frames', 'packet_loss_percent',
              'mean_desktop_verify_decrypt_us', 'wifi_rssi_dbm', 'mic_rms', 'result')
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction='ignore')
    writer.writeheader()
    writer.writerows(history)
    return output.getvalue()


def condition_authenticated_pcm(pcm: bytes, rate: int) -> tuple[bytes, dict]:
    """Remove residual DC and make authenticated PCM audible on the laptop."""
    if len(pcm) % 2:
        raise ValueError('Authenticated PCM is not aligned to 16-bit samples.')
    values = array.array('h')
    values.frombytes(pcm)
    if sys.byteorder != 'little':
        values.byteswap()
    if not values:
        return pcm, {'input_peak': 0, 'input_rms': 0.0, 'gain_x': 1.0,
                     'output_peak': 0, 'output_rms': 0.0}

    cutoff_hz = 40.0
    alpha = math.exp(-2.0 * math.pi * cutoff_hz / rate)
    previous_x = float(values[0])
    previous_y = 0.0
    filtered = []
    for value in values:
        x = float(value)
        y = alpha * (previous_y + x - previous_x)
        filtered.append(y)
        previous_x, previous_y = x, y

    input_peak = max(abs(value) for value in filtered)
    input_rms = math.sqrt(sum(value * value for value in filtered) / len(filtered))
    gain = 1.0 if input_peak < 1 else min(8.0, 28000.0 / input_peak)
    output_values = [max(-32768, min(32767, int(round(value * gain))))
                     for value in filtered]
    output = array.array('h', output_values)
    if sys.byteorder != 'little':
        output.byteswap()
    output_peak = max(abs(value) for value in output_values)
    output_rms = math.sqrt(sum(value * value for value in output_values) / len(output_values))
    return output.tobytes(), {
        'input_peak': round(input_peak, 1),
        'input_rms': round(input_rms, 1),
        'gain_x': round(gain, 3),
        'output_peak': output_peak,
        'output_rms': round(output_rms, 1),
        'high_pass_hz': cutoff_hz,
        'note': 'Applied only after every frame passed authenticated decryption.',
    }


class SerialMonitor:
    """One process-owned USB serial link shared by live logs and capture control."""
    def __init__(self, port: str, baud: int = 115200):
        import serial
        self.port = port
        self._condition = threading.Condition()
        self._write_lock = threading.Lock()
        self._events = deque(maxlen=600)
        self._sequence = 0
        self._stop = threading.Event()
        self._last_text = None
        self._repeat_count = 0
        self._last_emit = 0.0
        self._buffer = bytearray()
        self._last_rx = time.monotonic()
        # Configure modem-control lines before opening. Opening a CP2102 with
        # library defaults can pulse EN and start an ESP32 reboot just as the
        # dashboard sends its first command.
        self._serial = serial.Serial()
        self._serial.port = port
        self._serial.baudrate = baud
        self._serial.timeout = 0.12
        self._serial.write_timeout = 3
        if os.name != 'nt':
            self._serial.exclusive = True
        self._serial.dtr = False
        self._serial.rts = False
        self._serial.open()
        self._append(f"MONITOR_OPEN baud={baud}; dashboard owns this USB port")
        self._reader = threading.Thread(target=self._read_loop, name=f"serial-{port}", daemon=True)
        self._reader.start()

    def _append(self, text: str):
        with self._condition:
            self._sequence += 1
            stamp = datetime.now().strftime('%H:%M:%S')
            self._events.append((self._sequence, stamp, text))
            self._condition.notify_all()

    def _emit(self, raw: bytes):
        raw = raw.rstrip(b'\r\n')
        if not raw:
            return
        decoded = raw.decode('utf-8', errors='replace')
        printable = sum(ch.isprintable() or ch in '\t' for ch in decoded)
        if printable < max(1, int(len(decoded) * 0.85)):
            text = f"SERIAL_NOISE bytes={len(raw)} hex={raw[:48].hex()}" + ("…" if len(raw) > 48 else "")
        else:
            text = decoded.strip()
        now = time.monotonic()
        if text == self._last_text:
            self._repeat_count += 1
            if now - self._last_emit >= 1.0:
                self._append(f"REPEATED count={self._repeat_count} line={text[:180]}")
                self._repeat_count = 0
                self._last_emit = now
            return
        if self._repeat_count:
            self._append(f"REPEATED count={self._repeat_count} line={str(self._last_text)[:180]}")
            self._repeat_count = 0
        self._last_text = text
        self._last_emit = now
        self._append(text)

    def _read_loop(self):
        while not self._stop.is_set():
            try:
                raw = self._serial.read(256)
            except Exception as exc:
                if not self._stop.is_set():
                    self._append(f"SERIAL_READ_ERROR {type(exc).__name__}: {exc}")
                    time.sleep(0.1)
                continue
            now = time.monotonic()
            if raw:
                self._buffer.extend(raw)
                self._last_rx = now
                while b'\n' in self._buffer:
                    line, _, remainder = self._buffer.partition(b'\n')
                    self._buffer = bytearray(remainder)
                    self._emit(bytes(line))
                if len(self._buffer) > 512:
                    self._emit(bytes(self._buffer))
                    self._buffer.clear()
            elif self._buffer and now - self._last_rx > 0.4:
                self._emit(bytes(self._buffer))
                self._buffer.clear()

    @property
    def cursor(self) -> int:
        with self._condition:
            return self._sequence

    def lines_after(self, cursor: int = 0):
        with self._condition:
            return [text for seq, _stamp, text in self._events if seq > cursor]

    def send_line(self, line: str, display: str):
        if not self._serial.is_open:
            raise RuntimeError(f'{self.port} serial connection is closed')
        data = line.encode('ascii') + b'\n'
        with self._write_lock:
            self._serial.write(data)
            self._serial.flush()
        self._append(f'TX {display}')

    def wait_for(self, pattern: str, timeout: float, after: int = 0) -> str:
        matcher = re.compile(pattern)
        deadline = time.monotonic() + timeout
        scanned = after
        with self._condition:
            while True:
                for seq, _stamp, text in self._events:
                    if seq <= scanned:
                        continue
                    scanned = max(scanned, seq)
                    if text.startswith(('ERR', 'FATAL')):
                        raise RuntimeError(f'{self.port}: {text}')
                    if board_crash_line(text):
                        raise RuntimeError(
                            f'{self.port}: ESP32 firmware crashed during startup ({text}).'
                        )
                    if matcher.search(text):
                        return text
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f'{self.port} did not respond before the startup timeout.')
                self._condition.wait(min(0.2, remaining))

    def _hardware_reset(self):
        """Pulse ESP32 EN while keeping GPIO0 high (normal flash boot)."""
        with self._write_lock:
            self._serial.dtr = False
            self._serial.rts = True
            time.sleep(0.12)
            self._serial.rts = False
            self._serial.dtr = False

    def reset_board(self, role: str, timeout: float = 12):
        cursor = self.cursor
        self.send_line('RESET', 'RESET board')
        try:
            # Do not accept a CP2102-triggered boot that was already underway.
            # The explicit acknowledgement proves the firmware consumed our
            # RESET command, so configuration cannot be erased by a queued
            # restart after this method returns.
            self.wait_for(fr'^RESETTING role={re.escape(role)}$', 2.5, after=cursor)
            reset_cursor = self.cursor
        except TimeoutError:
            # The software command can be lost if the USB adapter happened to
            # reset the board while it was sent. A controlled EN pulse is the
            # reliable recovery and does not enter the bootloader.
            reset_cursor = self.cursor
            self._append('RESET_FALLBACK hardware EN pulse')
            self._hardware_reset()
        boot = self.wait_for(fr'BOOT role={re.escape(role)}\b', timeout, after=reset_cursor)
        waiting = {
            'sender': r'CAALC ESP32 A ready; waiting for trusted USB configuration',
            'relay': r'CAALC ESP32 B relay ready; waiting for laptop Wi-Fi configuration',
        }.get(role)
        if waiting:
            self.wait_for(waiting, timeout, after=reset_cursor)
        return boot

    def close(self):
        self._stop.set()
        try:
            self._serial.close()
        except Exception:
            pass
        if self._reader.is_alive():
            self._reader.join(timeout=0.5)


class SerialMonitorRegistry:
    def __init__(self):
        self._lock = threading.RLock()
        self._links = {}

    def get(self, port: str) -> SerialMonitor:
        with self._lock:
            link = self._links.get(port)
            if link is not None and link._serial.is_open:
                return link
            if link is not None:
                link.close()
            link = SerialMonitor(port)
            self._links[port] = link
            return link

    def keep_open(self, ports):
        wanted = set(ports)
        with self._lock:
            stale = [self._links.pop(port) for port in list(self._links) if port not in wanted]
        for link in stale:
            link.close()

    def close_all(self):
        with self._lock:
            links, self._links = list(self._links.values()), {}
        for link in links:
            link.close()


def get_serial_registry():
    # Streamlit reruns this script for every widget interaction. Store the
    # registry on the imported Streamlit module so one reader owns each port.
    import streamlit as st
    registry = getattr(st, '_caalc_serial_monitor_registry', None)
    if registry is None:
        registry = SerialMonitorRegistry()
        setattr(st, '_caalc_serial_monitor_registry', registry)
    return registry


def discover_lan_ip() -> str:
    # Prefer the actual Wi-Fi interface on macOS so a VPN route is not suggested by mistake.
    if sys.platform == 'darwin':
        try:
            ports = subprocess.run(['networksetup', '-listallhardwareports'], capture_output=True,
                                   text=True, timeout=2, check=True).stdout
            for block in re.split(r'\n(?=Hardware Port:)', ports):
                if re.search(r'Hardware Port: Wi-Fi', block, re.I):
                    device = re.search(r'Device: (\S+)', block)
                    if device:
                        result = subprocess.run(['ipconfig', 'getifaddr', device.group(1)],
                                                capture_output=True, text=True, timeout=2)
                        address = result.stdout.strip()
                        if result.returncode == 0 and address:
                            return address
        except (OSError, subprocess.SubprocessError):
            pass
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(('192.0.2.1', 80))
        return sock.getsockname()[0]
    except OSError:
        return ''
    finally:
        sock.close()


def serial_ports():
    try:
        from serial.tools import list_ports
    except ImportError as exc:
        raise RuntimeError('Install the project requirements first so serial ports can be listed.') from exc
    # Ignore macOS debug and Bluetooth pseudo-ports. The hardware demo needs the
    # USB-UART adapters attached to the two ESP32 DevKit V1 boards.
    ports = [port for port in list_ports.comports()
             if port.vid is not None and port.pid is not None]
    return [(port.device, f'{port.device} — {port.description}')
            for port in sorted(ports, key=lambda item: item.device)]


def hex_token(text: str) -> str:
    return text.encode('utf-8').hex() if text else '-'


def open_configured(link: SerialMonitor, line: str, received_pattern: str,
                    ready_pattern: str, timeout: float, display: str,
                    attempts: int = 3):
    """Deliver configuration reliably across CP2102/ESP32 boot timing.

    The firmware acknowledges the line before doing slow Wi-Fi/Bluetooth work.
    If that acknowledgement is absent, retransmit instead of waiting for the
    final READY line until a long timeout expires.
    """
    first_cursor = link.cursor
    acknowledged = False
    for attempt in range(1, attempts + 1):
        cursor = link.cursor
        link.send_line(line, f'{display} attempt={attempt}/{attempts}')
        try:
            link.wait_for(received_pattern, 3.0, after=cursor)
            acknowledged = True
            break
        except TimeoutError:
            if attempt < attempts:
                link._append(f'CONFIG_ACK_MISSING retry={attempt + 1}/{attempts}')
                time.sleep(0.25)
    if not acknowledged:
        raise TimeoutError(
            f'{link.port} did not acknowledge the configuration after '
            f'{attempts} attempts. Check board power, USB connection and firmware role.'
        )
    ready = link.wait_for(ready_pattern, timeout, after=first_cursor)
    return link, ready, link.lines_after(first_cursor)


def wait_stopped(link: SerialMonitor, timeout=2.5):
    cursor = link.cursor
    link.send_line('STOP', 'STOP sender')
    try:
        return link.wait_for(r'^STOPPED ', timeout, after=cursor)
    except TimeoutError:
        return '\n'.join(link.lines_after(cursor)[-4:]) or 'Sender stop was not confirmed.'


def run_capture(sender_port: str, relay_port: str, ssid: str, password: str,
                laptop_ip: str, udp_port: int, seconds: int, algorithm: str,
                progress, status, metrics, chart):
    import struct

    key, sid = os.urandom(16), os.urandom(8)
    suite = algorithm.upper()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
    udp.bind(('0.0.0.0', udp_port))
    udp.settimeout(0.025)
    registry = get_serial_registry()
    relay = sender = None
    sender_active = False
    receiver = core.SessionReceiver(key, sid, algorithm)
    jitter = None
    frames = []
    accepted = rejected = wire_bytes = 0
    decrypt_us = []
    rejection_reasons = {}
    relay_log_cursor = 0
    sender_log_cursor = 0
    sender_fw = relay_fw = 'unknown'
    try:
        status.info('Resetting ESP32 B and connecting it to Wi-Fi…')
        relay = registry.get(relay_port)
        try:
            relay.reset_board('relay')
        except Exception as exc:
            raise RuntimeError(f'ESP32 B reset stage failed: {exc}') from exc
        relay_cfg = f'CFG RELAY {hex_token(ssid)} {hex_token(password)} {laptop_ip} {udp_port}'
        try:
            relay, relay_ready, _ = open_configured(
                relay, relay_cfg, r'^SERIAL_CONFIG_RECEIVED .*role=relay$',
                r'READY RELAY', timeout=45,
                display='CFG RELAY (credentials redacted)')
        except Exception as exc:
            raise RuntimeError(f'ESP32 B configuration stage failed: {exc}') from exc
        mac_match = re.search(r'BT_MAC=([0-9A-Fa-f:]{17})', relay_ready)
        if not mac_match:
            raise RuntimeError(f'ESP32 B did not report its Bluetooth address: {relay_ready}')
        bt_mac = mac_match.group(1)
        relay_log_cursor = relay.cursor
        relay_fw_match = re.search(r'\bfw=([^ ]+)', '\n'.join(relay.lines_after(0)))
        relay_fw = relay_fw_match.group(1) if relay_fw_match else 'unknown'

        relay_ip_match = re.search(r'IP=([^ ]+)', relay_ready)
        relay_ip = relay_ip_match.group(1) if relay_ip_match else 'its Wi-Fi address'
        status.info(f'ESP32 B is online at {relay_ip}. Resetting ESP32 A…')
        sender = registry.get(sender_port)
        try:
            sender.reset_board('sender')
        except Exception as exc:
            raise RuntimeError(f'ESP32 A reset stage failed: {exc}') from exc
        sender_cfg = f'CFG SENDER {key.hex()} {sid.hex()} {bt_mac} {suite}'
        try:
            sender, _, _ = open_configured(
                sender, sender_cfg, r'^SERIAL_CONFIG_RECEIVED .*role=sender$',
                r'READY SENDER', timeout=90,
                display='CFG SENDER (key and session redacted)')
        except Exception as exc:
            raise RuntimeError(f'ESP32 A configuration stage failed: {exc}') from exc
        sender_active = True
        sender_log_cursor = sender.cursor
        sender_fw_match = re.search(r'\bfw=([^ ]+)', '\n'.join(sender.lines_after(0)))
        sender_fw = sender_fw_match.group(1) if sender_fw_match else 'unknown'

        start = time.monotonic()
        end = start + seconds
        next_refresh = start
        progress.progress(0.0, text='Receiving authenticated microphone frames…')
        status.info('Streaming: microphone → encrypted Bluetooth frames → Wi-Fi relay → dashboard.')
        while time.monotonic() < end:
            try:
                packet, _address = udp.recvfrom(2048)
                wire_bytes += len(packet)
                arrived = time.monotonic()
                try:
                    # Advance elapsed playout deadlines before inserting a new
                    # packet; otherwise a UI refresh can make a valid packet
                    # look outside the bounded reorder window.
                    if jitter is not None:
                        frames.extend(jitter.ready(arrived))
                    before = time.perf_counter_ns()
                    q, rate, ms, pcm = receiver.accept(packet)
                    elapsed_us = (time.perf_counter_ns() - before) / 1000
                    decrypt_us.append(elapsed_us)
                    if jitter is None:
                        jitter = core.JitterBuffer(rate, ms, delay_ms=300)
                    jitter.put(q, pcm, arrived)
                    accepted += 1
                except (ValueError, core.AuthenticationError) as exc:
                    rejected += 1
                    reason = str(exc) or type(exc).__name__
                    rejection_reasons[reason] = rejection_reasons.get(reason, 0) + 1
            except socket.timeout:
                arrived = time.monotonic()
            if jitter is not None:
                frames.extend(jitter.ready(arrived))
            if arrived >= next_refresh:
                elapsed = min(1.0, (arrived - start) / seconds)
                progress.progress(elapsed, text=f'Capturing {min(seconds, int(arrived-start))}/{seconds} seconds')
                metrics.metric('Frames authenticated', accepted)
                metrics.metric('Rejected packets', rejected)
                metrics.metric('Estimated missing frames', jitter.lost if jitter else 0)
                if frames:
                    pcm = b''.join(frames[-50:])
                    samples = [v[0] for v in struct.iter_unpack('<h', pcm)]
                    chart.line_chart(samples[::8], height=190)
                next_refresh = arrived + 1.0

        status.info('Stopping ESP32 A and collecting the final buffered frames…')
        stop_result = wait_stopped(sender)
        sender_active = False
        drain_until = time.monotonic() + 0.5
        while time.monotonic() < drain_until:
            try:
                packet, _address = udp.recvfrom(2048)
                wire_bytes += len(packet)
                arrived = time.monotonic()
                try:
                    if jitter is not None:
                        frames.extend(jitter.ready(arrived))
                    before = time.perf_counter_ns()
                    q, rate, ms, pcm = receiver.accept(packet)
                    decrypt_us.append((time.perf_counter_ns() - before) / 1000)
                    if jitter is None:
                        jitter = core.JitterBuffer(rate, ms, delay_ms=300)
                    jitter.put(q, pcm, arrived)
                    accepted += 1
                except (ValueError, core.AuthenticationError) as exc:
                    rejected += 1
                    reason = str(exc) or type(exc).__name__
                    rejection_reasons[reason] = rejection_reasons.get(reason, 0) + 1
            except socket.timeout:
                arrived = time.monotonic()
            if jitter is not None:
                frames.extend(jitter.ready(arrived))
        if jitter is None or not frames:
            raise RuntimeError('No authenticated audio arrived. Check the microphone wiring, Bluetooth connection and laptop Wi-Fi address.')

        pcm_all = b''.join(frames)
        raw_audio = core.wav_bytes(jitter.rate, pcm_all)
        conditioned_pcm, audio_conditioning = condition_authenticated_pcm(pcm_all, jitter.rate)
        audio = core.wav_bytes(jitter.rate, conditioned_pcm)
        DEFAULT_OUT.parent.mkdir(parents=True, exist_ok=True)
        DEFAULT_RAW_OUT.write_bytes(raw_audio)
        DEFAULT_OUT.write_bytes(audio)
        actual_seconds = len(pcm_all) / (2 * jitter.rate)
        sender_status_cursor = sender.cursor
        sender.send_line('STATUS', 'STATUS sender counters')
        try:
            sender_status = sender.wait_for(r'^SENDER_STATUS ', 2.0, after=sender_status_cursor)
        except TimeoutError:
            sender_status = ''
        relay_status_cursor = relay.cursor
        relay.send_line('STATUS', 'STATUS relay counters')
        try:
            exact_relay_status = relay.wait_for(r'^RELAY_STATUS ', 2.0, after=relay_status_cursor)
        except TimeoutError:
            exact_relay_status = 'Relay did not return exact final counters.'
        relay_logs = relay.lines_after(relay_log_cursor)
        relay_stats = [line for line in relay_logs if line.startswith('RELAY_STAT')]
        relay_final = next((line for line in relay_logs if line.startswith('RELAY_STATUS ')), '')
        sender_logs = sender.lines_after(sender_log_cursor)
        sender_stat = next((line for line in reversed(sender_logs) if line.startswith('SENDER_STATUS ')), '')
        if not sender_stat:
            sender_stat = next((line for line in reversed(sender_logs) if line.startswith('STAT ')), '')
        mic_fields = {key: int(value) for key, value in re.findall(
            r'\b(mic_peak|mic_rms|i2s_errors|frames|lost)=([0-9]+)', sender_stat)}
        relay_fields = {key: int(value) for key, value in re.findall(
            r'\b(forwarded|invalid|udp_errors|bt_dropped_bytes|bt_buffered|rssi|heap)=(-?[0-9]+)',
            relay_final)}
        if not relay_fields and relay_stats:
            relay_fields = {key: int(value) for key, value in re.findall(
                r'\b(forwarded|invalid|udp_errors|bt_dropped_bytes|rssi|heap)=(-?[0-9]+)',
                relay_stats[-1])}
        sent_frames = None
        sent_match = re.search(r'\bsent_frames=([0-9]+)', sender_status)
        if sent_match:
            sent_frames = int(sent_match.group(1))
        packet_loss = (max(0, 1 - accepted / max(1, sent_frames)) * 100
                       if sent_frames is not None else None)
        stage = {
            'microphone': mic_fields.get('mic_peak', 0) > 0,
            'encryption': sent_frames is not None and sent_frames > 0,
            'bluetooth': bool(mac_match),
            'relay': relay_fields.get('forwarded', 0) > 0,
            'wifi': bool(relay_ready),
            'authentication': accepted > 0 and rejected == 0,
            'wav': bool(audio),
        }
        audio_stats = audio_statistics(pcm_all)
        safe_tamper_result = tamper_check(key, sid, algorithm)
        timestamp = datetime.now().astimezone().isoformat(timespec='seconds')
        result_label = 'PASS' if (accepted > 0 and rejected == 0
                                  and relay_fields.get('bt_dropped_bytes', 0) == 0
                                  and relay_fields.get('udp_errors', 0) == 0) else 'PARTIAL'
        report = {
            'timestamp': timestamp,
            'algorithm': algorithm,
            'session_id': sid.hex(),
            'capture_seconds': seconds,
            'recovered_audio_seconds': round(actual_seconds, 3),
            'authenticated_frames': accepted,
            'rejected_packets': rejected,
            'rejection_reasons': rejection_reasons,
            'concealed_missing_frames': jitter.lost,
            'packet_loss_percent': round(packet_loss, 2) if packet_loss is not None else None,
            'late_frames': jitter.late,
            'pending_at_stop': len(jitter.pending),
            'ciphertext_udp_bytes': wire_bytes,
            'mean_desktop_verify_decrypt_us': round(sum(decrypt_us)/len(decrypt_us), 2) if decrypt_us else None,
            'sender_stop': stop_result,
            'relay_wifi_ready': True,
            'bluetooth_peer_discovered': bool(mac_match),
            'last_relay_counters': relay_stats[-1] if relay_stats else 'The relay reports counters every 100 forwarded frames.',
            'final_relay_counters': exact_relay_status,
            'sender_firmware': sender_fw,
            'relay_firmware': relay_fw,
            'pipeline_stages': stage,
            'microphone': mic_fields,
            'sender_frames_reported': sent_frames,
            'audio_quality': audio_stats,
            'network': relay_fields,
            'wifi_rssi_dbm': relay_fields.get('rssi'),
            'tamper_demo': safe_tamper_result,
            'result': result_label,
            'output_wav': str(DEFAULT_OUT.relative_to(ROOT)),
            'authenticated_raw_wav': str(DEFAULT_RAW_OUT.relative_to(ROOT)),
            'audio_conditioning': audio_conditioning,
            'key_saved': False,
        }
        DEFAULT_OUT.with_suffix('.wav.json').write_text(json.dumps(report, indent=2))
        save_run_history(report)
        return audio, report
    finally:
        if sender is not None and sender_active:
            try:
                sender.send_line('STOP', 'STOP sender after capture error')
            except Exception:
                pass
        udp.close()


def render():
    import streamlit as st
    st.set_page_config(page_title='CAALC Live Hardware Demo', page_icon='🎙️', layout='wide')
    st.markdown("""
    <style>
      .block-container {padding-top: 2rem; padding-bottom: 3rem; max-width: 1440px;}
      .hero {padding: 1.5rem 1.7rem; border-radius: 18px; margin: 0 0 1.15rem;
        background: linear-gradient(115deg, #111b3d 0%, #233a73 55%, #145c67 100%); color: #f8fafc;}
      .hero h1 {color: #fff; font-size: 2.15rem; margin: 0 0 .35rem;}
      .hero p {color: #dce7ff; margin: .2rem 0; font-size: 1rem;}
      .hero-flow {font-weight: 650; letter-spacing: .01em;}
      div[data-testid="stVerticalBlockBorderWrapper"] {border-radius: 14px;}
      div[data-testid="stMetric"] {background: rgba(90, 125, 180, .07); padding: .8rem; border-radius: 12px;}
      .section-note {color: #64748b; font-size: .92rem;}
    </style>
    <section class="hero">
      <h1>CAALC Live Audio Link</h1>
      <p>Record speech on the INMP441, send authenticated audio across two ESP32 boards, and listen to the recovered recording.</p>
      <p class="hero-flow">🎙️ ESP32 A &nbsp;→&nbsp; Bluetooth &nbsp;→&nbsp; ESP32 B &nbsp;→&nbsp; Wi-Fi &nbsp;→&nbsp; 🔊 Laptop</p>
    </section>
    """, unsafe_allow_html=True)
    overview = st.columns(3)
    for col, title, detail in zip(overview,
            ('1 · Capture', '2 · Protect', '3 · Listen & review'),
            ('INMP441 microphone on ESP32 A',
             'Authenticated encryption; ESP32 B relays ciphertext',
             'Verify, decrypt, play, and save the run report')):
        with col:
            with st.container(border=True):
                st.markdown(f'**{title}**')
                st.caption(detail)
    st.caption('The fresh session key stays on the laptop. Audio is released only after packet authentication succeeds.')

    try:
        ports = serial_ports()
    except RuntimeError as exc:
        st.error(str(exc)); return
    if not ports:
        get_serial_registry().close_all()
        st.warning('Connect both ESP32 DevKit V1 boards to this laptop with USB data cables, then refresh the page.')
        return
    labels = dict(ports)
    devices = [device for device, _label in ports]
    with st.container(border=True):
        st.subheader('Configure a capture')
        st.markdown('<p class="section-note">Choose each board once, set the shared Wi-Fi details, then start a short recording.</p>',
                    unsafe_allow_html=True)
        left, right = st.columns(2)
        with left:
            sender_port = st.selectbox('ESP32 A · microphone sender', devices, format_func=lambda item: labels[item], key='bt_sender_port')
            ssid = st.text_input('2.4 GHz Wi-Fi network name', key='bt_wifi_ssid')
            password = st.text_input('Wi-Fi password', type='password', key='bt_wifi_password')
        with right:
            relay_port = st.selectbox('ESP32 B · Wi-Fi relay', devices, index=min(1, len(devices)-1), format_func=lambda item: labels[item], key='bt_relay_port')
            laptop_ip = st.text_input('Laptop Wi-Fi IP address', value=discover_lan_ip(),
                                      placeholder='e.g. 192.168.1.25',
                                      help='Find this in System Settings → Wi-Fi → Details → IP address.',
                                      key='bt_laptop_ip')
        settings = st.columns(2)
        algorithm = settings[0].selectbox('Encryption algorithm', ['ascon', 'caalc'], format_func=lambda x: 'Ascon-AEAD128 · standardized' if x == 'ascon' else 'CAALC-128 · experimental', key='bt_algorithm')
        seconds = settings[1].slider('Recording length', 5, 60, 15, format='%d seconds', key='bt_capture_seconds')
        udp_port = st.number_input('Laptop UDP port', min_value=1024, max_value=65535, value=5005, step=1, key='bt_udp_port')

    registry = get_serial_registry()
    links, link_errors = {}, {}
    if sender_port != relay_port:
        registry.keep_open((sender_port, relay_port))
        for role, port in (('ESP32 A · sender', sender_port), ('ESP32 B · relay', relay_port)):
            try:
                links[role] = registry.get(port)
            except Exception as exc:
                link_errors[role] = f'Cannot connect to {role} on {port}: {exc}'
    else:
        registry.close_all()

    if sender_port == relay_port:
        st.warning('Choose two different USB ports, one for each ESP32.')
    elif link_errors:
        for error in link_errors.values():
            st.error(error)
        st.info('Close any other app using these ESP32 USB ports, then refresh this page.')
    else:
        st.success('Both ESP32 boards are connected and ready.')
    can_capture = sender_port != relay_port and len(links) == 2
    if st.button('Start live hardware capture', type='primary', disabled=not can_capture, use_container_width=True):
        if not ssid.strip() or not laptop_ip.strip():
            st.error('Enter the Wi-Fi network name and laptop IPv4 address. Leave the password blank for an open network.')
        elif len(ssid.encode('utf-8')) > 32 or len(password.encode('utf-8')) > 63:
            st.error('The Wi-Fi name or password is too long for the ESP32 configuration.')
        else:
            progress = st.empty(); status = st.empty()
            a, b, c, d = st.columns(4)
            m1, m2, m3, m4 = a.empty(), b.empty(), c.empty(), d.empty()
            chart = st.empty()
            try:
                with st.spinner('Starting the two ESP32 boards…'):
                    audio, report = run_capture(sender_port, relay_port, ssid, password,
                        laptop_ip.strip(), int(udp_port), int(seconds), algorithm,
                        progress, status, type('Metrics', (), {
                            'metric': lambda self, label, value: ({
                                'Frames authenticated': m1, 'Rejected packets': m2,
                                'Estimated missing frames': m3,
                                'Pipeline stages passed': m4}[label].metric(label, value))
                        })(), chart)
                status.success(f"Capture finished: {report['result']}. Recovered audio came from authenticated frames; missing frames are marked as silence.")
                progress.progress(1.0, text='Audio received')
                st.audio(audio, format='audio/wav')
                st.download_button('Download recovered WAV', audio, 'live_received.wav', 'audio/wav')
                wav_json = json.dumps(report, indent=2)
                st.download_button('Download run report (JSON)', wav_json,
                                   'live_received_report.json', 'application/json')
                stage_labels = {
                    'microphone': 'Microphone capture', 'encryption': 'Encrypted frames sent',
                    'bluetooth': 'Bluetooth peer', 'relay': 'ESP32 B relay', 'wifi': 'Wi-Fi path',
                    'authentication': 'Packet authentication', 'wav': 'Audio file',
                }
                st.subheader('Live pipeline')
                stage_cols = st.columns(len(stage_labels))
                for col, (name, label) in zip(stage_cols, stage_labels.items()):
                    if report['pipeline_stages'].get(name):
                        col.success(f'✓ {label}')
                    else:
                        col.error(f'! {label}')

                st.subheader('Session evidence')
                st.caption('ESP32 B relays ciphertext and does not receive the session key. The session key stays in laptop memory and is not included in reports.')
                security_cols = st.columns(4)
                security_cols[0].metric('Cipher', report['algorithm'].upper())
                security_cols[1].metric('Authenticated frames', report['authenticated_frames'])
                security_cols[2].metric('Rejected / tampered', report['rejected_packets'])
                security_cols[3].metric('Local tamper self-test', 'PASS' if report['tamper_demo']['tampered_packet_rejected'] else 'FAIL')
                st.caption(f"Session ID: `{report['session_id']}` · key saved: no · local tamper test altered a self-test packet only.")

                st.subheader('Audio quality')
                aq = report['audio_quality']; mic = report['microphone']
                quality_cols = st.columns(5)
                quality_cols[0].metric('Recovered duration', f"{report['recovered_audio_seconds']:.2f} s")
                quality_cols[1].metric('Mic peak', mic.get('mic_peak', 'not reported'))
                quality_cols[2].metric('Mic RMS', mic.get('mic_rms', 'not reported'))
                quality_cols[3].metric('Audio RMS', aq['rms'])
                quality_cols[4].metric('Clipped samples', f"{aq['clipped_percent']:.4f}%")
                plot_pcm, plot_rate = audio_plot_pcm(audio)
                st.pyplot(spectrogram_image(plot_pcm, plot_rate), clear_figure=True)

                st.subheader('Network health')
                network = report['network']
                network_cols = st.columns(5)
                network_cols[0].metric('Wi-Fi RSSI', f"{network['rssi']} dBm" if 'rssi' in network else 'not reported')
                network_cols[1].metric('Relay forwarded', network.get('forwarded', 0))
                network_cols[2].metric('Bluetooth dropped bytes', network.get('bt_dropped_bytes', 0))
                network_cols[3].metric('UDP relay errors', network.get('udp_errors', 0))
                loss_display = (f"{report['packet_loss_percent']}%"
                                if report['packet_loss_percent'] is not None else 'not measured')
                network_cols[4].metric('Packet loss estimate', loss_display)
                st.caption(f"Mean laptop verify/decrypt time: {report['mean_desktop_verify_decrypt_us']} µs. Missing audio frames are concealed with silence.")
                with st.expander('Developer diagnostics · raw metrics'):
                    st.json(report)
            except Exception as exc:
                status.error(f'Hardware capture failed: {exc}')

    history = load_run_history()
    st.divider()
    st.subheader('CAALC vs Ascon experiment history')
    if history:
        history_cols = st.columns(2)
        history_cols[0].download_button('Download experiment history (CSV)', history_csv(history),
                                        'caalc_ascon_experiments.csv', 'text/csv')
        history_cols[1].download_button('Download experiment history (JSON)',
                                        json.dumps(history, indent=2),
                                        'caalc_ascon_experiments.json', 'application/json')
        table_rows = [{
            'Run': row.get('timestamp'), 'Cipher': row.get('algorithm', '').upper(),
            'Seconds': row.get('capture_seconds'), 'Authenticated': row.get('authenticated_frames'),
            'Rejected': row.get('rejected_packets'), 'Lost frames': row.get('concealed_missing_frames'),
            'Packet loss %': row.get('packet_loss_percent'),
            'Decrypt µs': row.get('mean_desktop_verify_decrypt_us'),
            'RSSI dBm': row.get('wifi_rssi_dbm', row.get('network', {}).get('rssi')),
            'Result': row.get('result'),
        } for row in history]
        st.dataframe(table_rows, use_container_width=True, hide_index=True)
        comparisons = {}
        for cipher in ('caalc', 'ascon'):
            rows = [row for row in history if row.get('algorithm') == cipher]
            if rows:
                comparisons[cipher.upper()] = {
                    'runs': len(rows),
                    'mean_authenticated_frames': round(sum(r.get('authenticated_frames', 0) for r in rows) / len(rows), 2),
                    'mean_rejected_packets': round(sum(r.get('rejected_packets', 0) for r in rows) / len(rows), 2),
                    'mean_packet_loss_percent': (
                        round(sum(r['packet_loss_percent'] for r in rows
                                  if r.get('packet_loss_percent') is not None) /
                              max(1, sum(r.get('packet_loss_percent') is not None for r in rows)), 2)
                        if any(r.get('packet_loss_percent') is not None for r in rows) else None
                    ),
                    'mean_desktop_verify_decrypt_us': round(sum(r.get('mean_desktop_verify_decrypt_us') or 0 for r in rows) / len(rows), 2),
                }
        if comparisons:
            st.caption('Comparison summarizes saved physical runs; values are not inferred for a cipher without a run.')
            st.dataframe([{'Cipher': name, **values} for name, values in comparisons.items()],
                         use_container_width=True, hide_index=True)
    else:
        st.info('Run one capture with each cipher to build the comparison table.')

    st.divider()
    st.subheader('Hardware checklist')
    st.markdown('- Flash the sender sketch to ESP32 A and the relay sketch to ESP32 B. Close other apps using their USB ports before capture.\n- Connect one INMP441 to ESP32 A. Keep ESP32 B and the laptop on the same 2.4 GHz Wi-Fi network.\n- Use two original ESP32 DevKit V1 boards; Bluetooth Classic SPP is not supported on ESP32-S2/S3/C3 boards.\n- Keep both USB data cables connected for secure session setup and board status checks.')
    st.caption('Dashboard output is an authenticated software/hardware demonstration. It does not claim measured speech quality against a ground-truth recording or a tested RF range.')


if __name__ == '__main__':
    render()

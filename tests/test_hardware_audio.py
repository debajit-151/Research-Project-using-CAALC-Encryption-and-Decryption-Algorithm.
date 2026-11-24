import math
import struct
from pathlib import Path

import hardware_dashboard


def test_authenticated_pcm_conditioning_removes_dc_and_adds_bounded_gain():
    rate = 8000
    samples = [2000 + int(120 * math.sin(2 * math.pi * 440 * i / rate))
               for i in range(rate)]
    source = struct.pack(f'<{len(samples)}h', *samples)

    output, report = hardware_dashboard.condition_authenticated_pcm(source, rate)
    recovered = struct.unpack(f'<{len(samples)}h', output)

    assert len(output) == len(source)
    assert report['gain_x'] == 8.0
    assert 0 < report['output_peak'] <= 32767
    assert abs(sum(recovered) / len(recovered)) < 2


def test_authenticated_pcm_conditioning_accepts_empty_audio():
    output, report = hardware_dashboard.condition_authenticated_pcm(b'', 8000)
    assert output == b''
    assert report['output_peak'] == 0


def test_sender_uses_stereo_slot_detection_and_full_resolution_input():
    source = (Path(__file__).parents[1] / 'firmware' / 'esp32_bt_sender' /
              'esp32_bt_sender.ino').read_text()
    assert 'I2S_CHANNEL_FMT_RIGHT_LEFT' in source
    assert 'detectActiveMicSlot' in source
    assert 'FRAME_MS = 40' in source
    assert 'FRAME_SAMPLES = 320' in source
    assert 'rawWord >> 8' in source
    assert 'stereoSamples[2 * i + micActiveSlot]' in source
    assert 'packet + 28 + PCM_BYTES' in source
    assert 'packet + 348' not in source
    assert 'SENDER_STATUS sent_frames=' in source
    assert 'sentFrames > 0' in source or '++sentFrames' in source
    assert 'I2S_CHANNEL_FMT_ONLY_LEFT' not in source


def test_relay_uses_matching_low_packet_rate_format():
    source = (Path(__file__).parents[1] / 'firmware' / 'esp32_wifi_relay' /
              'esp32_wifi_relay.ino').read_text()
    assert 'ms == 40' in source
    assert 'payload == 640' in source
    assert 'WiFi.setSleep(true)' in source
    assert 'WiFi.setSleep(false)' not in source
    assert 'WIFI_COEX_POWER_SAVE' in source
    assert 'BT_STREAM_BYTES = 16384' in source
    assert 'SerialBT.onData(receiveBluetoothData)' in source
    assert 'xStreamBufferReceive' in source
    assert 'SerialBT.readBytes' not in source
    assert 'RELAY_STATUS' in source


def test_dashboard_recognizes_esp32_crash_output():
    assert hardware_dashboard.board_crash_line(
        'abort() was called at PC 0x401a7294 on core 1'
    )
    assert hardware_dashboard.board_crash_line(
        'Guru Meditation Error: Core 1 panic\'ed (LoadProhibited)'
    )
    assert not hardware_dashboard.board_crash_line(
        'CAALC ESP32 B relay ready; waiting for laptop Wi-Fi configuration'
    )


def test_audio_statistics_and_empty_audio():
    pcm = struct.pack('<4h', -32768, -100, 100, 32767)
    report = hardware_dashboard.audio_statistics(pcm)
    assert report == {'samples': 4, 'peak': 32768, 'rms': 23170.23,
                      'clipped_percent': 50.0}
    assert hardware_dashboard.audio_statistics(b'')['samples'] == 0


def test_tamper_demo_rejects_modified_packet_without_releasing_audio():
    result = hardware_dashboard.tamper_check(bytes(range(16)), bytes(range(8)), 'caalc')
    assert result['tampered_packet_rejected'] is True
    assert result['audio_released'] is False
    assert 'not modified' in result['scope']


def test_run_history_csv_exports_nested_metrics():
    row = {'timestamp': '2026-11-22T15:00:00+05:30', 'algorithm': 'ascon',
           'capture_seconds': 10, 'authenticated_frames': 250,
           'rejected_packets': 0, 'concealed_missing_frames': 0,
           'packet_loss_percent': 0.0, 'mean_desktop_verify_decrypt_us': 55.5,
           'wifi_rssi_dbm': -48, 'microphone': {'mic_rms': 920}, 'result': 'PASS'}
    csv_text = hardware_dashboard.history_csv([row])
    assert 'ascon' in csv_text and '250' in csv_text and 'PASS' in csv_text

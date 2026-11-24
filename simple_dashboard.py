"""One-page CAALC audio demo. UI helpers are separate from the unchanged cipher."""
from __future__ import annotations
import hashlib
import io
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
import wave

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import main as core

MAX_UPLOAD = 20 * 1024 * 1024
MAX_SECONDS = 60


def prepare_audio(data: bytes, filename: str):
    """Preserve supported PCM; convert other formats to mono PCM16/8 kHz."""
    if not data or len(data) > MAX_UPLOAD:
        raise ValueError('Upload a nonempty audio file smaller than 20 MB.')
    converted = False
    try:
        rate, pcm = core.wav_read(data)
    except (ValueError, wave.Error, EOFError):
        try:
            import imageio_ffmpeg
        except ImportError as exc:
            raise ValueError('For MP3/M4A or other audio formats, install the converter: python -m pip install imageio-ffmpeg==0.6.0') from exc
        suffix = Path(filename).suffix.lower()
        if suffix not in ('.wav', '.mp3', '.m4a', '.flac', '.ogg'):
            raise ValueError('Supported uploads: WAV, MP3, M4A, FLAC and OGG.')
        with tempfile.TemporaryDirectory(prefix='caalc_audio_') as folder:
            src, dst = Path(folder)/('input'+suffix), Path(folder)/'prepared.wav'
            src.write_bytes(data)
            # Local bytes only. Decode just enough to reject clips over the duration cap.
            command = [imageio_ffmpeg.get_ffmpeg_exe(), '-nostdin', '-v', 'error',
                       '-protocol_whitelist', 'file,pipe', '-i', str(src), '-vn',
                       '-map', '0:a:0', '-t', str(MAX_SECONDS+1), '-ac', '1', '-ar',
                       '8000', '-c:a', 'pcm_s16le', '-y', str(dst)]
            try:
                subprocess.run(command, check=True, capture_output=True, timeout=45)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
                raise ValueError('Could not decode this audio. Try a normal WAV, MP3 or M4A recording.') from exc
            rate, pcm = core.wav_read(dst.read_bytes())
            converted = True
    duration = len(pcm) / (2 * rate)
    if not pcm:
        raise ValueError('This file has no audio samples.')
    if duration > MAX_SECONDS:
        raise ValueError('For this initial demo, use an audio clip of 60 seconds or less.')
    return core.wav_bytes(rate, pcm), {'rate': rate, 'seconds': duration,
                                      'samples': len(pcm)//2, 'converted': converted}


def ciphertext_payload(container: bytes):
    """Extract only ciphertext for presentation, excluding headers and tags.

    This checks structure, NOT authentication. Only called on freshly generated
    local containers. Authentication remains mandatory for real decryption.
    """
    if len(container) < core.CONTAINER.size:
        raise ValueError('Short container')
    magic, version, alg, sid, rate, ms, total = core.CONTAINER.unpack_from(container)
    if (magic != b'CAF1' or version != 1 or alg not in (0, 1) or rate not in (8000, 16000)
            or ms not in (10, 20, 40) or total % 2 or total > len(container)):
        raise ValueError('Invalid CAALC container')
    pos, q, payload = core.CONTAINER.size, 0, bytearray()
    step = rate * ms // 1000 * 2
    count = max(1, (total + step - 1)//step)
    for q in range(count):
        if pos + 2 > len(container): raise ValueError('Truncated record')
        n = struct.unpack_from('<H', container, pos)[0]; pos += 2
        if not 44 <= n <= 1324 or pos+n > len(container): raise ValueError('Invalid record')
        packet = container[pos:pos+n]; pos += n
        pm, pv, pa, ps, pq, pr, pms, size = core.HEADER.unpack_from(packet)
        if ((pm, pv, pa, ps, pq, pr, pms) != (b'CAP1', 1, alg, sid, q, rate, ms)
                or size != min(step, max(0, total-q*step)) or n != size+44):
            raise ValueError('Invalid packet')
        payload.extend(packet[28:-16])
    if pos != len(container) or len(payload) != total:
        raise ValueError('Invalid container length')
    return rate, bytes(payload)


def make_preview(container: bytes):
    """Interpret ciphertext as PCM16 and attenuate to 8% for a listening preview."""
    import numpy as np
    rate, ciphertext = ciphertext_payload(container)
    pcm = (np.frombuffer(ciphertext, dtype='<i2').astype(np.float64)*0.08).astype('<i2')
    return core.wav_bytes(rate, pcm.tobytes())


def encrypt_audio(prepared: bytes, algorithm: str = 'caalc'):
    if algorithm not in ('caalc', 'ascon'):
        raise ValueError('Choose CAALC or Ascon AEAD.')
    key = os.urandom(16)
    start = time.perf_counter()
    container = core.seal_wav(prepared, key, ms=20, algorithm=algorithm)
    elapsed = time.perf_counter()-start
    _, ciphertext = ciphertext_payload(container)
    return {'key': key, 'container': container, 'preview': make_preview(container),
            'ciphertext_hex': ciphertext[:96].hex(),
            'algorithm': algorithm,
            'encrypt_seconds': elapsed, 'recovered': None, 'metrics': None}


def decrypt_audio(record, prepared: bytes):
    # Never substitute original audio for decryption output.
    start = time.perf_counter()
    recovered = core.unseal_wav(record['container'], record['key'])
    elapsed = time.perf_counter()-start
    rate, original_pcm = core.wav_read(prepared)
    recovered_rate, recovered_pcm = core.wav_read(recovered)
    if recovered_rate != rate:
        raise ValueError('Recovered sample rate differs')
    return recovered, core.metrics(original_pcm, recovered_pcm), elapsed


def render():
    import streamlit as st
    st.set_page_config(page_title='CAALC-128 | Audio Demo', page_icon='🔐', layout='wide',
                       initial_sidebar_state='collapsed')
    st.markdown('''<style>
    .block-container {max-width:1180px;padding-top:2.3rem;}
    div[data-testid="stMetric"] {background:rgba(125,140,170,.07);border-radius:12px;padding:14px;}
    </style>''', unsafe_allow_html=True)
    st.title('CAALC-128 Audio Demo')
    st.write('Upload your audio. Encrypt it. Decrypt it and hear the result.')
    st.caption('Experimental CA-inspired authenticated cipher · 128-bit key · 24 Feistel rounds')
    audio_algorithm = st.selectbox('Audio AEAD algorithm', ['caalc', 'ascon'],
                                   format_func=lambda x: 'CAALC-128 (experimental)' if x == 'caalc' else 'Ascon-AEAD128 (standardized)',
                                   key='audio_algorithm')
    with st.expander('Post-quantum authenticated session demo'):
        st.write('Runs logical sender and receiver roles locally using ML-KEM-512 and pinned ML-DSA-44 identities, then checks audio-frame encryption and tamper rejection.')
        pq_suite = st.selectbox('Session cipher', ['caalc', 'ascon'], key='pq_demo_suite')
        if st.button('Run authenticated session demo', key='pq_demo_run'):
            try:
                import pq_session
                with st.spinner('Establishing and verifying session…'):
                    st.session_state['pq_demo_report'] = pq_session.demo_exchange(pq_suite)
            except Exception as exc:
                st.error(f'Post-quantum session demo failed: {exc}')
        if st.session_state.get('pq_demo_report'):
            st.json(st.session_state['pq_demo_report'])
    uploaded = st.file_uploader('Choose your audio', type=['wav','mp3','m4a','flac','ogg'],
                                key='simple_audio_upload',
                                help='Up to 60 seconds and 20 MB. Other formats are converted to mono PCM16 at 8 kHz.')
    st.caption('WAV, MP3, M4A, FLAC or OGG · Start with a short voice recording.')
    if uploaded is None:
        st.session_state.pop('caalc_simple', None)
        st.info('Upload an audio file to begin. You can also use results/original.wav from the project.')
        return
    data = uploaded.getvalue()
    digest = hashlib.sha256(data).hexdigest()
    previous = st.session_state.get('caalc_simple')
    if previous is None or previous['digest'] != digest:
        # Immediately remove stale results when a different upload is selected.
        st.session_state.pop('caalc_simple', None)
        try:
            with st.spinner('Preparing your audio…'):
                prepared, info = prepare_audio(data, uploaded.name)
        except ValueError as exc:
            st.error(str(exc)); return
        st.session_state['caalc_simple'] = {'digest': digest, 'prepared': prepared,
                                             'info': info, 'record': None, 'error': None}
    state = st.session_state['caalc_simple']
    info = state['info']
    st.caption(f"{info['seconds']:.1f} seconds · {info['rate']:,} Hz · Mono · 16-bit PCM")
    if info['converted']:
        st.info('Your upload was converted to mono PCM16 at 8 kHz. The original player below plays this prepared audio; decryption is compared against it.')
    original, encrypted, decrypted = st.columns(3, gap='large')
    with original:
        st.subheader('1 · Original audio')
        st.audio(state['prepared'], format='audio/wav')
        st.caption('Listen to the audio that will be encrypted.')
        if st.button('Encrypt audio', type='primary', key='simple_encrypt', use_container_width=True):
            state['record'] = None; state['error'] = None
            try:
                with st.spinner(f'Encrypting with {audio_algorithm}…'):
                    state['record'] = encrypt_audio(state['prepared'], audio_algorithm)
            except (ValueError, OSError) as exc:
                state['error'] = str(exc)
        st.download_button('Download prepared WAV', state['prepared'], 'prepared_audio.wav',
                           mime='audio/wav', key='simple_prepared_download')
    record = state['record']
    with encrypted:
        st.subheader('2 · Encrypted audio')
        if record:
            st.caption('Ciphertext is authenticated binary data. It is not playable audio.')
            st.code(record['ciphertext_hex'][:192] + ('…' if len(record['ciphertext_hex']) > 192 else ''), language='text')
            st.caption(f"Encrypted container: {len(record['container']):,} bytes · {record['encrypt_seconds']:.3f} s")
            st.download_button('Download encrypted file', record['container'], 'encrypted_audio.caf',
                               mime='application/octet-stream', key='simple_container_download')
        else:
            st.info('Encrypt your audio to inspect its ciphertext and authenticated container.')
        if st.button('Decrypt audio', key='simple_decrypt', disabled=record is None,
                     use_container_width=True):
            record['recovered'] = None; record['metrics'] = None; state['error'] = None
            try:
                with st.spinner('Verifying tags and decrypting…'):
                    recovered, measured, elapsed = decrypt_audio(record, state['prepared'])
                record.update(recovered=recovered, metrics=measured, decrypt_seconds=elapsed)
            except (ValueError, OSError) as exc:
                state['error'] = str(exc)
    with decrypted:
        st.subheader('3 · Decrypted audio')
        if record and record['recovered'] is not None:
            st.audio(record['recovered'], format='audio/wav')
            st.success('Authentication verified. Audio recovered.')
            st.download_button('Download decrypted WAV', record['recovered'], 'decrypted_audio.wav',
                               mime='audio/wav', key='simple_recovered_download')
        else:
            st.info('Decrypt the encrypted file to hear the recovered audio.')
    if state['error']:
        st.error(state['error'])
    if record and record['metrics'] is not None:
        m = record['metrics']
        a,b,c = st.columns(3)
        a.metric('Samples recovered exactly', f"{100*m['exact_sample_fraction']:.1f}%")
        b.metric('MSE', f"{m['MSE']:.6g}")
        c.metric('PSNR', '∞ dB' if m['MSE'] == 0 else f"{m['PSNR_dB']:.2f} dB")
        st.caption('Recovery metrics compare the prepared original with authenticated decryption output. Noise-like ciphertext is not proof of security.')
    if record:
        with st.expander('Save your key / session details'):
            st.write('A fresh key is created automatically when you encrypt. Download it if you want to decrypt the CAF file after closing this page.')
            st.download_button('Download session key', record['key'].hex()+'\n', 'audio_session.key',
                               mime='text/plain', key='simple_key_download')
            st.caption('Keep the key separate from the encrypted file. A new upload or another encryption clears the previous on-screen result.')
            st.code('python main.py decrypt encrypted_audio.caf recovered.wav --key audio_session.key', language='bash')


if __name__ == '__main__':
    render()

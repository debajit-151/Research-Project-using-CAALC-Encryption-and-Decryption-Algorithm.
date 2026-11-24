import io
import sys
import struct
import subprocess
from pathlib import Path
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import main as core
import simple_dashboard as ui


def test_cipher_source_unchanged():
    # Checked separately against the previous release; this test checks supplied public vectors.
    import json
    for v in json.loads((core.ROOT/'test_vectors/caalc_vectors.json').read_text())['aead']:
        k,n,p,a=[bytes.fromhex(v[x]) for x in ('key','nonce','plaintext','ad')]
        c,t=core.encrypt(k,n,p,a)
        assert c.hex()==v['ciphertext'] and t.hex()==v['tag']


def test_preview_from_real_ciphertext_and_recovery():
    import numpy as np
    source=core.demo_wav(.061)
    prepared,info=ui.prepare_audio(source,'voice.wav')
    assert not info['converted']
    rec=ui.encrypt_audio(prepared)
    rate,payload=ui.ciphertext_payload(rec['container'])
    preview_rate,preview_pcm=core.wav_read(rec['preview'])
    assert preview_rate==rate==8000
    assert preview_pcm==(np.frombuffer(payload,dtype='<i2').astype(float)*.08).astype('<i2').tobytes()
    assert len(preview_pcm)==len(core.wav_read(prepared)[1])
    assert preview_pcm!=core.wav_read(prepared)[1]
    result,m,_=ui.decrypt_audio(rec,prepared)
    assert result==prepared and m['MSE']==0 and m['exact_sample_fraction']==1
    other=ui.encrypt_audio(prepared)
    assert rec['key']!=other['key'] and rec['container']!=other['container']


def test_tampered_and_wrong_key_rejected():
    prepared=core.demo_wav(.02)
    rec=ui.encrypt_audio(prepared)
    original=rec['container']
    rec['container']=original[:-1]+bytes([original[-1]^1])
    with pytest.raises(core.AuthenticationError):ui.decrypt_audio(rec,prepared)
    assert rec['recovered'] is None
    rec['container']=original;rec['key']=bytes(16)
    with pytest.raises(core.AuthenticationError):ui.decrypt_audio(rec,prepared)


def test_standardized_ascon_dashboard_roundtrip():
    prepared=core.demo_wav(.04)
    rec=ui.encrypt_audio(prepared, 'ascon')
    assert rec['algorithm']=='ascon'
    recovered,metrics,_=ui.decrypt_audio(rec,prepared)
    assert recovered==prepared
    assert metrics['MSE']==0 and metrics['exact_sample_fraction']==1


def test_conversion_stereo_44100_and_mp3(tmp_path):
    import numpy as np
    import wave
    import imageio_ffmpeg
    t=np.arange(4410)/44100
    pcm=(np.sin(2*np.pi*440*t)*10000).astype('<i2')
    buf=io.BytesIO()
    with wave.open(buf,'wb') as w:
        w.setnchannels(2);w.setsampwidth(2);w.setframerate(44100);w.writeframes(np.column_stack([pcm,pcm]).astype('<i2').tobytes())
    source=buf.getvalue()
    raw,info=ui.prepare_audio(source,'stereo.wav')
    assert info['converted'] and info['rate']==8000
    assert info['samples']==800
    (tmp_path/'source.wav').write_bytes(source)
    subprocess.run([imageio_ffmpeg.get_ffmpeg_exe(),'-v','error','-i',str(tmp_path/'source.wav'),'-y',str(tmp_path/'voice.mp3')],check=True)
    converted,info=ui.prepare_audio((tmp_path/'voice.mp3').read_bytes(),'voice.mp3')
    rec=ui.encrypt_audio(converted)
    assert ui.decrypt_audio(rec,converted)[0]==converted


def test_input_limits_and_malformed_preview():
    for raw in [b'',b'not an audio file']:
        with pytest.raises(ValueError):ui.prepare_audio(raw,'bad.wav')
    with pytest.raises(ValueError):ui.prepare_audio(core.wav_bytes(8000,b''),'empty.wav')
    with pytest.raises(ValueError):ui.prepare_audio(core.wav_bytes(8000,bytes(2*8000*61)),'long.wav')
    good=ui.encrypt_audio(core.demo_wav(.02))['container']
    for bad in [b'',good[:-1],good+b'x',b'bad!'+good[4:]]:
        with pytest.raises(ValueError):ui.ciphertext_payload(bad)


APP = '''
import io
from unittest.mock import patch
import streamlit as st
import main
import simple_dashboard
content = st.session_state.get('test_upload_bytes', main.demo_wav(.04))
upload = io.BytesIO(content)
upload.name = 'voice.wav'
with patch.object(st, 'file_uploader', return_value=upload):
    main.dashboard()
'''


def test_single_screen_click_flow_and_reset():
    from streamlit.testing.v1 import AppTest
    app=AppTest.from_string(APP,default_timeout=20).run()
    assert not app.exception
    assert not app.sidebar.radio
    assert app.button(key='simple_decrypt').disabled
    app.button(key='simple_encrypt').click().run()
    assert not app.exception
    record=app.session_state['caalc_simple']['record']
    assert record['preview'].startswith(b'RIFF') and record['recovered'] is None
    app.button(key='simple_decrypt').click().run()
    assert not app.exception and len(app.success)==1
    assert app.session_state['caalc_simple']['record']['metrics']['MSE']==0
    previous_key=app.session_state['caalc_simple']['record']['key']
    app.button(key='simple_encrypt').click().run()
    assert not app.exception
    assert app.session_state['caalc_simple']['record']['recovered'] is None
    assert app.session_state['caalc_simple']['record']['key']!=previous_key
    app.session_state['test_upload_bytes']=core.demo_wav(.05)
    app.run()
    assert app.session_state['caalc_simple']['record'] is None
    assert app.button(key='simple_decrypt').disabled


def test_ui_rejects_tamper_without_player():
    from streamlit.testing.v1 import AppTest
    app=AppTest.from_string(APP,default_timeout=20).run()
    app.button(key='simple_encrypt').click().run()
    record=app.session_state['caalc_simple']['record']
    raw=record['container'];record['container']=raw[:-1]+bytes([raw[-1]^1])
    app.button(key='simple_decrypt').click().run()
    assert not app.exception and len(app.error)==1
    assert app.session_state['caalc_simple']['record']['recovered'] is None
    assert len(app.success)==0


def test_empty_start_screen():
    from streamlit.testing.v1 import AppTest
    app=AppTest.from_string('import main; main.dashboard()',default_timeout=20).run()
    assert not app.exception and not app.sidebar.radio
    assert len(app.button)==1
    assert app.button(key='pq_demo_run').label == 'Run authenticated session demo'


def test_authenticated_session_button_runs_in_dashboard():
    from streamlit.testing.v1 import AppTest
    app=AppTest.from_string('import main; main.dashboard()',default_timeout=20).run()
    app.button(key='pq_demo_run').click().run()
    assert not app.exception
    assert app.session_state['pq_demo_report']['key_confirmation_verified']
    assert app.session_state['pq_demo_report']['audio_roundtrip']

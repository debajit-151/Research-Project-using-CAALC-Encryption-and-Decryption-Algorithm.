import sys,random,struct,ctypes,math,json
from pathlib import Path
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import main as m

def test_inverse():
    rng=random.Random(9)
    for _ in range(100):
        s=[rng.getrandbits(32) for _ in range(12)]; assert m.permutation(m.permutation(s),True)==s

def test_native_permutation():
    lib=m.Native('caalc').lib; fn=lib.caalc_permute; fn.argtypes=[ctypes.POINTER(ctypes.c_uint32),ctypes.c_int]
    rng=random.Random(55)
    for _ in range(100):
        s=[rng.getrandbits(32) for _ in range(12)]; a=(ctypes.c_uint32*12)(*s); fn(a,0); assert list(a)==m.permutation(s); fn(a,1); assert list(a)==s

@pytest.mark.parametrize('n',[0,1,2,15,16,17,31,32,33,160,320,1280,65536])
@pytest.mark.parametrize('alen',[0,1,16,17])
def test_roundtrip_cross_language(n,alen):
    k=bytes(range(16)); nonce=bytes(range(16,32)); p=bytes(i%256 for i in range(n)); ad=bytes(range(alen)); c,t=m.encrypt(k,nonce,p,ad)
    assert m.decrypt(k,nonce,c,ad,t)==p
    native=m.Native('caalc'); assert native.encrypt(k,nonce,p,ad)==(c,t); assert native.decrypt(k,nonce,c,ad,t)==p

@pytest.mark.parametrize('what',['key','nonce','ciphertext','tag','ad'])

@pytest.mark.parametrize('backend',['python','caalc','ascon'])
def test_tamper(what,backend):
    engine=m if backend=='python' else m.Native(backend)
    k=bytes(16); n=bytes(16); p=b'samples'; ad=b'header'; c,t=engine.encrypt(k,n,p,ad)
    fields=dict(key=k,nonce=n,ciphertext=c,tag=t,ad=ad); v=fields[what]; fields[what]=bytes([v[0]^1])+v[1:]
    with pytest.raises(m.AuthenticationError): engine.decrypt(fields['key'],fields['nonce'],fields['ciphertext'],fields['ad'],fields['tag'])

def test_ascon_official_kat():
    engine=m.Native('ascon'); count=0
    for block in (m.ROOT/'test_vectors/ascon_kat.txt').read_text().strip().split('\n\n'):
        d=dict(line.split(' = ',1) for line in block.splitlines() if ' = ' in line)
        k,n,p,ad,ct=[bytes.fromhex(d[x]) for x in ('Key','Nonce','PT','AD','CT')]
        c,t=engine.encrypt(k,n,p,ad); assert c+t==ct; assert engine.decrypt(k,n,c,ad,t)==p; count+=1
    assert count==1089

@pytest.mark.parametrize('rate',[8000,16000])
@pytest.mark.parametrize('ms',[10,20,40])
@pytest.mark.parametrize('alg',['caalc','ascon'])
def test_audio(rate,ms,alg):
    raw=m.demo_wav(.051,rate); k=bytes(16); sealed=m.seal_wav(raw,k,ms,alg); assert m.unseal_wav(sealed,k)==raw
    with pytest.raises(ValueError): m.unseal_wav(sealed[:-1],k)
    with pytest.raises(ValueError): m.unseal_wav(sealed+b'x',k)
    for pos in (0,6,14,18,26,30,len(sealed)-1):
        bad=bytearray(sealed); bad[pos]^=1
        with pytest.raises(ValueError): m.unseal_wav(bytes(bad),k)

def test_empty_audio():
    raw=m.wav_bytes(8000,b''); enc=m.seal_wav(raw,bytes(16)); assert m.unseal_wav(enc,bytes(16))==raw

def test_large_audio():
    # 1 MiB PCM (~65.5 sec at 8k), standardized/native path + 2 sec Python custom path.
    raw=m.wav_bytes(8000,bytes(1048576)); k=bytes(16)
    assert m.unseal_wav(m.seal_wav(raw,k,40,'ascon'),k)==raw
    raw=m.demo_wav(2); assert m.unseal_wav(m.seal_wav(raw,k),k)==raw

def test_metrics():
    a=struct.pack('<3h',0,1,-1); result=m.metrics(a,a); assert result['MSE']==0 and math.isinf(result['PSNR_dB']) and result['exact_sample_fraction']==1
    r=m.metrics(struct.pack('<h',1),struct.pack('<h',0)); assert r['MSE']==1 and r['SNR_dB']==0
    r=m.metrics(bytes(2),struct.pack('<h',1)); assert r['SNR_dB']==-math.inf
    assert m.metrics(bytes(2),bytes(2))['SNR_dB']==math.inf
    for x,y in [(b'',b''),(bytes(2),bytes(4))]:
        with pytest.raises(ValueError): m.metrics(x,y)

def test_replay_nonce_malformed():
    k=bytes(16); sid=bytes(8); r=m.SessionReceiver(k,sid)
    p=m.make_packet(k,sid,0,8000,20,bytes(320)); assert r.accept(p)[0]==0
    with pytest.raises(ValueError): r.accept(p)
    for q in (2,1,64): r.accept(m.make_packet(k,sid,q,8000,20,bytes(320)))
    with pytest.raises(ValueError): r.accept(p)
    for bad in (b'',p[:-1],p+b'x',b'xxxx'+p[4:]):
        with pytest.raises(ValueError): m.SessionReceiver(k,sid).accept(bad)
    bad=bytearray(p); bad[-1]^=1; clean=m.SessionReceiver(k,sid)
    with pytest.raises(ValueError): clean.accept(bytes(bad))
    assert clean.accept(p)[0]==0 # rejection must not advance replay state
    assert len({sid+struct.pack('<Q',q) for q in range(10000)})==10000
    with pytest.raises(ValueError): m.make_packet(k,sid,2**32,8000,20,b'')

def test_jitter():
    j=m.JitterBuffer(8000,20); j.put(1,b'b',0); j.put(0,b'a',.001)
    assert j.ready(.079)==[]; assert j.ready(.081)==[b'a']; assert j.ready(.101)==[b'b']; assert j.ready(.121)==[bytes(320)]; assert j.lost==1

def test_mlkem(tmp_path): assert m.mlkem_demo(tmp_path)['secret_agreement']

def test_structural_screening(tmp_path):
    r=m.experiments(tmp_path,16)
    assert .3<r['avalanche_mean']<.7; assert r['rotation_equivariance_matches_of_32']==0
    assert all(n==12 for n in r['repeated_word_output_distinct_words'])

def test_dashboard_launch():
    from streamlit.testing.v1 import AppTest
    app=AppTest.from_file(str(m.ROOT/'main.py'),default_timeout=20)
    # Run dashboard through tiny test-only entrypoint rather than the CLI parser.
    app=AppTest.from_string('import main; main.dashboard()',default_timeout=20); app.run(); assert not app.exception


def test_saved_vectors():
    vectors=json.loads((m.ROOT/'test_vectors/caalc_vectors.json').read_text())
    for v in vectors['aead']:
        k,n,p,ad=[bytes.fromhex(v[x]) for x in ('key','nonce','plaintext','ad')]
        c,t=m.encrypt(k,n,p,ad); assert c.hex()==v['ciphertext'] and t.hex()==v['tag']

@pytest.mark.parametrize('page',['Project Overview','Audio Encryption','Audio Decryption','Audio Analysis','Security Experiments','Cipher Comparison','Hardware Demonstration'])
def test_dashboard_screens(page):
    from streamlit.testing.v1 import AppTest
    app=AppTest.from_string('import main; main.advanced_dashboard()',default_timeout=20).run()
    app.sidebar.radio[0].set_value(page).run(); assert not app.exception

def test_udp_receiver(tmp_path):
    import socket,threading,time
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('127.0.0.1',0)); port=s.getsockname()[1]; s.close()
    key=bytes(16); sid=bytes(8); reports=[]; target=tmp_path/'udp.wav'
    thread=threading.Thread(target=lambda:reports.append(m.receive(key,sid,target,.6,port))); thread.start(); time.sleep(.08)
    sender=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    for q in range(8):
        packet=m.make_packet(key,sid,q,8000,20,struct.pack('<160h',*([q+1]*160)))
        sender.sendto(packet,('127.0.0.1',port))
        if q==0:
            sender.sendto(packet,('127.0.0.1',port)); bad=bytearray(packet);bad[-1]^=1;sender.sendto(bytes(bad),('127.0.0.1',port))
        time.sleep(.02)
    thread.join(5);sender.close();assert not thread.is_alive()
    assert reports[0]['accepted']==8 and reports[0]['rejected']==2
    r,pcm=m.wav_read(str(target));assert pcm[:320]==struct.pack('<160h',*([1]*160))

def test_invalid_wav():
    with pytest.raises((ValueError,EOFError)):m.wav_read(b'')
    with pytest.raises(ValueError):m.wav_read(m.wav_bytes(44100,bytes(100)))

def test_length_limits():
    with pytest.raises(ValueError):m.encrypt(bytes(16),bytes(16),bytes(65537))
    with pytest.raises(ValueError):m.encrypt(bytes(15),bytes(16),b'')
    with pytest.raises(ValueError):m.decrypt(bytes(16),bytes(16),b'',b'',bytes(15))

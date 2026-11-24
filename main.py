"""CAALC-128 v1 research prototype. Not an established secure cipher."""
from __future__ import annotations
import argparse, collections, ctypes, hashlib, hmac, io, json, math, os, platform, random
import socket, statistics, struct, subprocess, sys, time, wave
from pathlib import Path
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))
MASK = 0xffffffff
RC = [struct.unpack('<6I', hashlib.sha256(b'CAALC-128-v1/round/' + bytes([r])).digest()[:24]) for r in range(24)]
IV = b'CAALC128-AEAD-v1'
MAX_MESSAGE = 65536
HEADER = struct.Struct('<4sBB8sQHHH')  # 28 bytes
CONTAINER = struct.Struct('<4sBB8sHHQ') # 26 bytes; authenticated in every frame

class AuthenticationError(ValueError): pass

def rot(x,n): return ((x << n) | (x >> (32-n))) & MASK

def f_ca(r):
    return [r[i]^rot(r[i],1)^(rot(r[(i-1)%6],7)&(~rot(r[(i+1)%6],13)&MASK))^rot(r[(i+2)%6],17) for i in range(6)]

def permutation(s, inverse=False, rounds=24):
    if len(s)!=12 or not 1<=rounds<=24: raise ValueError('12 words and 1..24 rounds required')
    l,r=list(s[:6]),list(s[6:])
    for j in (range(rounds-1,-1,-1) if inverse else range(rounds)):
        if inverse: l,r=[b^f^c for b,f,c in zip(r,f_ca(l),RC[j])],l
        else: l,r=r,[a^f^c for a,f,c in zip(l,f_ca(r),RC[j])]
    return l+r

def pbytes(s): return bytearray(struct.pack('<12I',*permutation(struct.unpack('<12I',s))))
def xor_at(s,b,offset=0):
    for i,v in enumerate(b): s[offset+i]^=v

def domain(s,d):
    s[47]^=d
    return pbytes(s)

def absorb(s,data,full,end):
    for i in range(0,len(data)//16*16,16):
        xor_at(s,data[i:i+16]); s=domain(s,full)
    tail=data[len(data)//16*16:]; xor_at(s,tail); s[len(tail)]^=0x80
    return domain(s,end)

def _aead(key,nonce,data,ad,decrypting=False):
    if len(key)!=16 or len(nonce)!=16: raise ValueError('Key and nonce must each be 16 bytes')
    if len(data)>MAX_MESSAGE or len(ad)>MAX_MESSAGE: raise ValueError('Message/AD exceeds 65536 bytes')
    s=domain(bytearray(IV+key+nonce),1)
    s=absorb(s,ad,2,3)
    out=bytearray()
    for start in range(0,len(data)//16*16,16):
        block=data[start:start+16]; result=bytes(a^b for a,b in zip(s,block)); out.extend(result)
        s[:16]=block if decrypting else result
        s=domain(s,4)
    tail=data[len(data)//16*16:]; result=bytes(a^b for a,b in zip(s,tail)); out.extend(result)
    s[:len(tail)]=tail if decrypting else result
    s[len(tail)]^=0x80; s=domain(s,5)
    xor_at(s,struct.pack('<QQ',len(ad),len(data)),16)
    xor_at(s,key,32); s=domain(s,6)
    return bytes(out),bytes(a^b for a,b in zip(s[16:32],key))

def encrypt(key,nonce,plaintext,associated_data=b''): return _aead(key,nonce,plaintext,associated_data)
def decrypt(key,nonce,ciphertext,associated_data=b'',tag=b''):
    if len(tag)!=16: raise AuthenticationError('Invalid tag length')
    p,t=_aead(key,nonce,ciphertext,associated_data,True)
    if not hmac.compare_digest(t,tag): raise AuthenticationError('Authentication failed; no audio released')
    return p

def _ror64(x, n): return ((x >> n) | (x << (64 - n))) & 0xFFFFFFFFFFFFFFFF
_ASCON_ROUNDS = [0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b]
_ASCON_128A_IV = (1 << 0) | (12 << 16) | (8 << 20) | (128 << 24) | (16 << 40)

def _ascon_round(s, c):
    s[2] ^= c
    s[0] ^= s[4]; s[4] ^= s[3]; s[2] ^= s[1]
    t0 = (s[0] ^ (~s[1] & s[2])) & 0xFFFFFFFFFFFFFFFF
    t1 = (s[1] ^ (~s[2] & s[3])) & 0xFFFFFFFFFFFFFFFF
    t2 = (s[2] ^ (~s[3] & s[4])) & 0xFFFFFFFFFFFFFFFF
    t3 = (s[3] ^ (~s[4] & s[0])) & 0xFFFFFFFFFFFFFFFF
    t4 = (s[4] ^ (~s[0] & s[1])) & 0xFFFFFFFFFFFFFFFF
    t1 ^= t0; t0 ^= t4; t3 ^= t2; t2 = (~t2) & 0xFFFFFFFFFFFFFFFF
    s[0] = t0 ^ _ror64(t0, 19) ^ _ror64(t0, 28)
    s[1] = t1 ^ _ror64(t1, 61) ^ _ror64(t1, 39)
    s[2] = t2 ^ _ror64(t2, 1) ^ _ror64(t2, 6)
    s[3] = t3 ^ _ror64(t3, 10) ^ _ror64(t3, 17)
    s[4] = t4 ^ _ror64(t4, 7) ^ _ror64(t4, 41)

def _ascon_pa(s):
    for c in _ASCON_ROUNDS: _ascon_round(s, c)

def _ascon_pb(s):
    for c in _ASCON_ROUNDS[4:]: _ascon_round(s, c)

def _ascon_load(b): return int.from_bytes(b, 'little')
def _ascon_store(val, n): return val.to_bytes(8, 'little')[:n]
def _ascon_pad(n): return 0x01 << (8 * n)
def _ascon_clear(val, n): return val & (~((1 << (8 * n)) - 1))

def ascon_encrypt(k, npub, m, ad=b''):
    if len(k) != 16 or len(npub) != 16: raise ValueError('Invalid key/nonce')
    k0 = _ascon_load(k[:8]); k1 = _ascon_load(k[8:16])
    n0 = _ascon_load(npub[:8]); n1 = _ascon_load(npub[8:16])
    s = [_ASCON_128A_IV, k0, k1, n0, n1]
    _ascon_pa(s)
    s[3] ^= k0; s[4] ^= k1
    adlen = len(ad); pos = 0
    if adlen > 0:
        while adlen >= 16:
            s[0] ^= _ascon_load(ad[pos:pos+8]); s[1] ^= _ascon_load(ad[pos+8:pos+16])
            _ascon_pb(s); pos += 16; adlen -= 16
        if adlen >= 8:
            s[0] ^= _ascon_load(ad[pos:pos+8])
            s[1] ^= _ascon_load(ad[pos+8:pos+adlen]) ^ _ascon_pad(adlen - 8)
        else:
            s[0] ^= _ascon_load(ad[pos:pos+adlen]) ^ _ascon_pad(adlen)
        _ascon_pb(s)
    s[4] ^= (0x80 << 56)
    mlen = len(m); pos = 0; c = bytearray()
    while mlen >= 16:
        s[0] ^= _ascon_load(m[pos:pos+8]); s[1] ^= _ascon_load(m[pos+8:pos+16])
        c.extend(_ascon_store(s[0], 8)); c.extend(_ascon_store(s[1], 8))
        _ascon_pb(s); pos += 16; mlen -= 16
    if mlen >= 8:
        s[0] ^= _ascon_load(m[pos:pos+8]); s[1] ^= _ascon_load(m[pos+8:pos+mlen])
        c.extend(_ascon_store(s[0], 8)); c.extend(_ascon_store(s[1], mlen - 8))
        s[1] ^= _ascon_pad(mlen - 8)
    else:
        s[0] ^= _ascon_load(m[pos:pos+mlen])
        c.extend(_ascon_store(s[0], mlen)); s[0] ^= _ascon_pad(mlen)
    s[2] ^= k0; s[3] ^= k1; _ascon_pa(s); s[3] ^= k0; s[4] ^= k1
    return bytes(c), _ascon_store(s[3], 8) + _ascon_store(s[4], 8)

def ascon_decrypt(k, npub, c, ad=b'', tag=b''):
    if len(k) != 16 or len(npub) != 16 or len(tag) != 16: raise ValueError('Invalid key/nonce/tag')
    k0 = _ascon_load(k[:8]); k1 = _ascon_load(k[8:16])
    n0 = _ascon_load(npub[:8]); n1 = _ascon_load(npub[8:16])
    s = [_ASCON_128A_IV, k0, k1, n0, n1]
    _ascon_pa(s)
    s[3] ^= k0; s[4] ^= k1
    adlen = len(ad); pos = 0
    if adlen > 0:
        while adlen >= 16:
            s[0] ^= _ascon_load(ad[pos:pos+8]); s[1] ^= _ascon_load(ad[pos+8:pos+16])
            _ascon_pb(s); pos += 16; adlen -= 16
        if adlen >= 8:
            s[0] ^= _ascon_load(ad[pos:pos+8])
            s[1] ^= _ascon_load(ad[pos+8:pos+adlen]) ^ _ascon_pad(adlen - 8)
        else:
            s[0] ^= _ascon_load(ad[pos:pos+adlen]) ^ _ascon_pad(adlen)
        _ascon_pb(s)
    s[4] ^= (0x80 << 56)
    clen = len(c); pos = 0; m = bytearray()
    while clen >= 16:
        c0 = _ascon_load(c[pos:pos+8]); c1 = _ascon_load(c[pos+8:pos+16])
        m.extend(_ascon_store(s[0] ^ c0, 8)); m.extend(_ascon_store(s[1] ^ c1, 8))
        s[0] = c0; s[1] = c1; _ascon_pb(s); pos += 16; clen -= 16
    if clen >= 8:
        c0 = _ascon_load(c[pos:pos+8]); c1 = _ascon_load(c[pos+8:pos+clen])
        m.extend(_ascon_store(s[0] ^ c0, 8)); m.extend(_ascon_store(s[1] ^ c1, clen - 8))
        s[0] = c0; s[1] = (_ascon_clear(s[1], clen - 8) | c1) ^ _ascon_pad(clen - 8)
    else:
        c0 = _ascon_load(c[pos:pos+clen])
        m.extend(_ascon_store(s[0] ^ c0, clen)); s[0] = (_ascon_clear(s[0], clen) | c0) ^ _ascon_pad(clen)
    s[2] ^= k0; s[3] ^= k1; _ascon_pa(s); s[3] ^= k0; s[4] ^= k1
    t = _ascon_store(s[3], 8) + _ascon_store(s[4], 8)
    if not hmac.compare_digest(t, tag): raise AuthenticationError('Native authentication failed')
    return bytes(m)

class Native:
    """Identical ctypes call path for portable CAALC C++ and upstream Ascon C."""
    def __init__(self,name):
        suffix='.dll' if os.name=='nt' else ('.dylib' if sys.platform=='darwin' else '.so')
        path=ROOT/'build'/('lib'+name+suffix)
        self.name = name
        if path.exists():
            self.lib=ctypes.CDLL(str(path))
            self.enc=self.lib.crypto_aead_encrypt; self.dec=self.lib.crypto_aead_decrypt
            P=ctypes.c_void_p; U=ctypes.c_ulonglong
            self.enc.argtypes=[P,ctypes.POINTER(U),P,U,P,U,P,P,P]; self.enc.restype=ctypes.c_int
            self.dec.argtypes=[P,ctypes.POINTER(U),P,P,U,P,U,P,P]; self.dec.restype=ctypes.c_int
            self.has_lib = True
        else:
            self.has_lib = False
            if name not in ('caalc', 'ascon'):
                raise RuntimeError('Run python build_native.py first (C/C++ compiler required)')

    def encrypt(self,k,n,p,ad=b''):
        if not self.has_lib:
            if self.name == 'ascon': return ascon_encrypt(k, n, p, ad)
            return encrypt(k, n, p, ad)
        if len(k)!=16 or len(n)!=16: raise ValueError('Invalid key/nonce')
        out=ctypes.create_string_buffer(len(p)+16); size=ctypes.c_ulonglong()
        if self.enc(out,ctypes.byref(size),p,len(p),ad,len(ad),None,n,k)!=0: raise ValueError('Native encryption failed')
        raw=out.raw[:size.value]; return raw[:-16],raw[-16:]

    def decrypt(self,k,n,c,ad=b'',tag=b''):
        if not self.has_lib:
            if self.name == 'ascon': return ascon_decrypt(k, n, c, ad, tag)
            return decrypt(k, n, c, ad, tag)
        if len(k)!=16 or len(n)!=16 or len(tag)!=16: raise ValueError('Invalid key/nonce/tag')
        raw=c+tag; out=ctypes.create_string_buffer(max(1,len(c))); size=ctypes.c_ulonglong()
        if self.dec(out,ctypes.byref(size),None,raw,len(raw),ad,len(ad),n,k)!=0: raise AuthenticationError('Native authentication failed')
        return out.raw[:size.value]

def engine(name): return sys.modules[__name__] if name=='caalc' else Native(name)

def key_read(path):
    b=bytes.fromhex(Path(path).read_text().strip())
    if len(b)!=16: raise ValueError('Key file must contain exactly 32 hex characters')
    return b

def wav_read(src):
    with wave.open(src if isinstance(src,str) else io.BytesIO(src),'rb') as w:
        if w.getnchannels()!=1 or w.getsampwidth()!=2 or w.getframerate() not in (8000,16000) or w.getcomptype()!='NONE':
            raise ValueError('Need mono PCM16 WAV at 8000/16000 Hz. Convert: ffmpeg -i input -ac 1 -ar 8000 -c:a pcm_s16le output.wav')
        count=w.getnframes(); pcm=w.readframes(count); rate=w.getframerate()
        if len(pcm)!=count*2: raise ValueError('Truncated WAV')
        return rate,pcm

def wav_bytes(rate,pcm):
    b=io.BytesIO()
    with wave.open(b,'wb') as w: w.setnchannels(1); w.setsampwidth(2); w.setframerate(rate); w.writeframes(pcm)
    return b.getvalue()

def make_packet(k,sid,seq,rate,ms,pcm,algorithm='caalc',extra=b''):
    if len(sid)!=8 or not 0<=seq<2**32 or rate not in (8000,16000) or ms not in (10,20,40) or len(pcm)>rate*ms//1000*2 or len(pcm)%2: raise ValueError('Invalid frame parameters')
    alg=0 if algorithm=='caalc' else 1
    h=HEADER.pack(b'CAP1',1,alg,sid,seq,rate,ms,len(pcm))
    c,t=engine(algorithm).encrypt(k,sid+struct.pack('<Q',seq),pcm,h+extra)
    return h+c+t

def open_packet(k,packet,sid,algorithm='caalc',extra=b''):
    if len(packet)<44: raise ValueError('Short packet')
    magic,v,a,s,q,r,ms,n=HEADER.unpack(packet[:28])
    if magic!=b'CAP1' or v!=1 or a!=(0 if algorithm=='caalc' else 1) or s!=sid or q>=2**32 or r not in (8000,16000) or ms not in (10,20,40) or n%2 or n>r*ms//1000*2 or len(packet)!=44+n: raise ValueError('Malformed or unexpected session packet')
    p=engine(algorithm).decrypt(k,s+struct.pack('<Q',q),packet[28:-16],packet[:28]+extra,packet[-16:])
    return q,r,ms,p

class ReplayWindow:
    def __init__(self): self.high=-1; self.bits=0
    def accept(self,q):
        if q>self.high:
            self.bits=((self.bits << min(q-self.high,64))|1)&((1<<64)-1); self.high=q
        else:
            gap=self.high-q
            if gap>=64 or self.bits&(1<<gap): raise ValueError('Replay/too-old packet')
            self.bits|=1<<gap

class SessionReceiver:
    def __init__(self,k,sid,algorithm='caalc'): self.k=k; self.sid=sid; self.algorithm=algorithm; self.replay=ReplayWindow(); self.format=None
    def accept(self,p):
        q,r,m,b=open_packet(self.k,p,self.sid,self.algorithm)
        if self.format is not None and self.format!=(r,m): raise ValueError('Format changed within session')
        self.replay.accept(q); self.format=(r,m)
        return q,r,m,b

def seal_wav(raw,key,ms=20,algorithm='caalc'):
    rate,pcm=wav_read(raw)
    if ms not in (10,20,40): raise ValueError('Frame duration must be 10/20/40 ms')
    sid=os.urandom(8); step=rate*ms//1000*2; count=max(1,(len(pcm)+step-1)//step)
    if count>=2**32: raise ValueError('Session limit exceeded')
    h=CONTAINER.pack(b'CAF1',1,0 if algorithm=='caalc' else 1,sid,rate,ms,len(pcm))
    out=bytearray(h)
    for q in range(count):
        p=make_packet(key,sid,q,rate,ms,pcm[q*step:(q+1)*step],algorithm,h)
        out.extend(struct.pack('<H',len(p))); out.extend(p)
    return bytes(out)

def unseal_wav(raw,key):
    if len(raw)<26: raise ValueError('Short container')
    h=raw[:26]; magic,v,a,sid,rate,ms,total=CONTAINER.unpack(h)
    if magic!=b'CAF1' or v!=1 or a not in (0,1) or rate not in (8000,16000) or ms not in (10,20,40) or total%2: raise ValueError('Invalid container')
    algorithm='caalc' if a==0 else 'ascon'; step=rate*ms//1000*2
    # Bound allocations and work to bytes actually present, before trusting total.
    if total>len(raw) or max(1,(total+step-1)//step)>=2**32: raise ValueError('Impossible container length')
    out=bytearray(); pos=26; count=max(1,(total+step-1)//step)
    for expected in range(count):
        if pos+2>len(raw): raise ValueError('Truncated container')
        n=struct.unpack_from('<H',raw,pos)[0]; pos+=2
        if not 44<=n<=1324 or pos+n>len(raw): raise ValueError('Bad record length')
        q,r,m,p=open_packet(key,raw[pos:pos+n],sid,algorithm,h); pos+=n
        if q!=expected or (r,m)!=(rate,ms) or len(p)!=min(step,max(0,total-expected*step)): raise ValueError('Missing/reordered frame')
        out.extend(p)
    if pos!=len(raw) or len(out)!=total: raise ValueError('Trailing/truncated audio')
    return wav_bytes(rate,out)

def metrics(x,y):
    import numpy as np
    a=np.frombuffer(x,dtype='<i2').astype(np.float64); b=np.frombuffer(y,dtype='<i2').astype(np.float64)
    if not len(a) or a.shape!=b.shape: raise ValueError('Metrics need equal nonempty PCM lengths')
    err=float(np.sum((a-b)**2)); sig=float(np.sum(a*a)); mse=err/len(a)
    return {'MSE':mse,'PSNR_dB':math.inf if err==0 else 10*math.log10(32768**2/mse),'SNR_dB':math.inf if err==0 else (-math.inf if sig==0 else 10*math.log10(sig/err)), 'exact_sample_fraction':float(np.mean(a==b)),'samples':len(a)}

def entropy(b):
    return -sum((n/len(b))*math.log2(n/len(b)) for n in collections.Counter(b).values()) if b else 0.0

def analyze(a,b,out):
    import numpy as np
    import matplotlib; matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    ra,pa=wav_read(a); rb,pb=wav_read(b)
    if ra!=rb: raise ValueError('Sample rates differ')
    m=metrics(pa,pb); out=Path(out); out.mkdir(parents=True,exist_ok=True)
    fig,axs=plt.subplots(2,2,figsize=(11,6))
    for j,(pcm,title) in enumerate([(pa,'Original'),(pb,'Recovered')]):
        x=np.frombuffer(pcm,dtype='<i2'); axs[0,j].plot(np.arange(len(x))/ra,x,lw=.6); axs[0,j].set_title(title); axs[0,j].set_xlabel('Seconds')
        if len(x)>=256: axs[1,j].specgram(x.astype(float),NFFT=256,Fs=ra,noverlap=128)
        axs[1,j].set_xlabel('Seconds'); axs[1,j].set_ylabel('Hz')
    fig.tight_layout(); fig.savefig(out/'audio_analysis.png'); plt.close(fig)
    write_json(out/'audio_metrics.json',m); return m

def write_json(path,data):
    # Encode non-finite metrics as explicit strings: valid, portable JSON.
    def clean(v):
        if isinstance(v,float) and not math.isfinite(v): return str(v)
        if isinstance(v,dict): return {k:clean(x) for k,x in v.items()}
        if isinstance(v,(list,tuple)): return [clean(x) for x in v]
        return v
    Path(path).parent.mkdir(parents=True,exist_ok=True); Path(path).write_text(json.dumps(clean(data),indent=2))

def demo_wav(seconds=2,rate=8000):
    import numpy as np
    t=np.arange(int(seconds*rate))/rate
    # Synthetic test signal, not recorded speech.
    pcm=(12000*np.sin(2*np.pi*(300*t+150*t*t))*np.minimum(1,t*10)).astype('<i2').tobytes()
    return wav_bytes(rate,pcm)

def mlkem_demo(out):
    from pqcrypto.kem import ml_kem_512 as kem
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    pk,sk=kem.keygen(); ct,ss=kem.encaps(pk); other=kem.decaps(sk,ct)
    assert hmac.compare_digest(ss,other)
    salt=hashlib.sha256(bytes(pk)+ct).digest()
    def derive(s): return HKDF(algorithm=hashes.SHA256(),length=16,salt=salt,info=b'CAALC-128-v1/audio/sender-to-receiver').derive(s)
    k=derive(ss); k2=derive(other); assert k==k2
    c,t=encrypt(k,bytes(16),b'ML-KEM audio session'); assert decrypt(k2,bytes(16),c,b'',t)==b'ML-KEM audio session'
    out=Path(out); out.mkdir(parents=True,exist_ok=True)
    (out/'session.key').write_text(k.hex()+'\n'); os.chmod(out/'session.key',0o600)
    report={'algorithm':'ML-KEM-512','secret_agreement':True,'HKDF_key_agreement':True,'CAALC_roundtrip':True,'public_key_bytes':len(bytes(pk)),'ciphertext_bytes':len(ct),'endpoint_authenticated':False}
    write_json(out/'mlkem.json',report); return report

def experiments(out,trials=128):
    rng=random.Random(128); distances=[]; keydist=[]; diffusion={str(r):[] for r in (1,2,4,8,12,24)}; deltas=[]
    for i in range(trials):
        s=[rng.getrandbits(32) for _ in range(12)]; other=s.copy(); bit=rng.randrange(384); other[bit//32]^=1<<(bit%32)
        for r in (1,2,4,8,12,24):
            a=permutation(s,rounds=r); b=permutation(other,rounds=r); d=[x^y for x,y in zip(a,b)]
            diffusion[str(r)].append(sum(x.bit_count() for x in d)/384)
        distances.append(diffusion['24'][-1]); deltas.append(tuple(d))
        k=rng.randbytes(16); kk=bytearray(k); kk[(i%128)//8]^=1<<(i%8)
        c,t=encrypt(k,bytes(16),bytes(320)); cc,tt=encrypt(bytes(kk),bytes(16),bytes(320))
        keydist.append(sum((x^y).bit_count() for x,y in zip(c,cc))/(len(c)*8))
    patterns=[0,MASK,0xaaaaaaaa,0x55555555,1]
    repeated=[len(set(permutation([v]*12))) for v in patterns]
    rot_matches=0
    for _ in range(32):
        s=[rng.getrandbits(32) for _ in range(12)]
        rot_matches+=permutation([rot(x,1) for x in s])==[rot(x,1) for x in permutation(s)]
    sample=encrypt(bytes(16),bytes(16),rng.randbytes(65536))[0]
    report={'seed':128,'trials':trials,'avalanche_mean':statistics.mean(distances),'avalanche_min':min(distances),'avalanche_max':max(distances),'key_sensitivity_mean':statistics.mean(keydist),'diffusion_by_round':{r:statistics.mean(v) for r,v in diffusion.items()},'duplicate_sampled_output_differences':len(deltas)-len(set(deltas)),'repeated_word_output_distinct_words':repeated,'rotation_equivariance_matches_of_32':rot_matches,'ciphertext_byte_entropy_65536':entropy(sample),'warning':'Screening only; not differential bounds, security proof, or comprehensive cryptanalysis.'}
    write_json(Path(out)/'experiments.json',report); return report

def benchmark(raw,out,trials=50):
    import numpy as np
    import matplotlib; matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    rate,pcm=wav_read(raw); out=Path(out); out.mkdir(parents=True,exist_ok=True); rows=[]; raw_timings=[]
    for ms in (10,20,40):
        frame_bytes=rate*ms//1000*2
        audio_frames=[pcm[j:j+frame_bytes].ljust(frame_bytes,b'\0') for j in range(0,len(pcm),frame_bytes)] or [bytes(frame_bytes)]
        for name in ('caalc','ascon'):
            e=Native(name); k=bytes(range(16)); en=[]; de=[]
            for i in range(trials+5):
                payload=audio_frames[i%len(audio_frames)]
                n=i.to_bytes(16,'little'); ad=HEADER.pack(b'CAP1',1,0 if name=='caalc' else 1,bytes(8),i,rate,ms,len(payload))
                start=time.perf_counter_ns(); c,t=e.encrypt(k,n,payload,ad); t1=time.perf_counter_ns(); p=e.decrypt(k,n,c,ad,t); end=time.perf_counter_ns()
                assert p==payload
                if i>=5:
                    en.append((t1-start)/1000); de.append((end-t1)/1000)
                    raw_timings.append({'cipher':name,'frame_ms':ms,'trial':i-5,'enc_us':en[-1],'dec_us':de[-1]})
            rows.append({'cipher':name,'frame_ms':ms,'payload_bytes':len(payload),'enc_median_us':statistics.median(en),'dec_median_us':statistics.median(de),'enc_p95_us':float(np.percentile(en,95)),'throughput_MiB_s':len(payload)/(statistics.median(en)*1e-6)/1048576,'packet_overhead_bytes':44,'trials':trials})
    write_json(out/'benchmark_raw.json',raw_timings)
    write_json(out/'benchmark.json',{'platform':platform.platform(),'method':'Both portable native implementations, -O2, same ctypes wrapper, cycle same WAV frames; timings include FFI, 5 warmups. Not ESP32 measurements.','rows':rows})
    import csv
    with (out/'benchmark.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=rows[0]); w.writeheader(); w.writerows(rows)
    fig,ax=plt.subplots()
    for name in ('caalc','ascon'):
        rr=[r for r in rows if r['cipher']==name]; ax.plot([r['frame_ms'] for r in rr],[r['enc_median_us'] for r in rr],marker='o',label=name)
    ax.set(xlabel='Audio frame duration (ms)',ylabel='Native encryption median (µs)',title='Host benchmark (not ESP32)'); ax.legend(); fig.tight_layout(); fig.savefig(out/'benchmark.png'); plt.close(fig)
    return rows

class JitterBuffer:
    """Fixed deadline reorder buffer, bounded to 64 frames; silence for missing audio."""
    def __init__(self,rate,ms,start_seq=0,delay_ms=80):
        self.rate=rate; self.ms=ms; self.expected=start_seq; self.deadline=None; self.delay=delay_ms/1000; self.pending={}; self.lost=0; self.late=0
    def put(self,q,pcm,now):
        if self.deadline is None: self.deadline=now+self.delay
        if q<self.expected: self.late+=1; return
        if q>=self.expected+64: raise ValueError('Outside jitter window')
        self.pending[q]=pcm
    def ready(self,now):
        out=[]
        while self.deadline is not None and now>=self.deadline:
            pcm=self.pending.pop(self.expected,None)
            if pcm is None: pcm=bytes(self.rate*self.ms//1000*2); self.lost+=1
            out.append(pcm); self.expected+=1; self.deadline+=self.ms/1000
            if len(out)>=64: break
        return out

def receive(key,sid,output,seconds=10,port=5005,serial_port=None,play=False,algorithm='caalc',session_config=None,serial_audio=None):
    """One explicit session; no unauthenticated auto-switch or replay state reset."""
    if len(key)!=16 or len(sid)!=8 or seconds<=0: raise ValueError('Valid key, 8-byte session ID and positive duration required')
    Path(output).parent.mkdir(parents=True,exist_ok=True)
    receiver=SessionReceiver(key,sid,algorithm); jitter=None; sink=None; log=[]; accepted=0; rejected=0; prev=None; jit=0.0
    ser=None; sock=None; frames=[]; arrivals=[]; start=time.monotonic(); buf=bytearray(); audio=None; index=0
    if serial_port:
        import serial
        ser=serial.Serial(serial_port,921600,timeout=.005)
        time.sleep(2)
        if session_config:
            cfg=json.loads(Path(session_config).read_text()); suite=cfg.get('algorithm',algorithm).upper()
            if suite not in ('CAALC','ASCON'): raise ValueError('Unsupported hardware cipher suite')
            line='CFG '+key.hex()+' '+sid.hex()+' '+cfg.get('ssid','-')+' '+cfg.get('password','-')+' '+cfg.get('host','127.0.0.1')+' '+str(port)+' '+('USB' if serial_audio else cfg.get('mode','MIC'))+' '+suite+'\n'
            ser.write(line.encode()); ser.flush()
        if serial_audio:
            ar,audio=wav_read(str(serial_audio))
            if ar!=8000: raise ValueError('Firmware USB input requires 8 kHz')
    else:
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); sock.bind(('0.0.0.0',port)); sock.settimeout(.005)
    try:
        # Duration starts after serial reset/configuration.
        start=time.monotonic(); next_send=start
        while time.monotonic()-start<seconds:
            packet=None; now=time.monotonic()
            if ser:
                if audio is not None and index<len(audio) and now>=next_send:
                    chunk=audio[index:index+320].ljust(320,b'\0'); ser.write(b'PC'+struct.pack('<H',320)+chunk); index+=320; next_send+=.02
                buf.extend(ser.read(ser.in_waiting or 1))
                # Multiplex length-prefixed CA packets and ASCII diagnostic lines.
                at=buf.find(b'CA')
                if at<0:
                    if len(buf)>4096: del buf[:-1]
                else:
                    del buf[:at]
                    if len(buf)>=4:
                        n=struct.unpack_from('<H',buf,2)[0]
                        if not 44<=n<=1324: del buf[:2]
                        elif len(buf)>=4+n: packet=bytes(buf[4:4+n]); del buf[:4+n]
            else:
                try: packet=sock.recv(2048)
                except socket.timeout: pass
            now=time.monotonic()
            if packet:
                try:
                    before=time.perf_counter_ns(); q,r,m,p=receiver.accept(packet)
                    if jitter is None:
                        jitter=JitterBuffer(r,m)
                        if play:
                            import sounddevice as sd
                            sink=sd.RawOutputStream(samplerate=r,channels=1,dtype='int16'); sink.start()
                    jitter.put(q,p,now); accepted+=1
                    transit=now-q*m/1000
                    if prev is not None: jit+=(abs(transit-prev)-jit)/16
                    prev=transit; arrivals.append(now)
                    log.append({'seq':q,'arrival_s':now-start,'decrypt_us':(time.perf_counter_ns()-before)/1000,'jitter_ms':jit*1000})
                except (ValueError,AuthenticationError) as ex: rejected+=1; log.append({'rejected':str(ex)})
            if jitter:
                for pcm in jitter.ready(now):
                    frames.append(pcm)
                    if sink: sink.write(pcm)
    finally:
        if sink: sink.stop(); sink.close()
        if sock: sock.close()
        if ser: ser.close()
    if jitter: Path(output).write_bytes(wav_bytes(jitter.rate,b''.join(frames)))
    report={'accepted':accepted,'rejected':rejected,'concealed_missing_frames':jitter.lost if jitter else 0,'late_frames':jitter.late if jitter else 0,'pending_at_stop':len(jitter.pending) if jitter else 0,'jitter_ms':jit*1000,'events':log}
    write_json(str(output)+'.json',report); return {k:v for k,v in report.items() if k!='events'}

def simulate(raw,key,out,loss=.1,jitter_ms=15,seed=123):
    if not 0<=loss<=1 or not 0<=jitter_ms<=1000: raise ValueError('Loss must be 0..1 and jitter 0..1000 ms')
    rate,pcm=wav_read(raw); ms=20; size=rate//50*2; sid=bytes.fromhex('0123456789abcdef'); rng=random.Random(seed)
    recv=SessionReceiver(key,sid); jb=JitterBuffer(rate,ms); events=[]; count=(len(pcm)+size-1)//size
    for q in range(count):
        packet=make_packet(key,sid,q,rate,ms,pcm[q*size:(q+1)*size].ljust(size,b'\0'))
        if rng.random()>=loss: events.append((q*.02+rng.uniform(0,jitter_ms/1000),packet))
    result=[]
    for arrival,packet in sorted(events):
        result.extend(jb.ready(arrival)); q,r,m,p=recv.accept(packet); jb.put(q,p,arrival)
    if jb.deadline is not None:
        while jb.expected<count: result.extend(jb.ready(jb.deadline))
    else: result=[bytes(size)]*count; jb.lost=count
    recovered=b''.join(result)[:len(pcm)]; out=Path(out); out.mkdir(parents=True,exist_ok=True)
    (out/'loss_simulation.wav').write_bytes(wav_bytes(rate,recovered))
    report={'seed':seed,'loss_probability':loss,'max_injected_jitter_ms':jitter_ms,'frames':count,'received':len(events),'concealed_frames':jb.lost,'late_frames':jb.late,'quality':metrics(pcm,recovered)}
    write_json(out/'network_simulation.json',report); return report

def advanced_dashboard():
    import streamlit as st
    st.set_page_config(page_title='CAALC-128 Research Demonstrator',layout='wide')
    st.title('CAALC-128 · Secure IoT Audio Research')
    st.warning('Experimental cipher — no established security guarantee. ML-KEM demo does not authenticate endpoints.')
    page=st.sidebar.radio('Screen',['Project Overview','Audio Encryption','Audio Decryption','Audio Analysis','Security Experiments','Cipher Comparison','Hardware Demonstration'])
    if 'demo_key' not in st.session_state: st.session_state.demo_key=os.urandom(16).hex()
    keyhex=st.sidebar.text_input('Session key (32 hex characters)',value=st.session_state.demo_key,type='password')
    try:
        key=bytes.fromhex(keyhex)
        if len(key)!=16: raise ValueError()
    except ValueError: st.error('Enter a 16-byte key'); return
    st.sidebar.download_button('Save session key',key.hex()+'\n','session.key')
    try:
        if page=='Project Overview':
            st.subheader('CA-inspired word-oriented nonlinear transformation')
            st.latex(r'L_{r+1}=R_r,\qquad R_{r+1}=L_r\oplus F_{CA}(R_r)\oplus C_r')
            st.write('PCM audio → frames → CAALC encryption + tag → UDP/USB → verified packets → jitter buffer → laptop playback')
            st.write('384-bit state · 24 Feistel rounds · 128-bit key/nonce/tag · 128-bit rate')
            if st.button('Run ML-KEM-512 + HKDF demonstration'): st.json(mlkem_demo(ROOT/'results/dashboard_session'))
            st.caption('A new secret key is saved in results/dashboard_session/session.key; load it explicitly to use this session.')
        elif page=='Audio Encryption':
            f=st.file_uploader('PCM16 mono WAV',type=['wav']); ms=st.selectbox('Frame duration (ms)',[20,10,40]); alg=st.selectbox('Cipher',['caalc','ascon'])
            raw=f.getvalue() if f else demo_wav()
            st.audio(raw)
            if st.button('Encrypt'):
                begin=time.perf_counter(); enc=seal_wav(raw,key,ms,alg); elapsed=time.perf_counter()-begin
                st.session_state.encrypted=enc; st.json({'container_bytes':len(enc),'elapsed_seconds':elapsed,'cipher':alg,'note':'Encrypted bytes are data, not playable audio'})
            if 'encrypted' in st.session_state: st.download_button('Download encrypted container',st.session_state.encrypted,'audio.caf')
        elif page=='Audio Decryption':
            f=st.file_uploader('Encrypted CAF container',type=['caf'])
            if f and st.button('Verify and decrypt'):
                raw=unseal_wav(f.getvalue(),key); st.success('All frames verified'); st.audio(raw); st.download_button('Download recovered WAV',raw,'recovered.wav')
        elif page=='Audio Analysis':
            a=st.file_uploader('Original WAV',type=['wav'],key='original'); b=st.file_uploader('Recovered WAV',type=['wav'],key='recovered')
            if a and b:
                st.json(analyze(a.getvalue(),b.getvalue(),ROOT/'results/dashboard')); st.image(str(ROOT/'results/dashboard/audio_analysis.png'))
                st.caption('Perfect recovery gives MSE=0 and PSNR/SNR=∞. These are not security tests.')
        elif page=='Security Experiments':
            if st.button('Run reproducible screening'):
                st.json(experiments(ROOT/'results/dashboard',32)); c,t=encrypt(key,bytes(16),b'audio')
                try: decrypt(key,bytes(16),bytes([c[0]^1])+c[1:],b'',t)
                except AuthenticationError: st.success('Tampering rejected')
        elif page=='Cipher Comparison':
            f=st.file_uploader('Benchmark WAV (optional)',type=['wav'])
            if st.button('Benchmark both native implementations'):
                st.dataframe(benchmark(f.getvalue() if f else demo_wav(),ROOT/'results/dashboard')); st.image(str(ROOT/'results/dashboard/benchmark.png'))
        else:
            st.write('Start a bounded receiver here or use the CLI. Pin the expected session ID; provision a fresh key/session after every reboot.')
            sidhex=st.text_input('Expected session ID (16 hex characters)'); port=st.number_input('UDP port',1024,65535,5005); duration=st.number_input('Capture seconds',1,60,10)
            serial_port=st.text_input('Serial port (blank = UDP)'); config=st.text_input('Provisioning JSON path (serial only, optional)'); feed=st.text_input('USB input WAV path (optional)')
            if st.button('Receive and verify'):
                sid=bytes.fromhex(sidhex)
                if len(sid)!=8: raise ValueError('Session ID requires 8 bytes')
                target=ROOT/'results/received.wav'
                report=receive(key,sid,target,duration,int(port),serial_port or None,False,session_config=config or None,serial_audio=feed or None)
                st.json(report)
                if report['accepted'] and target.exists(): st.audio(target.read_bytes()); st.download_button('Save captured WAV',target.read_bytes(),'received.wav')
    except Exception as ex: st.error(str(ex))

def dashboard():
    from simple_dashboard import render
    render()

def cli():
    p=argparse.ArgumentParser(description=__doc__); sub=p.add_subparsers(dest='mode',required=True)
    sub.add_parser('test'); sub.add_parser('dashboard')
    for name in ('keygen','mlkem','experiments','demo'):
        s=sub.add_parser(name); s.add_argument('--out',default='results')
    for name in ('encrypt','decrypt'):
        s=sub.add_parser(name); s.add_argument('input'); s.add_argument('output'); s.add_argument('--key',required=True)
        if name=='encrypt': s.add_argument('--frame-ms',type=int,default=20,choices=[10,20,40]); s.add_argument('--algorithm',choices=['caalc','ascon'],default='caalc')
    s=sub.add_parser('analyze'); s.add_argument('original'); s.add_argument('recovered'); s.add_argument('--out',default='results')
    s=sub.add_parser('benchmark'); s.add_argument('input'); s.add_argument('--out',default='results'); s.add_argument('--trials',type=int,default=100)
    s=sub.add_parser('simulate'); s.add_argument('input'); s.add_argument('--key',required=True); s.add_argument('--loss',type=float,default=.1); s.add_argument('--jitter-ms',type=float,default=15); s.add_argument('--out',default='results')
    s=sub.add_parser('receiver'); s.add_argument('--key',required=True); s.add_argument('--sid',required=True); s.add_argument('--out',default='results/received.wav'); s.add_argument('--seconds',type=float,default=10); s.add_argument('--port',type=int,default=5005); s.add_argument('--serial'); s.add_argument('--play',action='store_true'); s.add_argument('--config'); s.add_argument('--feed-wav'); s.add_argument('--algorithm',choices=['caalc','ascon'],default='caalc')
    s=sub.add_parser('play'); s.add_argument('input')
    a=p.parse_args()
    if a.mode=='test': subprocess.run([sys.executable,'-m','pytest',str(ROOT/'tests'),'-q'],check=True)
    elif a.mode=='dashboard': subprocess.run([sys.executable,'-m','streamlit','run',str(ROOT/'main.py'),'--','--dashboard'],cwd=str(ROOT),check=True)
    elif a.mode=='keygen':
        out=Path(a.out); out.mkdir(parents=True,exist_ok=True); (out/'session.key').write_text(os.urandom(16).hex()+'\n'); os.chmod(out/'session.key',0o600); print('Created',out/'session.key')
    elif a.mode=='mlkem': print(json.dumps(mlkem_demo(a.out),indent=2))
    elif a.mode=='experiments': print(json.dumps(experiments(a.out),indent=2))
    elif a.mode=='encrypt': Path(a.output).write_bytes(seal_wav(Path(a.input).read_bytes(),key_read(a.key),a.frame_ms,a.algorithm))
    elif a.mode=='decrypt': Path(a.output).write_bytes(unseal_wav(Path(a.input).read_bytes(),key_read(a.key)))
    elif a.mode=='analyze': print(analyze(a.original,a.recovered,a.out))
    elif a.mode=='benchmark': print(benchmark(Path(a.input).read_bytes(),a.out,a.trials))
    elif a.mode=='simulate': print(simulate(Path(a.input).read_bytes(),key_read(a.key),a.out,a.loss,a.jitter_ms))
    elif a.mode=='receiver': print(receive(key_read(a.key),bytes.fromhex(a.sid),a.out,a.seconds,a.port,a.serial,a.play,a.algorithm,a.config,a.feed_wav))
    elif a.mode=='play':
        import sounddevice as sd
        import numpy as np
        r,b=wav_read(a.input); sd.play(np.frombuffer(b,dtype='<i2'),r); sd.wait()
    elif a.mode=='demo':
        out=Path(a.out); out.mkdir(parents=True,exist_ok=True); k=os.urandom(16); raw=demo_wav(); enc=seal_wav(raw,k); dec=unseal_wav(enc,k)
        (out/'demo.key').write_text(k.hex()+'\n'); (out/'original.wav').write_bytes(raw); (out/'encrypted.caf').write_bytes(enc); (out/'recovered.wav').write_bytes(dec)
        print(analyze(raw,dec,out)); print(simulate(raw,k,out))

if __name__=='__main__':
    if '--advanced-dashboard' in sys.argv: advanced_dashboard()
    elif '--dashboard' in sys.argv: dashboard()
    else:
        try: cli()
        except (ValueError,RuntimeError,OSError) as ex: sys.exit(str(ex))

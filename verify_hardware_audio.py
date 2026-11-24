import sys
from main import wav_read,metrics
if len(sys.argv)!=3:sys.exit('Usage: python verify_hardware_audio.py original.wav received.wav')
r,a=wav_read(sys.argv[1]);s,b=wav_read(sys.argv[2])
if r!=s or len(b)<len(a):sys.exit('FAIL: different sample rate or missing original samples')
print(metrics(a,b[:len(a)]));print('Trailing recorded/concealment samples:',(len(b)-len(a))//2)
if a!=b[:len(a)]:sys.exit('FAIL: original PCM prefix not exact')
print('PASS: original PCM prefix exactly recovered')

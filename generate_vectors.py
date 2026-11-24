from main import *
if __name__=='__main__':
    vectors={'spec':'CAALC-128-v1','constants':[[f'{w:08x}' for w in row] for row in RC],'permutations':[],'aead':[]}
    for s in ([0]*12,list(range(12)),[0xffffffff]*12): vectors['permutations'].append({'input_words':s,'output_words':permutation(s)})
    for n in (0,1,15,16,17,320):
        k=bytes(range(16)); nonce=bytes(range(16,32)); p=bytes(i%256 for i in range(n)); ad=b'CAALC test'; c,t=encrypt(k,nonce,p,ad)
        vectors['aead'].append(dict(key=k.hex(),nonce=nonce.hex(),plaintext=p.hex(),ad=ad.hex(),ciphertext=c.hex(),tag=t.hex()))
    write_json(ROOT/'test_vectors/caalc_vectors.json',vectors)

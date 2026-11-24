#include "../firmware/include/caalc_core.h"
extern "C" {
void caalc_permute(uint32_t*s,int inverse){caalc::perm(s,inverse!=0);}
int crypto_aead_encrypt(unsigned char*c,unsigned long long*clen,const unsigned char*m,unsigned long long mlen,const unsigned char*ad,unsigned long long alen,const unsigned char*,const unsigned char*n,const unsigned char*k){
 if(mlen>65536||alen>65536)return -1;
 if(!caalc::crypt(k,n,m,(size_t)mlen,ad,(size_t)alen,c,c+mlen))return -1;*clen=mlen+16;return 0;
}
int crypto_aead_decrypt(unsigned char*m,unsigned long long*mlen,unsigned char*,const unsigned char*c,unsigned long long clen,const unsigned char*ad,unsigned long long alen,const unsigned char*n,const unsigned char*k){
 *mlen=0;if(clen<16||clen>65552||alen>65536)return -1;
 if(!caalc::decrypt(k,n,c,(size_t)clen-16,ad,(size_t)alen,c+clen-16,m))return -1;*mlen=clen-16;return 0;
}
}

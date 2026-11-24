#ifndef CAALC_CORE_H
#define CAALC_CORE_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "round_constants.h"
namespace caalc {
static inline uint32_t rot(uint32_t x,unsigned n){return (x<<n)|(x>>(32-n));}
static inline uint32_t load32(const uint8_t *p){return uint32_t(p[0])|(uint32_t(p[1])<<8)|(uint32_t(p[2])<<16)|(uint32_t(p[3])<<24);}
static inline void store32(uint8_t*p,uint32_t x){for(unsigned i=0;i<4;i++)p[i]=uint8_t(x>>(8*i));}
static inline void store64(uint8_t*p,uint64_t x){for(unsigned i=0;i<8;i++)p[i]=uint8_t(x>>(8*i));}
static inline void f(const uint32_t*r,uint32_t*out){for(unsigned i=0;i<6;i++)out[i]=r[i]^rot(r[i],1)^(rot(r[(i+5)%6],7)&~rot(r[(i+1)%6],13))^rot(r[(i+2)%6],17);}
static inline void perm(uint32_t*s,bool inverse=false){
 uint32_t t[6],old[6];
 for(unsigned z=0;z<24;z++){
  unsigned j=inverse?23-z:z;
  if(inverse){f(s,t);memcpy(old,s,24);for(unsigned i=0;i<6;i++)s[i]=s[i+6]^t[i]^RC[j][i];memcpy(s+6,old,24);}
  else {f(s+6,t);memcpy(old,s,24);memcpy(s,s+6,24);for(unsigned i=0;i<6;i++)s[i+6]=old[i]^t[i]^RC[j][i];}
 }
}
static inline void domain(uint8_t*s,uint8_t d){s[47]^=d;uint32_t w[12];for(unsigned i=0;i<12;i++)w[i]=load32(s+4*i);perm(w);for(unsigned i=0;i<12;i++)store32(s+4*i,w[i]);}
static inline void absorb(uint8_t*s,const uint8_t*p,size_t n,uint8_t full,uint8_t end){
 while(n>=16){for(unsigned i=0;i<16;i++)s[i]^=p[i];domain(s,full);p+=16;n-=16;}
 for(size_t i=0;i<n;i++)s[i]^=p[i];s[n]^=0x80;domain(s,end);
}
// out may alias input. During decrypt it is PRIVATE scratch until tag verified.
static inline bool crypt(const uint8_t*k,const uint8_t*n,const uint8_t*in,size_t len,const uint8_t*ad,size_t alen,uint8_t*out,uint8_t*tag,bool dec=false){
 if(len>65536||alen>65536)return false;
 uint8_t s[48];
 memcpy(s,"CAALC128-AEAD-v1",16);memcpy(s+16,k,16);memcpy(s+32,n,16);domain(s,1);absorb(s,ad,alen,2,3);
 size_t pos=0;
 while(len-pos>=16){for(unsigned i=0;i<16;i++){uint8_t b=in[pos+i];out[pos+i]=b^s[i];s[i]=dec?b:out[pos+i];}domain(s,4);pos+=16;}
 size_t tail=len-pos;for(size_t i=0;i<tail;i++){uint8_t b=in[pos+i];out[pos+i]=b^s[i];s[i]=dec?b:out[pos+i];}
 s[tail]^=0x80;domain(s,5);uint8_t sizes[16];store64(sizes,alen);store64(sizes+8,len);
 for(unsigned i=0;i<16;i++){s[16+i]^=sizes[i];s[32+i]^=k[i];}domain(s,6);
 for(unsigned i=0;i<16;i++)tag[i]=s[16+i]^k[i];return true;
}
static inline bool decrypt(const uint8_t*k,const uint8_t*n,const uint8_t*c,size_t len,const uint8_t*ad,size_t alen,const uint8_t*tag,uint8_t*private_out){
 uint8_t t[16],d=0;if(!crypt(k,n,c,len,ad,alen,private_out,t,true))return false;
 for(unsigned i=0;i<16;i++)d|=t[i]^tag[i];if(d){memset(private_out,0,len);return false;}return true;
}
}
#endif

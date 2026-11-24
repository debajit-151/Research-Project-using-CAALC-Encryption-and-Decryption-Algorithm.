/* Optional hardware benchmark. Run prepare_hardware_benchmark.py first.
 * Both portable implementations use the same board, compiler and measurement loop.
 */
#include <Arduino.h>
#include "caalc_core.h"
extern "C" {
#include "src/ascon/crypto_aead.h"
}
uint8_t k[16]={},n[16]={},ad[28]={},m[1280]={},c[1296],p[1280],tag[16];
void setup(){
 Serial.begin(115200);delay(1000);Serial.println("cipher,bytes,enc_mean_us,dec_mean_us,free_heap");
 for(unsigned bytes=160;bytes<=1280;bytes*=2){
  for(unsigned alg=0;alg<2;alg++){
   uint64_t et=0,dt=0;unsigned long long clen=0,plen=0;
   for(unsigned j=0;j<205;j++){
    caalc::store64(n,j);uint32_t a=micros();
    if(alg==0)caalc::crypt(k,n,m,bytes,ad,28,c,tag);
    else crypto_aead_encrypt(c,&clen,m,bytes,ad,28,NULL,n,k);
    uint32_t b=micros();int ok;
    if(alg==0)ok=caalc::decrypt(k,n,c,bytes,ad,28,tag,p)?0:-1;
    else ok=crypto_aead_decrypt(p,&plen,NULL,c,clen,ad,28,n,k);
    uint32_t d=micros();if(ok||memcmp(p,m,bytes)){Serial.println("FAIL");while(true)delay(1000);}
    if(j>=5){et+=uint32_t(b-a);dt+=uint32_t(d-b);}
   }
   Serial.printf("%s,%u,%.3f,%.3f,%lu\n",alg?"ascon":"caalc",bytes,double(et)/200,double(dt)/200,(unsigned long)ESP.getFreeHeap());
  }
 }
}
void loop(){delay(1000);}

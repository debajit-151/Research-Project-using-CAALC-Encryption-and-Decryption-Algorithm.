/* CAALC-128 experimental audio sender. Target: Arduino-ESP32 2.0.17, ESP32 Dev Module.
 * No key/Wi-Fi credentials in source. Provision over trusted USB each boot.
 * CFG <32hexkey> <16hexsid> <ssid-or-> <password-or-> <hostIPv4> <port> <USB|MIC> <CAALC|ASCON>
 * SSID/password containing spaces are unsupported by this compact demo protocol.
 * USB mode: host sends 'PC' + uint16LE(320) + PCM; board responds 'CA' + uint16LE + packet.
 * MIC mode: INMP441 left channel, GPIO26 BCLK,25 WS,33 SD; UDP output.
 */
#include <WiFi.h>
#include <WiFiUdp.h>
#include <driver/i2s.h>
#include "caalc_core.h"
extern "C" {
#include "src/ascon/crypto_aead.h"
}
WiFiUDP udp;
uint8_t keyBytes[16],sessionId[8],pcm[320],packet[364];
uint64_t sequence=0;
bool provisioned=false,usbMode=true;
uint8_t algorithmId=0;
IPAddress host;uint16_t hostPort=5005;
uint32_t framesSent=0;uint64_t cryptoTotal=0;uint32_t cryptoMax=0;
char configLine[256];size_t configLen=0;

bool hexparse(const char*s,uint8_t*out,size_t n){
 if(strlen(s)!=2*n)return false;
 for(size_t i=0;i<n;i++){
  unsigned v=0;for(unsigned j=0;j<2;j++){char c=s[2*i+j];unsigned d;if(c>='0'&&c<='9')d=c-'0';else if(c>='a'&&c<='f')d=c-'a'+10;else if(c>='A'&&c<='F')d=c-'A'+10;else return false;v=(v<<4)|d;}out[i]=(uint8_t)v;
 }return true;
}
void halt(const char*msg){Serial.println(msg);provisioned=false;while(true)delay(1000);}
bool exactRead(uint8_t*p,size_t n){size_t pos=0;uint32_t start=millis();while(pos<n&&millis()-start<2000){int a=Serial.available();if(a>0){size_t take=min((size_t)a,n-pos);pos+=Serial.readBytes(p+pos,take);}else delay(1);}return pos==n;}
void startMic(){
 i2s_config_t c={};c.mode=(i2s_mode_t)(I2S_MODE_MASTER|I2S_MODE_RX);c.sample_rate=8000;c.bits_per_sample=I2S_BITS_PER_SAMPLE_32BIT;c.channel_format=I2S_CHANNEL_FMT_ONLY_LEFT;c.communication_format=I2S_COMM_FORMAT_STAND_I2S;c.intr_alloc_flags=0;c.dma_buf_count=4;c.dma_buf_len=160;c.use_apll=false;
 i2s_pin_config_t pins={};pins.bck_io_num=26;pins.ws_io_num=25;pins.data_out_num=I2S_PIN_NO_CHANGE;pins.data_in_num=33;pins.mck_io_num=I2S_PIN_NO_CHANGE;
 if(i2s_driver_install(I2S_NUM_0,&c,0,NULL)!=ESP_OK||i2s_set_pin(I2S_NUM_0,&pins)!=ESP_OK)halt("ERR I2S init");
}
void provision(){
 char kh[33],sh[17],ssid[33],pass[65],ip[32],mode[8],suite[8];unsigned port;
 if(sscanf(configLine,"CFG %32s %16s %32s %64s %31s %u %7s %7s",kh,sh,ssid,pass,ip,&port,mode,suite)!=8||port<1||port>65535||!hexparse(kh,keyBytes,16)||!hexparse(sh,sessionId,8)||!host.fromString(ip)||(strcmp(mode,"USB")&&strcmp(mode,"MIC"))||(strcmp(suite,"CAALC")&&strcmp(suite,"ASCON"))){Serial.println("ERR configuration");return;}
 algorithmId=!strcmp(suite,"ASCON")?1:0;
 usbMode=!strcmp(mode,"USB");hostPort=port;
 // Never permit reconfiguration and sequence reset in a running session.
 if(!usbMode){
  WiFi.mode(WIFI_STA);WiFi.begin(ssid,!strcmp(pass,"-")?"":pass);uint32_t start=millis();while(WiFi.status()!=WL_CONNECTED&&millis()-start<20000)delay(100);
  if(WiFi.status()!=WL_CONNECTED)halt("ERR WiFi connection");
  if(!udp.begin(5006))halt("ERR UDP init");startMic();
 }
 sequence=0;provisioned=true;memset(configLine,0,sizeof(configLine));memset(kh,0,sizeof(kh));memset(pass,0,sizeof(pass));Serial.println("READY");
}
void sendFrame(){
 if(sequence>=0x100000000ULL)halt("ERR session exhausted; provision fresh key after reboot");
 memcpy(packet,"CAP1",4);packet[4]=1;packet[5]=algorithmId;memcpy(packet+6,sessionId,8);caalc::store64(packet+14,sequence);
 packet[22]=0x40;packet[23]=0x1f;packet[24]=20;packet[25]=0;packet[26]=0x40;packet[27]=1;
 uint8_t nonce[16];memcpy(nonce,sessionId,8);caalc::store64(nonce+8,sequence);
 uint32_t begin=micros();
 if(algorithmId==0){if(!caalc::crypt(keyBytes,nonce,pcm,320,packet,28,packet+28,packet+348))halt("ERR cipher");}
 else{unsigned long long clen=0;if(crypto_aead_encrypt(packet+28,&clen,pcm,320,packet,28,NULL,nonce,keyBytes)!=0||clen!=336)halt("ERR Ascon cipher");}
 uint32_t elapsed=micros()-begin;
 cryptoTotal+=elapsed;if(elapsed>cryptoMax)cryptoMax=elapsed;
 if(usbMode){uint8_t prefix[4]={'C','A',108,1};Serial.write(prefix,4);Serial.write(packet,364);}
 else {if(!udp.beginPacket(host,hostPort))Serial.println("ERR UDP begin");else{udp.write(packet,364);if(!udp.endPacket())Serial.println("ERR UDP send");}}
 sequence++;framesSent++;
 if(framesSent%100==0)Serial.printf("STAT frames=%lu enc_mean_us=%lu enc_max_us=%lu heap=%lu\n",(unsigned long)framesSent,(unsigned long)(cryptoTotal/framesSent),(unsigned long)cryptoMax,(unsigned long)ESP.getFreeHeap());
}
void setup(){
 Serial.begin(921600);Serial.setTimeout(100);delay(500);
 uint32_t s[12]={},a[12]={};caalc::perm(s);caalc::perm(s,true);if(memcmp(s,a,sizeof(s)))halt("ERR inverse selftest");
 Serial.println("CAALC experimental; awaiting trusted USB CFG; fresh key/session required each boot");
}
void loop(){
 if(!provisioned){
  while(Serial.available()){char c=(char)Serial.read();if(c=='\n'){configLine[configLen]=0;provision();configLen=0;break;}if(c!='\r'){if(configLen>=sizeof(configLine)-1){configLen=0;Serial.println("ERR line too long");}else configLine[configLen++]=c;}}
  delay(1);return;
 }
 if(usbMode){
  if(Serial.available()<2){delay(1);return;}
  if(Serial.read()!='P')return;if(Serial.read()!='C')return;
  uint8_t length[2];if(!exactRead(length,2)||length[0]!=64||length[1]!=1){Serial.println("ERR PCM length");return;}
  if(!exactRead(pcm,320)){Serial.println("ERR PCM timeout");return;}
 }else{
  int32_t samples[160];size_t got=0;
  if(i2s_read(I2S_NUM_0,samples,sizeof(samples),&got,pdMS_TO_TICKS(100))!=ESP_OK||got!=sizeof(samples)){Serial.println("ERR I2S short frame");return;}
  for(unsigned i=0;i<160;i++){int16_t value=(int16_t)(samples[i]>>16);pcm[2*i]=(uint8_t)value;pcm[2*i+1]=(uint8_t)((uint16_t)value>>8);}
 }
 sendFrame();
}

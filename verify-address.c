#include <string.h>
#include <stdint.h>
#include <mbedtls/aes.h>
#include <stdio.h>
#include <stdlib.h>

int main (int argc, char *const*argv) {
  mbedtls_aes_context ctx;
  unsigned char key[16];
  unsigned char plaintext[16];
  unsigned char cyphertext[16];
  unsigned char addr[6];
  if(argc != 3) {
    fprintf(stderr,"Usage: verify-address <irk> <address>\n");
    exit(1);
  }
  const char *irk = argv[1];
  const char *address = argv[2];
  
  mbedtls_aes_init(&ctx);
  memset(plaintext,0,16);
  for(int i = 0; i < 16; i++) {
    unsigned int v;
    char buf[3] = {0,0,0};
    memcpy(buf,&irk[i<<1],2);
    sscanf(buf,"%x",&v);
    key[15-i] = v;
  }
  for(int i = 0; i < 6; i++) {
    unsigned int v;
    char buf[3] = {0,0,0};
    memcpy(buf,&address[3*i],2);
    sscanf(buf,"%x",&v);
    addr[5-i] = v;    
  }
  for(int i = 0; i < 3; i++) {
    plaintext[15-i] = addr[3+i];
  }
  mbedtls_aes_setkey_enc(&ctx,key,128);
  mbedtls_aes_crypt_ecb(&ctx,MBEDTLS_AES_ENCRYPT,(const unsigned char*)plaintext,cyphertext);
  if(cyphertext[13] == addr[2]
     && cyphertext[14] == addr[1]
     && cyphertext[15] == addr[0]) printf("Verified\n");
  char buf[33];
  for(int i = 0; i < 16; i++) sprintf(&buf[i<<1],"%02x",plaintext[i]);
  printf(" plaintext: %s\n",buf);
  for(int i = 0; i < 16; i++) sprintf(&buf[i<<1],"%02x",cyphertext[i]);
  printf("cyphertext: %s\n",buf);
}

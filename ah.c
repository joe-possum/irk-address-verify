#include <string.h>
#include <stdint.h>
#include <mbedtls/aes.h>
#include <stdio.h>

#define IM_ADDR_CLEARTEXT_LENGTH    3
#define IM_ADDR_CIPHERTEXT_LENGTH   3

#if(0)
void ah(uint8_t const * p_k, uint8_t const * p_r, uint8_t * p_local_hash)
{
    nrf_ecb_hal_data_t ecb_hal_data;
    for (uint32_t i = 0; i < SOC_ECB_KEY_LENGTH; i++)
    {
        ecb_hal_data.key[i] = p_k[SOC_ECB_KEY_LENGTH - 1 - i];
    }
    memset(ecb_hal_data.cleartext, 0, SOC_ECB_KEY_LENGTH - IM_ADDR_CLEARTEXT_LENGTH);
 
    for (uint32_t i = 0; i < IM_ADDR_CLEARTEXT_LENGTH; i++)
    {
        ecb_hal_data.cleartext[SOC_ECB_KEY_LENGTH - 1 - i] = p_r[i];
    }
 
    sd_ecb_block_encrypt(&ecb_hal_data);
 
    for (uint32_t i = 0; i < IM_ADDR_CIPHERTEXT_LENGTH; i++)
    {
        p_local_hash[i] = ecb_hal_data.ciphertext[SOC_ECB_KEY_LENGTH - 1 - i];
    }
}
#endif

char *keys[] = { "02de4b2ffe973e40bd9c6566d6453e9d" };
char *addresses[] = { "4d:2a:96:05:12:9a", "4a:6e:78:94:62:8b", "40:4b:1e:57:28:21" };

int main (int argc, char *const*argv) {
  mbedtls_aes_context ctx;
  unsigned char key[16];
  unsigned char plaintext[16];
  unsigned char cyphertext[16];
  unsigned char addr[6];
  mbedtls_aes_init(&ctx);
  memset(plaintext,0,16);
  for(int i = 0; i < 16; i++) {
    unsigned int v;
    char buf[3] = {0,0,0};
    memcpy(buf,&keys[0][i<<1],2);
    sscanf(buf,"%x",&v);
    key[15-i] = v;
  }
  for(int k = 0; k < sizeof(addresses)/sizeof(char*); k++) {
    for(int i = 0; i < 6; i++) {
      unsigned int v;
      char buf[3] = {0,0,0};
      memcpy(buf,&addresses[k][3*i],2);
      sscanf(buf,"%x",&v);
      addr[5-i] = v;    
    }
    for(int i = 0; i < 3; i++) {
      plaintext[15-i] = addr[3+i];
    }
    mbedtls_aes_setkey_enc(&ctx,key,128);
    mbedtls_aes_crypt_ecb(&ctx,MBEDTLS_AES_ENCRYPT,(const unsigned char*)plaintext,cyphertext);
    char buf[33];
    printf("Address: %s\n",addresses[k]);
    for(int i = 0; i < 16; i++) sprintf(&buf[i<<1],"%02x",plaintext[i]);
    printf(" plaintext: %s\n",buf);
    for(int i = 0; i < 16; i++) sprintf(&buf[i<<1],"%02x",cyphertext[i]);
    printf("cyphertext: %s\n",buf);
  }
}

#include "ozaes.h"

#include <hwcrypto/aes.h>


uint8_t * normalize(uint8_t in[], unsigned int inLen, unsigned int alignLen)
{
  uint8_t *alignIn = new uint8_t[alignLen];
  memcpy(alignIn, in, inLen);
  memset(alignIn + inLen, 0x00, alignLen - inLen);
  return alignIn;
}

unsigned int get_normalized_length(unsigned int len)
{
  const uint8_t blockBytesLen  = 16;
  unsigned int lengthWithPadding =  (len / blockBytesLen);
  if (len % blockBytesLen) {
	  lengthWithPadding++;
  }
  
  lengthWithPadding *=  blockBytesLen;
  
  return lengthWithPadding;
}

uint8_t * oz_aes::encrypt_CBC(uint8_t * input, unsigned int input_length, uint8_t * key,unsigned int key_length, unsigned int &out_length)
{
    if(input_length == 0 ) return nullptr;
    if(key_length != 32 && key_length != 24 && key_length != 16 ) return nullptr;

    esp_aes_context ctx;
	esp_aes_init( &ctx );
    int err = esp_aes_setkey( &ctx, key, key_length*8 );

    if(err == ERR_ESP_AES_INVALID_KEY_LENGTH)
    {
        return nullptr;
    }

    // initialize iv with first 16 char of key 
    uint8_t * iv = new uint8_t[16];
    memcpy(iv, key, 16);

    out_length = get_normalized_length(input_length);
    uint8_t * payload = normalize(input, input_length, out_length);
    uint8_t * encrypted = new uint8_t[out_length];
    err = esp_aes_crypt_cbc( &ctx, ESP_AES_ENCRYPT, out_length, iv, payload, (uint8_t*)encrypted);

    //delete[] iv;  

    if(err == ERR_ESP_AES_INVALID_INPUT_LENGTH)
    {
        //delete[] encrypted;
        return nullptr;
    }

    return encrypted;
}

uint8_t * oz_aes::encrypt_CBC(String input, uint8_t * key, unsigned int key_length, unsigned int &out_length)
{
    return encrypt_CBC((uint8_t *)input.c_str(),input.length(),key,key_length,out_length);
}

uint8_t * oz_aes::encrypt_CBC(String input, String key, unsigned int &out_length)
{
    return encrypt_CBC((uint8_t *)input.c_str(),input.length(),(uint8_t *)key.c_str(),key.length(),out_length);
}

uint8_t * oz_aes::decrypt_CBC(uint8_t * input, unsigned int input_length, uint8_t * key,unsigned int key_length)
{
    if(input_length == 0 || input_length % 16 != 0 ) return nullptr;
    if(key_length != 32 && key_length != 24 && key_length != 16 ) return nullptr;

    esp_aes_context ctx;
	esp_aes_init( &ctx );
    int err = esp_aes_setkey( &ctx, key, key_length*8 );

    if(err == ERR_ESP_AES_INVALID_KEY_LENGTH)
    {
        return nullptr;
    }

    // initialize iv with first 16 char of key 
    uint8_t * iv = new uint8_t[16];
    memcpy(iv, key, 16);

    uint8_t * decrypted = new uint8_t[input_length];
    err = esp_aes_crypt_cbc( &ctx, ESP_AES_DECRYPT, input_length, iv, (uint8_t*)input, (uint8_t*)decrypted );

    //delete[] iv;
    if(err == ERR_ESP_AES_INVALID_INPUT_LENGTH)
    {
        //delete[] decrypted;
        return nullptr;
    }

    return decrypted;
}

uint8_t * oz_aes::decrypt_CBC(uint8_t * input, unsigned int input_length, String key)
{
    return decrypt_CBC(input, input_length, (uint8_t *)key.c_str(),key.length());
}

String oz_aes::sdecrypt_CBC(uint8_t * input, unsigned int input_length, uint8_t * key,unsigned int key_length)
{
    return String((char *)decrypt_CBC(input,input_length,key,key_length));
}

String oz_aes::sdecrypt_CBC(uint8_t * input, unsigned int input_length, String key)
{
    return String((char *)decrypt_CBC(input,input_length,key));
}



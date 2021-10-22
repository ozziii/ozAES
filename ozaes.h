#ifndef OZ_AES_H
#define OZ_AES_H

#include "WString.h"

class oz_aes
{
public:
    static uint8_t * encrypt_CBC(uint8_t * input, unsigned int input_length, uint8_t * key, unsigned int key_length, unsigned int &out_length);
    static uint8_t * encrypt_CBC(uint8_t * input, unsigned int input_length, String key, unsigned int &out_length);
    static uint8_t * encrypt_CBC(String input, uint8_t * key, unsigned int key_length, unsigned int &out_length);
    static uint8_t * encrypt_CBC(String input, String key, unsigned int &out_length);

    static uint8_t * decrypt_CBC(uint8_t * input, unsigned int input_length, uint8_t * key,unsigned int key_length);
    static uint8_t * decrypt_CBC(uint8_t * input, unsigned int input_length, String key);
    static String sdecrypt_CBC(uint8_t * input, unsigned int input_length, uint8_t * key,unsigned int key_length);
    static String sdecrypt_CBC(uint8_t * input, unsigned int input_length, String key);
};

#endif
#ifndef AES_H
#define AES_H

#include <stdint.h>

#define ECB 0
#define CBC 1

typedef enum {
    AES_CYPHER_128,
    AES_CYPHER_192,
    AES_CYPHER_256
} AES_CYPHER_TYPE;

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

int aes_encrypt_ebc(AES_CYPHER_TYPE mode, u8 *data, int len, u8 *key);
int aes_decrypt_ebc(AES_CYPHER_TYPE mode, u8 *data, int len, u8 *key);
int aes_encrypt_cbc(AES_CYPHER_TYPE mode, u8 *data, int len, u8 *key, u8 *iv);
int aes_decrypt_cbc(AES_CYPHER_TYPE mode, u8 *data, int len, u8 *key, u8 *iv);

#endif
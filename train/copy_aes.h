#include <stdint.h> // uint8_t - uint64_t

typedef enum {
    AES_CYPHER_128,
    AES_CYPHER_192,
    AES_CYPHER_256,
} AES_TYPE;


int aes_encrypt_ecb(AES_TYPE mode, uint8_t *data, int len, uint8_t *key);
int aes_decrypt_ecb(AES_TYPE mode, uint8_t *data, int len, uint8_t *key);
int aes_encrypt_cbc(AES_TYPE mode, uint8_t *data, int len, uint8_t *key, uint8_t *iv);
int aes_decrypt_cbc(AES_TYPE mode, uint8_t *data, int len, uint8_t *key, uint8_t *iv);

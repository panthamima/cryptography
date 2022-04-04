#ifndef RC4_H
#define RC4_H

typedef unsigned char uint8;
typedef unsigned int uint32;

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8 se[256], sd[256];
    uint32 pose, posd;
    uint8 te, td;
} rc4_ctx;

void rc4_ks(rc4_ctx *ctx, const uint8 *key, uint32 key_len);
void rc4_encrypt(rc4_ctx *ctx, const uint8 *src, uint8 *dst, uint32 len);
void rc4_decrypt(rc4_ctx *ctx, const uint8 *src, uint8 *dst, uint32 len);


#ifdef __cplusplus
}
#endif

#endif /* !RC4_H */
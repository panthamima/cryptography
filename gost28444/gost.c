#include <stdio.h>
#include <stdint.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t  u8;

int feistel_init(u32 *block) {
    
}

int feistel(u32 block, u32 key) {
    return block | key;
}

int swap(u32 *left, u32 *right, u32 *key) {
    u32 temp;
}

void feistel_encrypt(u32 *left, u32 *right, u32 rounds, u32 *key) {
    u32 i, temp;

    for(i = 0; i < rounds; i++) {
        temp = *right ^ feistel(*left, key[i]);
        *right = *left;
        *left = temp;
    }
}

void feistel_decrypt(u32 *left, u32 *right, u32 rounds, u32 *key) {
    u32 i, temp;

    for(i = rounds; i >= 0; i--) {
        temp = *left ^ feistel(right, key[i]);
        *left = *right;
        *right = temp; 
    }
}

int main() {
    u32 key = {12, 323, 22, 31, 12, 66, 33, 11};
    u32 j;
    // feistel_encrypt()
}
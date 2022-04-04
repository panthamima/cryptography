#include <stdint.h>
#include <stdio.h>

typedef uint8_t  u8;
typedef uint32_t u32;
typedef uint64_t u64;

void init_gries(u8 *key) {
    int i;
    for(i = 0; i < 16; ++i) {
        
    }

    printf("%d|", (*key % 16)) ;
}

void key_expansion(u64 *key) {

}

void add_round() {

}

int main() {
    u8 key[16] = {0x15, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    init_gries(key);

}
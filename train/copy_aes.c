#include <stdio.h>
#include <memory.h>
#include "copy_aes.h"

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;


// key size 128-256
// размер ключа от 128 до 256
u8 aes_key_bits[] = {
    /* AES_CYPHER_128 */ 128,
    /* AES_CYPHER_192 */ 192,
    /* AES_CYPHER_256 */ 256,
};

// number of rounds depending on the length of the key   128(10) 192(12) 256(14)
// количество раундов в зависимости от длины ключа       128(10) 192(12) 256(14)
u8 aes_rounds[] = {
    /* AES_CYPHER_128 */  10,
    /* AES_CYPHER_192 */  12,
    /* AES_CYPHER_256 */  14,
};

// the number of 32-bit words that make up the cipher key  128(4) 192(6) 256(8)
// число 32-битных слов, составляющих шифроключ            128(4) 192(6) 256(8)
u8 aes_nk[] = {
    /* AES_CYPHER_128 */  4,
    /* AES_CYPHER_192 */  6,
    /* AES_CYPHER_256 */  8,
};

// the number of columns (32-bit words) that make up State  == 4
// число столбцов (32-битных слов), составляющих State      == 4
u8 aes_nb[] = {
    /* AES_CYPHER_128 */  4,
    /* AES_CYPHER_192 */  4,
    /* AES_CYPHER_256 */  4,
};

// an array that consists of bits of a 32-bit word and is constant for a given round calculated in advance
// массив, который состоит из битов 32-разрядного слова и является постоянным для данного раунда, заранее расчитан
static const u32 aes_rcon[] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1b000000, 0x36000000, 0x6c000000, 0xd8000000, 0xab000000, 0xed000000, 0x9a000000
};

// pre-calculated by a special function      S-box
// заранее рассчитанный специальной функцией S-box
static const u8 aes_sbox[256] = {
 /* 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F  */
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// pre-calculated by a special function reversed           S-box
// заранее рассчитанный специальной функцией перевернутый  S-box
static const u8 aes_inv_sbox[256] = {
 /* 0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F  */
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// getting a value from the s-box that is equal to value
// получение значения из s-box которому равно value
u8 aes_sub_sbox(u8 value) {
    return aes_sbox[value];
}

// takes a 32-bit word and, applying the S-box to each of the four bytes, outputs the output word
// берет 32-битовое слово и, применяя S-box к каждому из четырёх байтов, выдаёт выходное слово
u32 aes_sub_dword(u32 value) {
    u32 temp = 0;
   
    temp |= ((u32)aes_sub_sbox((u8)((value >>  0) & 0xFF))) <<  0;
    temp |= ((u32)aes_sub_sbox((u8)((value >>  8) & 0xFF))) <<  8;
    temp |= ((u32)aes_sub_sbox((u8)((value >> 16) & 0xFF))) << 16;
    temp |= ((u32)aes_sub_sbox((u8)((value >> 24) & 0xFF))) << 24;

    return temp;
}

// takes a 32-bit word and performs a cyclic permutation
// берет 32-битовое слово и производит циклическую перестановку
u32 aes_rot_dword(u32 value) {
    u32 temp = value;
   
    return (value >> 8) | ((temp & 0xFF) << 24);
}

// 
// 
u32 aes_swap_dword(u32 value) {
    return (((value & 0x000000FF) << 24) |
            ((value & 0x0000FF00) <<  8) |
            ((value & 0x00FF0000) >>  8) |
            ((value & 0xFF000000) >> 24) );
}

// 
//
void aes_key_expansion(AES_TYPE mode, uint8_t *key, uint8_t *round) {
    uint32_t *w = (uint32_t *)round;
    uint32_t  t;
    int      i = 0;

    do {
        w[i] = *((uint32_t *)&key[i * 4 + 0]);
    } while (++i < aes_nk[mode]);
   
    do {
        if ((i % aes_nk[mode]) == 0) {
            t = aes_rot_dword(w[i - 1]);
            t = aes_sub_dword(t);
            t = t ^ aes_swap_dword(aes_rcon[i/aes_nk[mode] - 1]);
        } else if (aes_nk[mode] > 6 && (i % aes_nk[mode]) == 4) {
            t = aes_sub_dword(w[i - 1]);
        } else {
            t = w[i - 1];
        }
        w[i] = w[i - aes_nk[mode]] ^ t;
    } while (++i < aes_nb[mode] * (aes_rounds[mode] + 1));
}
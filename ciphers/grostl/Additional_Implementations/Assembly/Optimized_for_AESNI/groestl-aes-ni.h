#ifndef __groestl_aes_h
#define __groestl_aes_h

#include <stdio.h>
#include <stdlib.h>

#include "brg_endian.h"
#define NEED_UINT_64T
#include "brg_types.h"

/* some sizes (number of bytes) */
#define ROWS 8
#define LENGTHFIELDLEN ROWS
#define COLS512 8
#define COLS1024 16
#define SIZE512 (ROWS*COLS512)
#define SIZE1024 (ROWS*COLS1024)

#define ROUNDS512 10
#define ROUNDS1024 14

#define ROTL64(a,n) ((((a)<<(n))|((a)>>(64-(n))))&li_64(ffffffffffffffff))

#if (PLATFORM_BYTE_ORDER == IS_BIG_ENDIAN)
#define EXT_BYTE(var,n) ((u8)((u64)(var) >> (8*(7-(n)))))
#define U64BIG(a) (a)
#endif /* IS_BIG_ENDIAN */

#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
#define EXT_BYTE(var,n) ((u8)((u64)(var) >> (8*n)))
#define U64BIG(a) \
  ((ROTL64(a, 8) & li_64(000000FF000000FF)) | \
   (ROTL64(a,24) & li_64(0000FF000000FF00)) | \
   (ROTL64(a,40) & li_64(00FF000000FF0000)) | \
   (ROTL64(a,56) & li_64(FF000000FF000000)))
#endif /* IS_LITTLE_ENDIAN */

typedef enum { LONG, SHORT } Var;

/* global variables  */
__attribute__ ((aligned (16))) unsigned char GLOBAL_CV_PTR[8*16];
__attribute__ ((aligned (16))) unsigned char ROUND_CONST_MUL[8];
__attribute__ ((aligned (16))) unsigned char ROUND_CONST_Lx[16];
__attribute__ ((aligned (16))) unsigned char ROUND_CONST_L0[ROUNDS512*16];
__attribute__ ((aligned (16))) unsigned char ROUND_CONST_L7[ROUNDS512*16];
__attribute__ ((aligned (16))) unsigned char ROUND_CONST_P[ROUNDS1024*16];
__attribute__ ((aligned (16))) unsigned char ROUND_CONST_Q[ROUNDS1024*16];
__attribute__ ((aligned (16))) unsigned char TRANSP_MASK[16];
__attribute__ ((aligned (16))) unsigned char ALL_7F[16];
__attribute__ ((aligned (16))) unsigned char ALL_1B[16];
__attribute__ ((aligned (16))) unsigned char ALL_FF[16];
__attribute__ ((aligned (16))) unsigned char SUBSH_MASK[8*16];
__attribute__ ((aligned (16))) unsigned char TEMP[8*16];
__attribute__ ((aligned (16))) unsigned char TMP_MUL1[8*16];
__attribute__ ((aligned (16))) unsigned char TMP_MUL2[8*16];
__attribute__ ((aligned (16))) unsigned char TMP_MUL4[16];
__attribute__ ((aligned (16))) unsigned char QTEMP[8*16];


/* NIST API begin */
typedef unsigned char BitSequence;
typedef unsigned long long DataLength;
typedef enum { SUCCESS = 0, FAIL = 1, BAD_HASHLEN = 2 } HashReturn;
typedef struct {
  u64 *chaining;            /* actual state */
  u64 block_counter;        /* message block counter */
  BitSequence *buffer;      /* data buffer */
  int buf_ptr;              /* data buffer pointer */
  int bits_in_last_byte;    /* no. of message bits in last byte of
                               data buffer */
  int columns;              /* no. of columns in state */
  int statesize;            /* total no. of bytes in state */
  Var v;                    /* LONG or SHORT */
} hashState;

HashReturn Init(hashState*);
HashReturn Update(hashState*, const BitSequence*, DataLength);
HashReturn Final(hashState*, BitSequence*);
HashReturn Hash(int, const BitSequence*, DataLength, BitSequence*);
/* NIST API end   */

#endif /* __groestl_aes_h */

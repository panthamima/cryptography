#ifndef __groestl_mmx_h
#define __groestl_mmx_h

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

#define ROTL32(a,n) ((((a)<<(n))|((a)>>(32-(n))))&li_32(ffffffff))

#if (PLATFORM_BYTE_ORDER == IS_BIG_ENDIAN)
#define EXT_BYTE(var,n) ((u8)((u64)(var) >> (8*(7-(n)))))
#define U32BIG(a) (a)
#endif /* IS_BIG_ENDIAN */

#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
#define EXT_BYTE(var,n) ((u8)((u64)(var) >> (8*n)))
#define U32BIG(a) \
  ((ROTL32(a, 8) & li_32(00FF00FF)) |		\
   (ROTL32(a,24) & li_32(FF00FF00)))
#endif /* IS_LITTLE_ENDIAN */


/* NIST API begin */
typedef unsigned char BitSequence;
typedef unsigned long long DataLength;
typedef enum { SUCCESS = 0, FAIL = 1, BAD_HASHLEN = 2 } HashReturn;
typedef struct {
  u32 *chaining;            /* actual state */
  u64 block_counter;        /* message block counter */
  int hashbitlen;           /* output length in bits */
  BitSequence *buffer;      /* data buffer */
  int buf_ptr;              /* data buffer pointer */
  int bits_in_last_byte;    /* no. of message bits in last byte of
			       data buffer */
  int columns;              /* no. of columns in state */
  int statesize;            /* total no. of bytes in state */
} hashState;

HashReturn Init(hashState*, int);
HashReturn Update(hashState*, const BitSequence*, DataLength);
HashReturn Final(hashState*, BitSequence*);
HashReturn Hash(int, const BitSequence*, DataLength, BitSequence*);
/* NIST API end   */

/* helper functions */
void PrintHash(const BitSequence*, int);

#endif /* __groestl_mmx_h */

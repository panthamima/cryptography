/******************************************************************************
 * Copyright 2007, 2008 Sony Corporation
 *
 * clefia_ref.h
 *
 * "The 128-bit Blockcipher CLEFIA"
 * Header file for Reference ANSI C code
 *
 * Version  1.0.1 (August 26 2008)
 *
 * NOTICE
 * This reference code is written for a clear understanding of the CLEFIA
 * blockcipher algorithm based on the specification of CLEFIA.
 * Therefore, this code does not include any optimizations for
 * high-speed or low-cost implementations or any countermeasures against
 * implementation attacks.
 *
 *****************************************************************************/

#ifndef _CLEFIA_REF_H_INCLUDED
#define _CLEFIA_REF_H_INCLUDED

#define CLEFIA_BLK_SIZE 16
#define CLEFIA_RK_MAX (8 * 26 + 16)

#ifdef __cplusplus
extern "C" {
#endif 

int ClefiaKeySet(unsigned char *rk, const unsigned char *skey, const int key_bitlen);
void ClefiaEncrypt(unsigned char *ct, const unsigned char *pt, const unsigned char *rk, const int r);
void ClefiaDecrypt(unsigned char *pt, const unsigned char *ct, const unsigned char *rk, const int r);

#ifdef __cplusplus
}
#endif 

#endif /* ?_CLEFIA_REF_H_INCLUDED */


/* end of file */


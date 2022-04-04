
/*  $Id: speedc.h,v 1.4 2003/01/21 08:50:40 lteo Exp $ */

/*
 *  speedc.h:  header file for speedc.c
 *
 *  Copyright (c) 2003 Calyptix Security Corporation
 *  All rights reserved.
 *
 *  This code is derived from software contributed to Calyptix Security
 *  Corporation by Yuliang Zheng.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution.
 *  3. Neither the name of Calyptix Security Corporation nor the
 *     names of its contributors may be used to endorse or promote
 *     products derived from this software without specific prior
 *     written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * -------------------------------------------------------------------
 *
 *  Reference:
 *       Y. Zheng:
 *       "The SPEED Cipher,"
 *       Financial Cryptography'97,
 *       Anquilla, BWI, 24-28 February 1997.
 *
 *  Authors:    Yuliang Zheng and Lawrence Teo
 *              Calyptix Security Corporation
 *              P.O. Box 561508, Charlotte, NC 28213, USA
 *              Email: info@calyptix.com
 *              URL:   http://www.calyptix.com/
 *              Voice: +1 704 806 8635
 */

/*
 * The following three parameters 
 *      (1) SPEED_DATA_LEN
 *      (2) SPEED_KEY_LEN
 *      (3) SPEED_NO_OF_RND
 * may be modified.
 *
 * Suggested combinations for providing adequate security:
 *
 *  +--------------------------------------------------+
 *  | SPEED_DATA_LEN | SPEED_KEY_LEN | SPEED_NO_OF_RND |
 *  |==================================================|
 *  |       64       |     >= 64     |     >= 64       | 
 *  |--------------------------------------------------|
 *  |      128       |     >= 64     |     >= 48       | 
 *  |--------------------------------------------------|
 *  |      256       |     >= 64     |     >= 48       | 
 *  +--------------------------------------------------+
 */
/*
 *
 * The following should NOT be modified.
 * -------------------------------------
 *
 */

/*
 * speed_word defines a SPEED internal word 
 * as an unsigned integer of 32 or more bits.
 *
 * Note: 
 *       lower  8 bits are used when SPEED_DATA_LEN = 64 
 *       lower 16 bits are used when SPEED_DATA_LEN = 128 
 *       lower 32 bits are used when SPEED_DATA_LEN = 256 
 */
typedef unsigned long  speed_word;              /* unsigned int of >= 32 bits */

#define SPEED_DATA_LEN_BYTE (SPEED_DATA_LEN/8)  /* no. of bytes in a p/c-text */
#define SPEED_KEY_LEN_BYTE  (SPEED_KEY_LEN/8)   /* no. of bytes in a key */

typedef unsigned char speed_key [SPEED_KEY_LEN_BYTE];  /* for user key */
typedef unsigned char speed_data[SPEED_DATA_LEN_BYTE]; /* for p/c-text */

typedef speed_word speed_ikey [SPEED_NO_OF_RND];/* for round keys */
typedef speed_word speed_idata[8];              /* for internal p/c-text */

/*
 * Interface I: character-oriented interface.
 */
void speed_encrypt (
      speed_data ptxt,   /* plaintext,  an array of SPEED_DATA_LEN_BYTE chars */
      speed_data ctxt,   /* ciphertext, an array of SPEED_DATA_LEN_BYTE chars */
      speed_key  key     /* user key,   an array of SPEED_KEY_LEN_BYTE  chars */
      );
void speed_decrypt (
      speed_data ptxt,   /* plaintext,  an array of SPEED_DATA_LEN_BYTE chars */
      speed_data ctxt,   /* ciphertext, an array of SPEED_DATA_LEN_BYTE chars */
      speed_key  key     /* user key,   an array of SPEED_KEY_LEN_BYTE  chars */
      );
/*
 * Interface II: internal word-oriented interface.
 *    (As the key scheduling may be called only once,
 *     this interface may be more efficient than Interface I)
 */
void speed_key_schedule (
      speed_key  key,    /* user key,   an array of SPEED_KEY_LEN_BYTE chars */
      speed_ikey ikey    /* round key,  an array of SPEED_NO_OF_RND words */ 
      );
void speed_encrypt_rk (
      speed_idata iptxt, /* internal plaintext,  an array of 8 words */ 
      speed_idata ictxt, /* internal ciphertext, an array of 8 words */ 
      speed_ikey  ikey   /* round key,  an array of SPEED_NO_OF_RND words */ 
      );
void speed_decrypt_rk (
      speed_idata iptxt, /* internal plaintext,  an array of 8 words */ 
      speed_idata ictxt, /* internal ciphertext, an array of 8 words */ 
      speed_ikey  ikey   /* round key,  an array of SPEED_NO_OF_RND words */ 
      );


/*****************************************************************

HIEROCRYPT-L1 block cipher

Implemented by Alexander Myasnikow

Block: 64 bit

Key: 128 bit

Web: www.darksoftware.narod.ru

*****************************************************************/


#include <stdio.h>
#include <stdlib.h>


#define primitiveGF8 0x163
#define MAX_ROUND 6

typedef u8 HCL1_KS[MAX_ROUND + 1][4][4];


/*
* constant parameters
*/

u8 sbox[256] =
{
  0x07, 0xFC, 0x55, 0x70, 0x98, 0x8E, 0x84, 0x4E, 0xBC, 0x75, 0xCE, 0x18,
  0x02, 0xE9, 0x5D, 0x80, 0x1C, 0x60, 0x78, 0x42, 0x9D, 0x2E, 0xF5, 0xE8,
  0xC6, 0x7A, 0x2F, 0xA4, 0xB2, 0x5F, 0x19, 0x87, 0x0B, 0x9B, 0x9C, 0xD3,
  0xC3, 0x77, 0x3D, 0x6F, 0xB9, 0x2D, 0x4D, 0xF7, 0x8C, 0xA7, 0xAC, 0x17,
  0x3C, 0x5A, 0x41, 0xC9, 0x29, 0xED, 0xDE, 0x27, 0x69, 0x30, 0x72, 0xA8,
  0x95, 0x3E, 0xF9, 0xD8, 0x21, 0x8B, 0x44, 0xD7, 0x11, 0x0D, 0x48, 0xFD,
  0x6A, 0x01, 0x57, 0xE5, 0xBD, 0x85, 0xEC, 0x1E, 0x37, 0x9F, 0xB5, 0x9A,
  0x7C, 0x09, 0xF1, 0xB1, 0x94, 0x81, 0x82, 0x08, 0xFB, 0xC0, 0x51, 0x0F,
  0x61, 0x7F, 0x1A, 0x56, 0x96, 0x13, 0xC1, 0x67, 0x99, 0x03, 0x5E, 0xB6,
  0xCA, 0xFA, 0x9E, 0xDF, 0xD6, 0x83, 0xCC, 0xA2, 0x12, 0x23, 0xB7, 0x65,
  0xD0, 0x39, 0x7D, 0x3B, 0xD5, 0xB0, 0xAF, 0x1F, 0x06, 0xC8, 0x34, 0xC5,
  0x1B, 0x79, 0x4B, 0x66, 0xBF, 0x88, 0x4A, 0xC4, 0xEF, 0x58, 0x3F, 0x0A,
  0x2C, 0x73, 0xD1, 0xF8, 0x6B, 0xE6, 0x20, 0xB8, 0x22, 0x43, 0xB3, 0x33,
  0xE7, 0xF0, 0x71, 0x7E, 0x52, 0x89, 0x47, 0x63, 0x0E, 0x6D, 0xE3, 0xBE,
  0x59, 0x64, 0xEE, 0xF6, 0x38, 0x5C, 0xF4, 0x5B, 0x49, 0xD4, 0xE0, 0xF3,
  0xBB, 0x54, 0x26, 0x2B, 0x00, 0x86, 0x90, 0xFF, 0xFE, 0xA6, 0x7B, 0x05,
  0xAD, 0x68, 0xA1, 0x10, 0xEB, 0xC7, 0xE2, 0xF2, 0x46, 0x8A, 0x6C, 0x14,
  0x6E, 0xCF, 0x35, 0x45, 0x50, 0xD2, 0x92, 0x74, 0x93, 0xE1, 0xDA, 0xAE,
  0xA9, 0x53, 0xE4, 0x40, 0xCD, 0xBA, 0x97, 0xA3, 0x91, 0x31, 0x25, 0x76,
  0x36, 0x32, 0x28, 0x3A, 0x24, 0x4C, 0xDB, 0xD9, 0x8D, 0xDC, 0x62, 0x2A,
  0xEA, 0x15, 0xDD, 0xC2, 0xA5, 0x0C, 0x04, 0x1D, 0x8F, 0xCB, 0xB4, 0x4F,
  0x16, 0xAB, 0xAA, 0xA0

};

u8 isbox[256] =
{
  0xB8, 0x49, 0x0C, 0x69, 0xF6, 0xBF, 0x80, 0x00, 0x5B, 0x55, 0x8F, 0x20,
  0xF5, 0x45, 0xA4, 0x5F, 0xC3, 0x44, 0x74, 0x65, 0xCB, 0xF1, 0xFC, 0x2F,
  0x0B, 0x1E, 0x62, 0x84, 0x10, 0xF7, 0x4F, 0x7F, 0x96, 0x40, 0x98, 0x75,
  0xE8, 0xE2, 0xB6, 0x37, 0xE6, 0x34, 0xEF, 0xB7, 0x90, 0x29, 0x15, 0x1A,
  0x39, 0xE1, 0xE5, 0x9B, 0x82, 0xCE, 0xE4, 0x50, 0xAC, 0x79, 0xE7, 0x7B,
  0x30, 0x26, 0x3D, 0x8E, 0xDB, 0x32, 0x13, 0x99, 0x42, 0xCF, 0xC8, 0xA2,
  0x46, 0xB0, 0x8A, 0x86, 0xE9, 0x2A, 0x07, 0xFB, 0xD0, 0x5E, 0xA0, 0xD9,
  0xB5, 0x02, 0x63, 0x4A, 0x8D, 0xA8, 0x31, 0xAF, 0xAD, 0x0E, 0x6A, 0x1D,
  0x11, 0x60, 0xEE, 0xA3, 0xA9, 0x77, 0x87, 0x67, 0xC1, 0x38, 0x48, 0x94,
  0xCA, 0xA5, 0xCC, 0x27, 0x03, 0x9E, 0x3A, 0x91, 0xD3, 0x09, 0xE3, 0x25,
  0x12, 0x85, 0x19, 0xBE, 0x54, 0x7A, 0x9F, 0x61, 0x0F, 0x59, 0x5A, 0x71,
  0x06, 0x4D, 0xB9, 0x1F, 0x89, 0xA1, 0xC9, 0x41, 0x2C, 0xEC, 0x05, 0xF8,
  0xBA, 0xE0, 0xD2, 0xD4, 0x58, 0x3C, 0x64, 0xDE, 0x04, 0x68, 0x53, 0x21,
  0x22, 0x14, 0x6E, 0x51, 0xFF, 0xC2, 0x73, 0xDF, 0x1B, 0xF4, 0xBD, 0x2D,
  0x3B, 0xD8, 0xFE, 0xFD, 0x2E, 0xC0, 0xD7, 0x7E, 0x7D, 0x57, 0x1C, 0x9A,
  0xFA, 0x52, 0x6B, 0x76, 0x97, 0x28, 0xDD, 0xB4, 0x08, 0x4C, 0xA7, 0x88,
  0x5D, 0x66, 0xF3, 0x24, 0x8B, 0x83, 0x18, 0xC5, 0x81, 0x33, 0x6C, 0xF9,
  0x72, 0xDC, 0x0A, 0xCD, 0x78, 0x92, 0xD1, 0x23, 0xB1, 0x7C, 0x70, 0x43,
  0x3F, 0xEB, 0xD6, 0xEA, 0xED, 0xF2, 0x36, 0x6F, 0xB2, 0xD5, 0xC6, 0xA6,
  0xDA, 0x4B, 0x95, 0x9C, 0x17, 0x0D, 0xF0, 0xC4, 0x4E, 0x35, 0xAA, 0x8C,
  0x9D, 0x56, 0xC7, 0xB3, 0xAE, 0x16, 0xAB, 0x2B, 0x93, 0x3E, 0x6D, 0x5C,
  0x01, 0x47, 0xBC, 0xBB
};

u8 hconst[5][4] =
{
  0x5a, 0x82, 0x79, 0x99,
  0x6e, 0xd9, 0xeb, 0xa1,
  0x8f, 0x1b, 0xbc, 0xdc,
  0xca, 0x62, 0xc1, 0xd6,
  0xf7, 0xde, 0xf5, 0x8a
};

int hindex[MAX_ROUND+1] =
{
  1,2,3,4,4,3,2
};


u8 mds[4][4] =
{
  {0xc4, 0x65, 0xc8, 0x8b},
  {0x8b, 0xc4, 0x65, 0xc8},
  {0xc8, 0x8b, 0xc4, 0x65},
  {0x65, 0xc8, 0x8b, 0xc4}
};

u8 mds_inv[4][4] =
{
  {0x82, 0xc4, 0x34, 0xf6},
  {0xf6, 0x82, 0xc4, 0x34},
  {0x34, 0xf6, 0x82, 0xc4},
  {0xc4, 0x34, 0xf6, 0x82}
};

int mdsh[2][2] =
{
  {0x5, 0x7},{0xa, 0xb}
};

int mdsh_inv[2][2] =
{
  {0xc, 0xa},{0x5, 0xb}
};


HCL1_KS ks;
HCL1_KS dks;


int
poly32_deg (u32 a)
{
  int n = -1;
  for (; a; a >>= 1)
    n++;
  return n;
}


u32
poly32_mul (u32 a, u32 b)
{
  u32 c = 0;

  for (; b; b >>= 1, a <<= 1)
    if (b & 1)
      c ^= a;

  return c;
}



u32
poly32_mod (u32 a, u32 b)
{
  int da = poly32_deg (a);
  int db = poly32_deg (b);
  u32 t;

  if (da < db)
    return a;

  if (da == db)
    return a ^ b;

  b <<= da - db;

  for (t = 1 << da; da >= db; da--)
    {
      if (a & t)
        a ^= b;
      b >>= 1;
      t >>= 1;
    }
  return a;
}


void
hcryptL1_mdsl (u8 * in, u8 * out)
{
  int i, j;
  u32 m;
  for (i = 0; i < 4; i++)
    {
      m = 0;
      for (j = 0; j < 4; j++)
        {
          m ^= poly32_mod (poly32_mul (mds[i][j], in[j]), primitiveGF8);
        }
      out[i] = (u8) m;

    }
}

void hcryptL1_xs (u8 * in, u8 * out, u8 * k1, u8 * k2)
{
  u8 t[4], u[4];
  int i;

  for (i = 0; i < 4; i++)
    u[i] = in[i] ^ k1[i];       /* key xOR */

  for (i = 0; i < 4; i++)
    t[i] = sbox[u[i]];          /* sbox */

  hcryptL1_mdsl (t, u);           /* MDS_L */

  for (i = 0; i < 4; i++)
    t[i] = u[i] ^ k2[i];        /*keyxOR */
  for (i = 0; i < 4; i++)
    out[i] = sbox[t[i]];        /* sbox */
}

/*
* op. over GF(2^4)  in MDS_H
*/

void
mdsh_mul (u8 * in, u8 * out, int x)
{
  int i;
  u8 u[4];
  for (i = 0; i < 4; i++)
    u[i] = 0;
  if (x & 1)
    {
      u[0] ^= in[0];
      u[1] ^= in[1];
      u[2] ^= in[2];
      u[3] ^= in[3];
    }
  if (x & 2)
    {
      u[0] ^= in[1];
      u[1] ^= in[2];
      u[2] ^= in[3] ^ in[0];
      u[3] ^= in[0];
    }
  if (x & 4)
    {
      u[0] ^= in[2];
      u[1] ^= in[3] ^ in[0];
      u[2] ^= in[0] ^ in[1];
      u[3] ^= in[1];
    }
  if (x & 8)
    {
      u[0] ^= in[0] ^ in[3];
      u[1] ^= in[1] ^ in[0];
      u[2] ^= in[2] ^ in[1];
      u[3] ^= in[2];
    }
  for (i = 0; i < 4; i++)
    out[i] = u[i];
}


void
hcryptL1_mdsh (u8 in[2][4], u8 out[2][4])
{
  int i, j, k;
  u8 tmp[4];
  for (i = 0; i < 2; i++)
    for (j = 0; j < 4; j++)
      out[i][j] = 0;
  for (i = 0; i < 2; i++)
    {
      for (j = 0; j < 2; j++)
        {
          mdsh_mul (&in[j][0], tmp, mdsh[i][j]);
          for (k = 0; k < 4; k++)
            out[i][k] ^= tmp[k];
        }
    }
}


void __stdcall __export
crypt (u8 * in)
{
  u8 t[2][4], u[2][4];
  int i, j, r;
  int n;
  
  for (r = i = 0; i < 2; i++)
    {
      for (j = 0; j < 4; j++, r++)
        {
          t[i][j] = in[r];
        }

    }

  n = 5;

  for (r = 0; r < n; r++)
    {
      hcryptL1_xs (&t[0][0], &u[0][0], &ks[r][0][0], &ks[r][2][0]);
      hcryptL1_xs (&t[1][0], &u[1][0], &ks[r][1][0], &ks[r][3][0]);
      hcryptL1_mdsh (u, t);
    }

  hcryptL1_xs (&t[0][0], &u[0][0], &ks[n][0][0], &ks[n][2][0]);
  hcryptL1_xs (&t[1][0], &u[1][0], &ks[n][1][0], &ks[n][3][0]);

  for (r = i = 0; i < 2; i++)
    {
      for (j = 0; j < 4; j++, r++)
        {
          in[r] = u[i][j] ^ ks[n + 1][i][j];
        }
    }
}


void
hcryptL1_imdsl (u8 * in, u8 * out)
{
  int i, j;
  u32 m;
  for (i = 0; i < 4; i++)
    {
      m = 0;
      for (j = 0; j < 4; j++)
        {
          m ^= poly32_mod (poly32_mul (mds_inv[i][j], in[j]), primitiveGF8);
        }
      out[i] = (u8)m;
    }
}

void
hcryptL1_ixs (u8 * in, u8 * out, u8 * k1, u8 * k2)
{
  u8 t[4], u[4];
  int i;

  for (i = 0; i < 4; i++)
    u[i] = in[i] ^ k1[i];       /* key xOR */

  for (i = 0; i < 4; i++)
    t[i] = isbox[u[i]];         /* sbox */

  hcryptL1_imdsl (t, u);          /*MDS_L */

  for (i = 0; i < 4; i++)
    t[i] = u[i] ^ k2[i];        /* key xOR */

  for (i = 0; i < 4; i++)
    out[i] = isbox[t[i]];       /* sbox */
}

void
hcryptL1_imdsh (u8 in[2][4], u8 out[2][4])
{
  int i, j, k;
  u8 tmp[4];
  for (i = 0; i < 4; i++)
    for (j = 0; j < 4; j++)
      out[i][j] = 0;
  for (i = 0; i < 2; i++)
    {
      for (j = 0; j < 2; j++)
        {
          mdsh_mul (&in[j][0], tmp, mdsh_inv[i][j]);

          for (k = 0; k < 4; k++)
            out[i][k] ^= tmp[k];

        }
    }
}


void __stdcall __export
decrypt (u8 * in)
{
  u8 t[4][4], u[4][4];
  int i, j, r;
  int n;
  for (r = i = 0; i < 2; i++)
    {
      for (j = 0; j < 4; j++, r++)
        {
          t[i][j] = in[r];
        }
    }
  n = MAX_ROUND-1;

  for (r = 0; r < n; r++)
    {
      hcryptL1_ixs (&t[0][0], &u[0][0], &dks[r][0][0], &dks[r][2][0]);
      hcryptL1_ixs (&t[1][0], &u[1][0], &dks[r][1][0], &dks[r][3][0]);
      hcryptL1_imdsh (u, t);
    }

  hcryptL1_ixs (&t[0][0], &u[0][0], &dks[r][0][0], &dks[n][2][0]);
  hcryptL1_ixs (&t[1][0], &u[1][0], &dks[r][1][0], &dks[n][3][0]);

  for (r = i = 0; i < 2; i++)
    {
      for (j = 0; j < 4; j++, r++)
        {
          in[r] = u[i][j] ^ dks[n + 1][i][j];

        }
    }
}


void
hcryptL1_keyf (u8 * in, u8 * fout, u8 * fkey)
{
  int i;
  /* F in */
  for (i = 0; i < 4; i++)
    fout[i] = sbox[in[i] ^ fkey[i]];

  /* P (16) */

  fout[0] ^= fout[2];
  fout[1] ^= fout[3];
  fout[2] ^= fout[1];
  fout[3] ^= fout[0];
}


void
swap_key (u8 * l, u8 * r)
{
  u8 t;
  int i;
  for (i = 0; i < 4; i++)
    {
      t = l[i];
      l[i] = r[i];
      r[i] = t;
    }
}


void
hcryptL1_keyp (u8 k[4][4], u8 kout[4][4], int index)
{
  int i;
  u8 fout[4];
  /* P(16) */
  for (i = 0; i < 2; i++)
    {
      k[2][i] ^= k[3][i];
      k[2][i + 2] ^= k[3][i + 2];
    }
  for (i = 0; i < 2; i++)
    {
      k[3][i] ^= k[2][i + 2];
      k[3][i + 2] ^= k[2][i];
    }

  /* multiple */
  mdsh_mul (&k[2][0], &k[2][0], 0x5);
  mdsh_mul (&k[3][0], &k[3][0], 0xb);

  for (i = 0; i < 4; i++)
    k[2][i] ^= hconst[index][i];

  hcryptL1_keyf (&k[1][0], fout, &k[2][0]);

  for (i = 0; i < 4; i++)
    k[0][i] ^= fout[i];         /* L xor f(R) */

  for (i = 0; i < 4; i++)
    {
      kout[0][i] = k[0][i];

    }

  for (i = 0; i < 4; i++)
    {
      kout[1][i] = fout[i] ^ k[2][i];
    }

  for (i = 0; i < 4; i++)
    {
      kout[2][i] = fout[i] ^ k[3][i];
    }

  for (i = 0; i < 4; i++)
    {
      kout[3][i] = k[1][i] ^ k[3][i];
    }

  swap_key (&k[0][0], &k[1][0]);
}

void
hcryptL1_keyc (u8 k[4][4], u8 kout[4][4], int index)
{
  int i;
  u8 fout[4];
  swap_key (&k[0][0], &k[1][0]);
  hcryptL1_keyf (&k[1][0], fout, &k[2][0]);

  for (i = 0; i < 4; i++)
    k[0][i] ^= fout[i];

  for (i = 0; i < 4; i++)
    {
      kout[0][i] = k[0][i] ^ k[2][i];
    }

  for (i = 0; i < 4; i++)
    k[2][i] ^= hconst[index][i];


  mdsh_mul (&k[2][0], &k[2][0], 0xb);
  mdsh_mul (&k[3][0], &k[3][0], 0x5);

  for (i = 0; i < 4; i++)
    {
      kout[1][i] = fout[i] ^ k[2][i];
    }

  for (i = 0; i < 4; i++)
    {
      kout[2][i] = fout[i] ^ k[3][i];
    }

  for (i = 0; i < 4; i++)
    {
      kout[3][i] = k[1][i] ^ k[3][i];
    }


  for (i = 0; i < 2; i++)
    {
      k[3][i] ^= k[2][i + 2];
      k[3][i + 2] ^= k[2][i];
    }  

  for (i = 0; i < 2; i++)
    {
      k[2][i] ^= k[3][i];
      k[2][i + 2] ^= k[3][i + 2];
    }
}


void __stdcall __export
setup (u8 * key)
{
  u8 k[4][4];
  u8 fout[4];
  int i, j, pos, r, n;

  pos = 0;
  for (i = 0; i < 4; i++)
    for (j = 0; j < 4; j++)
      k[i][j] = key[pos++];


  mdsh_mul (&k[2][0], &k[2][0], 0x5);
  mdsh_mul (&k[3][0], &k[3][0], 0xb);

  for (i = 0; i < 4; i++)
    k[2][i] ^= hconst[0][i];

  hcryptL1_keyf (&k[1][0], fout, &k[2][0]);

  for (i = 0; i < 4; i++)
    k[0][i] ^= fout[i];         /*L+f(R) */

  swap_key (&k[0][0], &k[1][0]);

  for (r = 0; r < 4; r++)
    hcryptL1_keyp (&k[0], &ks[r][0], hindex[r]);

  for (r = 4; r < 7; r++)
    hcryptL1_keyc (&k[0], &ks[r][0], hindex[r]);

  r = MAX_ROUND;

  for (j = 0; j < 2; j++)
    {
      for (n = 0; n < 4; n++)
        {
          dks[0][j][n] = ks[r][j][n];
        }
    }

  for (i = 1; i < r; i++)
    {
      for (j = 2; j < 4; j++)
        {
          hcryptL1_imdsl (&ks[r - i][j][0], &dks[i - 1][j][0]);
        }
      hcryptL1_imdsh (&ks[r - i][0], &dks[i][0]);
    }

  for (j = 2; j < 4; j++)
    {
      hcryptL1_imdsl (&ks[0][j][0], &dks[r - 1][j][0]);
    }

  for (j = 0; j < 2; j++)
    {
      for (n = 0; n < 4; n++)
        {
          dks[r][j][n] = ks[0][j][n];
        }
    }



}




#include <string.h>


u32 __stdcall __export
getblocksize ()
{
  return 64;
}

u32 __stdcall __export
getkeysize ()
{
  return 128;
}

void __stdcall __export
getciphername (u8 * p)
{
  strcpy (p, "Hierocrypt-L1");
}

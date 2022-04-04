/*
The Keccak sponge function, designed by Guido Bertoni, Joan Daemen,
Michaël Peeters and Gilles Van Assche. For more information, feedback or
questions, please refer to our website: http://keccak.noekeon.org/

Implementation by Ronny Van Keer,
hereby denoted as "the implementer".

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#include "Keccak-simple-settings.h"
#define cKeccakR_SizeInBytes    (cKeccakR / 8)
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#if defined(__GNUC__)
#define ALIGN __attribute__ ((aligned(32)))
#elif defined(_MSC_VER)
#define ALIGN __declspec(align(32))
#else
#define ALIGN
#endif

#if        (cKeccakB    == 1600) && (cKeccakR == 1024)
    const char *    testVectorFile = "ShortMsgKAT_0.txt";
#elif    (cKeccakB    == 1600) && (cKeccakR == 1152) && (cKeccakFixedOutputLengthInBytes == 28)
    const char *    testVectorFile = "ShortMsgKAT_224.txt";
#elif    (cKeccakB    == 1600) && (cKeccakR == 1088) && (cKeccakFixedOutputLengthInBytes == 32)
    const char *    testVectorFile = "ShortMsgKAT_256.txt";
#elif    (cKeccakB    == 1600) && (cKeccakR == 832) && (cKeccakFixedOutputLengthInBytes == 48)
    const char *    testVectorFile = "ShortMsgKAT_384.txt";
#elif    (cKeccakB    == 1600) && (cKeccakR == 576) && (cKeccakFixedOutputLengthInBytes == 64)
    const char *    testVectorFile = "ShortMsgKAT_512.txt";
#elif    (cKeccakB    == 1600) && (cKeccakR == 1344)
    const char *    testVectorFile = "ShortMsgKAT_r1344c256.txt";
#elif    (cKeccakB    == 800) && (cKeccakR == 544)
    const char *    testVectorFile = "ShortMsgKAT_r544c256.txt";
#elif    (cKeccakB    == 800) && (cKeccakR == 512)
    const char *    testVectorFile = "ShortMsgKAT_r512c288.txt";
#elif    (cKeccakB    == 800) && (cKeccakR == 256)
    const char *    testVectorFile = "ShortMsgKAT_r256c544.txt";
#elif    (cKeccakB    == 400) && (cKeccakR == 144)
    const char *    testVectorFile = "ShortMsgKAT_r144c256.txt";
#elif    (cKeccakB    == 400) && (cKeccakR == 128)
    const char *    testVectorFile = "ShortMsgKAT_r128c272.txt";
#elif    (cKeccakB    == 200) && (cKeccakR == 40)
    const char *    testVectorFile = "ShortMsgKAT_r40c160.txt";
#else
#error "Please set the vector file name here."
#endif

#define    cKeccakMaxMessageSizeInBytes    (2047/8)

ALIGN unsigned char input[cKeccakMaxMessageSizeInBytes];
ALIGN unsigned char output[cKeccakR_SizeInBytes];

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
#define MAX_MARKER_LEN      50

typedef unsigned char BitSequence;

int FindMarker(FILE *infile, const char *marker);
int FindMarker(FILE *infile, const char *marker)
{
    char    line[MAX_MARKER_LEN];
    int     i, len;

    len = (int)strlen(marker);
    if ( len > MAX_MARKER_LEN-1 )
        len = MAX_MARKER_LEN-1;

    for ( i=0; i<len; i++ )
        if ( (line[i] = fgetc(infile)) == EOF )
            return 0;
    line[len] = '\0';

    while ( 1 ) {
        if ( !strncmp(line, marker, len) )
            return 1;

        for ( i=0; i<len-1; i++ )
            line[i] = line[i+1];
        if ( (line[len-1] = fgetc(infile)) == EOF )
            return 0;
        line[len] = '\0';
    }

    // shouldn't get here
    return 0;
}

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int ReadHex(FILE *infile, BitSequence *A, int Length, char *str);
int ReadHex(FILE *infile, BitSequence *A, int Length, char *str)
{
    int         i, ch, started;
    BitSequence ich;

    if ( Length == 0 ) {
        A[0] = 0x00;
        return 1;
    }
    memset(A, 0x00, Length);
    started = 0;
    i = 0;
    if ( FindMarker(infile, str) )
        while ( (ch = fgetc(infile)) != EOF ) 
        {
            if ( !isxdigit(ch) ) {
                if ( !started ) {
                    if ( ch == '\n' )
                        break;
                    else
                        continue;
                }
                else
                    break;
            }
            started = 1;
            if ( (ch >= '0') && (ch <= '9') )
                ich = ch - '0';
            else if ( (ch >= 'A') && (ch <= 'F') )
                ich = ch - 'A' + 10;
            else if ( (ch >= 'a') && (ch <= 'f') )
                ich = ch - 'a' + 10;

            A[i / 2] = (A[i / 2] << 4) | ich;
            if ( (++i / 2) == Length )
                break;
        }
    else
        return 0;

    return 1;
}

int main( void )
{
    unsigned long long    inlen;
    int                    result = 0;
    FILE                *fp_in;
    char                marker[20];
    int                    refLen;

#ifdef cKeccakFixedOutputLengthInBytes
    refLen = cKeccakFixedOutputLengthInBytes;
#else
    refLen = cKeccakR_SizeInBytes;
#endif

    printf( "Testing Keccak[r=%u, c=%u] against %s over %d squeezed bytes\n", cKeccakR, cKeccakB - cKeccakR, testVectorFile, refLen );
    if ( (fp_in = fopen(testVectorFile, "r")) == NULL ) 
    {
        printf("Couldn't open <%s> for read\n", testVectorFile);
        return 1;
    }

    for ( inlen = 0; inlen <= cKeccakMaxMessageSizeInBytes; ++inlen )
    {
        sprintf( marker, "Len = %u", inlen * 8 );
        if ( !FindMarker(fp_in, marker) )
        {
            printf("ERROR: no test vector found (%u bytes)\n", inlen );
            result = 1;
            break;
        }
        if ( !ReadHex(fp_in, input, (int)inlen, "Msg = ") ) 
        {
            printf("ERROR: unable to read 'Msg' (%u bytes)\n", inlen );
            result = 1;
            break;
        }

        result = crypto_hash( output, input, inlen );
        if ( result != 0 )
        {
            printf("ERROR: crypto_hash() (%u bytes)\n", inlen);
            result = 1;
            break;
        }

        #ifdef cKeccakFixedOutputLengthInBytes
        if ( !ReadHex(fp_in, input, refLen, "MD = ") )
        #else
        if ( !ReadHex(fp_in, input, refLen, "Squeezed = ") )
        #endif
        {
            printf("ERROR: unable to read 'Squeezed/MD' (%u bytes)\n", inlen );
            result = 1;
            break;
        }
        if ( memcmp( output, input, refLen ) != 0) 
        {
            printf("ERROR: hash verification (%u bytes)\n", inlen );
            for(result=0; result<refLen; result++)
                printf("%02X ", output[result]);
            printf("\n");
            result = 1;
            break;
        }
    }

    fclose( fp_in );
    if ( !result )
        printf( "\nSuccess!\n");

    //printf( "\nPress a key ...");
    //getchar();
    //printf( "\n");
    return ( result );
}



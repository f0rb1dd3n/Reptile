#ifndef _AES_H
#define _AES_H

#ifndef uint8
#define uint8  unsigned char
#endif

#ifndef uint32
#define uint32 unsigned long int
#endif

struct aes_context
{
    int nr;             /* number of rounds */
    uint32 erk[64];     /* encryption round keys */
    uint32 drk[64];     /* decryption round keys */
};

int  aes_set_key( struct aes_context *ctx, uint8 *key, int nbits );
void aes_encrypt( struct aes_context *ctx, uint8 data[16] );
void aes_decrypt( struct aes_context *ctx, uint8 data[16] );

#endif /* aes.h */

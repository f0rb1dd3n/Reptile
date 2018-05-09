#ifndef _SHA1_H
#define _SHA1_H

#ifndef uint8
#define uint8  unsigned char
#endif

#ifndef uint32
#define uint32 unsigned long int
#endif

struct sha1_context
{
    uint32 total[2];
    uint32 state[5];
    uint8 buffer[64];
};

void sha1_starts( struct sha1_context *ctx );
void sha1_update( struct sha1_context *ctx, uint8 *input, uint32 length );
void sha1_finish( struct sha1_context *ctx, uint8 digest[20] );

#endif /* sha1.h */

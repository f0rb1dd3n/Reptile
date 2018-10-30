#ifndef __LOADER_H__
#define __LOADER_H__

#define do_encrypt(ptr, len, key)	do_encode(ptr, len, key)
#define do_decrypt(ptr, len, key)	do_encode(ptr, len, key)

static inline unsigned int custom_rol32(unsigned int val, int n)
{
	return ((val << n) | (val >> (32 - n)));
}

static inline void do_encode(void *ptr, unsigned int len, unsigned int key)
{
	while (len > sizeof(key)) {
		*(unsigned int *)ptr ^= custom_rol32(key ^ len, (len % 13));
		len -= sizeof(key), ptr += sizeof(key);
	}
}

#endif

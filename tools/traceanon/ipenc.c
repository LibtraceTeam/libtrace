#include "config.h"
#include "ipenc.h"
#include "panon.h"
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#ifndef HAVE_STRLCPY
static size_t strlcpy(char *dest, const char *src, size_t size)
{
	size_t ret;
	for(ret=0;src[ret] && ret<size; ret++) {
		dest[ret]=src[ret];
	}
	dest[ret++]='\0';
	return ret;
}
#endif

static enum enc_type_t enc_type = ENC_NONE;

static uint32_t masks[33] = {
		0x00000000, 0x80000000, 0xC0000000, 0xe0000000, 0xf0000000,
		0xf8000000, 0xfC000000, 0xfe000000, 0xff000000, 0xff800000,
		0xffC00000, 0xffe00000, 0xfff00000, 0xfff80000, 0xfffC0000,
		0xfffe0000, 0xffff0000, 0xffff8000, 0xffffC000, 0xffffe000,
		0xfffff000, 0xfffff800, 0xfffffC00, 0xfffffe00, 0xffffff00,
		0xffffff80, 0xffffffC0, 0xffffffe0, 0xfffffff0, 0xfffffff8,
		0xfffffffC, 0xfffffffe, 0xffffffff,
};

static uint32_t prefix;
static uint32_t netmask;
static void init_prefix(const char *key)
{
	int a,b,c,d;
	int bits;
	sscanf(key,"%i.%i.%i.%i/%i",
			&a, &b, &c, &d, &bits);
	prefix=(a<<24) + (b<<16) + (c<<8) + d;
	assert(bits>=0 && bits<=32);
	netmask = masks[bits];
}

static uint32_t prefix_substitute(uint32_t ip)
{
	return (prefix & netmask) | (ip & ~netmask);
}

void enc_init(enum enc_type_t type, char *key)
{
	char cryptopan_key[32];
	memset(cryptopan_key,0,sizeof(cryptopan_key));
	enc_type = type;
	switch (enc_type) {
		case ENC_NONE:
			break;
		case ENC_PREFIX_SUBSTITUTION:
			init_prefix(key);
			break;
		case ENC_CRYPTOPAN:
			strlcpy(cryptopan_key,key,sizeof(cryptopan_key));
			panon_init(cryptopan_key);
			break;
		default:
			assert(0 /* unknown encryption type */);
			_exit(1);
	}
}

uint32_t enc_ip(uint32_t orig_addr) 
{
	switch (enc_type) {
		case ENC_NONE:
			return orig_addr;
		case ENC_PREFIX_SUBSTITUTION:
			return prefix_substitute(orig_addr);
		case ENC_CRYPTOPAN:
			return cpp_anonymize(orig_addr);
		default:
			assert(0 /* unknown encryption type */);
			_exit(1);
	}
}

#ifndef _PANON_H_
#define _PANON_H_

/* $Id$ */

#include "rijndael.h"
#include <inttypes.h>

uint32_t anonymize( const uint32_t orig_addr );
uint32_t pp_anonymize( const uint32_t orig_addr );
uint32_t cpp_anonymize( const uint32_t orig_addr );
void panon_init_decrypt(const uint8_t * key);
void panon_init(const char * key);
void panon_init_cache(void); 
#endif 

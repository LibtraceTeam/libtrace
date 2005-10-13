#ifndef IPENC_H
#define IPENC_H
#include <inttypes.h>
/** The encryption algorithm used
 */
enum enc_type_t {
	ENC_NONE,			/**< No encryption */
	ENC_PREFIX_SUBSTITUTION,	/**< Substitute a prefix */
	ENC_CRYPTOPAN			/**< Prefix preserving encryption */
	};
void enc_init(enum enc_type_t type, char *key);
uint32_t enc_ip(uint32_t orig_addr);
#endif

#ifndef LIB_H
#define LIB_H
#include <inttypes.h>
#include <libtrace.h>

/** The encryption algorithm used
 */
enum enc_type_t {
	ENC_NONE,			/**< No encryption */
	ENC_PREFIX_SUBSTITUTION,	/**< Substitute a prefix */
	ENC_CRYPTOPAN			/**< Prefix preserving encryption */
	};

/** File type to write
 */
enum trace_format_t {
	TRACE_FORMAT_ERF,		/**< ERF format */
	TRACE_FORMAT_PCAP,		/**< PCAP format */
};

/** (re)initialise the IP encryption module
 * @param type The encryption type
 * @param key a key (format dependant on the type of key)
 *
 * @note calling this function clears the cache.
 */
void trace_enc_init(enum enc_type_t type,char *key);

/** encrypt one IP address
 * @param orig_addr the original IP address in HOST byte order
 * @returns the encrypted IP in HOST byte order
 *
 * @note: requires you to have called trace_enc_init() first
 */
uint32_t trace_enc_ip(uint32_t orig_addr);

#endif

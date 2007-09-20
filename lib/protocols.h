/* These are protocol decoders that haven't yet seen enough use to consider
 * their API stable enough to move into libtrace.h where they probably belong
 *
 * These API's are not stable enough to be exported from libtrace and used
 * by user code
 *
 * These are generally used by the next higher level, so really we should
 * be defining API's that mean that these don't need to be known by the
 * higher level.
 */

/* pkt meta headers */

/* l2 headers */
void *trace_get_mpls_payload_from_ethernet_payload(void *ethernet,
		uint16_t *type, uint32_t *remaining);
void *trace_get_payload_from_ethernet(void *ethernet, 
		uint16_t *type,
		uint32_t *remaining);
/* l3 definitions */
struct ports_t {
	uint16_t src;
	uint16_t dst;
};



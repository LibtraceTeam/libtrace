#include "lib.h"
#include <assert.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	trace_enc_init(ENC_NONE,"");
	printf("none     : %08x\n",trace_enc_ip  (0x7f000001));
	assert( trace_enc_ip( 0x7f000001) == 0x7f000001);

	trace_enc_init(ENC_PREFIX_SUBSTITUTION,"10.10.0.0/16");
	printf("prefix   : %08x\n",trace_enc_ip (0x7f000001));
	assert( trace_enc_ip( 0x7f000001) == 0x0a0a0001);

	printf("prefix   : %08x\n",trace_enc_ip (0x12345678));
	assert( trace_enc_ip( 0x12345678) == 0x0a0a5678);

	trace_enc_init(ENC_CRYPTOPAN,"swordfish");
	printf("cryptopan: %08x\n",trace_enc_ip (0x7f000001));
	assert( trace_enc_ip( 0x7f000001) == 0x9eff7fe1);
	return 0;
}

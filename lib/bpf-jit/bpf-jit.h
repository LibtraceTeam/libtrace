#include <pcap.h>
#include <pcap-bpf.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef unsigned int (*bpf_run_t)(unsigned char *packet, unsigned int length);

typedef struct bpf_jit_t {
	bpf_run_t bpf_run;
} bpf_jit_t;

bpf_jit_t *compile_program(struct bpf_insn insns[], int plen);
void destroy_program(struct bpf_jit_t *bpf_jit);

#ifdef __cplusplus
}
#endif


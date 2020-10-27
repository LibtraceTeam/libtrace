/*
 *
 * Copyright (c) 2007-2016 The University of Waikato, Hamilton, New Zealand.
 * All rights reserved.
 *
 * This file is part of libtrace.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libtrace is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libtrace is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *
 */


/*
 * This file is not linked into libtrace in the normal way you would expect.
 *
 * It is passed to llvm-gcc, which generates .bc, and then through llc which
 * generates a .cc file of the llvm code to /generate/ this file.  This is
 * then included into bpf-jit.
 */
#include <inttypes.h>
#include <arpa/inet.h>
#define MEMLEN 16

typedef struct bpf_state_t {
	unsigned int A;
	unsigned int X;
	const unsigned char *P;
	uint32_t len;
	unsigned int mem[MEMLEN];
} bpf_state_t;

#define OPCODE(name) \
static unsigned int name(bpf_state_t *state, unsigned char jt, unsigned char jf, unsigned long k)

#define P_WORD(x)  ntohl(*(uint32_t*)&state->P[x])
#define P_HWORD(x) ntohs(*(uint16_t*)&state->P[x])
#define P_BYTE(x) (state->P[(x)])

OPCODE(bpf_ldw_abs) { 
	if (k+3>=state->len)
		return 0;	/* Read past end of packet: Fail */
	state->A = P_WORD(k); 
	return ~0U;
}
OPCODE(bpf_ldh_abs) { 
	if (k+1>=state->len)
		return 0;
	state->A = P_HWORD(k); 
	return ~0U;
}
OPCODE(bpf_ldb_abs) { 
	if (k>=state->len)
		return 0;
	state->A = P_BYTE(k); 
	return ~0U;
}
OPCODE(bpf_ldw_ind) { 
	if (k+state->X+3 >= state->len)
		return 0;
	state->A = P_WORD(k+state->X); 
	return ~0U;
}
OPCODE(bpf_ldh_ind) { 
	if (k+state->X+1 >= state->len)
		return 0;
	state->A = P_HWORD(k+state->X); 
	return ~0U;
}
OPCODE(bpf_ldb_ind) { 
	if (k+state->X >= state->len)
		return 0;
	state->A = P_BYTE(k+state->X); 
	return ~0U;
}
OPCODE(bbf_ldw_ind) { state->A = state->len; return ~0;}
OPCODE(bpf_ld_imm)  { state->A = k; return ~0;}
OPCODE(bpf_ld_mem)  { 
	if (k>=MEMLEN)
		return 0; /* Fail Immediately */
	state->A = state->mem[k]; 
	return ~0;
}

OPCODE(bpf_ldx_imm) { state->X = k; return ~0;}
OPCODE(bpf_ldx_mem) { 
	if (k>=MEMLEN)
		return 0; /* Fail Immediately */
	state->X = state->mem[k]; 
	return ~0;
}
OPCODE(bpf_ldx_len) { state->X = state->len; return ~0;}
OPCODE(bpf_ldx_msh) { 
	if (k>=state->len)
		return 0; /* Read past end of packet: Fail */
	state->X = 4*(P_BYTE(k)&0x0F); 
	return ~0;
}

OPCODE(bpf_sd) { 
	if (k>=MEMLEN)
		return 0; /* Fail Immediately */
	state->mem[k] = state->A; 
	return ~0;
}
OPCODE(bpf_sdx) { 
	if (k>=MEMLEN)
		return 0; /* Fail Immediately */
	state->mem[k] = state->X; 
	return ~0;
}

OPCODE(bpf_alu_add_k) { state->A += k; return ~0;}
OPCODE(bpf_alu_sub_k) { state->A -= k; return ~0;}
OPCODE(bpf_alu_mul_k) { state->A *= k; return ~0;}
OPCODE(bpf_alu_div_k) { state->A /= k; return ~0;}
OPCODE(bpf_alu_and_k) { state->A &= k; return ~0;}
OPCODE(bpf_alu_or_k)  { state->A |= k; return ~0;}
OPCODE(bpf_alu_lsh_k) { state->A = state->A << k; return ~0;}
OPCODE(bpf_alu_rsh_k) { state->A = state->A >> k; return ~0;}
OPCODE(bpf_alu_neg) { state->A = -state->A; return ~0;}

OPCODE(bpf_alu_add_x) { state->A += state->X; return ~0;}
OPCODE(bpf_alu_sub_x) { state->A -= state->X; return ~0;}
OPCODE(bpf_alu_mul_x) { state->A *= state->X; return ~0;}
OPCODE(bpf_alu_div_x) { state->A /= state->X; return ~0;}
OPCODE(bpf_alu_and_x) { state->A &= state->X; return ~0;}
OPCODE(bpf_alu_or_x)  { state->A |= state->X; return ~0;}
OPCODE(bpf_alu_lsh_x) { state->A = state->A << state->X; return ~0;}
OPCODE(bpf_alu_rsh_x) { state->A = state->A >> state->X; return ~0;}

/* These are created by code
OPCODE(bpf_ja)    { state->pc += k; return ~0;}
OPCODE(bpf_gt_k)  { state->pc += (state->A > k) ? jt : jf; return ~0;}
OPCODE(bpf_ge_k)  { state->pc += (state->A >= k) ? jt : jf; return ~0;}
OPCODE(bpf_eq_k)  { state->pc += (state->A == k) ? jt : jf; return ~0;}
OPCODE(bpf_set_k) { state->pc += (state->A & k) ? jt : jf; return ~0;}
OPCODE(bpf_gt_x)  { state->pc += (state->A > state->X) ? jt : jf; return ~0;}
OPCODE(bpf_ge_x)  { state->pc += (state->A >= state->X) ? jt : jf; return ~0;}
OPCODE(bpf_eq_x)  { state->pc += (state->A == state->X) ? jt : jf; return ~0;}
OPCODE(bpf_set_x) { state->pc += (state->A & state->X) ? jt : jf; return ~0;}
*/

OPCODE(bpf_ret_a) { return state->A; }
OPCODE(bpf_ret_k) { return k; }

OPCODE(bpf_tax) { state->X = state->A; return ~0; }
OPCODE(bpf_txa) { state->A = state->X; return ~0; }


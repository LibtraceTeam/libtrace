#define OPTIMISE 1
#define OUTPUT_COMPILED 0

#include "bpf-jit/bpf-jit.h"
#include <llvm/LLVMContext.h>
namespace llvm {
class LLVMContext;
LLVMContext *libtraceContext;
}
#define getGlobalContext() (*libtraceContext)
#include <llvm/Module.h>
#include <llvm/DerivedTypes.h>
#include <llvm/Constants.h>
#include <llvm/Instructions.h>
#include <llvm/ModuleProvider.h>
#include <llvm/Analysis/Verifier.h>
#include <llvm/ExecutionEngine/JIT.h>
#include <llvm/ExecutionEngine/Interpreter.h>
#include <llvm/ExecutionEngine/GenericValue.h>

#include <llvm/CallingConv.h>
#include <llvm/PassManager.h>
#include <llvm/Support/StandardPasses.h>
#include <llvm/Target/TargetData.h>
#include <llvm/Target/TargetSelect.h>
#ifdef OUTPUT_COMPILED
#include <llvm/Assembly/PrintModulePass.h>
#include <llvm/Support/FormattedStream.h>
#endif
#include <llvm/LinkAllPasses.h>

#include <iostream>
#include <algorithm>
#include <map>
#include <stdarg.h>

#include <pcap-bpf.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <boost/lexical_cast.hpp>


using namespace llvm;

#include "bpf-jit/bpf-opcodes.llvm.cc"

static const char *opcode_names[256];

template <class X>
static std::vector<X> construct_vector(int items, ...)
{
	std::vector<X> ret;
	va_list va;
	va_start(va,items);
	for(int i=0;i<items;++i) {
		ret.push_back(va_arg(va,X));
	}
	va_end(va);
	return ret;
}

static void construct_jeq_k(Module *mod, int insnum, const struct bpf_insn &insn, 
		AllocaInst *ptr_state,
		std::map<int,BasicBlock *> &blocks)
{
	BasicBlock *this_block = blocks[insnum];
	BasicBlock *true_block = blocks[insnum+1+insn.jt];
	BasicBlock *false_block = blocks[insnum+1+insn.jf];

	std::vector<Value*> a_offsets = construct_vector<Value*>(2,
		ConstantInt::get(getGlobalContext(),APInt(32,0)),
		ConstantInt::get(getGlobalContext(),APInt(32,0))
	);

	Instruction *a = GetElementPtrInst::Create(ptr_state,
			a_offsets.begin(), a_offsets.end(), "state_a", this_block);

	ICmpInst *cmp = new ICmpInst(*this_block, ICmpInst::ICMP_EQ, 
				new LoadInst(a,"avalue", this_block),
				ConstantInt::get(getGlobalContext(), APInt(32, insn.k)),
				std::string("cmp_a_vs_")+boost::lexical_cast<std::string>(insn.k));

	BranchInst::Create(true_block, false_block, cmp, this_block);
}

static void construct_jgt_k(Module *mod, int insnum, const struct bpf_insn &insn, 
		AllocaInst *ptr_state,
		std::map<int,BasicBlock *> &blocks)
{
	BasicBlock *this_block = blocks[insnum];
	BasicBlock *true_block = blocks[insnum+1+insn.jt];
	BasicBlock *false_block = blocks[insnum+1+insn.jf];

	std::vector<Value*> a_offsets = construct_vector<Value*>(2,
		ConstantInt::get(getGlobalContext(),APInt(32,0)),
		ConstantInt::get(getGlobalContext(),APInt(32,0))
	);

	Instruction *a = GetElementPtrInst::Create(ptr_state,
			a_offsets.begin(), a_offsets.end(), "state_a", this_block);

	ICmpInst *cmp = new ICmpInst(*this_block, ICmpInst::ICMP_UGT, 
				new LoadInst(a,"avalue", this_block),
				ConstantInt::get(getGlobalContext(), APInt(32, insn.k)),
				"cmp_a_vs_k");

	BranchInst::Create(true_block, false_block, cmp, this_block);
}

static void construct_jge_k(Module *mod, int insnum, const struct bpf_insn &insn, 
		AllocaInst *ptr_state,
		std::map<int,BasicBlock *> &blocks)
{
	BasicBlock *this_block = blocks[insnum];
	BasicBlock *true_block = blocks[insnum+1+insn.jt];
	BasicBlock *false_block = blocks[insnum+1+insn.jf];

	std::vector<Value*> a_offsets = construct_vector<Value*>(2,
		ConstantInt::get(getGlobalContext(),APInt(32,0)),
		ConstantInt::get(getGlobalContext(),APInt(32,0))
	);

	Instruction *a = GetElementPtrInst::Create(ptr_state,
			a_offsets.begin(), a_offsets.end(), "state_a", this_block);

	ICmpInst *cmp = new ICmpInst(*this_block, ICmpInst::ICMP_UGE, 
				new LoadInst(a,"avalue", this_block),
				ConstantInt::get(getGlobalContext(), APInt(32, insn.k)),
				"cmp_a_vs_k");

	BranchInst::Create(true_block, false_block, cmp, this_block);
}

static void construct_jeq_x(Module *mod, int insnum, const struct bpf_insn &insn, 
		AllocaInst *ptr_state,
		std::map<int,BasicBlock *> &blocks)
{
	BasicBlock *this_block = blocks[insnum];
	BasicBlock *true_block = blocks[insnum+1+insn.jt];
	BasicBlock *false_block = blocks[insnum+1+insn.jf];

	std::vector<Value*> a_offsets = construct_vector<Value*>(2,
		ConstantInt::get(getGlobalContext(),APInt(32,0)),
		ConstantInt::get(getGlobalContext(),APInt(32,0))
	);

	std::vector<Value*> x_offsets = construct_vector<Value*>(2,
		ConstantInt::get(getGlobalContext(),APInt(32,0)),
		ConstantInt::get(getGlobalContext(),APInt(32,1))
	);

	Instruction *a = GetElementPtrInst::Create(ptr_state,
			a_offsets.begin(), a_offsets.end(), "state_a", this_block);

	Instruction *x = GetElementPtrInst::Create(ptr_state,
			x_offsets.begin(), x_offsets.end(), "state_x", this_block);

	ICmpInst *cmp = new ICmpInst(*this_block, ICmpInst::ICMP_EQ, 
				new LoadInst(a,"avalue", this_block),
				new LoadInst(x,"xvalue", this_block),
				"cmp_a_vs_x");

	BranchInst::Create(true_block, false_block, cmp, this_block);
}

static void construct_jgt_x(Module *mod, int insnum, const struct bpf_insn &insn, 
		AllocaInst *ptr_state,
		std::map<int,BasicBlock *> &blocks)
{
	BasicBlock *this_block = blocks[insnum];
	BasicBlock *true_block = blocks[insnum+1+insn.jt];
	BasicBlock *false_block = blocks[insnum+1+insn.jf];

	std::vector<Value*> a_offsets = construct_vector<Value*>(2,
		ConstantInt::get(getGlobalContext(),APInt(32,0)),
		ConstantInt::get(getGlobalContext(),APInt(32,0))
	);

	std::vector<Value*> x_offsets = construct_vector<Value*>(2,
		ConstantInt::get(getGlobalContext(),APInt(32,0)),
		ConstantInt::get(getGlobalContext(),APInt(32,1))
	);

	Instruction *a = GetElementPtrInst::Create(ptr_state,
			a_offsets.begin(), a_offsets.end(), "state_a", this_block);

	Instruction *x = GetElementPtrInst::Create(ptr_state,
			x_offsets.begin(), x_offsets.end(), "state_x", this_block);

	ICmpInst *cmp = new ICmpInst(*this_block, ICmpInst::ICMP_UGT, 
				new LoadInst(a,"avalue", this_block),
				new LoadInst(x,"xvalue", this_block),
				"cmp_a_vs_x");

	BranchInst::Create(true_block, false_block, cmp, this_block);
}

static void construct_jset_x(Module *mod, int insnum, const struct bpf_insn &insn, 
		AllocaInst *ptr_state,
		std::map<int,BasicBlock *> &blocks)
{
	BasicBlock *this_block = blocks[insnum];
	BasicBlock *true_block = blocks[insnum+1+insn.jt];
	BasicBlock *false_block = blocks[insnum+1+insn.jf];

	std::vector<Value*> a_offsets = construct_vector<Value*>(2,
		ConstantInt::get(getGlobalContext(),APInt(32,0)),
		ConstantInt::get(getGlobalContext(),APInt(32,0))
	);

	std::vector<Value*> x_offsets = construct_vector<Value*>(2,
		ConstantInt::get(getGlobalContext(),APInt(32,0)),
		ConstantInt::get(getGlobalContext(),APInt(32,1))
	);

	Instruction *a = GetElementPtrInst::Create(ptr_state,
			a_offsets.begin(), a_offsets.end(), "state_a", this_block);

	Instruction *x = GetElementPtrInst::Create(ptr_state,
			x_offsets.begin(), x_offsets.end(), "state_x", this_block);

	BinaryOperator* band = BinaryOperator::Create(Instruction::And, 
				new LoadInst(a,"valuea_", this_block),
				new LoadInst(a,"valuex_", this_block),
				"and_a_and_x_",
				this_block
				);

	ICmpInst *cmp = new ICmpInst(*this_block, ICmpInst::ICMP_EQ, 
				band,
				ConstantInt::get(getGlobalContext(), APInt(32, 0)),
				"cmp_a_and_x");

	BranchInst::Create(true_block, false_block, cmp, this_block);
}

static void construct_jge_x(Module *mod, int insnum, const struct bpf_insn &insn, 
		AllocaInst *ptr_state,
		std::map<int,BasicBlock *> &blocks)
{
	BasicBlock *this_block = blocks[insnum];
	BasicBlock *true_block = blocks[insnum+1+insn.jt];
	BasicBlock *false_block = blocks[insnum+1+insn.jf];

	std::vector<Value*> a_offsets = construct_vector<Value*>(2,
		ConstantInt::get(getGlobalContext(),APInt(32,0)),
		ConstantInt::get(getGlobalContext(),APInt(32,0))
	);

	std::vector<Value*> x_offsets = construct_vector<Value*>(2,
		ConstantInt::get(getGlobalContext(),APInt(32,0)),
		ConstantInt::get(getGlobalContext(),APInt(32,1))
	);

	Instruction *a = GetElementPtrInst::Create(ptr_state,
			a_offsets.begin(), a_offsets.end(), "state_a", this_block);

	Instruction *x = GetElementPtrInst::Create(ptr_state,
			x_offsets.begin(), x_offsets.end(), "state_x", this_block);

	ICmpInst *cmp = new ICmpInst(*this_block, ICmpInst::ICMP_UGE, 
				new LoadInst(a,"avalue", this_block),
				new LoadInst(x,"xvalue", this_block),
				"cmp_a_vs_x");

	BranchInst::Create(true_block, false_block, cmp, this_block);
}

Module* build_bpf_program(struct bpf_insn insns[], int plen) 
{
  // Module Construction
  Module* mod = makeLLVMModule();
  
  FunctionType* memsetType = FunctionType::get(
    /*Result=*/Type::getVoidTy(getGlobalContext()),
    		construct_vector<const Type*>(5,
			PointerType::get(IntegerType::get(getGlobalContext(), 8), 0), /*dest*/
			IntegerType::get(getGlobalContext(), 8),  /* i8 val */
			IntegerType::get(getGlobalContext(), 64), /* i64 len */
			IntegerType::get(getGlobalContext(), 32), /* i32 align */
			IntegerType::get(getGlobalContext(), 1)  /* i1 volatile */
			),
    /*isVarArg=*/false);
  
  // Function Declarations
  
  Function* func_bpf_run = Function::Create(
    /*Type=*/FunctionType::get(
    	IntegerType::get(getGlobalContext(), 32),
	construct_vector<const Type*>(2,
		PointerType::get(IntegerType::get(getGlobalContext(), 8), 0),
		IntegerType::get(getGlobalContext(), 32)),
		false),
    /*Linkage=*/GlobalValue::ExternalLinkage,
    /*Name=*/"bpf_run", mod); 
  func_bpf_run->setCallingConv(CallingConv::C);
  AttrListPtr func_bpf_run_PAL;
  {
    SmallVector<AttributeWithIndex, 4> Attrs;
    AttributeWithIndex PAWI;
    PAWI.Index = 4294967295U; PAWI.Attrs = 0  | Attribute::NoUnwind;
    Attrs.push_back(PAWI);
    func_bpf_run_PAL = AttrListPtr::get(Attrs.begin(), Attrs.end());
    
  }
  func_bpf_run->setAttributes(func_bpf_run_PAL);

  Function* func_llvm_memset_i64 = Function::Create(
    /*Type=*/memsetType,
    /*Linkage=*/GlobalValue::ExternalLinkage,
    /*Name=*/"llvm.memset.i64", mod); // (external, no body)
  func_llvm_memset_i64->setCallingConv(CallingConv::C);
  AttrListPtr func_llvm_memset_i64_PAL;
  {
    SmallVector<AttributeWithIndex, 4> Attrs;
    AttributeWithIndex PAWI;
    PAWI.Index = 1U; PAWI.Attrs = 0  | Attribute::NoCapture;
    Attrs.push_back(PAWI);
    PAWI.Index = 4294967295U; PAWI.Attrs = 0  | Attribute::NoUnwind;
    Attrs.push_back(PAWI);
    func_llvm_memset_i64_PAL = AttrListPtr::get(Attrs.begin(), Attrs.end());
    
  }
  func_llvm_memset_i64->setAttributes(func_llvm_memset_i64_PAL);
  
  
  // Global Variable Declarations

  
  // Constant Definitions
  ConstantInt* const_int8_12 = ConstantInt::get(getGlobalContext(), APInt(8,  StringRef("0"), 10));
  ConstantInt* const_int64_13 = ConstantInt::get(getGlobalContext(), APInt(64,  StringRef("1056"), 10));
  ConstantInt* const_int32_14 = ConstantInt::get(getGlobalContext(), APInt(32,  StringRef("8"), 10));
  ConstantInt* const_int1_false = ConstantInt::get(getGlobalContext(), APInt(1,  StringRef("0"), 10));
  
  // Function: bpf_run (func_bpf_run)
  {
    Function::arg_iterator args = func_bpf_run->arg_begin();
    Value* ptr_packet = args++;
    ptr_packet->setName("packet");
    Value* int32_len = args++;
    int32_len->setName("len");
    
    BasicBlock* label_entry = BasicBlock::Create(getGlobalContext(), "entry",func_bpf_run,0);
    
    // Block entry (label_entry)
/* Create function variables */
    AllocaInst* ptr_packet_addr = new AllocaInst(
    	PointerType::get(IntegerType::get(getGlobalContext(), 8), 0), "packet_addr", label_entry);
    AllocaInst* ptr_len_addr = new AllocaInst(IntegerType::get(getGlobalContext(), 32), "len_addr", label_entry);
    AllocaInst* ptr_retval = new AllocaInst(IntegerType::get(getGlobalContext(), 32), "retval", label_entry);
    AllocaInst* ptr_state = new AllocaInst(mod->getTypeByName(std::string("struct.bpf_state_t")),
    				 "state", label_entry);
/* Store the arguments */
     new StoreInst(ptr_packet, ptr_packet_addr, false, label_entry);
     new StoreInst(int32_len, ptr_len_addr, false, label_entry);
/* Memset state */
    CastInst* ptr_state1 = new BitCastInst(ptr_state, 
		PointerType::get(IntegerType::get(getGlobalContext(), 8), 0),
		"state1", label_entry);
    std::vector<Value*> void_25_params;
    void_25_params.push_back(ptr_state1);	/* dest */
    void_25_params.push_back(const_int8_12);	/* value */
    void_25_params.push_back(const_int64_13);	/* length */
    void_25_params.push_back(const_int32_14);	/* alignment */
    void_25_params.push_back(const_int1_false);	/* volatile */
    CallInst* void_25 = CallInst::Create(func_llvm_memset_i64, 
    		void_25_params.begin(), void_25_params.end(), 
		"", 
		label_entry);
    void_25->setCallingConv(CallingConv::C);
    void_25->setTailCall(false);
    AttrListPtr void_25_PAL;
    void_25->setAttributes(void_25_PAL);
 
 /* set state->P */
    std::vector<Value*> state_p_offset = construct_vector<Value*>(2, 
		ConstantInt::get(getGlobalContext(),APInt(32,0)),
		ConstantInt::get(getGlobalContext(),APInt(32,2)));

    Instruction* state_p_ptr = GetElementPtrInst::Create(ptr_state, 
    	state_p_offset.begin(), 
	state_p_offset.end(), "state_p_ptr", 
	label_entry);

    new StoreInst(new LoadInst(ptr_packet_addr, "load_ptr_packet_addr", false, label_entry), 
    	state_p_ptr, false, label_entry);

 /* set state->len */
    std::vector<Value*> state_len_offset = construct_vector<Value*>(2, 
		ConstantInt::get(getGlobalContext(),APInt(32,0)),
		ConstantInt::get(getGlobalContext(),APInt(32,3)));
    Instruction* state_len_ptr = GetElementPtrInst::Create(ptr_state, state_len_offset.begin(), state_len_offset.end(), "state_len_ptr", label_entry);
     new StoreInst(new LoadInst(ptr_len_addr, "len", false, label_entry), state_len_ptr, false, label_entry);
    
    // Build one block per bpf instruction in our program
    std::map<int, BasicBlock *> blocks;
    BasicBlock *fail = BasicBlock::Create(getGlobalContext(), "fail", func_bpf_run, 0);
    BasicBlock *success = BasicBlock::Create(getGlobalContext(), "success", func_bpf_run, 0);
    for(int i=0; i<plen; ++i) {
    	    char name[32];
	    sprintf(name,"bpf_isn_%d",i);
	    blocks.insert(std::make_pair(i, 
	    	BasicBlock::Create(getGlobalContext(), std::string(name), func_bpf_run, 0)));
    }

    BranchInst::Create(blocks[0], label_entry);

    // For each opcode, generate a call to the opcode that implements that function
    // check if the function returns "continue" (~0U) "fail" (0) or "success" (other wise)
    for(int i=0; i<plen; ++i) {
	    BasicBlock *this_block = blocks[i];
	    BasicBlock *next_block;
	    if (blocks.find(i+1) != blocks.end()) 
		    next_block = blocks[i+1];
	    else
		    next_block = fail;

	    switch (insns[i].code) {
		    case BPF_JMP+BPF_JGE+BPF_K:
		    	construct_jge_k(mod,i,insns[i],ptr_state,blocks);
			break;

		    case BPF_JMP+BPF_JEQ+BPF_K:
		    	construct_jeq_k(mod,i,insns[i],ptr_state,blocks);
			break;

		    case BPF_JMP+BPF_JGT+BPF_K:
		    	construct_jgt_k(mod,i,insns[i],ptr_state,blocks);
			break;

		    case BPF_JMP+BPF_JSET+BPF_K:
		    	construct_jset_x(mod,i,insns[i],ptr_state,blocks);
			break;

		    case BPF_JMP+BPF_JGE+BPF_X:
		    	construct_jge_x(mod,i,insns[i],ptr_state,blocks);
			break;

		    case BPF_JMP+BPF_JEQ+BPF_X:
		    	construct_jeq_x(mod,i,insns[i],ptr_state,blocks);
			break;

		    case BPF_JMP+BPF_JGT+BPF_X:
		    	construct_jgt_x(mod,i,insns[i],ptr_state,blocks);
			break;

		    case BPF_JMP+BPF_JSET+BPF_X:
		    	abort();


		    default:
			    if (!opcode_names[insns[i].code])
				    printf("Unknown opcode %02x\n", insns[i].code);


			    Function* func_opcode = mod->getFunction(opcode_names[insns[i].code]);
			    if (!func_opcode) {
				    printf("Couldn't find function for %s\n",opcode_names[insns[i].code]);
			    }

			    std::vector<Value*> opcode_params;
			    opcode_params.push_back(ptr_state);
			    opcode_params.push_back(
					    ConstantInt::get(getGlobalContext(), APInt(8, insns[i].jt)));
			    opcode_params.push_back(
					    ConstantInt::get(getGlobalContext(), APInt(8, insns[i].jf)));
			    opcode_params.push_back(
					    ConstantInt::get(getGlobalContext(), APInt(64, insns[i].k)));

			    CallInst* opcode = CallInst::Create(
					    func_opcode, 
					    opcode_params.begin(), 
					    opcode_params.end(), "bpf_opcode_call", 
					    this_block);
			    opcode->setCallingConv(CallingConv::C);
			    opcode->setTailCall(false);
			    AttrListPtr opcode_PAL;
			    {
				    SmallVector<AttributeWithIndex, 4> Attrs;
				    AttributeWithIndex PAWI;
				    PAWI.Index = 2U; PAWI.Attrs = 0  | Attribute::ZExt;
				    Attrs.push_back(PAWI);
				    PAWI.Index = 3U; PAWI.Attrs = 0  | Attribute::ZExt;
				    Attrs.push_back(PAWI);
				    PAWI.Index = 4294967295U; PAWI.Attrs = 0  | Attribute::NoUnwind;
				    Attrs.push_back(PAWI);
				    opcode_PAL = AttrListPtr::get(Attrs.begin(), Attrs.end());
			    }
			    opcode->setAttributes(opcode_PAL);

			    new StoreInst(opcode, ptr_retval, this_block);

			    ICmpInst *cmp = new ICmpInst(*this_block, ICmpInst::ICMP_NE, opcode, 
					    ConstantInt::get(getGlobalContext(), APInt(32, ~0U)),
					    "cmp_failure");

			    BranchInst::Create(success, next_block, cmp, this_block);
			    break;
	    }
    }

    /* Create an instruction so if we get here we fail */
    ReturnInst::Create(getGlobalContext(), 
    	ConstantInt::get(getGlobalContext(), APInt(32, 0)),
	fail);

    /* Create a success return */
    ReturnInst::Create(getGlobalContext(), 
		    new LoadInst(ptr_retval, "retval", success),
		    success);
  }

  return mod;
  
}

void initialise_array(void)
{
	opcode_names[BPF_LD+BPF_W+BPF_ABS] 	= "bpf_ldw_abs";
	opcode_names[BPF_LD+BPF_H+BPF_ABS] 	= "bpf_ldh_abs";
	opcode_names[BPF_LD+BPF_B+BPF_ABS] 	= "bpf_ldb_abs";
	opcode_names[BPF_LD+BPF_W+BPF_IND] 	= "bpf_ldw_ind";
	opcode_names[BPF_LD+BPF_H+BPF_IND] 	= "bpf_ldh_ind";
	opcode_names[BPF_LD+BPF_B+BPF_IND] 	= "bpf_ldb_ind";
	opcode_names[BPF_LD+BPF_IMM] 		= "bpf_ldb_imm";
	opcode_names[BPF_LD+BPF_MEM] 		= "bpf_ldb_mem";
	
	opcode_names[BPF_LDX+BPF_W+BPF_IMM]	= "bpf_ldx_imm";
	opcode_names[BPF_LDX+BPF_W+BPF_MEM]	= "bpf_ldx_mem";
	opcode_names[BPF_LDX+BPF_W+BPF_LEN]	= "bpf_ldx_len";
	opcode_names[BPF_LDX+BPF_B+BPF_MSH]	= "bpf_ldx_msh";

	opcode_names[BPF_ST]			= "bpf_st";
	opcode_names[BPF_STX]			= "bpf_stx";

	opcode_names[BPF_ALU+BPF_ADD+BPF_K]	= "bpf_alu_add_k";
	opcode_names[BPF_ALU+BPF_SUB+BPF_K]	= "bpf_alu_sub_k";
	opcode_names[BPF_ALU+BPF_MUL+BPF_K]	= "bpf_alu_mul_k";
	opcode_names[BPF_ALU+BPF_DIV+BPF_K]	= "bpf_alu_div_k";
	opcode_names[BPF_ALU+BPF_AND+BPF_K]	= "bpf_alu_and_k";
	opcode_names[BPF_ALU+BPF_OR+BPF_K]	= "bpf_alu_or_k";
	opcode_names[BPF_ALU+BPF_LSH+BPF_K]	= "bpf_alu_lsh_k";
	opcode_names[BPF_ALU+BPF_RSH+BPF_K]	= "bpf_alu_rsh_k";

	opcode_names[BPF_ALU+BPF_NEG]		= "bpf_alu_neg";

	opcode_names[BPF_ALU+BPF_ADD+BPF_X]	= "bpf_alu_add_x";
	opcode_names[BPF_ALU+BPF_SUB+BPF_X]	= "bpf_alu_sub_x";
	opcode_names[BPF_ALU+BPF_MUL+BPF_X]	= "bpf_alu_mul_x";
	opcode_names[BPF_ALU+BPF_DIV+BPF_X]	= "bpf_alu_div_x";
	opcode_names[BPF_ALU+BPF_AND+BPF_X]	= "bpf_alu_and_x";
	opcode_names[BPF_ALU+BPF_OR+BPF_X]	= "bpf_alu_or_x";
	opcode_names[BPF_ALU+BPF_LSH+BPF_X]	= "bpf_alu_lsh_x";
	opcode_names[BPF_ALU+BPF_RSH+BPF_X]	= "bpf_alu_rsh_x";

	opcode_names[BPF_JMP+BPF_JA]		= "bpf_ja";
	opcode_names[BPF_JMP+BPF_JGT+BPF_K]	= "bpf_gt_k";
	opcode_names[BPF_JMP+BPF_JGE+BPF_K]	= "bpf_ge_k";
	opcode_names[BPF_JMP+BPF_JEQ+BPF_K]	= "bpf_eq_k";
	opcode_names[BPF_JMP+BPF_JSET+BPF_K]	= "bpf_set_k";
	opcode_names[BPF_JMP+BPF_JGT+BPF_X]	= "bpf_gt_x";
	opcode_names[BPF_JMP+BPF_JGE+BPF_X]	= "bpf_ge_x";
	opcode_names[BPF_JMP+BPF_JEQ+BPF_X]	= "bpf_eq_x";
	opcode_names[BPF_JMP+BPF_JSET+BPF_X]	= "bpf_set_x";

	opcode_names[BPF_RET+BPF_A]		= "bpf_ret_a";
	opcode_names[BPF_RET+BPF_K]		= "bpf_ret_k";

	opcode_names[BPF_MISC+BPF_TAX]		= "bpf_tax";
	opcode_names[BPF_MISC+BPF_TXA]		= "bpf_txa";

}

/* Sample BPF Program */
struct bpf_insn insns[] = {
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_REVARP, 0, 3),
	BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 20),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, /*REVARP_REQUEST*/6, 0, 1),
	BPF_STMT(BPF_RET+BPF_K, sizeof(struct ether_arp) +
			sizeof(struct ether_header)),
	BPF_STMT(BPF_RET+BPF_K, 0),
};


/* To external users we pass around a "bpf_jit_t", but actually it's layed out as a bpf_jit_private_t
 * This is so people can use this from C, even tho we have C++ objects refered to from here.
 */
struct bpf_jit_private_t {
	bpf_jit_t bpf_jit;
	LLVMContext context;
  	ExecutionEngine *EE;
};


extern "C"
bpf_jit_t *compile_program(struct bpf_insn insns[], int plen) 
{
  initialise_array();

  struct bpf_jit_private_t * bpf_jitpriv
  	= (bpf_jit_private_t*)malloc(sizeof(bpf_jit_private_t));
  Module *mod;

  libtraceContext = new LLVMContext();
  mod = build_bpf_program(insns,plen);

  verifyModule(*mod, PrintMessageAction);

  PassManager PM;

  std::string errorStr;
  PM.add(new TargetData(mod));

#if OPTIMISE
  /* We need -O3, because inlining is very important to us */
  createStandardModulePasses(&PM, 
  	/* -O3 */ 3,
	false, 	/* Optimise for size? */
	true,	/* UnitAtAtime -- Allow optimisations that may make global module changes*/
	false,	/* Loop Unrolling? -- We don't support loops! */
	true,	/* Simplify Library Calls */
	false,	/* Exception support needed? */
	createFunctionInliningPass() /* Inlining Pass To use */
  );

  createStandardLTOPasses(&PM,
  	false,	/* Internalize -- Useless, we've done it already */
	true,	/* Run Inliner -- If anything hasn't been inlined, do it now */
	false	/* Verify Each */
  );
#endif

#if OUTPUT_COMPILED
  /* Display the output */
  PM.add(createPrintModulePass(&outs()));
#endif

  PM.run(*mod);

  InitializeNativeTarget();

  EngineBuilder EB = EngineBuilder(mod);
  EB.setErrorStr(&errorStr);
  EB.setEngineKind(EngineKind::JIT);

  bpf_jitpriv->EE = EB.create();
  if (!bpf_jitpriv->EE) {
  	std::cerr << "Failed to create JIT: " << errorStr << std::endl;
  }
  assert(bpf_jitpriv->EE);

  bpf_jitpriv->bpf_jit.bpf_run = 
  	reinterpret_cast<bpf_run_t>(bpf_jitpriv->EE->getPointerToFunction(mod->getFunction("bpf_run")));


/*
  delete bpf_jit->EE;
  delete libtraceContext;
  free(bpf_jit);
*/

  return reinterpret_cast<bpf_jit_t*>(bpf_jitpriv);
}

extern "C"
void destroy_program(struct bpf_jit_t *bpf_jit)
{
	struct bpf_jit_private_t *priv=reinterpret_cast<bpf_jit_private_t*>(bpf_jit);

	delete priv->EE;
	delete libtraceContext;
	priv->bpf_jit.bpf_run = NULL;
	free(bpf_jit);
}


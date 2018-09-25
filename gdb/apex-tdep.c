/*
 * Copyrights
 */
//#include "demangle.h"
#include "defs.h"
#include <string.h>
#include "frame.h"
#include "inferior.h"
#include "symtab.h"
#include "value.h"
#include "gdbcmd.h"
#include "language.h"
#include "gdbcore.h"
#include "symfile.h"
#include "objfiles.h"
#include "gdbtypes.h"
#include "target.h"
#include "regcache.h"
#include "gdbarch.h"
#include "gdbserver/tdesc.h"
#include "apex-tdep.h"
#include "features/apex.c"
#include "safe-ctype.h"
#include "block.h"
#include "reggroups.h"
#include "arch-utils.h"
#include "frame.h"
#include "frame-unwind.h"
#include "frame-base.h"
#include "dwarf2-frame.h"
#include "trad-frame.h"
#include "regset.h"
#include "remote.h"
#include "target-descriptions.h"
#include "bfd-in2.h"

#include "value.h"


#include <inttypes.h>

#include "dis-asm.h"
#include "common/errors.h"

#include "prologue-value.h"

void apex_objfile_relocate();

static enum return_value_convention
apex_return_value (struct gdbarch  *gdbarch,
		   struct value    *functype,
		   struct type     *valtype,
		   struct regcache *regcache,
		   gdb_byte        *readbuf,
		   const gdb_byte  *writebuf)
{
	//TODO:
  return RETURN_VALUE_ABI_RETURNS_ADDRESS;
}

static const char *const acp_register_names[] = {
  "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
  "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
  "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
  "r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31",
  "ov","pc"
};

static const char *const vcu_gp_regs[] = {
	"v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7"
};

static const char *const vcu_ctl_regs[] = {
	"ovv","vc0","vc1","vc2","vc3","vcsptr",
	"vcs0","vcs1","vcs2","vcs3","vcs4","vcs5",
	"vcs6","vcs7"
};

static const char *const ctrl_regs [] = {
		"cmem_if_apu_pm_start",
		"cmem_if_apu_dm_start"
};


static struct type *
apex_builtin_type_vec_512 (struct gdbarch *gdbarch)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  if (!tdep->apex_vector_512_type){

	  const struct builtin_type *bt = builtin_type (gdbarch);
      struct type *t;
      t = arch_composite_type (gdbarch, "__gdb_builtin_type_vec_512", TYPE_CODE_UNION);
      append_composite_type_field (t, "vec_512", init_vector_type (bt->builtin_uint16, 32));
      TYPE_VECTOR (t) = 1;
      TYPE_NAME (t) = "apex_builtin_type_vec_512";
      tdep->apex_vector_512_type = t;
    }

  return tdep->apex_vector_512_type;
}

static struct type *
apex_pseudo_register_type (struct gdbarch *gdbarch, int regnum){
	struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
	const struct builtin_type *bt = builtin_type (gdbarch);

	if (regnum>=APEX_R0_REGNUM && regnum<APEX_ACP_REGS_END)
		return bt->builtin_uint32;
	if (regnum>=APEX_ACP_REGS_END && regnum<VECTORS_END)
	 	return apex_builtin_type_vec_512 (gdbarch);
	if (regnum>=VECTORS_END && regnum<vcsptr_REGNUM)
		return bt->builtin_uint32;
 	if (regnum == vcsptr_REGNUM)
		return bt->builtin_uint8;
    if (regnum>vcsptr_REGNUM && regnum<VCU_REGS_END)
		return bt->builtin_uint32;
 	//default
 	return bt->builtin_uint32;
}

static const char *
apex_register_name (struct gdbarch *gdbarch,
		    		int regnum){

	if (regnum>=APEX_R0_REGNUM && regnum<APEX_ACP_REGS_END)
		return acp_register_names[regnum];
	if (regnum>=APEX_ACP_REGS_END && regnum<VECTORS_END)
		return vcu_gp_regs[regnum-APEX_ACP_REGS_END];
    if (regnum>=VECTORS_END && regnum<VCU_REGS_END)
		return vcu_ctl_regs[regnum-VECTORS_END];
    if (regnum == cmem_if_apu_pm_start_regnum)
    	return ctrl_regs[0];
    if (regnum == cmem_if_apu_dm_start_regnum)
    	return ctrl_regs[1];

  return "no_name";
}

static struct type *
apex_register_type (struct gdbarch *gdbarch, int regnum){

	struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
	const struct builtin_type *bt = builtin_type (gdbarch);

	if (regnum>=APEX_R0_REGNUM && regnum<APEX_ACP_REGS_END)
		return bt->builtin_uint32;
	if (regnum>=APEX_ACP_REGS_END && regnum<VECTORS_END)
	 	return apex_builtin_type_vec_512 (gdbarch);
	if (regnum>=VECTORS_END && regnum<vcsptr_REGNUM)
		return bt->builtin_uint32;
 	if (regnum == vcsptr_REGNUM)
		return bt->builtin_uint8;
    if (regnum>vcsptr_REGNUM && regnum<VCU_REGS_END)
		return bt->builtin_uint32;
 	//default
 	return bt->builtin_uint32;
}
/*
static void
apex_registers_info (struct gdbarch    *gdbarch,
		     struct ui_file    *file,
		     struct frame_info *frame,
		     int                regnum,
		     int                all)
{
	//TODO:
  return;
}
*/

static const gdb_byte *
apex_breakpoint_from_pc (struct gdbarch *gdbarch,
			 CORE_ADDR      *bp_addr,
			 int            *bp_size)
{
  static const gdb_byte breakpoint[] = {0};
  *bp_size = 4;
  return breakpoint;

}


#define WORD2BYTE 4

static CORE_ADDR
apex_read_pc (struct regcache* regcache){

	  ULONGEST pc;
	  regcache_cooked_read_unsigned (regcache, APEX_PC_REGNUM, &pc);
	  return (CORE_ADDR)(pc & 0xFFFFFFFF);
}
/*
static CORE_ADDR
apex_read_lr (struct regcache* regcache){

	  ULONGEST lr;
	  regcache_cooked_read_unsigned (regcache, APEX_LR_REGNUM, &lr);
	  return (CORE_ADDR)(lr & 0x1FFFF) * WORD2BYTE;
}
*/

#define HW_PC_MASK 0x20000
#define MAX_PC_VAL HW_PC_MASK - 1
#define MEM_PC_TO_REG_PC(pc) (pc >= HW_PC_MASK) ? (pc & MAX_PC_VAL)*WORD2BYTE : pc

/* Implement the "unwind_pc" gdbarch method.  */
static CORE_ADDR
apex_unwind_pc (struct gdbarch *gdbarch, struct frame_info *this_frame){

	  ULONGEST pc;
	  ULONGEST dm_start,pm_start;

	  struct regcache* regcache = get_current_regcache();
	  regcache_cooked_read_unsigned (regcache, cmem_if_apu_dm_start_regnum, &dm_start);
	  regcache_cooked_read_unsigned (regcache, cmem_if_apu_pm_start_regnum, &pm_start);

	  pc = frame_unwind_register_unsigned (this_frame, APEX_PC_REGNUM);
	  //Little bit tricky. LR and PC reg values from the GDB server comes in bytes format and max value is 0x1FFFFF
	  //so when we read value more than 0x20000 it means that value was stored in the memory (stack) and we need to convert it.
	  pc = ((pm_start > dm_start) & pc < pm_start) ? pc*WORD2BYTE:pc; /*MEM_PC_TO_REG_PC(pc);*/
	  return (CORE_ADDR)(pc & MAX_PC_VAL);
}

/* Implement the "unwind_sp" gdbarch method.  */
static CORE_ADDR
apex_unwind_sp (struct gdbarch *gdbarch, struct frame_info *this_frame)
{
	ULONGEST sp;
	sp = frame_unwind_register_unsigned (this_frame, APEX_SP_REGNUM);
	return (CORE_ADDR)(sp & MAX_PC_VAL) * WORD2BYTE;
}


struct apex_prologue_cache
{
  /* The program counter at the start of the function.  It is used to
     identify this frame as a prologue frame.  */
  CORE_ADDR func;

  /* The program counter at the time this frame was created; i.e. where
     this function was called from.  It is used to identify this frame as a
     stub frame.  */
  CORE_ADDR prev_pc;

  /* The stack pointer at the time this frame was created; i.e. the
     caller's stack pointer when this function was called.  It is used
     to identify this frame.  */
  CORE_ADDR prev_sp;

  /* Is the target available to read from?  */
  int available_p;

  /* The frame base for this frame is just prev_sp - frame size.
     FRAMESIZE is the distance from the frame pointer to the
     initial stack pointer.  */
  int framesize;

  /* The register used to hold the frame pointer for this frame.  */
  int framereg;

  /* Saved register offsets.  */
  struct trad_frame_saved_reg *saved_regs;
};

/* Analyze a prologue, looking for a recognizable stack frame
   and frame pointer.  Scan until we encounter a store that could
   clobber the stack frame unexpectedly, or an unknown instruction.  */


#define MAX_ARGS 5
#define MAX_PARTS 2


struct ArgPart{
    unsigned char bitsize;//num bits
    unsigned char start; //src bit
    unsigned char offset; //dst bit
};

enum ArgType {screg, vreg, uval, sval5bit, sval8bit, sval12bit, sval15bit, sval16bit, sval25bit ,sval32bit };

struct arg_type{
    enum ArgType    type;
    gdb_byte        size;
    struct ArgPart  part[MAX_PARTS];
};

typedef enum InstType {scalar, vector, mix64, scalar64} instType;

enum InstSize {b32, b64};

enum InstLogic {load, store, branch, stack, integer, add};

struct InstMask{
    enum InstSize   size;
    LONGEST         mask; //mask value
    LONGEST         bits; //opcode
};

typedef struct Instruction {
    instType        type;
    enum InstLogic  lgc;
    gdb_byte		delay_slots;
    struct InstMask mask;
    gdb_byte        num_params;
    struct arg_type args[MAX_ARGS];
}instruction;

#define SIZE(x) x
#define OFFSET(x) x

//{INST_TYPE, CMD_TYPE, DELAY_SLOTS, {MASK_SIZE, MASK, VAL}, NUM_OF_PARAMS, {PARAM_TYPE, PARTS_NUM, {SIZE, SRC_OFFSET, DST_OFFSET}}}
struct Instruction isa_scalar[] ={
    {scalar, store, 0, {b32, 0x3E000000, 0x2A000000}, 3, { /*sw s2, c(s1)*/
        {screg, 1, {SIZE(5), OFFSET(20), 0}}, {screg, 1, {SIZE(5), OFFSET(15), 0}}, {sval15bit, 1, {SIZE(15), OFFSET(0), 0}}}},

	{scalar, store, 0, {b32, 0x3E0000FF, 0x00000029}, 3, { /*sw s2, (s1+=c)*/
	    {screg, 1, {SIZE(5), OFFSET(20), 0}}, {screg, 1, {SIZE(5), OFFSET(15), 0}}, {sval5bit, 1, {SIZE(5), OFFSET(10), 0}}}},

	{scalar, add, 0, {b32, 0x3E0000FF, 0x00000003}, 3, { /*add d1,s1,s2*/
	    {screg, 1, {SIZE(5), OFFSET(20), 0}}, {screg, 1, {SIZE(5), OFFSET(15), 0}}, {screg, 1, {SIZE(5), OFFSET(10), 0}}}},
	{scalar, add, 0, {b32, 0x3E0000FF, 0x00000004}, 3, { /*addx d1,s1,s2*/
		{screg, 1, {SIZE(5), OFFSET(20), 0}}, {screg, 1, {SIZE(5), OFFSET(15), 0}}, {screg, 1, {SIZE(5), OFFSET(10), 0}}}},

	{scalar, add, 0, {b32, 0x3FE00000, 0x04000000}, 2, { /*addi d1,d1,imm*/
			{screg, 1, {SIZE(5), OFFSET(16), 0}}, {sval16bit, 1, {SIZE(16), OFFSET(0), 0}}}},
	{scalar, add, 0, {b32, 0x3FE00000, 0x04200000}, 2, { /*addix d1,s1,imm*/
						{screg, 1, {SIZE(5), OFFSET(16), 0}}, {sval16bit, 1, {SIZE(16), OFFSET(0), 0}}}},

	{scalar, add, 0, {b32, 0x3FE00000, 0x06000000}, 2, { /*addui d1,d1,imm*/
			{screg, 1, {SIZE(5), OFFSET(16), 0}}, {sval16bit, 1, {SIZE(16), OFFSET(0), 0}}}},
	{scalar, add, 0, {b32, 0x3FE00000, 0x06200000}, 2, { /*adduix d1,s1,imm*/
			{screg, 1, {SIZE(5), OFFSET(16), 0}}, {sval16bit, 1, {SIZE(16), OFFSET(0), 0}}}},

	{scalar, branch, 2, {b32, 0x3E000000, 0x08000000}, 2, { /*beqz s1,#imm*/
		{screg, 1, {SIZE(5), OFFSET(16), 0}}, {sval16bit, 1, {SIZE(16), OFFSET(0), 0}}}},
	{scalar, branch, 2, {b32, 0x3E000000, 0x0A000000}, 2, { /*bnez s1,#imm*/
		{screg, 1, {SIZE(5), OFFSET(16), 0}}, {sval16bit, 1, {SIZE(16), OFFSET(0), 0}}}},

	{scalar, branch, 1, {b32, 0x3E000000, 0x10000000}, 1,  /*j #imm*/
			{sval25bit, 1, {SIZE(25), OFFSET(0), 0}}},
	{scalar, branch, 2, {b32, 0x3E000000, 0x16000000}, 1,  /*jr s1*/
			{screg, 1, {SIZE(5), OFFSET(20), 0 }}},

	{scalar, branch, 1, {b32, 0x3E000000, 0x12000000}, 1,  /*jal #imm*/
			{sval25bit, 1, {SIZE(25), OFFSET(0), 0 }}},
	{scalar, branch, 2, {b32, 0x3E000000, 0x14000000}, 1,  /*jalr s1*/
			{screg, 1, {SIZE(5), OFFSET(20), 0 }}}
};

#define ISA_SCALAR_SIZE sizeof(isa_scalar)/sizeof(isa_scalar[0])


struct Instruction isa_vector[] = {

    {vector, add, 0, {b32, 0x3E0003F8, 0x00000338}, 2,{ /*padd s0 += imm*/
        {screg, 1, {SIZE(5), OFFSET(20), 0}}, {sval12bit, 2, {{SIZE(10), OFFSET(10), 0}, {SIZE(3), OFFSET(0), 10}}} }},
    {vector, add, 0, {b32, 0x3E0003F8, 0x140000B8}, 3,{ /*add d0, s0, #imm*/
        {screg, 1, {SIZE(5), OFFSET(20), 0}}, {screg, 1, {SIZE(5), OFFSET(15), 0}}, {sval8bit, 2,{ {SIZE(5), OFFSET(10), 0}, {SIZE(3), OFFSET(0), 5}} } }}

};
#define ISA_VECTOR_SIZE sizeof(isa_vector)/sizeof(isa_vector[0])


struct Instruction isa_scalar64[] = {
    {scalar, load, 0, {b64, 0x3F80000000000000, 0x1200000000000000}, 3,{ /*andli d0,s1,imm*/
        {screg, 1, {SIZE(5), OFFSET(50), 0}}, {screg, 1, {SIZE(5), OFFSET(55), 0}}, {sval32bit, 1, {SIZE(32), OFFSET(0), 0}}}},
    {scalar, load, 0, {b64, 0x3F80000000000000, 0x1280000000000000}, 3, { /*orli d0,s1,imm*/
        {screg, 1, {SIZE(5), OFFSET(50), 0}}, {screg, 1, {SIZE(5), OFFSET(55), 0}}, {sval32bit, 1, {SIZE(32), OFFSET(0), 0}}}}
};
#define ISA_SCALAR64_SIZE sizeof(isa_scalar64)/sizeof(isa_scalar64[0])

struct Arg{
    enum ArgType type;
    int value;
};


struct Command{
    enum InstLogic type;
    gdb_byte delay_slot;
    gdb_byte arg_size;
    struct Arg args[5];
};


#define INST_TYPE_MASK      0xC0000000
#define INST_TYPE_SCALAR    0x00000000
#define INST_TYPE_VECTOR    0x40000000
#define INST_TYPE_MIX       0x80000000
#define INST_TYPE_SCALAR64  0xC0000000


static bool find_opcode(LONGEST data, Instruction *lst, unsigned int list_size,Instruction **found){
    while(list_size--){
        if ((lst->mask.mask & data) == lst->mask.bits){
            *found = lst;
            return true;
        }
        lst++;
    }
    return false;
}

//check income type and extend sign if required
static int ext_sign(enum ArgType type, int val){
	switch(type){
		case sval5bit:
			return (val & 10) ? (val | 0xFFFFFFF0) : val;
		case sval8bit:
			return (val & 0x80) ? (val | 0xFFFFFF00) : val;
		case sval12bit:
			return (val & 0x800) ? (val | 0xFFFFF000) : val;
		case sval15bit:
			return (val & 0x4000) ? (val | 0xFFFF8000) : val;
		case sval16bit:
			return (val & 0x8000) ? (val | 0xFFFF0000) : val;
		case sval25bit:
			return (val & 0x1000000) ? (val | 0xFF000000) : val;
	}
	return val;
}

static bool map_opcode_command(LONGEST data, struct Instruction *opcode, struct Command *cmd){
    
    cmd->type = opcode->lgc;
    //convert args
    for (int param = 0 ; param < opcode->num_params; param++){
        LONGEST value = 0;
        for (int param_part = 0; param_part < opcode->args[param].size; param_part++){
            LONGEST mask =  (1 << opcode->args[param].part[param_part].bitsize) - 1;
            value |= ((data >> opcode->args[param].part[param_part].start) & mask) << opcode->args[param].part[param_part].offset;
        }
        cmd->args[param].value = ext_sign(opcode->args[param].type, value);
        cmd->args[param].type = opcode->args[param].type;
    }
    
    cmd->arg_size = opcode->num_params;
    cmd->delay_slot = opcode->delay_slots;

    return true;
}



#define SINGLE_INST_SIZE 4
#define DOUBLE_INST_SIZE SINGLE_INST_SIZE*2

static unsigned int decode_instruction(struct gdbarch *gdbarch,
                               CORE_ADDR addr, struct Command *cmd, gdb_byte* size){
    
    enum bfd_endian byte_order_for_code = gdbarch_byte_order_for_code (gdbarch);
    
    *size = 0;

    LONGEST insn, insn2;
    struct Instruction *ins;
    insn = read_memory_unsigned_integer (addr, SINGLE_INST_SIZE, byte_order_for_code);
    switch(insn & INST_TYPE_MASK){
        case INST_TYPE_SCALAR:
        	if (find_opcode(insn, &isa_scalar[0], ISA_SCALAR_SIZE, &ins)){
            	map_opcode_command(insn, ins, cmd);
            	*size =1;
        	}
            return SINGLE_INST_SIZE;
            break;
        case INST_TYPE_VECTOR:
            if (find_opcode(insn, &isa_vector[0], ISA_VECTOR_SIZE, &ins)){
            	map_opcode_command(insn, ins, cmd);
            	*size = 1;
            }
            return SINGLE_INST_SIZE;
            break;
        case INST_TYPE_MIX:
            if (find_opcode(insn, &isa_scalar[0], ISA_SCALAR_SIZE, &ins)){
            	map_opcode_command(insn, ins, cmd);
            	*size = 1;
            }
            insn = read_memory_unsigned_integer (addr + SINGLE_INST_SIZE, SINGLE_INST_SIZE, byte_order_for_code);
            if (find_opcode(insn, &isa_vector[0], ISA_VECTOR_SIZE, &ins)){
            	map_opcode_command(insn, ins, &cmd[1]);
            	*size = 2;
            }
            return DOUBLE_INST_SIZE;
            break;
        case INST_TYPE_SCALAR64:
            insn = read_memory_unsigned_integer (addr, DOUBLE_INST_SIZE, byte_order_for_code);
            if (find_opcode(insn, &isa_scalar64[0], ISA_SCALAR64_SIZE, &ins)){
            	map_opcode_command(insn, ins, cmd);
            	*size = 1;
            }return DOUBLE_INST_SIZE;
            break;
    }

    //shouldn't come here
    return SINGLE_INST_SIZE;
}


static CORE_ADDR
apex_analyze_prologue (struct gdbarch *gdbarch,
			  CORE_ADDR start, CORE_ADDR limit,
			  struct apex_prologue_cache *cache)
{
    enum bfd_endian byte_order_for_code = gdbarch_byte_order_for_code (gdbarch);
    pv_t regs[APEX_ACP_REGS_END];
    struct pv_area *stack;
    struct cleanup *back_to;
    struct Command cmd[2];
    bool is_leaf=false, is_sp_moved = false;
    
    int i;
    for (i = 0; i < APEX_ACP_REGS_END; i++)
        regs[i] = pv_register (i, 0);
  
    stack = make_pv_area (APEX_SP_REGNUM, gdbarch_addr_bit (gdbarch));
    back_to = make_cleanup_free_pv_area (stack);
    
    
    for (; start < limit;){
    	gdb_byte cmd_num = 0;
        int skip = decode_instruction(gdbarch, start, &cmd[0], &cmd_num);
        start += skip;
        
        //we need to check do we have one 64bit/32bit cmd or 2 32bit
        int index = 0;
        struct Command* c = cmd;
        while(cmd_num--){
        	switch(cmd->type){
        		case add:
        		{
        			int rd = cmd->args[0].value;
        			int rs = cmd->args[0].value;
        			if (cmd->arg_size == 2){
        				if (rd == APEX_SP_REGNUM){
        					if (is_sp_moved){
        						//ignore this and stop analyze
        						is_leaf = true;
        					}else{
        						regs[rd] = pv_add_constant( regs[rs], cmd->args[1].value);
        						is_sp_moved = true;
        					}
        				}else{
        					regs[rd] = pv_add_constant( regs[rs], cmd->args[1].value);
        				}
        			}

        		}
        			break;
        		case store:
        			{
        				gdb_byte rd = cmd->args[0].value;
        				gdb_byte rb = cmd->args[1].value;
        				int offset = cmd->args[2].value;
        				if (rb == APEX_SP_REGNUM)
        					pv_area_store (stack, pv_add_constant(regs[rb], offset), 4, regs[rd]);
        			}
        			break;

        		case branch:
        			//analyze delay slots and stop
        			limit = start + cmd->delay_slot * 4;
        			break;

        	}
        }

        if (is_leaf)
        	break;
    }

  if (cache == NULL){
      do_cleanups (back_to);
      return start;
  }

  if (pv_is_register (regs[APEX_SP_REGNUM], APEX_SP_REGNUM)){
      /* Try the stack pointer.  */
      cache->framesize = -regs[APEX_SP_REGNUM].k;
      cache->framereg = APEX_SP_REGNUM;
  }else{
      /* We're just out of luck.  We don't know where the frame is.  */
      cache->framereg = -1;
      cache->framesize = 0;
  }

  for (i = 0; i < APEX_ACP_REGS_END; i++){
      CORE_ADDR offset;

      if (pv_area_find_reg (stack, gdbarch, i, &offset))
    	  cache->saved_regs[i].addr = offset;
  }

  do_cleanups (back_to);
  return start;
}

static CORE_ADDR
apex_skip_prologue (struct gdbarch *gdbarch, CORE_ADDR pc)
{
  unsigned long inst;
  CORE_ADDR skip_pc;
  CORE_ADDR func_addr, limit_pc;
  struct symtab_and_line sal;

  /* See if we can determine the end of the prologue via the symbol
     table.  If so, then return either PC, or the PC after the
     prologue, whichever is greater.  */
  if (find_pc_partial_function (pc, NULL, &func_addr, NULL)){
      CORE_ADDR post_prologue_pc = skip_prologue_using_sal (gdbarch, func_addr);

      if (post_prologue_pc != 0)
    	  return max (pc, post_prologue_pc);
  }

  /* Can't determine prologue from the symbol table, need to examine
     instructions.  */

  /* Find an upper limit on the function prologue using the debug
     information.  If the debug information could not be used to
     provide that bound, then use an arbitrary large number as the
     upper bound.  */
  limit_pc = skip_prologue_using_sal (gdbarch, pc);
  if (limit_pc == 0)
    limit_pc = pc + 128;	/* Magic.  */

  /* Try disassembling prologue.  */
  return apex_analyze_prologue (gdbarch, pc, limit_pc, NULL);
}


static void
apex_scan_prologue (struct frame_info *this_frame,
		       struct apex_prologue_cache *cache)
{
  CORE_ADDR block_addr = get_frame_address_in_block (this_frame);
  CORE_ADDR prologue_start;
  CORE_ADDR prologue_end;
  CORE_ADDR prev_pc = get_frame_pc (this_frame);
  struct gdbarch *gdbarch = get_frame_arch (this_frame);

  cache->prev_pc = prev_pc;

  /* Assume we do not find a frame.  */
  cache->framereg = -1;
  cache->framesize = 0;

  if (find_pc_partial_function (block_addr, NULL, &prologue_start,
				&prologue_end))
    {
	  //as we don't have prologue/epilogue in function we must analyze without sal, r29 will stored right before call
      prologue_end = min (prologue_end, prev_pc);//but we need to limit it by current pc;
      apex_analyze_prologue (gdbarch, prologue_start, prologue_end, cache);
    }
}

static void
apex_make_prologue_cache_1 (struct frame_info *this_frame,
			       struct apex_prologue_cache *cache)
{
  CORE_ADDR unwound_fp;
  int reg;

  apex_scan_prologue (this_frame, cache);

  if (cache->framereg == -1)
    return;

  unwound_fp = get_frame_register_unsigned (this_frame, cache->framereg);
  if (unwound_fp == 0)
    return;

  cache->prev_sp = unwound_fp + cache->framesize;

  /* Calculate actual addresses of saved registers using offsets
     determined by apex_analyze_prologue.  */
  for (reg = 0; reg < gdbarch_num_regs (get_frame_arch (this_frame)); reg++)
    if (trad_frame_addr_p (cache->saved_regs, reg))
      cache->saved_regs[reg].addr += cache->prev_sp;

  cache->func = get_frame_func (this_frame);

  cache->available_p = 1;
}


static struct apex_prologue_cache *
apex_make_prologue_cache (struct frame_info *this_frame, void **this_cache)
{
  struct apex_prologue_cache *cache;

  if (*this_cache != NULL)
    return (struct apex_prologue_cache *) *this_cache;

  cache = FRAME_OBSTACK_ZALLOC (struct apex_prologue_cache);
  cache->saved_regs = trad_frame_alloc_saved_regs (this_frame);
  *this_cache = cache;

  TRY
    {
      apex_make_prologue_cache_1 (this_frame, cache);
    }
  CATCH (ex, RETURN_MASK_ERROR)
    {
      if (ex.error != NOT_AVAILABLE_ERROR)
    	  throw_exception (ex);
    }
  END_CATCH

  return cache;
}


static enum unwind_stop_reason
apex_prologue_frame_unwind_stop_reason (struct frame_info *this_frame,
					   void **this_cache)
{
  struct apex_prologue_cache *cache
    = apex_make_prologue_cache (this_frame, this_cache);

  if (!cache->available_p)
    return UNWIND_UNAVAILABLE;

  /* We've hit a wall, stop.  */
  if (cache->prev_sp == 0 || cache->prev_pc == 0)
    return UNWIND_OUTERMOST;

  return UNWIND_NO_REASON;
}

static void
apex_prologue_this_id (struct frame_info *this_frame,
			  void **this_cache, struct frame_id *this_id)
{
  struct apex_prologue_cache *cache
    = apex_make_prologue_cache (this_frame, this_cache);

  if (!cache->available_p)
    *this_id = frame_id_build_unavailable_stack (cache->func);
  else
    *this_id = frame_id_build (cache->prev_sp, cache->func);
}

static struct value *
apex_prologue_prev_register (struct frame_info *this_frame,
				void **this_cache, int prev_regnum)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  struct apex_prologue_cache *cache
    = apex_make_prologue_cache (this_frame, this_cache);

  /* If we are asked to unwind the PC, then we need to return the LR
     instead.  The prologue may save PC, but it will point into this
     frame's prologue, not the next frame's resume location.  */
  if (prev_regnum == APEX_PC_REGNUM)
    {
      CORE_ADDR lr;

      lr = frame_unwind_register_unsigned (this_frame, APEX_LR_REGNUM);
      return frame_unwind_got_constant (this_frame, prev_regnum, lr);
    }

  /* SP is generally not saved to the stack, but this frame is
     identified by the next frame's stack pointer at the time of the
     call.  The value was already reconstructed into PREV_SP.  */
  /*
         +----------+  ^
         | saved lr |  |
      +->| saved fp |--+
      |  |          |
      |  |          |     <- Previous SP
      |  +----------+
      |  | saved lr |
      +--| saved fp |<- FP
         |          |
         |          |<- SP
         +----------+  */
  if (prev_regnum == APEX_SP_REGNUM)
    return frame_unwind_got_constant (this_frame, prev_regnum,
				      cache->prev_sp);

  if (prev_regnum == APEX_LR_REGNUM){
	  return trad_frame_get_prev_register (this_frame, cache->saved_regs, prev_regnum);
  }

  return trad_frame_get_prev_register (this_frame, cache->saved_regs,
				       prev_regnum);
}

struct frame_unwind apex_prologue_unwind =
{
  NORMAL_FRAME,
  apex_prologue_frame_unwind_stop_reason,
  apex_prologue_this_id,
  apex_prologue_prev_register,
  NULL,
  default_frame_sniffer
};

static struct apex_prologue_cache *
apex_make_stub_cache (struct frame_info *this_frame, void **this_cache)
{
  struct apex_prologue_cache *cache;

  if (*this_cache != NULL)
    return (struct apex_prologue_cache *) *this_cache;

  cache = FRAME_OBSTACK_ZALLOC (struct apex_prologue_cache);
  cache->saved_regs = trad_frame_alloc_saved_regs (this_frame);
  *this_cache = cache;

  TRY
    {
      cache->prev_sp = get_frame_register_unsigned (this_frame, APEX_SP_REGNUM);
      cache->prev_pc = get_frame_pc (this_frame);
      cache->available_p = 1;
    }
  CATCH (ex, RETURN_MASK_ERROR)
    {
      if (ex.error != NOT_AVAILABLE_ERROR)
	throw_exception (ex);
    }
  END_CATCH

  return cache;
}


static enum unwind_stop_reason
apex_stub_frame_unwind_stop_reason (struct frame_info *this_frame,
				       void **this_cache)
{
  struct apex_prologue_cache *cache
    = apex_make_stub_cache (this_frame, this_cache);

  if (!cache->available_p)
    return UNWIND_UNAVAILABLE;

  return UNWIND_NO_REASON;
}

static void
apex_stub_this_id (struct frame_info *this_frame,
		      void **this_cache, struct frame_id *this_id)
{
  struct apex_prologue_cache *cache
    = apex_make_stub_cache (this_frame, this_cache);

  if (cache->available_p)
    *this_id = frame_id_build (cache->prev_sp, cache->prev_pc);
  else
    *this_id = frame_id_build_unavailable_stack (cache->prev_pc);
}


//Becouse standart unwinder it heavy we just check befor is it possible to unwind/
static int
apex_stub_unwind_sniffer (const struct frame_unwind *self,
			     struct frame_info *this_frame,
			     void **this_prologue_cache)
{
  CORE_ADDR addr_in_block;
  gdb_byte dummy[4];

  addr_in_block = get_frame_address_in_block (this_frame);
  if (in_plt_section (addr_in_block)
      /* We also use the stub winder if the target memory is unreadable
	 to avoid having the prologue unwinder trying to read it.  */
      || target_read_memory (get_frame_pc (this_frame), dummy, 4) != 0)
    return 1;

  return 0;
}

struct frame_unwind apex_stub_unwind =
{
  NORMAL_FRAME,
  apex_stub_frame_unwind_stop_reason,
  apex_stub_this_id,
  apex_prologue_prev_register,
  NULL,
  apex_stub_unwind_sniffer
};

static CORE_ADDR
apex_normal_frame_base (struct frame_info *this_frame, void **this_cache)
{
  struct apex_prologue_cache *cache
    = apex_make_prologue_cache (this_frame, this_cache);

  return cache->prev_sp - cache->framesize;
}

struct frame_base apex_normal_base =
{
  &apex_prologue_unwind,
  apex_normal_frame_base,
  apex_normal_frame_base,
  apex_normal_frame_base
};

static struct frame_id
apex_dummy_id (struct gdbarch *gdbarch, struct frame_info *this_frame)
{
  return frame_id_build (get_frame_register_unsigned (this_frame,
						      APEX_SP_REGNUM),
			 get_frame_pc (this_frame));
}


//read previouse value of the register for the PC it's LR
static struct value *
apex_dwarf2_prev_register (struct frame_info *this_frame,
			      void **this_cache, int regnum)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  CORE_ADDR lr;

  switch (regnum)
    {
    case APEX_PC_REGNUM:
      lr = frame_unwind_register_unsigned (this_frame, APEX_LR_REGNUM);
      return frame_unwind_got_constant (this_frame, regnum, lr);
      break;
    default:
      internal_error (__FILE__, __LINE__,
		      _("Unexpected register %d"), regnum);
    }
}

//setup the way how to get PC value
static void
apex_dwarf2_frame_init_reg (struct gdbarch *gdbarch, int regnum,
			       struct dwarf2_frame_state_reg *reg,
			       struct frame_info *this_frame)
{
  switch (regnum)
    {
    case APEX_PC_REGNUM:
    	reg->how = DWARF2_FRAME_REG_FN;
    	reg->loc.fn = apex_dwarf2_prev_register;
    	break;
    }
}


/* Map a DWARF register REGNUM onto the appropriate GDB register
   number.  */
static int
apex_dwarf_reg_to_regnum (struct gdbarch *gdbarch, int reg)
{
  /* Core integer regs.  */
  if (reg >= 19 && reg <= 50)
    return APEX_R0_REGNUM + reg - 19;

  return -1;
}

static CORE_ADDR
apex_adjust_dwarf2_addr (CORE_ADDR elf_addr){
	return elf_addr;
}

static CORE_ADDR
apex_adjust_dwarf2_line (CORE_ADDR elf_addr, int rel){
	return elf_addr;
}


static int
apex_gdb_print_insn (bfd_vma memaddr, disassemble_info *info){
	return print_insn_apex (memaddr, info);
}


#define APEX_VIRTUAL_VEC_MEM 0x2000000
void apex_objfile_relocate(){
	CORE_ADDR text_addr, data_addr;
	struct section_offsets *offs;

	if (symfile_objfile == NULL)
		return;

	ULONGEST dm_start,pm_start;
	struct regcache* regcache = get_current_regcache();
	regcache_cooked_read_unsigned (regcache, cmem_if_apu_dm_start_regnum, &dm_start);
	regcache_cooked_read_unsigned (regcache, cmem_if_apu_pm_start_regnum, &pm_start);

	offs = ((struct section_offsets *)
		  alloca (SIZEOF_N_SECTION_OFFSETS (symfile_objfile->num_sections)));

	for (int i = 0; i < symfile_objfile->num_sections; i++){
	  //look through all sections and if it executable or allocated do smthing.
		struct bfd_section *sect = symfile_objfile->sections[i].the_bfd_section;
			offs->offsets[i] = 0;

		if (sect == 0){
			continue;
		}

		if (strcmp(symfile_objfile->sections[i].the_bfd_section->name,".vdata.VMb") == 0){
			if (sect->flags & SEC_ALLOC){
				offs->offsets[i] = APEX_VIRTUAL_VEC_MEM;
				continue;
			}
		}

		if ((sect->flags & (SEC_CODE | SEC_ALLOC | SEC_HAS_CONTENTS)) == (SEC_CODE | SEC_ALLOC | SEC_HAS_CONTENTS)){
			offs->offsets[i] = pm_start;
		}else if (sect->flags & SEC_ALLOC){
			offs->offsets[i] = dm_start;
		}
	}
	objfile_relocate (symfile_objfile, offs);
}

/* Evaluate a location description, starting at DATA and with length
   SIZE, to find the current location of variable of TYPE in the
   context of FRAME.  BYTE_OFFSET is applied after the contents are
   computed.  */
static bool
is_vector(struct type *type){
	if (type->main_type != 0){
		if (type->main_type->flag_vector != 0){
				return true;
		}
		if (type->main_type->target_type != 0 && type->main_type->code != TYPE_CODE_UNDEF){
			 return is_vector(type->main_type->target_type);
		 }
		 return false;
 	 }
	return false;
}

//Address for vector varaiables calculated as vector so we nned to transform it to standart view
static CORE_ADDR
apex_adjust_dwarf_local_vars(struct type* type, CORE_ADDR addr){
	if (is_vector(type)){
		addr = addr * 32 + APEX_VIRTUAL_VEC_MEM;
	}
	return addr;
}


//Vector variables in the DWARF2 contains information about offset from the .vdata.VMb section
//so we must relocate it by our selves.
//it's backward compatibility dependency and will not fixed in the future.
static bool
apex_adjust_dwarf_symbol(struct symbol *symbol){

	if (!is_vector(symbol->type) || symfile_objfile == NULL){
		return false;
	}

	for (int i = 0; i < symfile_objfile->num_sections; i++){
		if (strcmp(symfile_objfile->sections[i].the_bfd_section->name,".vdata.VMb") == 0){
			symbol->ginfo.value.ivalue *= 32;
			symbol->ginfo.value.ivalue += symfile_objfile->sections[i].the_bfd_section->vma;
			symbol->ginfo.section = i;
			return true;
		}
	}

	return false;
}

static struct gdbarch *
apex_gdbarch_init (struct gdbarch_info info,
		   struct gdbarch_list *arches)
{
  static const char *const apex_sp_names[] = { "r31", "sp", NULL };
  static const char *const apex_vsp_names[] = { "r30", "vsp", NULL };
  static const char *const apex_lr_names[] = { "r29", "lr", NULL };
      
  struct gdbarch       *gdbarch;
  struct gdbarch_tdep  *tdep;
  struct tdesc_arch_data *tdesc_data = NULL;
  const struct target_desc *tdesc=info.target_desc;
  const struct tdesc_feature *feature,*feature_vcu,*feature_ctrl;

  int i;
  int valid_p = 1;
  unsigned int regs_num = 0;


  /* Ensure we always have a target descriptor.  */
  if (!tdesc_has_registers (tdesc)){
    //warning("tdesc has NO registers");
    tdesc = tdesc_apex;
  }
  gdb_assert (tdesc);

  
  feature = tdesc_find_feature (tdesc, "org.gnu.gdb.apex.apu.acp");

  if (feature == NULL){
    error ("apex_gdbarch_init: no feature org.gnu.gdb.apex.apu.acp");
    return NULL;
  }

  tdesc_data = tdesc_data_alloc ();


  for (i = 0; i < APEX_LR_REGNUM; i++){
    valid_p &= tdesc_numbered_register (feature, tdesc_data, i,
                                        acp_register_names[i]);
  }

  valid_p &= tdesc_numbered_register_choices (feature, tdesc_data, APEX_LR_REGNUM,
                                              apex_lr_names);
  i++;

  valid_p &= tdesc_numbered_register_choices (feature, tdesc_data, APEX_VSP_REGNUM,
                                              apex_vsp_names);
  i++;

  valid_p &= tdesc_numbered_register_choices (feature, tdesc_data, APEX_SP_REGNUM,
                                              apex_sp_names);
  i++;

  valid_p &= tdesc_numbered_register (feature, tdesc_data, APEX_OV_REGNUM, "ov");
  i++;
  
  valid_p &= tdesc_numbered_register (feature, tdesc_data, APEX_PC_REGNUM, "pc");
  i++;


  if (!valid_p) {
      tdesc_data_cleanup (tdesc_data);
      return NULL;
  }

    
  feature_vcu = tdesc_find_feature (tdesc, "org.gnu.gdb.apex.apu.vec");
    
  if (feature_vcu == NULL){
    error ("apex_gdbarch_init: no feature org.gnu.gdb.apex.apu.vec");
    return NULL;
  }

  for (; i < VECTORS_END; i++){
    valid_p &= tdesc_numbered_register (feature_vcu, tdesc_data, i,
                                        vcu_gp_regs[i-APEX_ACP_REGS_END]);
  }
  for (;i<VCU_REGS_END;i++){
	    valid_p &= tdesc_numbered_register (feature_vcu, tdesc_data, i,
	                                        vcu_ctl_regs[i-VECTORS_END]);
  }
  if (!valid_p){
     tdesc_data_cleanup (tdesc_data);
     return NULL;
  }
  feature_ctrl = tdesc_find_feature(tdesc,"org.gnu.gdb.apex.apu.acp.dbg");

  if (feature_ctrl == NULL){
    error ("apex_gdbarch_init: no feature org.gnu.gdb.apex.apu.acp.dbg");
    return NULL;
  }
  valid_p &= tdesc_numbered_register (feature_ctrl, tdesc_data, i,
	  	  	  	  	  	  	  	  	  ctrl_regs[i-VCU_REGS_END]);
  i++;
  valid_p &= tdesc_numbered_register (feature_ctrl, tdesc_data, i,
		  	  	  	  	  	  	  	  ctrl_regs[i-VCU_REGS_END]);
  i++;
  if (!valid_p){
     tdesc_data_cleanup (tdesc_data);
     return NULL;
  } else {
      regs_num += i;
  }


  tdep = XCNEW (struct gdbarch_tdep);
  gdbarch = gdbarch_alloc (&info, tdep);

  /* Target data types.  */
  set_gdbarch_short_bit             (gdbarch, 16);
  set_gdbarch_int_bit               (gdbarch, 32);
  set_gdbarch_long_bit              (gdbarch, 32);
  set_gdbarch_long_long_bit         (gdbarch, 64);

  /* Register architecture */
  set_gdbarch_pc_regnum (gdbarch, APEX_PC_REGNUM);
  set_gdbarch_sp_regnum (gdbarch, APEX_SP_REGNUM);
  set_gdbarch_num_regs  (gdbarch, regs_num);

    /* Information about the target architecture */
  set_gdbarch_return_value          (gdbarch, apex_return_value);
  set_gdbarch_breakpoint_from_pc    (gdbarch, apex_breakpoint_from_pc);

  set_tdesc_pseudo_register_type (gdbarch, apex_pseudo_register_type);

    /* Internal <-> external register number maps.  */
  set_gdbarch_dwarf2_reg_to_regnum (gdbarch, apex_dwarf_reg_to_regnum);

  /* Functions to supply register information */
  set_gdbarch_register_name         (gdbarch, apex_register_name);
  set_gdbarch_register_type         (gdbarch, apex_register_type);
 // set_gdbarch_print_registers_info  (gdbarch, apex_registers_info);

  /* Frame handling.  */
  set_gdbarch_dummy_id (gdbarch, apex_dummy_id);
  set_gdbarch_unwind_pc (gdbarch, apex_unwind_pc);
  set_gdbarch_unwind_sp (gdbarch, apex_unwind_sp);  
//  frame_unwind_append_unwinder (gdbarch, &apex_frame_unwind);

  /* Program counter */
  set_gdbarch_read_pc (gdbarch, apex_read_pc);

  /* Functions to analyse frames */
  set_gdbarch_skip_prologue         (gdbarch, apex_skip_prologue);
  //set_gdbarch_inner_than            (gdbarch, core_addr_lessthan);
  set_gdbarch_inner_than            (gdbarch, core_addr_greaterthan);//this function used to determine inner of frame

  /*Associates registers description with arch*/
  tdesc_use_registers (gdbarch, tdesc, tdesc_data);

  /* instruction set printer */
  set_gdbarch_print_insn (gdbarch, apex_gdb_print_insn);

  dwarf2_frame_set_init_reg (gdbarch, apex_dwarf2_frame_init_reg);

  frame_unwind_append_unwinder (gdbarch, &apex_stub_unwind);
  dwarf2_append_unwinders (gdbarch);
  frame_unwind_append_unwinder (gdbarch, &apex_prologue_unwind);

  frame_base_set_default (gdbarch, &apex_normal_base);

  set_gdbarch_adjust_dwarf2_local_vars(gdbarch, &apex_adjust_dwarf_local_vars);
  set_gdbarch_adjust_dwarf2_symbol(gdbarch, &apex_adjust_dwarf_symbol);

  return gdbarch;
} /* apex_gdbarch_init() */

/*----------------------------------------------------------------------------*/
/*!Dump the target specific data for this architecture

   @param[in] gdbarch  The architecture of interest
   @param[in] file     Where to dump the data */
/*---------------------------------------------------------------------------*/
static void
apex_dump_tdep (struct gdbarch *gdbarch,
		struct ui_file *file)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  if (NULL == tdep){
      return;			/* Nothing to report */
  }

  fprintf_unfiltered (file, "apex_dump_tdep: %d matchpoints available\n",
		      tdep->num_matchpoints);
  fprintf_unfiltered (file, "apex_dump_tdep: %d general purpose registers\n",
		      tdep->scalar_gp_regs_num);
  fprintf_unfiltered (file, "apex_dump_tdep: %d bytes per word\n",
		      tdep->bytes_per_scalar_word);
  fprintf_unfiltered (file, "apex_dump_tdep: %d bytes per address\n",
		      tdep->bytes_per_dmem_address);

}


/*----------------------------------------------------------------------------*/
/*!Main entry point for target architecture initialization

   In this version initializes the architecture via
   registers_gdbarch_init(). Add a command to set and show special purpose
   registers. */
/*---------------------------------------------------------------------------*/

static struct cmd_list_element *apexcmdlist = NULL;

static void
apex_command(char *args, int from_tty)
{
  printf_unfiltered (_("\
\"apex\" must be followed by an apporpriate subcommand.\n"));
  help_list (apexcmdlist, "apex ", all_commands, gdb_stdout);
}


/* allow to dinamically relocate obj file inside in tdep */
static void
apexcmd_dyn_relocate (char *cmd, int from_tty)
{
	//gdbarch_objfile_relocate(target_gdbarch ()/*, symfile_objfile*/);
	apex_objfile_relocate();
}

extern initialize_file_ftype _initialize_apex_tdep; /* -Wmissing-prototypes */


void
_initialize_apex_tdep (void)
{
	  gdbarch_register (bfd_arch_apex, apex_gdbarch_init, apex_dump_tdep);

	  initialize_tdesc_apex_apu();
	  /* Tell remote stub that we support XML target description.  */
	  register_remote_support_xml ("apex");


	  add_prefix_cmd ("apex", no_class, apex_command,
	  		  _("Various APEX-specific commands."),
	  		  &apexcmdlist, "apex ", 0, &cmdlist);

	  add_cmd ("dynamic-relocate", no_class, apexcmd_dyn_relocate,
	            _("Dynamic relocate object file."),
	            &apexcmdlist);
} /* _initialize_apex_tdep() */


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

#include <inttypes.h>

#include "dis-asm.h"
#include "common/errors.h"

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

CORE_ADDR apex_apu_data_mem_start;

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

static const gdb_byte *
apex_breakpoint_from_pc (struct gdbarch *gdbarch,
			 CORE_ADDR      *bp_addr,
			 int            *bp_size)
{
  static const gdb_byte breakpoint[] = {0};
  *bp_size = 1;
  return breakpoint;

}

/*static CORE_ADDR
apex_pc_to_imem_addr (ULONGEST pc, ULONGEST dm_start){

	CORE_ADDR imem_addr = (CORE_ADDR)(pc & 0xFFFFFFFF) *4 \
			- (CORE_ADDR)(dm_start & 0xFFFFFFFF);

	//for P&E_multilink_universal
	CORE_ADDR imem_addr;

	union mem_mapped_dm_start{
		unsigned long addr;
		gdb_byte addr_bytes[4];
	}mem_mapped_dm_start;

	if(0 > target_read_memory(0x0018000cU,mem_mapped_dm_start.addr_bytes,4)){
		fprintf(stderr,"_apex_pc_to_imem_addr_: \
				can't read from target memory with target_read_memory\n");
		return 0;
	}
	imem_addr = pc*4 - mem_mapped_dm_start.addr;

	return imem_addr;
}*/

static CORE_ADDR
apex_read_pc (struct regcache* regcache){

	  ULONGEST dm_start_temp, pc;
	  regcache_cooked_read_unsigned (regcache, APEX_PC_REGNUM, &pc);
	  regcache_cooked_read_unsigned (regcache, cmem_if_apu_dm_start_regnum, &dm_start_temp);
	  apex_apu_data_mem_start = (CORE_ADDR)(dm_start_temp & 0xFFFFFFFF);
	  return (CORE_ADDR)(pc & 0xFFFFFFFF);
}

/* Implement the "unwind_pc" gdbarch method.  */
static CORE_ADDR
apex_unwind_pc (struct gdbarch *gdbarch, struct frame_info *this_frame){

	  ULONGEST pc;
	  pc = frame_unwind_register_unsigned (this_frame, APEX_PC_REGNUM);
	  return (CORE_ADDR)(pc&0xFFFFFFFF);
}

/* Implement the "unwind_sp" gdbarch method.  */
static CORE_ADDR
apex_unwind_sp (struct gdbarch *gdbarch, struct frame_info *this_frame)
{
	return frame_unwind_register_unsigned (this_frame, APEX_SP_REGNUM);
}
/* apex cache structure.  */
struct apex_unwind_cache
{
  /* The frame's base, optionally used by the high-level debug info.  */
  CORE_ADDR base;

  /* The previous frame's inner most stack address.  Used as this
     frame ID's stack_ baddr.  */
  CORE_ADDR cfa;

  /* The address of the first instruction in this function */
  CORE_ADDR pc;

  /* The offset of register saved on stack.  If register is not saved, the
     corresponding element is -1.  */
  CORE_ADDR reg_saved[APEX_ACP_REGS_END];
};

static void
apex_setup_default (struct apex_unwind_cache *cache)
{
  int i;

  for (i = 0; i < APEX_ACP_REGS_END; i++)
    cache->reg_saved[i] = -1;
}

/* Returns the address of the first instruction after the prologue.  */
static CORE_ADDR
apex_analyze_prologue (struct gdbarch *gdbarch,
		       CORE_ADDR start_pc, CORE_ADDR current_pc,
		       struct apex_unwind_cache *cache,
		       struct frame_info *this_frame)
{
  CORE_ADDR pc = start_pc;
  CORE_ADDR return_pc = start_pc;
  int frame_base_offset_to_sp = 0;

  if (start_pc >= current_pc)
    return_pc = current_pc;

  if (cache)
  {
    cache->base = 0;

    if (this_frame)
      {
	cache->base = get_frame_register_unsigned (this_frame, APEX_SP_REGNUM);
	cache->cfa = cache->base + frame_base_offset_to_sp;
      }
  }

  return return_pc;
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
  if (find_pc_partial_function (pc, NULL, &func_addr, NULL))
    {
      CORE_ADDR post_prologue_pc =
	skip_prologue_using_sal (gdbarch, func_addr);

      if (post_prologue_pc != 0)
	return max (pc, post_prologue_pc);
    }

   return pc;
}

/* Frame base handling.  */
static struct apex_unwind_cache *
apex_frame_unwind_cache (struct frame_info *this_frame, void **this_cache)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  struct apex_unwind_cache *cache;
  CORE_ADDR current_pc;

  if (*this_cache != NULL)
    return (struct apex_unwind_cache *) *this_cache;

  cache = FRAME_OBSTACK_ZALLOC (struct apex_unwind_cache);
  (*this_cache) = cache;

  apex_setup_default (cache);

  cache->pc = get_frame_func (this_frame);
  current_pc = get_frame_pc (this_frame);

  /* Prologue analysis does the rest...  */
  if ((cache->pc & 0xFFFFFFFF) != 0)
    apex_analyze_prologue (gdbarch, cache->pc, current_pc, cache, this_frame);

  return cache;
}

/* Implement the "stop_reason" frame_unwind method.  */
static enum unwind_stop_reason
apex_frame_unwind_stop_reason (struct frame_info *this_frame,
					   void **this_cache)
{
  struct apex_unwind_cache *cache
    = apex_frame_unwind_cache (this_frame, this_cache);

  /* We've hit a wall, stop.  */
  if (cache->base == 0)
    return UNWIND_OUTERMOST;

  return UNWIND_NO_REASON;
}

static void
apex_frame_this_id (struct frame_info *this_frame,
			  void **this_cache, struct frame_id *this_id)
{
  struct apex_unwind_cache *cache =
     apex_frame_unwind_cache (this_frame, this_cache);

  /* This marks the outermost frame.  */
  if (cache->base == 0)
    return;

  (*this_id) = frame_id_build (cache->cfa, cache->pc);
}

static struct value *
apex_frame_prev_register (struct frame_info *this_frame,
			  void **this_cache, int regnum)
{
  struct apex_unwind_cache *cache =
	apex_frame_unwind_cache (this_frame, this_cache);
  CORE_ADDR noFrame;
  int i;

  /* If we are asked to unwind the PC, then we need to unwind PC ? */
  if (regnum == APEX_PC_REGNUM)
      //return apex_prev_pc_register(this_frame);
	  return frame_unwind_got_register(this_frame,regnum, regnum);

  if (regnum == APEX_SP_REGNUM && cache->cfa)
    return frame_unwind_got_constant (this_frame, regnum, cache->cfa);

  /* If we've worked out where a register is stored then load it from
     there.  */
  if (regnum < APEX_ACP_REGS_END && cache->reg_saved[regnum] != -1)
    return frame_unwind_got_memory (this_frame, regnum,
				    cache->reg_saved[regnum]);

  return frame_unwind_got_register (this_frame, regnum, regnum);
}

/* APEX prologue unwinder.  */
static const struct frame_unwind apex_frame_unwind =
{
  NORMAL_FRAME,
  apex_frame_unwind_stop_reason,
  apex_frame_this_id,
  apex_frame_prev_register,
  NULL,
  default_frame_sniffer
};

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

static int
apex_gdb_print_insn (bfd_vma memaddr, disassemble_info *info){

	return print_insn_apex (memaddr*4-apex_apu_data_mem_start, info);
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

  for (i; i < VECTORS_END; i++){
    valid_p &= tdesc_numbered_register (feature_vcu, tdesc_data, i,
                                        vcu_gp_regs[i-APEX_ACP_REGS_END]);
  }
  for (i;i<VCU_REGS_END;i++){
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
  set_gdbarch_unwind_pc (gdbarch, apex_unwind_pc);
  set_gdbarch_unwind_sp (gdbarch, apex_unwind_sp);  
  frame_unwind_append_unwinder (gdbarch, &apex_frame_unwind);

  /* Program counter */
  set_gdbarch_read_pc (gdbarch, apex_read_pc);

  /* Functions to analyse frames */
  set_gdbarch_skip_prologue         (gdbarch, apex_skip_prologue);
  set_gdbarch_inner_than            (gdbarch, core_addr_lessthan);

  /*Associates registers description with arch*/
  tdesc_use_registers (gdbarch, tdesc, tdesc_data);

  /* instruction set printer */
  set_gdbarch_print_insn (gdbarch, apex_gdb_print_insn);



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

extern initialize_file_ftype _initialize_apex_tdep; /* -Wmissing-prototypes */

void
_initialize_apex_tdep (void)
{
	  gdbarch_register (bfd_arch_apex, apex_gdbarch_init, apex_dump_tdep);

	  initialize_tdesc_apex_apu();
	  /* Tell remote stub that we support XML target description.  */
	  register_remote_support_xml ("apex");


} /* _initialize_apex_tdep() */


/*
 * Copyrights
 */

#ifndef OPCODE_APEX_H
#define OPCODE_APEX_H

#define SHIFT_LEFT(v, p) ((v)<<(p)) //v - value; p - number of positions to shift
#define SHIFT_RIGHT(v, p) ((v)>>(p))

#define OPERAND_s0				0x00000C00U //[10:11] bits
#define OPERAND_i0				0x01C00000U //[22:24] bits
#define OPERAND_i0_shftd_right	0x00380000U //[19:21] bits
#define OPERAND_d0				0x01800000U //[22:23] bits

#define MAX_OPERANDS            8

typedef enum operand_type{
	gap,
	reg_t,
    vreg_t,
	imm_t,
	imm_t_lsp, //less significant part of imm
	imm_t_msp, //most significant part of imm
    int5_t,
    int12_t,
	vcs_t,
	f_t,
	sel_t,
    neg_op_t,
/*    vadd_cmd, //set of short commands
    vmull_cmd,
    vacc_cmd,
    vcomp_cmd*/
    vadd_op_t,
    vadd_op3_t,
    vmul_op1_t,
    vmul_op2_t,
    vmul_op3_t,
    vmul_op4_t,
    vcomp_op_t,
    vec_ldst_op1_t,
    vec_ldst_op2_t,
    vnop_t,
    vmov_op1_t,
    vmov_op2_t,
    vmov_op3_t,
    vsh_op1_t,
    vsh_op2_t,
    vsh_op3_t,
    vsh_op4_t,
    vsh_vc_op1_t,
    vsh_vc_op2_t,
    vsh_vc_op3_t,
    vswap_op_t,
    vcreg_t,
    
    valu_short_t,
    vmul_short_t,
    vsh_short_t,
    vldst_short_t,
    vldst2_short_t,
    vswap_short_t,
}operand_type;

typedef struct apex_opc_info_t
{
  const char *name;
  unsigned long opcode;
  unsigned int num_of_operands;
  operand_type op_type[MAX_OPERANDS];
  unsigned long op_mask[MAX_OPERANDS]; //operands positions
  unsigned int op_offset[MAX_OPERANDS];
  unsigned long non_read_pos; //positions of instr, that not reads by.

} apex_opc_info_t;

typedef struct apex_64_bit_opc_info_t
{
  const char *name;
  unsigned long long opcode;
  unsigned int num_of_operands;
  operand_type op_type[MAX_OPERANDS];
  unsigned long long op_mask[MAX_OPERANDS];
  unsigned int op_offset[MAX_OPERANDS];
  unsigned long long non_read_pos;

} apex_64_bit_opc_info_t;

//command tables
extern const apex_opc_info_t apex_short_valu_op_opc_info[];
extern const apex_opc_info_t apex_short_vmul_op_opc_info[];
extern const apex_opc_info_t apex_short_vsh_op_opc_info[];
extern const apex_opc_info_t apex_short_vldst_op_opc_info[];
extern const apex_opc_info_t apex_short_vldst2_op_opc_info[];
extern const apex_opc_info_t apex_short_vswap_op_opc_info[];

#endif // OPCODE_APEX_H

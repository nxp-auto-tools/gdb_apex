/*
 * Copyrights
 */
#include "sysdep.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "dis-asm.h"
#include "apex-opc.h"
#include "apex-dis.h"
#include "elf-bfd.h"

#define SINGLE_CMD_SIZE 4
#define DOUBLE_CMD_SIZE 8

#define MAX_STR 255

typedef struct operand{
	int value;
	operand_type type;
}operand;

const char* vcs_str[] = {
		"push_l 0",
		"push_l 2",
		"nop",
		"fpop",
		"push_l 1",
		"push_l 3",
		"flip",
		"pop"
};
extern const apex_opc_info_t apex_APC_32b_scalar_opc_info[];
extern const apex_64_bit_opc_info_t apex_APC_64b_scalar_opc_info[];
extern const apex_opc_info_t apex_APC_32b_vector_opc_info[];

extern const char* vmul_op1[];
extern const char* vmul_op2[];
extern const char* vmul_op3[];
extern const char* vmul_op4[];
extern const char* vadd_op[];
extern const char* vadd_op3[];
extern const char* vcomp_op[];
extern const char* vec_ldst_op1[];
extern const char* vec_ldst_op2[];
extern const char* vnop[];
extern const char* vmov_op1[];
extern const char* vmov_op2[];
extern const char* vmov_op3[];

extern const char* vsh_op1[];
extern const char* vsh_op2[];
extern const char* vsh_op3[];
extern const char* vsh_op4[];
extern const char* vsh_vc_op1[];
extern const char* vsh_vc_op2[];
extern const char* vsh_vc_op3[];
extern const char* vswap_op[];
extern const char* neg_op[];

//extern const apex_opc_info_t apex_short_vadd_op_opc_info[];
//extern const apex_opc_info_t apex_short_vmul_opc_info[];

int get_instruction_type (bfd_vma instruction_word);
const apex_opc_info_t* find_in_table (const apex_opc_info_t* table, bfd_vma insn_bits);
const apex_opc_info_t* find_in_table_scalar_insn_part (const apex_opc_info_t* table, bfd_vma insn_bits);
const apex_opc_info_t* find_in_table_vector_insn_part (const apex_opc_info_t* table, bfd_vma insn_bits);
const apex_64_bit_opc_info_t* find_in_vliw_table (const apex_64_bit_opc_info_t* table, vliw_t insn_bits);
int extract_operands (const apex_opc_info_t* operation,operand* operands,bfd_vma insn_bits);
int extract_vliw_operands (const apex_64_bit_opc_info_t* operation,operand* operands,vliw_t insn_bits);
int compose_scalar_mnemonic (const apex_opc_info_t* instruction,operand* operands,char* string, bool vliw);
int compose_64b_scalar_mnemonic (const apex_64_bit_opc_info_t* instruction,operand* operands,char* string);
int compose_vector_mnemonic (const apex_opc_info_t* instruction,operand* operands,char* string, bool vliw);
int (*compose_mnemonic) (const apex_opc_info_t* instruction,operand* operands,char* string, bool vliw);

int get_instruction_type (bfd_vma instruction_word){ //read first two bit in instruction
	instruction_word &=0xc0000000;
	instruction_word >>= 30;
	switch (instruction_word){
	case 0:
		return scalar_instruction_type;
	case 1:
		return vector_instruction_type;
	case 2:
		return combined_instruction_type;
	case 3:
		return scalar64_instruction_type;
	default:
		return wrong_insruction_type;
	}
}
const apex_opc_info_t* find_in_table (const apex_opc_info_t* table, bfd_vma insn_bits){ // brute force yet
	bfd_vma op_pos;//operand position
	unsigned int ind;
	for(;table->name;table++){
		for (ind=0,op_pos=0;ind<table->num_of_operands;ind++)
			op_pos|=SHIFT_LEFT(table->op_mask[ind],table->op_offset[ind]);
		op_pos|=table->non_read_pos;
		if ((insn_bits & ~op_pos) == table->opcode)
			return table;
	}
	return NULL;
}
const apex_opc_info_t* find_in_table_scalar_insn_part (const apex_opc_info_t* table, bfd_vma insn_bits){ // brute force yet
	bfd_vma op_pos;//operand position
	unsigned int ind;
	for(;table->name;table++){
		for (ind=0,op_pos=0;ind<table->num_of_operands;ind++)
			op_pos|=SHIFT_LEFT(table->op_mask[ind],table->op_offset[ind]);
		op_pos|=table->non_read_pos;
		if (((insn_bits) & ~op_pos) == (table->opcode | 0x80000000))
			return table;
	}
	return NULL;
}
const apex_opc_info_t* find_in_table_vector_insn_part (const apex_opc_info_t* table, bfd_vma insn_bits){ // brute force yet
	bfd_vma op_pos;//operand position
	unsigned int ind;
	for(;table->name;table++){
		for (ind=0,op_pos=0;ind<table->num_of_operands;ind++)
			op_pos|=SHIFT_LEFT(table->op_mask[ind],table->op_offset[ind]);
		op_pos|=table->non_read_pos;
		if (((insn_bits & 0x3FFFFFFF) & ~op_pos) == (table->opcode & 0x3FFFFFFF))
			return table;
	}
	return NULL;
}
const apex_64_bit_opc_info_t* find_in_vliw_table (const apex_64_bit_opc_info_t* table, vliw_t insn_bits){ // brute force yet
	vliw_t op_pos;//operand position
	unsigned int ind;
	for(;table->name;table++){
		for (ind=0,op_pos=0;ind<table->num_of_operands;ind++)
			op_pos|=SHIFT_LEFT(table->op_mask[ind],table->op_offset[ind]);
		op_pos|=table->non_read_pos;
		if ((insn_bits & ~op_pos) == table->opcode)
			return table;
	}
	return NULL;
}

int extract_operands (const apex_opc_info_t* operation,operand* operands,bfd_vma insn_bits){

	unsigned int index;
	for (index=0; index<operation->num_of_operands;index++){
		operands[index].type = operation->op_type[index];
		operands[index].value = SHIFT_RIGHT(insn_bits, operation->op_offset[index]) & operation->op_mask[index];
	}
	return index;
}
int extract_vliw_operands (const apex_64_bit_opc_info_t* operation,operand* operands,vliw_t insn_bits){

	unsigned int index;
	for (index=0; index<operation->num_of_operands;index++){
		operands[index].type = operation->op_type[index];
		operands[index].value = SHIFT_RIGHT(insn_bits, operation->op_offset[index]) & operation->op_mask[index];
	}
	return index;
}

int compose_scalar_mnemonic (const apex_opc_info_t* instruction,operand* operands, char* string, bool vliw){
	unsigned int index;
	char value_string [MAX_STR];
	memset (value_string,0,MAX_STR);
	strncat(string, instruction->name, MAX_STR);
	for (index=0;index<instruction->num_of_operands;index++){
		switch(operands[index].type){
		case gap:
			strncat(string," _g_", MAX_STR);
			break;
		case reg_t:
			strncat(string," r", MAX_STR);
			snprintf(value_string, MAX_STR,"%d",operands[index].value);
			break;
        case vreg_t:
            strncat(string," v", MAX_STR);
			snprintf(value_string,MAX_STR,"%d",operands[index].value);
            break;  
		case imm_t:
			strncat(string," #", MAX_STR);
			snprintf(value_string, MAX_STR,"%d",operands[index].value);
			break;
		default:
	        fprintf (stdout,"_compose_scalar_mnemonic: wrong operand type\n");
	        break;

		}
	strncat(string,value_string, MAX_STR);
	}
	return strlen(string);
}
int compose_64b_scalar_mnemonic (const apex_64_bit_opc_info_t* instruction,operand* operands, char* string){
	unsigned int index;
	char value_string [MAX_STR];
	memset (value_string,0,MAX_STR);
	strncat(string, instruction->name, MAX_STR);
	if (strlen(instruction->name) == 0){//combined instruction no name
			strncat(string,".vliw_start", MAX_STR);
	}
	for (index=0;index<instruction->num_of_operands;index++){
		switch(operands[index].type){
		case gap:
			strncat(string," _g_", MAX_STR);
			break;
		case reg_t:
			strncat(string," r", MAX_STR);
			snprintf(value_string, MAX_STR,"%d",operands[index].value);
			break;
		case imm_t:
			strncat(string," #", MAX_STR);
			snprintf(value_string, MAX_STR,"%d",operands[index].value);
			break;
        
                
        case valu_short_t:
                find_and_compose(apex_short_valu_op_opc_info, operands[index].value, string);
                break;
        case vmul_short_t:
                find_and_compose(apex_short_vmul_op_opc_info, operands[index].value, string);
                break;
        case vsh_short_t:
                find_and_compose(apex_short_vsh_op_opc_info, operands[index].value, string);
                break;
        case vldst_short_t:
                find_and_compose(apex_short_vldst_op_opc_info, operands[index].value, string);
                break;
        case vldst2_short_t:
                find_and_compose(apex_short_vldst2_op_opc_info, operands[index].value, string);
                break;
        case vswap_short_t:
                find_and_compose(apex_short_vswap_op_opc_info, operands[index].value, string);
                break;
		default:
	        fprintf (stdout,"_compose_scalar_mnemonic: wrong operand type\n");
	        break;

		}
	strncat(string,value_string, MAX_STR);
	}
	if (strlen(instruction->name) == 0){//combined instruction no name
		strncat(string,"\n.vliw_end", MAX_STR);
	}
	return strlen(string);
}

void find_and_compose(const apex_opc_info_t* opc_table, bfd_vma instruction, char* string){
	operand opr[MAX_OPERANDS];
    const apex_opc_info_t *table;
	memset(opr, 0, MAX_OPERANDS*sizeof(opr[0]));

	table = find_in_table(opc_table,instruction);
    if (table != NULL){
    	if (extract_operands(table, opr, instruction) != 0){
    		compose_vector_mnemonic(table, opr, string, true);
    		//strncat(string, "\n", MAX_STR);
    	}else{
    		strncat(string,"\n", MAX_STR);
    		strncat(string,table->name, MAX_STR);//nope instruction
    	}
	}else{
		strncat(string, "\n__compose error", MAX_STR);
	}
}

int compose_vector_mnemonic (const apex_opc_info_t* instruction,operand* operands, char* string, bool vliw){
	unsigned int index;
	int imm;
	char value_string [MAX_STR];
	memset (value_string,0,MAX_STR);

    if (vliw==true && strlen(instruction->name) != 0){
        strncat(string, "\n", MAX_STR);
    }
	strncat(string, instruction->name, MAX_STR);
	if (strlen(instruction->name) == 0 && vliw == false){//combined instruction no name
		strncat(string,".vliw_start", MAX_STR);
	}
	for (index=0;index<instruction->num_of_operands;index++){
		memset (value_string,0,MAX_STR);
		switch(operands[index].type){
		case gap:
			strncat(string," _g_", MAX_STR);
			break;
		case reg_t:
			strncat(string," r", MAX_STR);
			snprintf(value_string, MAX_STR,"%d",operands[index].value);
			break;
        case vreg_t:
            strncat(string," v", MAX_STR);
			snprintf(value_string, MAX_STR,"%d",operands[index].value);
            break;                
		case imm_t:
			strncat(string," #", MAX_STR);
			snprintf(value_string, MAX_STR,"%d",operands[index].value);
			break;
		case imm_t_lsp:
			imm = 0;
			if(index<instruction->num_of_operands-1){
				if(operands[index+1].type==imm_t_msp){
					unsigned int imm_lsp_len;
					if (instruction->op_mask[index] == 0x3FF)
						imm_lsp_len = 10; // Less significant part of imm got 10-bits len
					else if (instruction->op_mask[index] == 0x1F)
						imm_lsp_len = 5; // Less significant part of imm got 5-bits len
					imm=(SHIFT_LEFT(operands[index+1].value,imm_lsp_len)|operands[index].value);
				index++;
				}
			}
			strncat(string," #", MAX_STR);
			snprintf(value_string, MAX_STR,"%d",imm);
		break;
		case vcs_t:
			strncat(string," vcs", MAX_STR);
			snprintf(value_string, MAX_STR,"%s", vcs_str[operands[index].value]);
			break;
		case f_t:
			strncat(string," flag=", MAX_STR);
			if (operands[index].value > 0)
				snprintf(value_string, MAX_STR,"true");
			else
				snprintf(value_string, MAX_STR,"false");
			break;
		case sel_t:
			strncat(string, MAX_STR," sel");
			snprintf(value_string, MAX_STR,"%d",operands[index].value);
			break;
        case vadd_op_t:
        	strncat(string, "\n", MAX_STR);
            strncat(string, vadd_op[operands[index].value], MAX_STR);
            break;
        case vadd_op3_t:
        	strncat(string, "\n", MAX_STR);
            strncat(string, vadd_op3[operands[index].value], MAX_STR);
            break;
        case vmul_op1_t:
        	strncat(string, "\n", MAX_STR);
            strncat(string, vmul_op1[operands[index].value], MAX_STR);
            break;
        case vmul_op2_t:
        	strncat(string, "\n", MAX_STR);
            strncat(string, vmul_op2[operands[index].value], MAX_STR);
            break;
        case vmul_op3_t:
        	strncat(string, "\n", MAX_STR);
            strncat(string, vmul_op3[operands[index].value], MAX_STR);
            break;
        case vmul_op4_t:
        	strncat(string, "\n", MAX_STR);
            strncat(string, vmul_op4[operands[index].value], MAX_STR);
            break;
        case vcomp_op_t:
        	strncat(string, "\n", MAX_STR);
            strncat(string, vcomp_op[operands[index].value], MAX_STR);
            break;
        case vec_ldst_op1_t:
        	strncat(string, "\n", MAX_STR);
            strncat(string, vec_ldst_op1[operands[index].value], MAX_STR);
            break;
        case vec_ldst_op2_t:
        	strncat(string, "\n", MAX_STR);
            strncat(string, vec_ldst_op2[operands[index].value], MAX_STR);
            break;
        case vnop_t:
        	strncat(string, "\n", MAX_STR);
            strncat(string, vnop[0], MAX_STR);
            break;
        case vmov_op1_t:
        	strncat(string, "\n", MAX_STR);
            strncat(string, vmov_op1[operands[index].value], MAX_STR);
            break;
        case vmov_op2_t:
        	strncat(string, "\n", MAX_STR);
            strncat(string, vmov_op2[operands[index].value], MAX_STR);
            break;
        case vmov_op3_t:
        	strncat(string, "\n", MAX_STR);
            strncat(string, vmov_op3[operands[index].value], MAX_STR);
            break;
                
        case vsh_op1_t:
        	strncat(string, "\n", MAX_STR);
            strncat(string, vsh_op1[operands[index].value], MAX_STR);
            break;
        case vsh_op2_t:
        	strncat(string, "\n", MAX_STR);
            strncat(string, vsh_op2[operands[index].value], MAX_STR);
            break;
        case vsh_op3_t:
        	strncat(string, "\n", MAX_STR);
            strncat(string, vsh_op3[operands[index].value], MAX_STR);
            break;
        case vsh_op4_t:
        	strncat(string, "\n", MAX_STR);
            strncat(string, vsh_op4[operands[index].value], MAX_STR);
            break;
                
        case vsh_vc_op1_t:
        	strncat(string, "\n", MAX_STR);
            strncat(string, vsh_vc_op1[operands[index].value], MAX_STR);
            break;
        case vsh_vc_op2_t:
        	strncat(string, "\n", MAX_STR);
            strncat(string, vsh_vc_op2[operands[index].value], MAX_STR);
            break;
        case vsh_vc_op3_t:
        	strncat(string, "\n", MAX_STR);
            strncat(string, vsh_vc_op3[operands[index].value], MAX_STR);
            break;
        case vswap_op_t:
        	strncat(string, "\n", MAX_STR);
            strncat(string, vswap_op[operands[index].value], MAX_STR);
            break;
        case neg_op_t:
            strncat(string, "\n", MAX_STR);
            strncat(string, neg_op[operands[index].value], MAX_STR);
            break;
                
        case int5_t:{
            signed char t = operands[index].value;
            t = (t & 0x10) ? (t|0xF0) : t;
            snprintf(value_string," %d(#%d)",t, operands[index].value, MAX_STR);
            }
            break;
        case int12_t:{
            signed short t = operands[index].value;
            t = (t & 0x800) ? (t|0xF000) : t;
            snprintf(value_string," %d(#%d)",t, operands[index].value, MAX_STR);
            }
            break;
        case vcreg_t:
            strncat(string," vc", MAX_STR);
			snprintf(value_string,"%d",operands[index].value, MAX_STR);
            break;               
/*                
        case vadd_cmd:
        	find_and_compose(apex_short_vadd_op_opc_info, operands[index].value, string);
            break;
        case vmull_cmd:
        	find_and_compose(apex_short_vmul_opc_info, operands[index].value, string);
            break;
*/            
		}
	strncat(string,value_string, MAX_STR);
	}

	if (strlen(instruction->name) == 0 && vliw == false){//combined instruction no name
		strncat(string,"\n.vliw_end", MAX_STR);
	}

	return strlen(string);
}

/*Return vaules is offset to next command*/
int
print_insn_apex(bfd_vma cur_insn_addr, disassemble_info *info){

	bfd_vma next_insn_addr = cur_insn_addr + bytes_per_word;
	bfd_vma cur_pc = cur_insn_addr;
	bfd_vma high_bits,low_bits;
	bfd_byte instr_low_bytes [bytes_per_word];
	bfd_byte instr_high_bytes [bytes_per_word];
	const apex_opc_info_t *opcode_table;
	const apex_opc_info_t *current_instruction,*scalar_insn_part,*vector_insn_part;
	operand operands[MAX_OPERANDS];
	char insns_mnemonic[mnemomic_string_len];

	memset(insns_mnemonic,0,mnemomic_string_len);
	memset(operands,0,MAX_OPERANDS*sizeof(operands[0]));

    // read instruction-word at address pointed by "pc"
	int status = (*info->read_memory_func) (cur_pc, instr_high_bytes,
    									bytes_per_word, info);

    if (status != 0){
      (*info->memory_error_func) (status, cur_insn_addr, info);
      fprintf (stderr,"memory read func worked in wrong way\n");
      return -1;
    }

    // todo:
    // To disassemble from ELF we need "is_big_endian = 1",
    // while from target "is_big_endian = 0"; Some mechanism should be implemented
    // high_bits = bfd_get_bits (instr_high_bytes, bits_per_word, is_big_endian);
    high_bits = bfd_get_bits (instr_high_bytes, bits_per_word, 0);//0 - disassemble target

    switch (get_instruction_type(high_bits)){

    case scalar_instruction_type:
    	compose_mnemonic = compose_scalar_mnemonic;
    	opcode_table = apex_APC_32b_scalar_opc_info;
    	break;
    case vector_instruction_type:
    	compose_mnemonic = compose_vector_mnemonic;
    	opcode_table = apex_APC_32b_vector_opc_info;
    	break;

    case combined_instruction_type:
        // read next instruction-word at address pointed by "pc+1" (for 64-bit insns)
        status = (*info->read_memory_func) (cur_pc + SINGLE_CMD_SIZE, instr_low_bytes,
        		bytes_per_word, info);
        if (status != 0)
        {
          (*info->memory_error_func) (status, cur_pc + SINGLE_CMD_SIZE, info);
          return -1;
        }
        // todo:
        // To disassemble from ELF we need "is_big_endian = 1",
        // while from target "is_big_endian = 0"; Some mechanism should be implemented
        // high_bits = bfd_get_bits (instr_high_bytes, bits_per_word, is_big_endian);
        low_bits = bfd_get_bits (instr_low_bytes, bits_per_word, 0);// 0 - disassemble target
    	opcode_table = apex_APC_32b_scalar_opc_info;
    	scalar_insn_part = find_in_table_scalar_insn_part(opcode_table,high_bits);
     	opcode_table = apex_APC_32b_vector_opc_info;
    	vector_insn_part = find_in_table_vector_insn_part(opcode_table,low_bits);
        info->fprintf_func(info->stream, "_vliw ");
    	compose_mnemonic = compose_scalar_mnemonic;
    	int scalar_result = 0;
        if (scalar_insn_part != NULL){
        	if(extract_operands(scalar_insn_part,operands,high_bits)==scalar_insn_part->num_of_operands){
        		scalar_result = compose_mnemonic(scalar_insn_part,operands,insns_mnemonic,false);
        		strncat(insns_mnemonic,"\n", MAX_STR);
        	} else {
                fprintf (stdout,"_print_insn_combined_: scalar operands extracted in wrong way; addr=0x%08lx\n",cur_pc);
                info->fprintf_func(info->stream, "0x%08lx ",high_bits);
        	}
        } else{
            fprintf (stdout,"_print_insn_combined_: scalar insn part not found; addr=0x%08lx\n",cur_pc);
            info->fprintf_func(info->stream, "0x%08lx ",high_bits);
        }
		compose_mnemonic = compose_vector_mnemonic;
		if (vector_insn_part != NULL){
			if(extract_operands(vector_insn_part,operands,high_bits)==vector_insn_part->num_of_operands){
				compose_mnemonic(vector_insn_part,operands,insns_mnemonic,false);
				info->fprintf_func(info->stream, " %s", insns_mnemonic);
			} else {
		        if(scalar_result>0)
					info->fprintf_func(info->stream, " %s", insns_mnemonic);
		        info->fprintf_func(info->stream, "0x%08lx ",low_bits);
		        fprintf (stdout,"_print_insn_combined_: vector operands extracted in wrong way; addr=0x%08lx\n",cur_pc);
			}
		} else {
	        if(scalar_result>0)
				info->fprintf_func(info->stream, " %s", insns_mnemonic);
	        info->fprintf_func(info->stream, "0x%08lx ",low_bits);
	        fprintf (stdout,"_print_insn_combined_: vector insn part not found; addr=0x%08lx;\n",cur_pc);

		}
		return DOUBLE_CMD_SIZE;
    case scalar64_instruction_type:
        // read next instruction-word at address pointed by "pc+1" (for 64-bit insns)
        status = (*info->read_memory_func) (next_insn_addr, instr_low_bytes,
        		bytes_per_word, info);
        if (status != 0)
        {
          (*info->memory_error_func) (status, next_insn_addr, info);
          return -1;
        }
        low_bits = bfd_get_bits (instr_low_bytes, bits_per_word, is_big_endian);

        //composing vliw_command
        vliw_t vliw_insn_value = high_bits;
        vliw_insn_value<<=bits_per_word;
        vliw_insn_value|=low_bits;

        const apex_64_bit_opc_info_t *vliw_opcode_table=apex_APC_64b_scalar_opc_info;

    	const apex_64_bit_opc_info_t *vliw_insn_entity = find_in_vliw_table(vliw_opcode_table,vliw_insn_value);
        //info->fprintf_func(stdout, "_vliw ");

        if (vliw_insn_entity != NULL){
        	extract_vliw_operands(vliw_insn_entity,operands,vliw_insn_value);
        	if(compose_64b_scalar_mnemonic(vliw_insn_entity,operands,insns_mnemonic)>0){
        		info->fprintf_func(info->stream, "%s",insns_mnemonic);
        		return DOUBLE_CMD_SIZE;
        	}
        }
        fprintf (stdout,"_print_insn_scalar_64b_: unparsed command with addr=0x%08lx\n",cur_pc);
        info->fprintf_func(info->stream, "0x%08lx ",high_bits);
        info->fprintf_func(info->stream, "0x%08lx ",low_bits);
		return DOUBLE_CMD_SIZE;

    default:
    	fprintf (stdout,"_print_insn: unrecognized insn type\n");
        info->fprintf_func(info->stream, "0x%08lx",high_bits);
    	return SINGLE_CMD_SIZE;
    }


    current_instruction = find_in_table(opcode_table,high_bits);

    if (current_instruction != NULL){
    	extract_operands(current_instruction,operands,high_bits);
    	if(compose_mnemonic(current_instruction,operands,insns_mnemonic, false)>0){
    		info->fprintf_func(info->stream,"%s", insns_mnemonic);
    		return SINGLE_CMD_SIZE;
    	}
    }

    fprintf (stdout,"_print_insn: unparsed command with addr=0x%08lx\n",cur_pc);
    info->fprintf_func(info->stream, "0x%08lx",high_bits);
	return SINGLE_CMD_SIZE;
}

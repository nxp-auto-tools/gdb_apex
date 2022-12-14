/*
 * Copyrights
 */


#include "sysdep.h"
#include "apex-opc.h"

const apex_opc_info_t apex_APC_32b_scalar_opc_info[] =
{
		/*Load and Store instructions*/
	{        "lb", 0x18000000UL, 3, {reg_t,reg_t,imm_t,	gap,gap}, {0x1F,0x1F,0x7fff,0,0},	{20,15,0,0,0}, 		0},
	{       "lbu", 0x1A000000UL, 3, {reg_t,reg_t,imm_t,	gap,gap}, {0x1F,0x1F,0x7fff,0,0},	{20,15,0,0,0}, 		0},
	{  		 "lh", 0x1C000000UL, 3, {reg_t,reg_t,imm_t,	gap,gap}, {0x1F,0x1F,0x7fff,0,0},	{20,15,0,0,0}, 		0},
	{       "lhu", 0x20000000UL, 3, {reg_t,reg_t,imm_t,	gap,gap}, {0x1F,0x1F,0x7fff,0,0},	{20,15,0,0,0}, 		0},
	{        "lw", 0x22000000UL, 3, {reg_t,reg_t,imm_t,	gap,gap}, {0x1F,0x1F,0x7fff,0,0},	{20,15,0,0,0}, 		0},
	{      	 "sb", 0x26000000UL, 3, {reg_t,reg_t,imm_t,	gap,gap}, {0x1F,0x1F,0x7fff,0,0},	{20,15,0,0,0}, 		0},
	{        "sh", 0x28000000UL, 3, {reg_t,reg_t,imm_t,	gap,gap}, {0x1F,0x1F,0x7fff,0,0},	{20,15,0,0,0}, 		0},
	{        "sw", 0x2A000000UL, 3, {reg_t,reg_t,imm_t,	gap,gap}, {0x1F,0x1F,0x7fff,0,0},	{20,15,0,0,0}, 		0},
	{    "lbpost", 0x00000022UL, 3, {reg_t,reg_t,imm_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{	"lbupost", 0x00000023UL, 3, {reg_t,reg_t,imm_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{  	 "lhpost", 0x00000024UL, 3, {reg_t,reg_t,imm_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{  	"lhupost", 0x00000025UL, 3, {reg_t,reg_t,imm_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{    	"lhi", 0x1E000000UL, 2, {reg_t,imm_t,  gap,	gap,gap}, {0x1F,0xFFFF,0,0,0}, 		{20,0,0,0,0}, 0xF0000},
	{    "lwpost", 0x00000026UL, 3, {reg_t,reg_t,imm_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{    "sbpost", 0x00000027UL, 3, {reg_t,reg_t,imm_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{    "shpost", 0x00000028UL, 3, {reg_t,reg_t,imm_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{    "swpost", 0x00000029UL, 3, {reg_t,reg_t,imm_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
			/*ACP Integer instructions*/
	{		"add", 0x00000003UL, 3, {reg_t,reg_t,reg_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{      "addx", 0x00000004UL, 3, {reg_t,reg_t,reg_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{	   "addi", 0x04000000UL, 2, {reg_t,imm_t,gap,	gap,gap}, {0x1F,0xFFFF,0,0,0},		{16,0,0,0,0},		0},
	{     "addix", 0x04200000UL, 2, {reg_t,imm_t,gap,	gap,gap}, {0x1F,0xFFFF,0,0,0},		{16,0,0,0,0},		0},
	{     "addui", 0x06000000UL, 2, {reg_t,imm_t,gap,	gap,gap}, {0x1F,0xFFFF,0,0,0},		{16,0,0,0,0},		0},
	{    "adduix", 0x06200000UL, 2, {reg_t,imm_t,gap,	gap,gap}, {0x1F,0xFFFF,0,0,0},		{16,0,0,0,0},		0},
	{     	"sub", 0x0000001BUL, 3, {reg_t,reg_t,reg_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{      "subx", 0x0000001CUL, 3, {reg_t,reg_t,reg_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{      "subi", 0x04400000UL, 2, {reg_t,imm_t,gap,	gap,gap}, {0x1F,0xFFFF,0,0,0},		{16,0,0,0,0},		0},
	{     "subix", 0x04600000UL, 2, {reg_t,imm_t,gap,	gap,gap}, {0x1F,0xFFFF,0,0,0},		{16,0,0,0,0},		0},
	{     "subui", 0x06400000UL, 2, {reg_t,imm_t,gap,	gap,gap}, {0x1F,0xFFFF,0,0,0},		{16,0,0,0,0},		0},
	{    "subuix", 0x06600000UL, 2, {reg_t,imm_t,gap,	gap,gap}, {0x1F,0xFFFF,0,0,0},		{16,0,0,0,0},		0},
	{       "sll", 0x00000015UL, 3, {reg_t,reg_t,reg_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{      "slli", 0x0000001FUL, 3, {reg_t,reg_t,imm_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{      "ssll", 0x00000031UL, 3, {reg_t,reg_t,reg_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{     "sslli", 0x00000034UL, 2, {reg_t,imm_t,gap,	gap,gap}, {0x1F,0x3F,0,0,0},		{15,9,0,0,0},  	0x100},
	{ 	   "ssla", 0x00000032UL, 3, {reg_t,reg_t,reg_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{     "sslai", 0x00000035UL, 2, {reg_t,imm_t,gap,	gap,gap}, {0x1F,0x3F,0,0,0},		{15,9,0,0,0},  	0x100},
	{       "sra", 0x00000019UL, 3, {reg_t,reg_t,reg_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{      "srai", 0x00000020UL, 3, {reg_t,reg_t,imm_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{       "srl", 0x0000001AUL, 3, {reg_t,reg_t,reg_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{      "srli", 0x00000021UL, 3, {reg_t,reg_t,imm_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{        "rl", 0x00000033UL, 3, {reg_t,reg_t,reg_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{       "rli", 0x00000036UL, 3, {reg_t,reg_t,imm_t,  gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{      "srlo", 0x00000042UL, 3, {reg_t,reg_t,reg_t,  gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{   "add_sll", 0x02000001UL, 4, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0x1F,0},	{20,15,10,5,0},	0},
	{   "add_sra", 0x02000002UL, 4, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0x1F,0},	{20,15,10,5,0},	0},
	{   "add_srl", 0x02000003UL, 4, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0x1F,0},	{20,15,10,5,0},	0},
	{  "addx_sll", 0x02000005UL, 4, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0x1F,0},	{20,15,10,5,0},	0},
	{  "addx_sra", 0x02000006UL, 4, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0x1F,0},	{20,15,10,5,0},	0},
	{  "addx_srl", 0x02000007UL, 4, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0x1F,0},	{20,15,10,5,0},	0},
	{   "sub_sll", 0x02000009UL, 4, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0x1F,0},	{20,15,10,5,0},	0},
	{   "sub_sra", 0x0200000AUL, 4, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0x1F,0},	{20,15,10,5,0},	0},
	{   "sub_srl", 0x0200000BUL, 4, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0x1F,0},	{20,15,10,5,0},	0},
	{  "subx_sll", 0x0200000DUL, 4, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0x1F,0},	{20,15,10,5,0},	0},
	{  "subx_sra", 0x0200000EUL, 4, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0x1F,0},	{20,15,10,5,0},	0},
	{  "subx_srl", 0x0200000FUL, 4, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0x1F,0},	{20,15,10,5,0},	0},
	{   "and_sll", 0x02000011UL, 4, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0x1F,0},	{20,15,10,5,0},	0},
	{   "and_sra", 0x02000012UL, 4, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0x1F,0},	{20,15,10,5,0},	0},
	{   "and_srl", 0x02000013UL, 4, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0x1F,0},	{20,15,10,5,0},	0},
	{    "or_sll", 0x02000015UL, 4, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0x1F,0},	{20,15,10,5,0},	0},
	{    "or_sra", 0x02000016UL, 4, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0x1F,0},	{20,15,10,5,0},	0},
	{    "or_srl", 0x02000017UL, 4, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0x1F,0},	{20,15,10,5,0},	0},
	{   "xor_sll", 0x02000019UL, 4, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0x1F,0},	{20,15,10,5,0},	0},
	{   "xor_sra", 0x0200001AUL, 4, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0x1F,0},	{20,15,10,5,0},	0},
	{   "xor_srl", 0x0200001BUL, 4, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0x1F,0},	{20,15,10,5,0},	0},
	{   "xtd_sll", 0x0200001DUL, 4, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0x1F,0},	{20,15,10,5,0},	0},
	{   "xtd_sra", 0x0200001EUL, 4, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0x1F,0},	{20,15,10,5,0},	0},
	{   "xtd_srl", 0x0200001FUL, 4, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0x1F,0},	{20,15,10,5,0},	0},
	{   	"xtd", 0x0000001EUL, 3, {reg_t,reg_t,reg_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{      "xtdi", 0x07600000UL, 2, {reg_t,imm_t,gap, 	gap,gap}, {0x1F,0xFFFF,0,0,0},		{16,0,0,0,0},	0},
	{    "hadduu", 0x00000038UL, 3, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{    "haddss", 0x00000039UL, 3, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{   "rhadduu", 0x0000003AUL, 3, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{   "rhaddss", 0x0000003BUL, 3, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{  "abs_diff", 0x0000003CUL, 3, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{ "abs_diffu", 0x0000003DUL, 3, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{   "add_sat", 0x0000003EUL, 3, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{  "add_satu", 0x0000003FUL, 3, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{   "sub_sat", 0x00000040UL, 3, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{  "sub_satu", 0x00000041UL, 3, {reg_t,reg_t,reg_t,imm_t,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{       "clb", 0x00000007UL, 2, {reg_t,reg_t,gap,	gap,gap}, {0x1F,0x1F,0,0,0},		{20,15,0,0,0}, 	0x7F00},
	{       "clz", 0x0000002FUL, 2, {reg_t,reg_t,gap,	gap,gap}, {0x1F,0x1F,0,0,0},		{20,15,0,0,0}, 	0x7F00},
	{      "pcnt", 0x00000030UL, 2, {reg_t,reg_t,gap,	gap,gap}, {0x1F,0x1F,0,0,0},		{20,15,0,0,0}, 	0x7F00},
	{       "abs", 0x00000037UL, 2, {reg_t,reg_t,gap,	gap,gap}, {0x1F,0x1F,0,0,0},		{20,15,0,0,0}, 	0x7F00},
	{       "sel", 0x34000000UL, 4, {reg_t,reg_t,reg_t,reg_t,gap}, {0x1F,0x1F,0x1F,0x1F,0},	{20,15,10,5,0}, 0x1F},
	{  "mulss_lo", 0x00000044UL, 3, {reg_t,reg_t,reg_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x200},
	{  "mulss_hi", 0x00000144UL, 3, {reg_t,reg_t,reg_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x200},
	{  "mulsu_lo", 0x00000045UL, 3, {reg_t,reg_t,reg_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x200},
	{  "mulsu_hi", 0x00000145UL, 3, {reg_t,reg_t,reg_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x200},
	{  "muluu_lo", 0x00000046UL, 3, {reg_t,reg_t,reg_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x200},
	{  "muluu_hi", 0x00000146UL, 3, {reg_t,reg_t,reg_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x200},
	{    "lmulss", 0x00000009UL, 2, {reg_t,reg_t,gap,	gap,gap}, {0x1F,0x1F,0,0,0}, 		{15,10,0,0,0},	0x1F00300},
	{    "lmulsu", 0x0000000AUL, 2, {reg_t,reg_t,gap,	gap,gap}, {0x1F,0x1F,0,0,0}, 		{15,10,0,0,0},	0x1F00300},
	{    "lmuluu", 0x0000000BUL, 2, {reg_t,reg_t,gap,	gap,gap}, {0x1F,0x1F,0,0,0}, 		{15,10,0,0,0},	0x1F00300},
		/*ACP Logical instructions*/
	{       "and", 0x00000005UL, 3, {reg_t,reg_t,reg_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{      "andi", 0x06800000UL, 2, {reg_t,imm_t,gap,	gap,gap}, {0x1F,0xFFFF,0,0,0},		{16,0,0,0,0},	0},
	{      "andi", 0x2E000000UL, 3, {reg_t,reg_t,imm_t,	gap,gap}, {0x1F,0x1F,0x7FFF,0,0},	{20,15,0,0,0},	0},
	{        "or", 0x0000000DUL, 3, {reg_t,reg_t,reg_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{       "ori", 0x06A00000UL, 2, {reg_t,imm_t,gap,	gap,gap}, {0x1F,0xFFFF,0,0,0},		{16,0,0,0,0},	0},
	{       "ori", 0x2C000000UL, 3, {reg_t,reg_t,imm_t,	gap,gap}, {0x1F,0x1F,0x7fff,0,0},	{20,15,0,0,0},	0},
	{       "xor", 0x0000001DUL, 3, {reg_t,reg_t,reg_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{      "xori", 0x06C00000UL, 2, {reg_t,reg_t,imm_t,	gap,gap}, {0x1F,0xFFFF,0,0,0},		{16,0,0,0,0},	0},
	{      "xori", 0x30000000UL, 3, {reg_t,reg_t,imm_t,	gap,gap}, {0x1F,0x1F,0x7fff,0,0},	{20,15,0,0,0},	0},
	{       "neg", 0x00000006UL, 2, {reg_t,reg_t,gap,	gap,gap}, {0x1F,0x1F,0,0,0},		{20,15,0,0,0}, 	0x7F00},
		/*ACP Comparision instructions*/
	{       "seq", 0x0000000EUL, 3, {reg_t,reg_t,reg_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{      "seqi", 0x04800000UL, 2, {reg_t,imm_t,gap,	gap,gap}, {0x1F,0xFFFF,0,0,0},		{16,0,0,0,0},	0},
	{       "sne", 0x00000018UL, 3, {reg_t,reg_t,reg_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{      "snei", 0x05200000UL, 2, {reg_t,imm_t,gap,	gap,gap}, {0x1F,0xFFFF,0,0,0},		{16,0,0,0,0},	0},
	{       "sge", 0x0000000FUL, 3, {reg_t,reg_t,reg_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{      "sgei", 0x04A00000UL, 2, {reg_t,imm_t,gap,	gap,gap}, {0x1F,0xFFFF,0,0,0},		{16,0,0,0,0},	0},
	{      "sgeu", 0x00000010UL, 3, {reg_t,reg_t,reg_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{     "sgeui", 0x06E00000UL, 2, {reg_t,imm_t,gap,	gap,gap}, {0x1F,0xFFFF,0,0,0},		{16,0,0,0,0},	0},
	{       "sgt", 0x00000011UL, 3, {reg_t,reg_t,reg_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{      "sgti", 0x04C00000UL, 2, {reg_t,imm_t,gap,	gap,gap}, {0x1F,0xFFFF,0,0,0},		{16,0,0,0,0},	0},
	{      "sgtu", 0x00000012UL, 3, {reg_t,reg_t,reg_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{     "sgtui", 0x07000000UL, 2, {reg_t,imm_t,gap,	gap,gap}, {0x1F,0xFFFF,0,0,0},		{16,0,0,0,0},	0},
	{       "sle", 0x00000013UL, 3, {reg_t,reg_t,reg_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{      "slei", 0x04E00000UL, 2, {reg_t,imm_t,gap,	gap,gap}, {0x1F,0xFFFF,0,0,0},		{16,0,0,0,0},	0},
	{      "sleu", 0x00000014UL, 3, {reg_t,reg_t,reg_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{     "sleui", 0x07000000UL, 2, {reg_t,imm_t,gap,	gap,gap}, {0x1F,0xFFFF,0,0,0},		{16,0,0,0,0},	0},
	{       "slt", 0x00000016UL, 3, {reg_t,reg_t,reg_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{      "slti", 0x05000000UL, 2, {reg_t,imm_t,gap,	gap,gap}, {0x1F,0xFFFF,0,0,0},		{16,0,0,0,0},	0},
	{      "sltu", 0x00000017UL, 3, {reg_t,reg_t,reg_t,	gap,gap}, {0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0}, 0x300},
	{     "sltui", 0x07400000UL, 2, {reg_t,imm_t,gap,	gap,gap}, {0x1F,0xFFFF,0,0,0},		{16,0,0,0,0},	0},
				/*Control instructions*/
	{      "beqz", 0x08000000UL, 2, {reg_t,imm_t,gap,	gap,gap}, {0x1F,0xFFFF,0,0,0},		{16,0,0,0,0},	0},
	{      "bnez", 0x0A000000UL, 2, {reg_t,imm_t,gap,	gap,gap}, {0x1F,0xFFFF,0,0,0},		{16,0,0,0,0},	0},
	{         "j", 0x10000000UL, 1, {imm_t,gap,gap,		gap,gap}, {0x01FFFFFF,0,0,0,0},		{0,0,0,0,0},	0},
	{        "jr", 0x16000000UL, 1, {reg_t,gap,gap,		gap,gap}, {0x1F,0,0,0,0},			{20,0,0,0,0},	0xFFFFF},
	{       "jal", 0x12000000UL, 1, {imm_t,gap,gap,		gap,gap}, {0x01FFFFFF,0,0,0,0},		{0,0,0,0,0},	0},
//-----------------------------------------------------------------------------------------------------------------------------
// There is an error in Apex Insruction Set documentation. There noted that mask for "jalr"=0x16000000UL. It is a BAG!!!!
	{      "jalr", 0x14000000UL, 1, {reg_t,gap,gap,		gap,gap}, {0x1F,0,0,0,0},			{20,0,0,0,0},	0xFFFFF},
//-----------------------------------------------------------------------------------------------------------------------------
	{        "do", 0x0C000000UL, 2, {reg_t,imm_t,gap,	gap,gap}, {0x1F,0xFFFF,0,0,0},		{20,0,0,0,0}, 	0xF0000},
	{       "doi", 0x0E000000UL, 2, {imm_t,imm_t,gap,	gap,gap}, {0xFFF,0xFFF,0,0,0},		{13,0,0,0,0},	0},
	{     "swbrk", 0x00000001UL, 0, {gap,gap,gap,gap,		gap}, {0x0,0,0,0,0},			{0,0,0,0,0},	0},
	{       "nop", 0x00000000UL, 0, {gap,gap,gap,gap,		gap}, {0x0,0,0,0,0},			{0,0,0,0,0},	0},
	{      "Wait", 0x32000000UL, 1, {imm_t,gap,gap,		gap,gap}, {0xFFFF,0,0,0,0},			{0,0,0,0,0},	0x1FF0000},
	{       	/*On-Chip debugger Instructions*/
			 "mv", 0x0000002EUL, 1, {reg_t,gap,gap,		gap,gap}, {0x1F,0,0,0,0},			{15,0,0,0,0},	0x1F07F00},
	{     "sltui", 0x0000002DUL, 1, {reg_t,gap,gap,		gap,gap}, {0x1F,0,0,0,0},			{20,0,0,0,0},	0xFFF00},
    
	{ 		 NULL, 0,			0, {0,0,0,0,0},					  {0,0,0,0,0},				{0,0,0,0,0},	0}
};

const apex_opc_info_t apex_APC_32b_vector_opc_info[] =
{
				/*Vector Stack Instructions*/
	{   "vcspush", 0x400002C8UL, 1, {reg_t,gap,gap,		gap,gap}, {0x3,0,0,0,0},			{10,0,0,0,0},	0x1FFF000},
	{    "vcspop", 0x400002D0UL, 0, {gap,gap,gap,		gap,gap}, {0,0,0,0,0},				{0,0,0,0,0},	0x1FFFC07},
	{   "vcsflip", 0x400002D8UL, 0, {gap,gap,gap,		gap,gap}, {0,0,0,0,0},				{0,0,0,0,0},	0x1FFFC07},
	{   "vcsfpop", 0x400002E0UL, 0, {gap,gap,gap,		gap,gap}, {0,0,0,0,0},				{0,0,0,0,0},	0x1FFFC07},
	{    "vcsref", 0x400002F0UL, 1, {reg_t,gap,gap,		gap,gap}, {0x3,0,0,0},				{10,0,0,0,0},	0x1FFF007},
	{"vcsinvrefine",0x400002e8UL,1, {imm_t,gap,gap,		gap,gap}, {0x7,0,0,0,0},			{22,0,0,0,0},	0x3FFC07},
	{"vcsptr_get", 0x40000388UL, 1, {reg_t,gap,gap,		gap,gap}, {0x1F,0,0,0,0},			{20,0,0,0,0},	0x3FFC07},
	{"vcsptr_inc", 0x40000380UL, 0, {gap,gap,gap,		gap,gap}, {0,0,0,0,0},				{0,0,0,0,0},	0x1FFFC07},
	{"vcsptr_set", 0x40000390UL, 1, {imm_t,gap,gap,		gap,gap}, {0x7,0,0,0,0},			{19,0,0,0,0},	0x1C7FC07},
	{   "vcs_set", 0x40000378UL, 0, {gap,gap,gap,		gap,gap}, {0,0,0,0,0},				{0,0,0,0,0},	0x1FFFC07},
	{      "vcmv", 0x402805D8UL, 2, {reg_t,reg_t,gap,gap,gap,gap}, {0x3,0x7,0,0,0},			{22,19,0,0,0},	0x7F807},
	{     "vcinv", 0x402805D0UL, 1, {reg_t,gap,gap,		gap,gap}, {0x3,0,0,0,0},			{22,0,0,0,0},	0x7F807},
				/*Vector Memory LD/ST instructions*/
	{    	"vlb", 0x46000000UL, 4, {reg_t,reg_t,imm_t,vcs_t,gap}, {0x7,0x1F,0xFFF,0x7,0},	{22,17,3,0,0},	0},
	{      "vlbu", 0x46008000UL, 4, {reg_t,reg_t,imm_t,vcs_t,gap}, {0x7,0x1F,0xFFF,0x7,0},	{22,17,3,0,0},	0},
	{       "vlw", 0x46010000UL, 4, {reg_t,reg_t,imm_t,vcs_t,gap}, {0x7,0x1F,0xFFF,0x7,0},	{22,17,3,0,0},	0},
	{    	"vsb", 0x4A000000UL, 4, {reg_t,reg_t,imm_t,vcs_t,gap}, {0x7,0x1F,0xFFF,0x7,0},	{22,17,3,0,0},	0},
	{    	"vsw", 0x4A008000UL, 4, {reg_t,reg_t,imm_t,vcs_t,gap}, {0x7,0x1F,0xFFF,0x7,0},	{22,17,3,0,0},	0},
	{      "vclb", 0x44000000UL, 4, {reg_t,reg_t,imm_t,vcs_t,gap}, {0x3,0x7,0xFFF,0x7,0},	{22,17,3,0,0},	0x300000},
	{      "vclw", 0x44008000UL, 4, {reg_t,reg_t,imm_t,vcs_t,gap}, {0x3,0x7,0xFFF,0x7,0},	{22,17,3,0,0},	0x300000},
	{      "vcsw", 0x45018000UL, 4, {reg_t,reg_t,imm_t,vcs_t,gap}, {0x3,0x7,0xFFF,0x7,0},	{22,17,3,0,0},	0x300000},
	{   "vlbpost", 0x40000008UL, 4, {reg_t,reg_t,imm_t,vcs_t,gap}, {0x7,0x1F,0x1F,0x7,0},	{22,16,11,0,0},	0x200400},
	{  "vlbupost", 0x40000010UL, 4, {reg_t,reg_t,imm_t,vcs_t,gap}, {0x7,0x1F,0x1F,0x7,0},	{22,16,11,0,0},	0x200400},
	{   "vlwpost", 0x40000018UL, 4, {reg_t,reg_t,imm_t,vcs_t,gap}, {0x7,0x1F,0x1F,0x7,0},	{22,16,11,0,0},	0x200400},
	{   "vsbpost", 0x40000020UL, 4, {reg_t,reg_t,imm_t,vcs_t,gap}, {0x7,0x1F,0x1F,0x7,0},	{21,16,11,0,0},	0x1000400},
	{   "vswpost", 0x40000028UL, 4, {reg_t,reg_t,imm_t,vcs_t,gap}, {0x7,0x1F,0x1F,0x7,0},	{21,16,11,0,0},	0x1000400},
	{      "vilb", 0x40007E18UL, 3, {reg_t,reg_t,vcs_t,gap,	gap}, {0x7,0x7,0x7,0,0},		{22,16,0,0,0},	0x388000},
	{     "vilbu", 0x40007E20UL, 3, {reg_t,reg_t,vcs_t,gap,	gap}, {0x7,0x7,0x7,0,0},		{22,16,0,0,0},	0x388000},
	{      "vilw", 0x40007E28UL, 3, {reg_t,reg_t,vcs_t,gap,	gap}, {0x7,0x7,0x7,0,0},		{22,16,0,0,0},	0x388000},
	{      "visb", 0x40003E30UL, 3, {reg_t,reg_t,vcs_t,gap,	gap}, {0x7,0x7,0x7,0,0},		{19,16,0,0,0},	0x1C08000},
	{      "visw", 0x40003E38UL, 3, {reg_t,reg_t,vcs_t,gap,	gap}, {0x7,0x7,0x7,0,0},		{19,16,0,0,0},	0x1C08000},
			/*Vector ALU instructions*/
	{      "vadd", 0x40000030UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap}, 	{0x7,0x7,0x7,0x7,0},		{22,19,16,0,0},	0xF800},
	{     "vaddx", 0x40000038UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap}, 	{0x7,0x7,0x7,0x7,0},		{22,19,16,0,0},	0xF800},
	{      "vadd", 0x40000430UL, 5, {reg_t,reg_t,reg_t,f_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1800},
	{     "vaddx", 0x40000438UL, 5, {reg_t,reg_t,reg_t,f_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1800},
	{      "vadd", 0x400002B8UL, 3, {reg_t,imm_t,vcs_t,gap,gap},		{0x7,0xFF,0x7,0,0},			{22,14,0,0,0},	0x2000},
	{     "vaddx", 0x400006B8UL, 3, {reg_t,imm_t,vcs_t,gap,gap},		{0x7,0xFF,0x7,0,0},			{22,14,0,0,0},	0x2000},
	{      "vadd", 0x50000000UL, 3, {reg_t,reg_t,imm_t,gap,gap}, 	{0x7,0x7,0xFFFF,0,0},		{22,19,3,0,0},	0x0},
	{     "vaddx", 0x50000001UL, 3, {reg_t,reg_t,imm_t,gap,gap}, 	{0x7,0x7,0xFFFF,0,0},		{22,19,3,0,0},	0x0},
	{      "vsub", 0x40000040UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{22,19,16,0,0}, 0xF800},
	{     "vsubx", 0x40000050UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{22,19,16,0,0}, 0xF800},
	{      "vsub", 0x40000440UL, 5, {reg_t,reg_t,reg_t,f_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1800},
	{     "vsubx", 0x40000450UL, 5, {reg_t,reg_t,reg_t,f_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1800},
	{     "vsubr", 0x40000448UL, 5, {reg_t,reg_t,reg_t,f_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1800},
	{      "vsub", 0x50000002UL, 3, {reg_t,reg_t,imm_t,gap,gap}, 	{0x7,0x7,0xFFFF,0,0},		{22,19,3,0,0},	0x0},
	{     "vsubx", 0x50000003UL, 3, {reg_t,reg_t,imm_t,gap,gap}, 	{0x7,0x7,0xFFFF,0,0},		{22,19,3,0,0},	0x0},
	{      "vsub", 0x40000AB8UL, 3, {reg_t,imm_t,vcs_t,gap,gap}, 	{0x7,0xFF,0x7,0,0},			{22,14,0,0,0},	0x2000},
	{     "vsubx", 0x40000EB8UL, 3, {reg_t,imm_t,vcs_t,gap,gap}, 	{0x7,0xFF,0x7,0,0},			{22,14,0,0,0},	0x2000},
	{      "vand", 0x40000058UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{22,19,16,0,0}, 0xF800},
	{       "vor", 0x40000068UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{22,19,16,0,0}, 0xF800},
	{      "vxor", 0x40000070UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{22,19,16,0,0}, 0xF800},
	{      "vand", 0x40000458UL, 5, {reg_t,reg_t,reg_t,f_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1800},
	{       "vor", 0x40000468UL, 5, {reg_t,reg_t,reg_t,f_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1800},
	{      "vxor", 0x40000470UL, 5, {reg_t,reg_t,reg_t,f_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1800},
	{      "vand", 0x50000004UL, 3, {reg_t,reg_t,imm_t,gap,gap},		{0x7,0x7,0xFFFF,0,0},		{22,19,3,0,0},	0x1800},
	{       "vor", 0x50000005UL, 3, {reg_t,reg_t,imm_t,gap,gap},		{0x7,0x7,0xFFFF,0,0},		{22,19,3,0,0},	0x1800},
	{      "vxor", 0x60000006UL, 3, {reg_t,reg_t,imm_t,gap,gap},		{0x7,0x7,0xFFFF,0,0},		{22,19,3,0,0},	0x1800},
	{      "vxtd", 0x40000078UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{22,19,16,0,0}, 0xF800},
	{      "vxtd", 0x40000678UL, 5, {reg_t,reg_t,reg_t,reg_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1800},
	{      "vxtd", 0x50000007UL, 3, {reg_t,reg_t,imm_t,gap,gap},		{0x7,0x7,0xFFFF,0,0},		{22,19,3,0,0},	0x0},
	{   "vhadduu", 0x400003A8UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{22,19,16,0,0}, 0xF800},
	{   "vhadduu", 0x400007A8UL, 5, {reg_t,reg_t,reg_t,reg_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1800},
	{   "vhaddss", 0x400003B0UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{22,19,16,0,0}, 0xF800},
	{   "vhaddss", 0x400007B0UL, 5, {reg_t,reg_t,reg_t,reg_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1800},
	{  "vrhadduu", 0x400002B8UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{22,19,16,0,0}, 0xF800},
	{  "vrhadduu", 0x400007B8UL, 5, {reg_t,reg_t,reg_t,reg_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1800},
	{  "vrhaddss", 0x400003C0UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{22,19,16,0,0}, 0xF800},
	{  "vrhaddss", 0x400007C0UL, 5, {reg_t,reg_t,reg_t,reg_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1800},
	{ "vabs_diff", 0x400003C8UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{22,19,16,0,0}, 0xF800},
	{ "vabs_diff", 0x400007C8UL, 5, {reg_t,reg_t,reg_t,reg_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1800},
	{"vabs_diffu", 0x400003D0UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{22,19,16,0,0}, 0xF800},
	{"vabs_diffu", 0x400007D0UL, 5, {reg_t,reg_t,reg_t,reg_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1800},
	{  "vadd_sat", 0x400003D8UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{22,19,16,0,0}, 0xF800},
	{  "vadd_sat", 0x400007D8UL, 5, {reg_t,reg_t,reg_t,reg_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1800},
	{ "vadd_satu", 0x400003E0UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{22,19,16,0,0}, 0xF800},
	{ "vadd_satu", 0x400007E0UL, 5, {reg_t,reg_t,reg_t,reg_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1800},
	{  "vsub_sat", 0x400003E8UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{22,19,16,0,0}, 0xF800},
	{  "vsub_sat", 0x400007E8UL, 5, {reg_t,reg_t,reg_t,reg_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1800},
	{ "vsub_satu", 0x400003F0UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{22,19,16,0,0}, 0xF800},
	{ "vsub_satu", 0x400007F0UL, 5, {reg_t,reg_t,reg_t,reg_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1800},
	{      "vsat", 0x40000F07UL, 4, {reg_t,reg_t,reg_t,reg_t,gap},	{0x7,0x7,0x7,0x7,0},		{22,19,16,13,0},0x1000},
	{      "vsat", 0x40000B07UL, 4, {reg_t,reg_t,reg_t,reg_t,gap},	{0x7,0x7,0x7,0x7,0},		{22,19,16,13,0},0x1000},
	{      "vsat", 0x40000707UL, 4, {reg_t,reg_t,reg_t,reg_t,gap},	{0x7,0x7,0x7,0x7,0},		{22,19,16,13,0},0x1000},
	{      "vsat", 0x40000307UL, 4, {reg_t,reg_t,reg_t,reg_t,gap},	{0x7,0x7,0x7,0x7,0},		{22,19,16,13,0},0x1000},
	{      "vabs", 0x400002F8UL, 3, {reg_t,reg_t,vcs_t,gap,gap},		{0x7,0x7,0x7,0,0},			{22,19,0,0,0},  0x7F800},
	{      "vclz", 0x40000340UL, 3, {reg_t,reg_t,vcs_t,gap,gap},		{0x7,0x7,0x7,0,0},			{22,19,0,0,0},  0x7F800},
	{      "vcld", 0x40000348UL, 3, {reg_t,reg_t,vcs_t,gap,gap},		{0x7,0x7,0x7,0,0},			{22,19,0,0,0},	0x7F800},
	{     "vpcnt", 0x40000350UL, 3, {reg_t,reg_t,vcs_t,gap,gap},		{0x7,0x7,0x7,0,0},			{22,19,0,0,0},	0x7F800},
	{   "vacc32u", 0x55000048UL, 5, {reg_t,reg_t,reg_t,reg_t,vcs_t},	{0x7,0x7,0x7,0x1,0x7},		{19,16,13,10,0},0x7F800},
	{"vacc32u_sl8",0x55000050UL, 5, {reg_t,reg_t,reg_t,reg_t,vcs_t},	{0x7,0x7,0x7,0x1,0x7},		{19,16,13,10,0},0x7F800},
	{   "vacc32s", 0x55000058UL, 5, {reg_t,reg_t,reg_t,reg_t,vcs_t},	{0x7,0x7,0x7,0x1,0x7},		{19,16,13,10,0},0x7F800},
	{"vacc32s_sl8",0x55000060UL, 5, {reg_t,reg_t,reg_t,reg_t,vcs_t},	{0x7,0x7,0x7,0x1,0x7},		{19,16,13,10,0},0x7F800},
	{      "vasb", 0x40000000UL, 6, {reg_t,reg_t,reg_t,reg_t,f_t,vcs_t},{0x7,0x7,0x7,0x3,0x1,0x7},	{22,19,16,14,10,0},0x3000},
	{      "vasb", 0x400001F8UL, 6, {reg_t,reg_t,reg_t,reg_t,f_t,vcs_t},{0x7,0x7,0x1F,0x3,0x1,0x7},	{22,19,16,14,10,0},0x0},
	{      "vasb", 0x400009F8UL, 6, {reg_t,reg_t,reg_t,reg_t,f_t,vcs_t},{0x7,0x7,0x1F,0x3,0x1,0x7},	{22,19,16,14,10,0},0x0},
	{     "vasbs", 0x40000210UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{22,19,16,0,0},0xF400},
	{     "vasbs", 0x40000208UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x1F,0x7,0},		{22,19,14,0,0},0x3400},
	{     "vasbs", 0x40000A08UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{22,19,16,0,0},0xF400},
			/*Vector multiplication instructions*/
	{ "vmul_lulu", 0x402005B0UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{18,15,12,0,0},0x800},
	{ "vmul_lslu", 0x404005B0UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{18,15,12,0,0},0x800},
	{ "vmul_lsls", 0x406005B0UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{18,15,12,0,0},0x800},
	{ "vmul_hulu", 0x408005B0UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{18,15,12,0,0},0x800},
	{ "vmul_huls", 0x40A005B0UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{18,15,12,0,0},0x800},
	{ "vmul_hslu", 0x40C005B0UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{18,15,12,0,0},0x800},
	{ "vmul_huhu", 0x40E005B0UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{18,15,12,0,0},0x800},
	{ "vmul_hshu", 0x412005B0UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{18,15,12,0,0},0x800},
	{ "vmul_hshs", 0x414005B0UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{18,15,12,0,0},0x800},
	{      "vmul", 0x416005B0UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{18,15,12,0,0},0x800},
	{ "vmul_lulu", 0x40000258UL, 5, {reg_t,reg_t,reg_t,f_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1000},
	{ "vmul_lslu", 0x40000260UL, 5, {reg_t,reg_t,reg_t,f_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1000},
	{ "vmul_lsls", 0x40000268UL, 5, {reg_t,reg_t,reg_t,f_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1000},
	{ "vmul_hulu", 0x40000270UL, 5, {reg_t,reg_t,reg_t,f_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1000},
	{ "vmul_huls", 0x40000278UL, 5, {reg_t,reg_t,reg_t,f_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1000},
	{ "vmul_hslu", 0x40000280UL, 5, {reg_t,reg_t,reg_t,f_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1000},
	{ "vmul_hsls", 0x40000288UL, 5, {reg_t,reg_t,reg_t,f_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1000},
	{ "vmul_huhu", 0x40000290UL, 5, {reg_t,reg_t,reg_t,f_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1000},
	{ "vmul_hshu", 0x40000298UL, 5, {reg_t,reg_t,reg_t,f_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1000},
	{ "vmul_hshs", 0x400002A0UL, 5, {reg_t,reg_t,reg_t,f_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1000},
	{      "vmul", 0x400001B0UL, 5, {reg_t,reg_t,reg_t,f_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1000},
	{ "vmul_lslu", 0x40000A60UL, 5, {reg_t,reg_t,reg_t,f_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1000},
	{ "vmul_hulu", 0x40000A70UL, 5, {reg_t,reg_t,reg_t,f_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1000},
	{ "vmul_huls", 0x40000A78UL, 5, {reg_t,reg_t,reg_t,f_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1000},
	{ "vmul_hslu", 0x40000A80UL, 5, {reg_t,reg_t,reg_t,f_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1000},
	{ "vmul_hsls", 0x40000A88UL, 5, {reg_t,reg_t,reg_t,f_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1000},
	{ "vmul_hshu", 0x40000A98UL, 5, {reg_t,reg_t,reg_t,f_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1000},
	{     "vimul", 0x4E000000UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0xFFFF,0x7,0},		{22,19,3,0,0},0x0},
	{      "vsll", 0x40000080UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{22,19,16,0,0},0xF000},
	{      "vsra", 0x40000088UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{22,19,16,0,0},0xF000},
	{      "vsrl", 0x40000090UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{22,19,16,0,0},0xF000},
	{     "vssla", 0x40000360UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{22,19,16,0,0},0xF000},
	{     "vssll", 0x40000358UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{22,19,16,0,0},0xF000},
	{       "vrl", 0x40000368UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},		{22,19,16,0,0},0xF000},
	{      "vsll", 0x40000880UL, 5, {reg_t,reg_t,reg_t,f_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1000},
	{      "vsra", 0x40000888UL, 5, {reg_t,reg_t,reg_t,f_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1000},
	{      "vsrl", 0x40000890UL, 5, {reg_t,reg_t,reg_t,f_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1000},
	{     "vssla", 0x40000B60UL, 5, {reg_t,reg_t,reg_t,f_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1000},
	{     "vssll", 0x40000B58UL, 5, {reg_t,reg_t,reg_t,f_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1000},
	{       "vrl", 0x40000B68UL, 5, {reg_t,reg_t,reg_t,f_t,vcs_t},	{0x7,0x7,0x1F,0x1,0x7},		{22,19,14,13,0},0x1000},
	{      "vsll", 0x40000480UL, 4, {reg_t,reg_t,imm_t,vcs_t,gap},	{0x7,0x7,0xF,0x7,0},		{22,19,15,0,0},0x7000},
	{      "vsra", 0x40000488UL, 4, {reg_t,reg_t,imm_t,vcs_t,gap},	{0x7,0x7,0xF,0x7,0},		{22,19,15,0,0},0x7000},
	{     "vssla", 0x40000760UL, 4, {reg_t,reg_t,imm_t,vcs_t,gap},	{0x7,0x7,0x1F,0x7,0},		{22,19,14,0,0},0x3000},
	{     "vssll", 0x40000758UL, 4, {reg_t,reg_t,imm_t,vcs_t,gap},	{0x7,0x7,0x1F,0x7,0},		{22,19,14,0,0},0x3000},
	{      "vsrl", 0x40000490UL, 4, {reg_t,reg_t,imm_t,vcs_t,gap},	{0x7,0x7,0xF,0x7,0},		{22,19,15,0,0},0x7000},
	{       "vrl", 0x40000768UL, 4, {reg_t,reg_t,imm_t,vcs_t,gap},	{0x7,0x7,0xF,0x7,0},		{22,19,15,0,0},0x7000},
	{   "vsrl_ov", 0x54000068UL, 3, {reg_t,reg_t,imm_t,vcs_t,gap},	{0x7,0x7,0x7,0,0},			{22,19,16,0,0},0x38F000},
	{   "vsll_ov", 0x54000070UL, 3, {reg_t,reg_t,imm_t,vcs_t,gap},	{0x7,0x7,0x7,0,0},			{22,19,16,0,0},0x38F000},
	{   "vsrl_vc", 0x54000078UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x3,0x7,0x7,0},		{22,19,16,0,0},0x20F000},
	{   "vsll_vc", 0x54000080UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x3,0x7,0x7,0},		{22,19,16,0,0},0x20F000},
	{    "vsllxi", 0x42000064UL, 5, {reg_t,reg_t,imm_t,reg_t,reg_t},	{0x7,0x7,0x1F,0x7,0x7,0},		{22,19,14,11,8},0x80},
	{    "vsraxi", 0x42000065UL, 5, {reg_t,reg_t,imm_t,reg_t,reg_t},	{0x7,0x7,0x1F,0x7,0x7,0},		{22,19,14,11,8},0x80},
	{    "vsrlxi", 0x42000066UL, 5, {reg_t,reg_t,imm_t,reg_t,reg_t},	{0x7,0x7,0x1F,0x7,0x7,0},		{22,19,14,11,8},0x80},
	{     "vsllx", 0x420000E1UL, 5, {reg_t,reg_t,reg_t,reg_t,reg_t},	{0x7,0x7,0x1F,0x7,0x7,0},		{22,19,14,11,8},0x0},
	{     "vsrax", 0x420000E2UL, 5, {reg_t,reg_t,reg_t,reg_t,reg_t},	{0x7,0x7,0x1F,0x7,0x7,0},		{22,19,14,11,8},0x0},
	{     "vsrlx", 0x420000E3UL, 5, {reg_t,reg_t,reg_t,reg_t,reg_t},	{0x7,0x7,0x1F,0x7,0x7,0},		{22,19,14,11,8},0x0},
	{     "vsllx", 0x42000061UL, 5, {reg_t,reg_t,imm_t,reg_t,reg_t},	{0x7,0x7,0x1F,0x7,0x7,0},		{22,19,14,11,8},0x0},
	{     "vsrax", 0x42000062UL, 5, {reg_t,reg_t,imm_t,reg_t,reg_t},	{0x7,0x7,0x1F,0x7,0x7,0},		{22,19,14,11,8},0x0},
	{     "vsrlx", 0x42000063UL, 5, {reg_t,reg_t,imm_t,reg_t,reg_t},	{0x7,0x7,0x1F,0x7,0x7,0},		{22,19,14,11,8},0x0},
	{       "vmv", 0x40000190UL, 3, {reg_t,reg_t,vcs_t,gap,gap},		{0x7,0x7,0x7,0,0},		{22,19,0,0,0},0x7F800},
	{      "vmv2", 0x40000590UL, 3, {reg_t,reg_t,vcs_t,gap,gap},		{0x7,0x7,0x7,0,0},		{16,13,0,0,0},0x1F81800},
	{       "vli", 0x48000000UL, 3, {reg_t,imm_t,vcs_t,gap,gap},		{0x7,0xFFFF,0x7,0,0},		{22,3,0,0,0},0x380000},
	{     "vmrhi", 0x40000138UL, 3, {reg_t,reg_t,vcs_t,gap,gap},		{0x7,0x1F,0x7,0,0},		{22,17,0,0,0},0x1F800},
	{      "vmrh", 0x40000140UL, 3, {reg_t,reg_t,vcs_t,gap,gap},		{0x7,0x1F,0x7,0,0},		{22,17,0,0,0},0x1F800},
	{      "vmrb", 0x40000148UL, 3, {reg_t,reg_t,vcs_t,gap,gap},		{0x7,0x1F,0x7,0,0},		{22,17,0,0,0},0x1F800},
	{     "vmrbu", 0x40000150UL, 3, {reg_t,reg_t,vcs_t,gap,gap},		{0x7,0x1F,0x7,0,0},		{22,17,0,0,0},0x1F800},
			/*Vector condition register instructions*/
	{     "vcand", 0x400001E0UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x3,0x3,0x3,0x7,0},		{22,19,16,0,0},0x4F800},
	{      "vcor", 0x400001E8UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x3,0x3,0x3,0x7,0},		{22,19,16,0,0},0x4F800},
	{     "vcxor", 0x400001F0UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x3,0x3,0x3,0x7,0},		{22,19,16,0,0},0x4F800},
	{      "vcsr", 0x400001C0UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x3,0x3,0x3,0x7,0},		{22,19,16,0,0},0x4F800},
	{      "vcsl", 0x400001C8UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x3,0x3,0x3,0x7,0},		{22,19,16,0,0},0x4F800},
	{     "vcand", 0x400005E0UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x3,0x3,0x3,0x7,0},		{22,19,16,0,0},0x4F800},
	{      "vcor", 0x400005E8UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x3,0x3,0x3,0x7,0},		{22,19,16,0,0},0x4F800},
	{     "vcxor", 0x400005F0UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x3,0x3,0x3,0x7,0},		{22,19,16,0,0},0x4F800},
	{     "vcinv", 0x400001D0UL, 3, {reg_t,reg_t,vcs_t,gap,gap},		{0x3,0x3,0x7,0,0},			{22,19,0,0,0},0x7FC00},
	{      "vcmv", 0x400001D8UL, 3, {reg_t,reg_t,vcs_t,gap,gap},		{0x3,0x3,0x7,0,0},			{22,19,16,0,0},0x7F800},
	{      "vcmv", 0x401001D8UL, 3, {reg_t,reg_t,vcs_t,gap,gap},		{0x7,0x3,0x7,0,0},			{22,19,0,0,0},0x7F800},
	{      "vcmv", 0x402001D8UL, 3, {reg_t,reg_t,vcs_t,gap,gap},		{0x3,0x7,0x7,0,0},			{22,19,0,0,0},0x7F800},
	{      "vcsr", 0x400005C0UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x3,0x3,0x7,0x7,0},		{22,19,15,0,0},0x4F800},
	{      "vcsl", 0x400005C8UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x3,0x3,0x7,0x7,0},		{22,19,15,0,0},0x47800},
	{      "vmvc", 0x400001A0UL, 3, {reg_t,reg_t,vcs_t,gap,gap},		{0x3,0x7,0x7,0,0},			{22,19,0,0,0},0x107FC00},
	{      "vmcv", 0x400001A8UL, 3, {reg_t,reg_t,vcs_t,gap,gap},		{0x3,0x3,0x7,0,0},			{22,19,0,0,0},0x7FC00},
	{       "vwe", 0x4C000000UL, 5, {reg_t,reg_t,reg_t,imm_t,vcs_t},	{0x7,0x7,0x1F,0xFF,0x7},	{22,19,14,3,0},0x0},
	{       "vwe", 0x4C002000UL, 5, {reg_t,reg_t,reg_t,reg_t,vcs_t},	{0x7,0x7,0x1F,0x1F,0x7},	{22,19,14,3,0},0x700},
	{       "vwe", 0x4C001000UL, 5, {reg_t,reg_t,reg_t,imm_t,vcs_t},	{0x7,0x7,0x7,0xFF,0x7},		{22,19,16,3,0},0x0},
	{       "vwe", 0x4C001800UL, 5, {reg_t,reg_t,reg_t,reg_t,vcs_t},	{0x7,0x7,0x1F,0xFF,0x7},	{22,19,16,13,0},0x7F8},
	{       "vwe", 0x4C000800UL, 5, {reg_t,reg_t,reg_t,reg_t,vcs_t},	{0x7,0x7,0x7,0x7,0x7},		{22,19,16,13,0},0x7F8},
	{      "vexi", 0x40000160UL, 4, {reg_t,reg_t,imm_t,vcs_t,gap},	{0x1F,0x7,0x7F,0x7,0},		{20,17,10,0,0},0x47800},
	{     "vexiu", 0x40000398UL, 4, {reg_t,reg_t,imm_t,vcs_t,gap},	{0x1F,0x7,0x7F,0x7,0},		{20,17,10,0,0},0x47800},
	{      "vexr", 0x40000168UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x1F,0x7,0x1F,0x7,0},		{20,17,12,0,0},0xC00},
	{     "vexru", 0x400003A0UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x1F,0x7,0x1F,0x7,0},		{20,17,12,0,0},0xC00},
	{    "vex_vc", 0x54000098UL, 3, {reg_t,sel_t,reg_t,gap,gap},		{0x1F,0x3,0x3,0,0},			{20,18,15,0,0},0x27C07},
	{      "vput", 0x540000A0UL, 3, {reg_t,reg_t,sel_t,gap,gap},		{0x3,0x1F,0x3,0,0},			{20,15,13,0,0},0x1C01C07},
	{      "vany", 0x54000088UL, 2, {reg_t,reg_t,gap,gap,gap},		{0x1F,0x3,0,0,0},			{20,15,0,0,0},0xC7807},
	{      "vall", 0x54000090UL, 2, {reg_t,reg_t,gap,gap,gap},		{0x1F,0x3,0,0,0},			{20,15,0,0,0},0xC7807},
	{  "vany_vcs", 0x54000488UL, 1, {reg_t,gap,gap,gap,gap},			{0x1F,0,0,0,0},				{20,0,0,0,0},0xFF107},
	{  "vall_vcs", 0x54000490UL, 1, {reg_t,gap,gap,gap,gap},			{0x1F,0,0,0,0},				{20,0,0,0,0},0xFF107},
	{  "vany_ovv", 0x540C0088UL, 1, {reg_t,gap,gap,gap,gap},			{0x1F,0,0,0,0},				{20,0,0,0,0},0xC7807},
	{  "vall_ovv", 0x54000090UL, 1, {reg_t,gap,gap,gap,gap},			{0x1F,0,0,0,0},				{20,0,0,0,0},0xFF107},
	{      "vseq", 0x40000098UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x3,0x7,0x7,0x7,0},		{22,19,16,0,0},0x100F800},
	{      "vsne", 0x400000A0UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x3,0x7,0x7,0x7,0},		{22,19,16,0,0},0x100F800},
	{      "vsge", 0x400000A8UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x3,0x7,0x7,0x7,0},		{22,19,16,0,0},0x100F800},
	{      "vsgt", 0x400000B0UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x3,0x7,0x7,0x7,0},		{22,19,16,0,0},0x100F800},
	{      "vsle", 0x400000B8UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x3,0x7,0x7,0x7,0},		{22,19,16,0,0},0x100F800},
	{      "vslt", 0x400000C0UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x3,0x7,0x7,0x7,0},		{22,19,16,0,0},0x100F800},
	{     "vsgeu", 0x400000C8UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x3,0x7,0x7,0x7,0},		{22,19,16,0,0},0x100F800},
	{     "vsgtu", 0x400000D0UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x3,0x7,0x7,0x7,0},		{22,19,16,0,0},0x100F800},
	{     "vsleu", 0x400000D8UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x3,0x7,0x7,0x7,0},		{22,19,16,0,0},0x100F800},
	{     "vsltu", 0x400000E0UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x3,0x7,0x7,0x7,0},		{22,19,16,0,0},0x100F800},
	{      "vseq", 0x40000498UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x3,0x7,0x1F,0x7,0},		{22,19,14,0,0},0x1003800},
	{      "vsne", 0x400004A0UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x3,0x7,0x1F,0x7,0},		{22,19,14,0,0},0x1003800},
	{      "vsge", 0x400004A8UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x3,0x7,0x1F,0x7,0},		{22,19,14,0,0},0x1003800},
	{      "vsgt", 0x400004B0UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x3,0x7,0x1F,0x7,0},		{22,19,14,0,0},0x1003800},
	{      "vsle", 0x400004B8UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x3,0x7,0x1F,0x7,0},		{22,19,14,0,0},0x1003800},
	{      "vslt", 0x400004C0UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x3,0x7,0x1F,0x7,0},		{22,19,14,0,0},0x1003800},
	{     "vsgeu", 0x400004C8UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x3,0x7,0x1F,0x7,0},		{22,19,14,0,0},0x1003800},
	{     "vsgtu", 0x400004D0UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x3,0x7,0x1F,0x7,0},		{22,19,14,0,0},0x1003800},
	{     "vsleu", 0x400004D8UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x3,0x7,0x1F,0x7,0},		{22,19,14,0,0},0x100F800},
	{     "vsltu", 0x400004E0UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x3,0x7,0x1F,0x7,0},		{22,19,14,0,0},0x100F800},
			/*Vector pointer modification instructions*/
	{      "padd", 0x40000338UL, 3, {reg_t,imm_t_lsp,imm_t_msp,gap,gap},		{0x1F,0x3FF,0x7,0,0},		{20,10,0,0,0},0x0},
	{       "add", 0x540000B8UL, 4, {reg_t,reg_t,imm_t_lsp,imm_t_msp,gap},	{0x1F,0x1F,0x1F,0x7,0},		{20,15,10,0,0},0x0},
	{       "add", 0x540000C0UL, 3, {reg_t,reg_t,reg_t,gap,gap},		{0x1F,0x1F,0x1F,0,0},		{20,15,10,0,0},0x7},
	{       "mov", 0x540000C8UL, 2, {reg_t,reg_t,gap,gap,gap},		{0x1F,0x1F,0,0,0},			{20,15,0,0,0},0x7C07},
			/*Vector to vector movement*/
	{     "vmrlv", 0x40000180UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},			{22,19,16,0,0},0xFC00},
	{     "vmrrv", 0x40000188UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x7,0x7,0},			{22,19,16,0,0},0xFC00},
	{     "vmrlr", 0x40000170UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x1F,0,0},			{22,19,14,0,0},0x3C00},
	{     "vmrrr", 0x40000178UL, 4, {reg_t,reg_t,reg_t,vcs_t,gap},	{0x7,0x7,0x1F,0,0},			{22,19,14,0,0},0x3C00},
			/*Vector swap*/
	{     "vspge", 0x540000F0UL, 2, {reg_t,reg_t,gap,gap,gap},		{0x7,0x7,0,0,0},			{22,19,0,0,0},0x7FC07},
	{     "vspgt", 0x540000F8UL, 2, {reg_t,reg_t,gap,gap,gap},		{0x7,0x7,0,0,0},			{22,19,0,0,0},0x7FC07},
	{     "vsple", 0x54000100UL, 2, {reg_t,reg_t,gap,gap,gap},		{0x7,0x7,0,0,0},			{22,19,0,0,0},0x7FC07},
	{     "vsplt", 0x54000108UL, 2, {reg_t,reg_t,gap,gap,gap},		{0x7,0x7,0,0,0},			{22,19,0,0,0},0x7FC07},
	{    "vspgeu", 0x54000110UL, 2, {reg_t,reg_t,gap,gap,gap},		{0x7,0x7,0,0,0},			{22,19,0,0,0},0x7FC07},
	{    "vspgtu", 0x54000118UL, 2, {reg_t,reg_t,gap,gap,gap},		{0x7,0x7,0,0,0},			{22,19,0,0,0},0x7FC07},
	{    "vspleu", 0x54000120UL, 2, {reg_t,reg_t,gap,gap,gap},		{0x7,0x7,0,0,0},			{22,19,0,0,0},0x7FC07},
	{    "vspltU", 0x54000128UL, 2, {reg_t,reg_t,gap,gap,gap},		{0x7,0x7,0,0,0},			{22,19,0,0,0},0x7FC07},
	{  		 "Op", 0x400000E8UL, 4, {reg_t,reg_t,reg_t,f_t,gap},	{0x3,0x7,0x7,0x1,0},		{17,19,22,16,0},0xFC07},
	{      "vsel", 0x54000000UL, 5, {reg_t,reg_t,reg_t,f_t,reg_t},	{0x7,0x7,0x7,0x1,0x3},		{13,19,22,16,17},0x1807},
	{      "vsel", 0x54000400UL, 5, {reg_t,reg_t,reg_t,f_t,reg_t},	{0x7,0x7,0x1F,0x1,0x3},		{11,17,20,14,15},0x7},
	{     "vsleu", 0x400004D8UL, 4, {reg_t,reg_t,reg_t,reg_t,gap},	{0x3,0x7,0x1F,0x7,0},		{22,19,14,11,0},0x1003800},
	{     "vsltu", 0x400004E0UL, 4, {reg_t,reg_t,reg_t,reg_t,gap},	{0x3,0x7,0x1F,0x7,0},		{22,19,14,11,0},0x1003800},
    
 
      {          "", 0x56000000UL, 4, {vadd_op_t,reg_t,vreg_t, vmul_op2_t,gap},                 {0x7,0x7,0x7, 0xF,0,0,0},       {21,18,15, 9,0,0,0}, 0},
      {          "", 0x57000000UL, 4, {vadd_op_t,reg_t,reg_t,  vmul_op2_t,gap},                 {0x7,0x7,0x7, 0xF,0,0,0},       {21,18,15, 9,0,0,0}, 0},
      {          "", 0x56000000UL, 7, {vadd_op_t,reg_t,vreg_t, vmul_op2_t,reg_t,vreg_t,vreg_t}, {0x7,0x7,0x7, 0xF,0x7,0x7,0x7}, {21,18,15, 9,6,3,0}, 0},
      {          "", 0x56004000UL, 7, {vadd_op_t,reg_t,vreg_t, vmul_op2_t,reg_t,vreg_t,reg_t},  {0x7,0x7,0x7, 0xF,0x7,0x7,0xF}, {21,18,15, 10,7,4,0},0},
      {          "", 0x56002000UL, 7, {vadd_op_t,reg_t,vreg_t, vmul_op3_t,reg_t,vreg_t,reg_t},  {0x7,0x7,0x7, 0x7,0x7,0x7,0xF}, {21,18,15, 10,7,4,0},0},
      {          "", 0x57000000UL, 7, {vadd_op_t,reg_t,reg_t,  vmul_op2_t,reg_t,vreg_t,vreg_t}, {0x7,0x7,0x7, 0xF,0x7,0x7,0x7}, {21,18,15, 9,6,3,0}, 0},
      {          "", 0x57004000UL, 7, {vadd_op_t,reg_t,reg_t,  vmul_op2_t,reg_t,vreg_t,reg_t},  {0x7,0x7,0x7, 0xF,0x7,0x7,0xF}, {21,18,15, 10,7,4,0},0},
      {          "", 0x57002000UL, 7, {vadd_op_t,reg_t,reg_t,  vmul_op3_t,reg_t,vreg_t,reg_t},  {0x7,0x7,0x7, 0xF,0x7,0x7,0xF}, {21,18,15, 10,7,4,0},0},
    
      {          "", 0x58000000UL, 8, {vadd_op3_t,vreg_t,vreg_t,vreg_t, vmul_op4_t,reg_t,vreg_t,reg_t}, {0x7,0x7,0x7,0x7,0x7,0x7,0x7,0xF}, {22,19,16,13, 10,7,4,0},0},
    
      {          "", 0x5A000000UL, 8, {vadd_op3_t,vreg_t,vreg_t,vreg_t, vmul_op1_t,reg_t,vreg_t,vreg_t}, {0x7,0x7,0x7,0x7,0x7,0x7,0x7,0x7}, {22,19,16,13, 9,6,3,0},0x1000},
    
      {          "", 0x5E000000UL, 8, {vadd_op_t,reg_t,vreg_t,vreg_t, vcomp_op_t,imm_t,vreg_t,vreg_t}, {0x7,0x7,0x7,0x7,0x7,0x3,0x7,0x7}, {21,18,15,12, 8,6,3,0},0},
      {          "", 0x5E000800UL, 8, {vadd_op_t,reg_t,vreg_t,vreg_t, vcomp_op_t,imm_t,vreg_t,reg_t},  {0x7,0x7,0x7,0x7,0x7,0x3,0x7,0x7}, {21,18,15,12, 8,6,3,0},0},
      {          "", 0x5F000000UL, 8, {vadd_op_t,reg_t,vreg_t,reg_t,  vcomp_op_t,imm_t,vreg_t,vreg_t}, {0x7,0x7,0x7,0x7,0x7,0x3,0x7,0x7}, {21,18,15,12, 8,6,3,0},0},
      {          "", 0x5F000800UL, 8, {vadd_op_t,reg_t,vreg_t,reg_t,  vcomp_op_t,imm_t,vreg_t,reg_t},  {0x7,0x7,0x7,0x7,0x7,0x3,0x7,0x7}, {21,18,15,12, 8,6,3,0},0},
    
      {          "", 0x5C000000UL, 4, {vadd_op_t,reg_t,vreg_t,  vnop_t},                      {0x7,0x7,0x7, 0x1},              {21,18,15, 11},      0x47FF},//nop
      {          "", 0x5D000000UL, 4, {vadd_op_t,reg_t,reg_t,   vnop_t},                      {0x7,0x7,0x7, 0x1},              {21,18,15, 11},      0x47FF},//nop
      {          "", 0x5C002000UL, 7, {vadd_op_t,reg_t,vreg_t,  vec_ldst_op1_t,vreg_t,reg_t,int5_t},  {0x7,0x7,0x7, 0x3,0x7,0x7,0x1F}, {21,18,15, 11,8,5,0},0x4000},
      {          "", 0x5D002000UL, 7, {vadd_op_t,reg_t,reg_t,   vec_ldst_op1_t,vreg_t,reg_t,int5_t},  {0x7,0x7,0x7, 0x3,0x7,0x7,0x1F}, {21,18,15, 11,8,5,0},0x4000},
      {          "", 0x5C000000UL, 7, {vadd_op_t,reg_t,vreg_t,  vec_ldst_op2_t,vreg_t,reg_t,int5_t},  {0x7,0x7,0x7, 0x3,0x7,0x7,0x1F}, {21,18,15, 11,8,5,0},0x4000},
      {          "", 0x5D000000UL, 7, {vadd_op_t,reg_t,reg_t,   vec_ldst_op2_t,vreg_t,reg_t,int5_t},  {0x7,0x7,0x7, 0x3,0x7,0x7,0x1F}, {21,18,15, 11,8,5,0},0x4000},
    
      {          "", 0x62000000UL, 8, {vadd_op3_t,vreg_t,vreg_t,vreg_t,  vmov_op1_t,vreg_t,vreg_t,vreg_t},  {0x1,0x7,0x7,0x7, 0x1,0x7,0x7,0x7},  {24,21,18,15, 11,8,5,0}, 0x18},
      {          "", 0x62001000UL, 8, {vadd_op3_t,vreg_t,vreg_t,vreg_t,  vmov_op2_t,vreg_t,vreg_t,reg_t },  {0x1,0x7,0x7,0x7, 0x1,0x7,0x7,0x1F}, {24,21,18,15, 11,8,5,0}, 0},
      {          "", 0x62002000UL, 7, {vadd_op3_t,vreg_t,vreg_t,vreg_t,  vmov_op3_t,vreg_t,reg_t        },  {0x1,0x7,0x7,0x7, 0x2,0x7,0x1F},     {24,21,18,15, 11,8,3},   0x7},
    
      
      {          "", 0x61003F20UL, 5, {vadd_op_t,reg_t,reg_t,   vsh_vc_op3_t,vcreg_t},           {0x7,0x7,0x7, 0x1,0x3},         {21,18,15,  6,3},      0x4007},
      {          "", 0x60003F20UL, 5, {vadd_op_t,reg_t,vreg_t,  vsh_vc_op3_t,vcreg_t},           {0x7,0x7,0x7, 0x1,0x3},         {21,18,15,  6,3},      0x4007},
      {          "", 0x61003C00UL, 4, {vadd_op_t,reg_t,reg_t,   vnop_t},                         {0x7,0x7,0x7, 0x1},             {21,18,15,  0},        0x41ff},
      {          "", 0x60003C00UL, 4, {vadd_op_t,reg_t,vreg_t,  vnop_t},                         {0x7,0x7,0x7, 0x1},             {21,18,15,  0},        0x41ff},
      {          "", 0x61003F00UL, 5, {vadd_op_t,reg_t,reg_t,   vsh_vc_op3_t,imm_t},             {0x7,0x7,0x7, 0x1,0x3},         {21,18,15,  6,3},      0x4007},
      {          "", 0x60003F00UL, 5, {vadd_op_t,reg_t,vreg_t,  vsh_vc_op3_t,imm_t},             {0x7,0x7,0x7, 0x1,0x3},         {21,18,15,  6,3},      0x4007},
      {          "", 0x61003E80UL, 6, {vadd_op_t,reg_t,reg_t,   vsh_vc_op2_t,reg_t,vcreg_t},     {0x7,0x7,0x7, 0x1,0x7,0x3},     {21,18,15,  6,3,0},    0x4004},
      {          "", 0x60003E80UL, 6, {vadd_op_t,reg_t,vreg_t,  vsh_vc_op2_t,reg_t,vcreg_t},     {0x7,0x7,0x7, 0x1,0x7,0x3},     {21,18,15,  6,3,0},    0x4004},
      {          "", 0x61003E80UL, 6, {vadd_op_t,reg_t,reg_t,   vsh_vc_op2_t,vcreg_t,vreg_t},    {0x7,0x7,0x7, 0x1,0x3,0x7},     {21,18,15,  6,3,0},    0x4020},
      {          "", 0x60003E80UL, 6, {vadd_op_t,reg_t,vreg_t,  vsh_vc_op2_t,vcreg_t,vreg_t},    {0x7,0x7,0x7, 0x1,0x3,0x7},     {21,18,15,  6,3,0},    0x4020},
      {          "", 0x61003E00UL, 6, {vadd_op_t,reg_t,reg_t,   vsh_vc_op1_t,reg_t,vreg_t},      {0x7,0x7,0x7, 0x1,0x7,0x7},     {21,18,15,  6,3,0},    0x4000},
      {          "", 0x60003E00UL, 6, {vadd_op_t,reg_t,vreg_t,  vsh_vc_op1_t,reg_t,vreg_t},      {0x7,0x7,0x7, 0x1,0x7,0x7},     {21,18,15,  6,3,0},    0x4000},
      {          "", 0x61002000UL, 7, {vadd_op_t,reg_t,reg_t,   vsh_op4_t,reg_t,vreg_t,reg_t},   {0x7,0x7,0x7, 0x3,0x7,0x7,0xF}, {21,18,15,  10,7,4,0}, 0x4000},
      {          "", 0x60002000UL, 7, {vadd_op_t,reg_t,vreg_t,  vsh_op4_t,reg_t,vreg_t,reg_t},   {0x7,0x7,0x7, 0x3,0x7,0x7,0xF}, {21,18,15,  10,7,4,0}, 0x4000},
      {          "", 0x61001000UL, 7, {vadd_op_t,reg_t,reg_t,   vsh_op3_t,reg_t,vreg_t,reg_t},   {0x7,0x7,0x7, 0x3,0x7,0x7,0xF}, {21,18,15,  10,7,4,0}, 0x4000},
      {          "", 0x60001000UL, 7, {vadd_op_t,reg_t,vreg_t,  vsh_op3_t,reg_t,vreg_t,reg_t},   {0x7,0x7,0x7, 0x3,0x7,0x7,0xF}, {21,18,15,  10,7,4,0}, 0x4000},
      {          "", 0x61003000UL, 7, {vadd_op_t,reg_t,reg_t,   vsh_op2_t,reg_t,vreg_t,imm_t},   {0x7,0x7,0x7, 0x3,0x7,0x7,0xF}, {21,18,15,  10,7,4,0}, 0x4000},
      {          "", 0x60003000UL, 7, {vadd_op_t,reg_t,vreg_t,  vsh_op2_t,reg_t,vreg_t,imm_t},   {0x7,0x7,0x7, 0x3,0x7,0x7,0xF}, {21,18,15,  10,7,4,0}, 0x4000},
      {          "", 0x61000000UL, 7, {vadd_op_t,reg_t,reg_t,   vsh_op1_t,reg_t,vreg_t,vreg_t},  {0x7,0x7,0x7, 0x3,0x7,0x7,0x7}, {21,18,15,  10,7,4,1}, 0x4001},
      {          "", 0x60000000UL, 7, {vadd_op_t,reg_t,vreg_t,  vsh_op1_t,reg_t,vreg_t,vreg_t},  {0x7,0x7,0x7, 0x3,0x7,0x7,0x7}, {21,18,15,  10,7,4,1}, 0x4001},
      
      
     
	{ 		 NULL, 0,			0, {0,0,0,0,0,0},					{0,0,0,0,0,0},				{0,0,0,0,0,0},	0}
};

/*Scalar_64_bits instructions*/

const apex_64_bit_opc_info_t apex_APC_64b_scalar_opc_info[] =
{
	{     "andli", 0xD200000000000000ULL, 3, {reg_t,reg_t,imm_t,gap,gap},			{0x1F,0x1F,0xFFFFFFFF,0,0},	{50,45,0,0,0},0x1FFF00000000},
	{      "orli", 0xD280000000000000ULL, 3, {reg_t,reg_t,imm_t,gap,gap},			{0x1F,0x1F,0xFFFFFFFF,0,0},	{50,45,0,0,0},0x1FFF00000000},
	{     "xorli", 0xD300000000000000ULL, 3, {reg_t,reg_t,imm_t,gap,gap},			{0x1F,0x1F,0xFFFFFFFF,0,0},	{50,45,0,0,0},0x1FFF00000000},
	{       "sll", 0xD400000000000000ULL, 5, {reg_t,reg_t,reg_t,reg_t,reg_t,gap},	{0x1F,0x1F,0x1F,0x1F,0x1F},	{47,42,37,32,27},0x7FFFFFF},
	{       "sra", 0xF410000000000000ULL, 5, {reg_t,reg_t,reg_t,reg_t,reg_t,gap},	{0x1F,0x1F,0x1F,0x1F,0x1F},	{47,42,37,32,27},0x7FFFFFF},
	{       "srl", 0xF420000000000000ULL, 5, {reg_t,reg_t,reg_t,reg_t,reg_t,gap},	{0x1F,0x1F,0x1F,0x1F,0x1F},	{47,42,37,32,27},0x7FFFFFF},
	{      "slli", 0xF430000000000000ULL, 5, {reg_t,reg_t,reg_t,reg_t,imm_t,gap},	{0x1F,0x1F,0x1F,0x1F,0x1F},	{47,42,37,32,26},0x100000003FFFFFF},
	{      "srai", 0xF440000000000000ULL, 5, {reg_t,reg_t,reg_t,reg_t,imm_t,gap},	{0x1F,0x1F,0x1F,0x1F,0x1F},	{47,42,37,32,26},0x100000003FFFFFF},
	{      "srli", 0xF450000000000000ULL, 5, {reg_t,reg_t,reg_t,reg_t,imm_t,gap},	{0x1F,0x1F,0x1F,0x1F,0x1F},	{47,42,37,32,26},0x100000003FFFFFF},
	{       "add", 0xF460000000000000ULL, 6, {reg_t,reg_t,reg_t,reg_t,reg_t,reg_t}, {0x1F,0x1F,0x1F,0x1F,0x1F,0x1F}, {47,42,37,32,27,22},0x3FFFFF},
	{      "addx", 0xF470000000000000ULL, 6, {reg_t,reg_t,reg_t,reg_t,reg_t,reg_t}, {0x1F,0x1F,0x1F,0x1F,0x1F,0x1F}, {47,42,37,32,27,22},0x3FFFFF},
	{       "sub", 0xF480000000000000ULL, 6, {reg_t,reg_t,reg_t,reg_t,reg_t,reg_t}, {0x1F,0x1F,0x1F,0x1F,0x1F,0x1F}, {47,42,37,32,27,22},0x3FFFFF},
	{      "subx", 0xF490000000000000ULL, 6, {reg_t,reg_t,reg_t,reg_t,reg_t,reg_t}, {0x1F,0x1F,0x1F,0x1F,0x1F,0x1F}, {47,42,37,32,27,22},0x3FFFFF},
	{       "and", 0xF4A0000000000000ULL, 6, {reg_t,reg_t,reg_t,reg_t,reg_t,reg_t}, {0x1F,0x1F,0x1F,0x1F,0x1F,0x1F}, {47,42,37,32,27,22},0x3FFFFF},
	{        "or", 0xF4B0000000000000ULL, 6, {reg_t,reg_t,reg_t,reg_t,reg_t,reg_t}, {0x1F,0x1F,0x1F,0x1F,0x1F,0x1F}, {47,42,37,32,27,22},0x3FFFFF},
	{       "xor", 0xF4C0000000000000ULL, 6, {reg_t,reg_t,reg_t,reg_t,reg_t,reg_t}, {0x1F,0x1F,0x1F,0x1F,0x1F,0x1F}, {47,42,37,32,27,22},0x3FFFFF},
    
    {       "",    0xC000000000000000ULL, 4, {valu_short_t,vmul_short_t,vsh_short_t,vldst_short_t}, {0x3FFF, 0x7FFF, 0x3FFF, 0x3FFF},    {43,28,14,0}, 0},
    {       "",    0xC800000000000000ULL, 3, {valu_short_t, vmul_short_t,  vldst2_short_t},            {0x3FFF, 0x7FFF, 0xFFFFFFF}, {43,28,0},     0},
    {       "",    0xE000000000000000ULL, 3, {valu_short_t, vswap_short_t, vldst2_short_t},            {0x3FFF, 0x7FFF, 0xFFFFFFF}, {43,28,0},     0},
    
//  {          "", 0x56000000UL, 2, {vadd_cmd,vmull_cmd,gap,gap,gap},{0x3FF,0x7FFF,0,0,0},  {15, 0,0,0,0},  0},//packed instructions
//  {          "", 0x58000000UL, 2, {vadd_op3_cmd,vmull_op4_cmd,gap,gap,gap},{0xFFF,0x1FFF,0,0,0},  {13, 0,0,0,0},  0},//packed instructions
    
	{ 		 NULL, 0,			        0, {0,0,0,0,0,0},					{0,0,0,0,0,0},				{0,0,0,0,0,0},	0}

};

//valu_short 14bit
const apex_opc_info_t apex_short_valu_op_opc_info[] ={
    { "vnop", 0x0000, 0,{ gap },{0}, {0}, 0xFFF},
    { "",     0x3000, 4,{vadd_op_t, reg_t, vreg_t, vreg_t},{0x7, 0x7, 0x7, 0x7}, {9, 6,3,0}, 0},
    { "",     0x2000, 4,{vadd_op_t, reg_t, vreg_t, reg_t },{0x7, 0x7, 0x7, 0x7}, {9, 6,3,0}, 0},
    { 		 NULL, 0,			        0, {0,0,0,0,0,0},					{0,0,0,0,0,0},				{0,0,0,0,0,0},	0}
};

//vmul_short 15bit
const apex_opc_info_t apex_short_vmul_op_opc_info[] = {
    { "vnop", 0x0000, 0,{ gap }, {0}, {0}, 0},
    { "",     0x2000, 4,{vmul_op3_t, reg_t, vreg_t, reg_t},   {0x7, 0x7, 0x7, 0xF}, {10, 7,4,0}, 0},
    { "",     0x4000, 4,{vmul_op2_t, reg_t, vreg_t, vreg_t }, {0xF, 0x7, 0x7, 0xF}, {10, 7,4,0}, 0},
    { "",     0x0000, 4,{vmul_op2_t, reg_t, vreg_t, vreg_t }, {0xF, 0x7, 0x7, 0x7}, {9,  6,3,0}, 0},
    { 		 NULL, 0,			        0, {0,0,0,0,0,0},					{0,0,0,0,0,0},				{0,0,0,0,0,0},	0}
};


//vsh_short 14bit
const apex_opc_info_t apex_short_vsh_op_opc_info[] = {
    { "",    0x3F20, 2 ,{vsh_vc_op3_t, vcreg_t},        {0x1, 0x3},    {6 ,3},    0x7}, 
    { "",    0x3F00, 2 ,{vsh_vc_op3_t, vcreg_t},        {0x1, 0x3},    {6 ,3},    0x7}, 
    { "vmvc",0x3E80, 2 ,{vcreg_t, vreg_t},              { 0x3,0x7},     {3,0},  0x20}, //?????
    { "vmcv",0x3EC0, 2 ,{vreg_t, vcreg_t},              { 0x7,0x3},     {3,0},  0x4}, //?????
    { "",    0x3E00, 3 ,{vsh_vc_op1_t, reg_t, vreg_t},  {0x1, 0x3,0x3},{6 ,3,0},  0x0}, 
    { "vnop",0x3C00, 0 ,{gap},                          {0},           {0},       0x1FF}, 
    { "",    0x2000, 4 ,{vsh_op4_t, reg_t, vreg_t, reg_t}, {0x3, 0x7,0x7,0xF}, {10,7 ,4,0},  0x0}, 
    { "",    0x1000, 4 ,{vsh_op3_t, reg_t, vreg_t, reg_t}, {0x3, 0x7,0x7,0xF}, {10,7 ,4,0},  0x0}, 
    { "",    0x3000, 4 ,{vsh_op2_t, reg_t, vreg_t, imm_t}, {0x3, 0x7,0x7,0xF}, {10,7 ,4,0},  0x0}, 
    { "",    0x0000, 4 ,{vsh_op1_t, reg_t, vreg_t, vreg_t},{0x3, 0x7,0x7,0x7}, {10,7 ,4,1},  0x1},
    { 		 NULL, 0,			        0, {0,0,0,0,0,0},					{0,0,0,0,0,0},				{0,0,0,0,0,0},	0}
};

//vldst_short 14bit
const apex_opc_info_t apex_short_vldst_op_opc_info[] = {
    {"vnop", 0x0000, 0, {gap}, {0}, {0}, 0x7FF},
    {"", 0x0000, 4,{vec_ldst_op2_t,vreg_t,reg_t,int5_t}, {0x3,0x7,0x7,0x1F},{11,8,5,0}, 0},
    {"", 0x2000, 4,{vec_ldst_op1_t,vreg_t,reg_t,int5_t}, {0x3,0x7,0x7,0x1F},{11,8,5,0}, 0},
    { 		 NULL, 0,			        0, {0,0,0,0,0,0},					{0,0,0,0,0,0},				{0,0,0,0,0,0},	0}
};

//vldst2_short 28bit
const apex_opc_info_t apex_short_vldst2_op_opc_info[] = {
    {"vnop", 0x0000000, 0, {gap}, {0}, {0}, 0xFFFC7FF},
    {"",     0x0002000, 4, {vec_ldst_op1_t, vreg_t, reg_t, int12_t}, {0x3, 0x7,0x1F,0xFFF}, {11, 8,3,16}, 0xC007},
    {"",     0x0000000, 4, {vec_ldst_op2_t, vreg_t, reg_t, int12_t}, {0x3, 0x7,0x1F,0xFFF}, {11, 8,3,16}, 0xC007},
    {		 NULL, 0,	0, {0,0,0,0,0,0}, {0,0,0,0,0,0}, {0,0,0,0,0,0},	0}
};

//vswap_short 15bit
const apex_opc_info_t apex_short_vswap_op_opc_info[] = {
    {"vnop",     0x4800, 0, {gap}, {0}, {0}, 0x7FF},
    {"vsel_vc",  0x4000, 4, {vreg_t, vreg_t, vreg_t, neg_op_t},     {0x7,0x7,0x3,0x1},     { 8,5,3,2}, 0x2},
    {"vswap_vc", 0x4001, 4, {vreg_t, vreg_t, vreg_t, neg_op_t},     {0x7,0x7,0x3,0x1},     { 8,5,3,2}, 0x2},
    {"",         0x0000, 3, {vswap_op_t, reg_t, reg_t},           {0x3, 0x7,0x1F,0xFFF},   {11,8,5}, 0x1E},
    {		 NULL, 0,	0, {0,0,0,0,0,0}, {0,0,0,0,0,0}, {0,0,0,0,0,0},	0}
};


/*
const apex_opc_info_t apex_short_vadd_op_opc_info[] ={
    { "vadd", 0x000, 2,{reg_t, vreg_t, gap,gap,gap},{0x7, 0x7, 0,0,0}, {3, 0, 0,0,0}, 0},
    { "vaddx",0x040, 2,{reg_t, vreg_t, gap,gap,gap},{0x7, 0x7, 0,0,0}, {3, 0, 0,0,0}, 0},
    { "vaub", 0x080, 2,{reg_t, vreg_t, gap,gap,gap},{0x7, 0x7, 0,0,0}, {3, 0, 0,0,0}, 0},
    { "vaubx",0x0C0, 2,{reg_t, vreg_t, gap,gap,gap},{0x7, 0x7, 0,0,0}, {3, 0, 0,0,0}, 0},
    { "vand", 0x100, 2,{reg_t, vreg_t, gap,gap,gap},{0x7, 0x7, 0,0,0}, {3, 0, 0,0,0}, 0},
    { "vor",  0x140, 2,{reg_t, vreg_t, gap,gap,gap},{0x7, 0x7, 0,0,0}, {3, 0, 0,0,0}, 0},
    { "vxor", 0x180, 2,{reg_t, vreg_t, gap,gap,gap},{0x7, 0x7, 0,0,0}, {3, 0, 0,0,0}, 0},
    { "vxtd", 0x1C0, 2,{reg_t, vreg_t, gap,gap,gap},{0x7, 0x7, 0,0,0}, {3, 0, 0,0,0}, 0},
    { "vadd", 0x200, 2,{reg_t, reg_t, gap,gap,gap},{0x7, 0x7, 0,0,0}, {3, 0, 0,0,0}, 0},
    { "vaddx",0x240, 2,{reg_t, reg_t, gap,gap,gap},{0x7, 0x7, 0,0,0}, {3, 0, 0,0,0}, 0},
    { "vaub", 0x280, 2,{reg_t, reg_t, gap,gap,gap},{0x7, 0x7, 0,0,0}, {3, 0, 0,0,0}, 0},
    { "vaubx",0x2C0, 2,{reg_t, reg_t, gap,gap,gap},{0x7, 0x7, 0,0,0}, {3, 0, 0,0,0}, 0},
    { "vand", 0x300, 2,{reg_t, reg_t, gap,gap,gap},{0x7, 0x7, 0,0,0}, {3, 0, 0,0,0}, 0},
    { "vor",  0x340, 2,{reg_t, reg_t, gap,gap,gap},{0x7, 0x7, 0,0,0}, {3, 0, 0,0,0}, 0},
    { "vxor", 0x380, 2,{reg_t, reg_t, gap,gap,gap},{0x7, 0x7, 0,0,0}, {3, 0, 0,0,0}, 0},
    { "vxtd", 0x3C0, 2,{reg_t, reg_t, gap,gap,gap},{0x7, 0x7, 0,0,0}, {3, 0, 0,0,0}, 0},
    { NULL, 0, 0,{0,0,0,0,0}, {0,0,0,0,0}, {0,0,0,0,0}, 0}
};

const apex_opc_info_t apex_short_vadd_op3_opc_info[] ={
    { "vacc32s", 0x000, 3,{vreg_t, vreg_t, vreg_t,gap,gap},{0x7, 0x7, 0x7,0,0}, {6, 3, 0,0,0}, 0},
    { "vacc32u", 0x200, 3,{vreg_t, vreg_t, vreg_t,gap,gap},{0x7, 0x7, 0x7,0,0}, {6, 3, 0,0,0}, 0},
    { "vacc32s_s18", 0x400, 3,{vreg_t, vreg_t, vreg_t,gap,gap},{0x7, 0x7, 0x7,0,0}, {6, 3, 0,0,0}, 0},
    { "vacc32u_s18", 0x600, 3,{vreg_t, vreg_t, vreg_t,gap,gap},{0x7, 0x7, 0x7,0,0}, {6, 3, 0,0,0}, 0},
    { NULL, 0, 0,{0,0,0,0,0}, {0,0,0,0,0}, {0,0,0,0,0}, 0}
};

const apex_opc_info_t apex_short_vmul_op4_opc_info[] ={
    { "vmul_lulu", 0x0000, 3,{reg_t, vreg_t, reg_t,gap,gap},{0x7, 0x7, 0xF,0,0}, {7, 4, 0,0,0}, 0},
    { "vmul_hslu", 0x0400, 3,{reg_t, vreg_t, reg_t,gap,gap},{0x7, 0x7, 0xF,0,0}, {7, 4, 0,0,0}, 0},
    { "vmul_hulu", 0x0800, 3,{reg_t, vreg_t, reg_t,gap,gap},{0x7, 0x7, 0xF,0,0}, {7, 4, 0,0,0}, 0},
    { "vmul_hshu", 0x0C00, 3,{reg_t, vreg_t, reg_t,gap,gap},{0x7, 0x7, 0xF,0,0}, {7, 4, 0,0,0}, 0},
    { "vmul_luhs", 0x1000, 3,{reg_t, vreg_t, reg_t,gap,gap},{0x7, 0x7, 0xF,0,0}, {7, 4, 0,0,0}, 0},
    { "vmul_luhu", 0x1400, 3,{reg_t, vreg_t, reg_t,gap,gap},{0x7, 0x7, 0xF,0,0}, {7, 4, 0,0,0}, 0},
    { "vmul_huhs", 0x1800, 3,{reg_t, vreg_t, reg_t,gap,gap},{0x7, 0x7, 0xF,0,0}, {7, 4, 0,0,0}, 0},
    { "vmul_hshs", 0x1C00, 3,{reg_t, vreg_t, reg_t,gap,gap},{0x7, 0x7, 0xF,0,0}, {7, 4, 0,0,0}, 0},
    { NULL, 0, 0,{0,0,0,0,0}, {0,0,0,0,0}, {0,0,0,0,0}, 0}
};

const apex_opc_info_t apex_short_vmul_opc_info[] ={
    { "vmul_lulu", 0x0200, 3,{reg_t, vreg_t, vreg_t,gap,gap},{0x7, 0x7, 0x7,0,0}, {6, 3, 0,0,0}, 0},
    { "vmul_lslu", 0x0400, 3,{reg_t, vreg_t, vreg_t,gap,gap},{0x7, 0x7, 0x7,0,0}, {6, 3, 0,0,0}, 0},
    { "vmul_lsls", 0x0600, 3,{reg_t, vreg_t, vreg_t,gap,gap},{0x7, 0x7, 0x7,0,0}, {6, 3, 0,0,0}, 0},
    { "vmul_hulu", 0x0800, 3,{reg_t, vreg_t, vreg_t,gap,gap},{0x7, 0x7, 0x7,0,0}, {6, 3, 0,0,0}, 0},
    { "vmul_huls", 0x0A00, 3,{reg_t, vreg_t, vreg_t,gap,gap},{0x7, 0x7, 0x7,0,0}, {6, 3, 0,0,0}, 0},
    { "vmul_hslu", 0x0C00, 3,{reg_t, vreg_t, vreg_t,gap,gap},{0x7, 0x7, 0x7,0,0}, {6, 3, 0,0,0}, 0},
    { "vmul_hsls", 0x0E00, 3,{reg_t, vreg_t, vreg_t,gap,gap},{0x7, 0x7, 0x7,0,0}, {6, 3, 0,0,0}, 0},
    { "vmul_huhu", 0x1000, 3,{reg_t, vreg_t, vreg_t,gap,gap},{0x7, 0x7, 0x7,0,0}, {6, 3, 0,0,0}, 0},
    { "vmul_hshu", 0x1200, 3,{reg_t, vreg_t, vreg_t,gap,gap},{0x7, 0x7, 0x7,0,0}, {6, 3, 0,0,0}, 0},
    { "vmul_hshs", 0x1600, 3,{reg_t, vreg_t, vreg_t,gap,gap},{0x7, 0x7, 0x7,0,0}, {6, 3, 0,0,0}, 0},
    { "vmul",      0x1800, 3,{reg_t, vreg_t, vreg_t,gap,gap},{0x7, 0x7, 0x7,0,0}, {6, 3, 0,0,0}, 0},
    
    { "vmul_lulu", 0x4400, 3,{reg_t, vreg_t, reg_t,gap,gap},{0x7, 0x7, 0xF,0,0}, {7, 4, 0,0,0}, 0},
    { "vmul_lslu", 0x4800, 3,{reg_t, vreg_t, reg_t,gap,gap},{0x7, 0x7, 0xF,0,0}, {7, 4, 0,0,0}, 0},
    { "vmul_lsls", 0x4C00, 3,{reg_t, vreg_t, reg_t,gap,gap},{0x7, 0x7, 0xF,0,0}, {7, 4, 0,0,0}, 0},
    { "vmul_hulu", 0x5000, 3,{reg_t, vreg_t, reg_t,gap,gap},{0x7, 0x7, 0xF,0,0}, {7, 4, 0,0,0}, 0},
    { "vmul_huls", 0x5400, 3,{reg_t, vreg_t, reg_t,gap,gap},{0x7, 0x7, 0xF,0,0}, {7, 4, 0,0,0}, 0},
    { "vmul_hslu", 0x5800, 3,{reg_t, vreg_t, reg_t,gap,gap},{0x7, 0x7, 0xF,0,0}, {7, 4, 0,0,0}, 0},
    { "vmul_hsls", 0x5C00, 3,{reg_t, vreg_t, reg_t,gap,gap},{0x7, 0x7, 0xF,0,0}, {7, 4, 0,0,0}, 0},
    { "vmul_huhu", 0x6000, 3,{reg_t, vreg_t, reg_t,gap,gap},{0x7, 0x7, 0xF,0,0}, {7, 4, 0,0,0}, 0},
    { "vmul_hshu", 0x6400, 3,{reg_t, vreg_t, reg_t,gap,gap},{0x7, 0x7, 0xF,0,0}, {7, 4, 0,0,0}, 0},
    { "vmul_hshs", 0x6800, 3,{reg_t, vreg_t, reg_t,gap,gap},{0x7, 0x7, 0xF,0,0}, {7, 4, 0,0,0}, 0},
    { "vmul",      0x6C00, 3,{reg_t, vreg_t, reg_t,gap,gap},{0x7, 0x7, 0xF,0,0}, {7, 4, 0,0,0}, 0},
    
    { "vmul_luls", 0x2000, 3,{reg_t, vreg_t, reg_t,gap,gap},{0x7, 0x7, 0xF,0,0}, {7, 4, 0,0,0}, 0},
    { "vmul_luhu", 0x2400, 3,{reg_t, vreg_t, reg_t,gap,gap},{0x7, 0x7, 0xF,0,0}, {7, 4, 0,0,0}, 0},
    { "vmul_lshu", 0x2800, 3,{reg_t, vreg_t, reg_t,gap,gap},{0x7, 0x7, 0xF,0,0}, {7, 4, 0,0,0}, 0},
    { "vmul_luhs", 0x2C00, 3,{reg_t, vreg_t, reg_t,gap,gap},{0x7, 0x7, 0xF,0,0}, {7, 4, 0,0,0}, 0},
    { "vmul_lshs", 0x3000, 3,{reg_t, vreg_t, reg_t,gap,gap},{0x7, 0x7, 0xF,0,0}, {7, 4, 0,0,0}, 0},
    { "vmul_huhs", 0x3400, 3,{reg_t, vreg_t, reg_t,gap,gap},{0x7, 0x7, 0xF,0,0}, {7, 4, 0,0,0}, 0},
    { "vmul_nop",  0x0000, 0,{gap,gap,gap,gap,gap},{0x0, 0x0, 0x0,0,0}, {0,0,0,0,0}, 0},
    
    { NULL, 0, 0,{0,0,0,0,0}, {0,0,0,0,0}, {0,0,0,0,0}, 0}
};
*/




const char* vmul_op1[] = {
    "vmul_lulu",
    "vmul_hslu",
    "vmul_hulu",
    "vmul_hshu",
    "vmul_huhu",
    "vmul_hshs",
    "vmul",
    "unknonw"
};

const char* vmul_op2[] = {
    "vmul_nop",
    "vmul_lulu",
    "vmul_lslu",
    "vmul_lsls",
    "vmul_hulu",
    "vmul_huls",
    "vmul_hslu",
    "vmul_hsls",
    "vmul_huhu",
    "vmul_hshu",
    "vmul_hshs",
    "vmul"
};

const char* vmul_op3[] = {
    "vmul_luls",
    "vmul_luhu",
    "vmul_lshu",
    "vmul_luhs",
    "vmul_lshs",
    "vmul_huhs",
    "unknown",
    "unknown"
};

const char* vmul_op4[] = {
    "vmul_lulu",
    "vmul_hslu",
    "vmul_hulu",
    "vmul_hshu",
    "vmul_luhs",
    "vmul_luhu",
    "vmul_huhs",
    "vmul_hshs"
};

const char* vadd_op[] = {
    "vadd",
    "vaddx",
    "vsub",
    "vsubx",
    "vand",
    "vor",
    "vxor",
    "vxtd"
};

const char* vadd_op3[] = {
    "vacc32s",
    "vacc32u",
    "vacc32s_s18",
    "vacc32u_s18"
};

const char* vcomp_op[] = {
    "vseq",
    "vsge",
    "vsgt",
    "vsle",
    "vslt",
    "vsgeu",
    "vsgtu",
    "vsltu"
};

const char* vec_ldst_op1[] = {
    "unknown",
    "vsb",
    "vsw",
    "unknown"
};

const char* vec_ldst_op2[] = {
    "unknown",
    "vlb",
    "vlbu",
    "vlw"
};

const char* vnop[] = {
    "nop"
};

const char* vmov_op1[] = {
    "vmrlv",
    "vmrrv"
};

const char* vmov_op2[] = {
    "vmrlr",
    "vmrrr"
};

const char* vmov_op3[] = {
    "vmrhi",
    "vmrh",
    "vmrb",
    "vmrbu"
};

const char* vsh_op1[] = {
    "vsll",
    "vsra",
    "vsrl",
    "vrl"
};

const char* vsh_op2[] = {
    "vslli",
    "vsrai",
    "vsrli",
    "unknown"
};

const char* vsh_op3[] = {
    "vsllrl",
    "vsrarl",
    "vsrlrl",
    "vrlrl"
};

const char* vsh_op4[] = {
    "vsllrh",
    "vsrarh",
    "vsrlrh",
    "vrlrh"
};

const char* vsh_vc_op1[] = {
    "vsrl_ov",
    "vsll_ov"
};

const char* vsh_vc_op2[] = {
    "vmvc",
    "vmcv"
};

const char* vsh_vc_op3[] = {
    "vcinv",
    "vcmv"
};

const char* vswap_op[] = {
    "vspge",
    "vspgt",
    "vsple",
    "vsplt",
    "vspgeu",
    "vspgtu",
    "vspleu",
    "vspltu"
};

const char* neg_op[] = {
    "pass",
    "negate"
};
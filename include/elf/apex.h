/*
 * Copyrights
 */

#ifndef _ELF_APEX_H
#define _ELF_APEX_H

#include "elf/reloc-macros.h"

START_RELOC_NUMBERS (elf_apex_reloc_type)
  RELOC_NUMBER (R_APEX_NONE, 0)
END_RELOC_NUMBERS(R_APEX_max)
    
#define ELF_EF_APEX_CORE(f)       ( (f) & 0xffUL )


#endif

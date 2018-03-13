/*
 * Copyrights
 */

#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"
#include "elf-bfd.h"
#include "elf/apex.h"


static reloc_howto_type apex_elf_howto_table[] = {
  /* This reloc does nothing.  */
  HOWTO (R_APEX_NONE,		/* type */
	 0,			/* rightshift */
	 3,			/* size (0 = byte, 1 = short, 2 = long) */
	 0,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_APEX_NONE",	/* name */
	 FALSE,			/* partial_inplace */
	 0,			/* src_mask */
	 0,			/* dst_mask */
	 FALSE),		/* pcrel_offset */
};


static reloc_howto_type *
apex_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED,
			  bfd_reloc_code_real_type code)
{
  // Note that the apex_elf_howto_table is indexed by the R_
  // constants. Thus, the order that the howto records appear in the
  // table *must* match the order of the relocation types defined in
  // include/elf/apex.h.  
  return &apex_elf_howto_table[(int) R_APEX_NONE];
}

static reloc_howto_type *
apex_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED, const char *r_name)
{
  return NULL;
}



static reloc_howto_type *
bfd_elf32_bfd_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED,
				 bfd_reloc_code_real_type code ATTRIBUTE_UNUSED)
{

  return NULL;
}


static bfd_boolean
apex_elf_object_p (bfd * abfd)
{
  
  return bfd_default_set_arch_mach (abfd, bfd_arch_apex, ELF_EF_APEX_CORE (elf_elfheader (abfd)->e_flags));
}

//static bfd_boolean
//elf32_apex_swap_symbol_in (bfd * abfd,
//			  const void *psrc,
//			  const void *pshn,
//			  Elf_Internal_Sym *dst)
//{
//  return TRUE;
//}



/* We use this to override swap_symbol_in.  */
const struct elf_size_info elf32_apex_size_info =
{
  sizeof (Elf32_External_Ehdr),
  sizeof (Elf32_External_Phdr),
  sizeof (Elf32_External_Shdr),
  sizeof (Elf32_External_Rel),
  sizeof (Elf32_External_Rela),
  sizeof (Elf32_External_Sym),
  sizeof (Elf32_External_Dyn),
  sizeof (Elf_External_Note),
  4,
  1,
  32, 2,
  ELFCLASS32, EV_CURRENT,
  bfd_elf32_write_out_phdrs,
  bfd_elf32_write_shdrs_and_ehdr,
  bfd_elf32_checksum_contents,
  bfd_elf32_write_relocs,
  //elf32_apex_swap_symbol_in,
  bfd_elf32_swap_symbol_in,
  bfd_elf32_swap_symbol_out,
  bfd_elf32_slurp_reloc_table,
  bfd_elf32_slurp_symbol_table,
  bfd_elf32_swap_dyn_in,
  bfd_elf32_swap_dyn_out,
  bfd_elf32_swap_reloc_in,
  bfd_elf32_swap_reloc_out,
  bfd_elf32_swap_reloca_in,
  bfd_elf32_swap_reloca_out
};


#define ELF_ARCH		bfd_arch_apex
#define ELF_MACHINE_CODE	EM_NONE
#define ELF_MAXPAGESIZE		1

//#define ELF_MAXPAGESIZE 0x100000
//#define ELF_COMMONPAGESIZE 0x2000
//#define ELF_MACHINE_CODE	EM_NONE

#define TARGET_BIG_SYM						apex_elf32_def_vec
#define TARGET_BIG_NAME						"elf32-apex"
//#define elf_info_to_howto_rel				NULL
//#define elf_info_to_howto					apex_info_to_howto_rela
#define bfd_elf32_bfd_reloc_type_lookup		apex_reloc_type_lookup
#define bfd_elf32_bfd_reloc_name_lookup		apex_reloc_name_lookup
#define elf_backend_object_p				apex_elf_object_p
//#define elf_backend_post_process_headers	apex_elf_post_process_headers
//#define elf_backend_size_info				elf32_apex_size_info
//#define bfd_elf32_get_section_contents  	apex_get_section_contents
//#define bfd_elf32_set_section_contents		apex_set_section_contents
//#define bfd_elf32_find_nearest_line	      	apex_find_nearest_line

#include "elf32-target.h"

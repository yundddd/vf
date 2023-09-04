/* Do not use directly. This is not a valid linker script. */
ENTRY(_start)
SECTIONS
{
  /* Order some common sections so they don't show up in between sections
     we want to extract. */
  .interp         : { *(.interp) }
  .note.gnu.build-id  : { *(.note.gnu.build-id) }
  .hash           : { *(.hash) }
  .gnu.hash       : { *(.gnu.hash) }
  .dynsym         : { *(.dynsym) }
  .dynstr         : { *(.dynstr) }
  .gnu.version    : { *(.gnu.version) }
  .gnu.version_d  : { *(.gnu.version_d) }
  .gnu.version_r  : { *(.gnu.version_r) }
  .rela.dyn       :
    {
      *(.rela.*)
    }
  .rela.plt       :
    {
      *(.rela.plt)
      *(.rela.iplt)
    }

  /* Our binary extractor will take all bits from here till parasite_end.
     The text section must be aligned by pages, otherwise compiler would
     generate wrong offset for rodata for pie parasites. learned from hard
     lessons. */
  .text     ALIGN(4096)   :
  {
    __parasite_start = .;
    *(.text.start_parasite)
    *(.text.unlikely .text.*_unlikely .text.unlikely.*)
    *(.text.exit .text.exit.*)
    *(.text.startup .text.startup.*)
    *(.text.hot .text.hot.*)
    *(SORT(.text.sorted.*))
    *(.text .stub .text.* .gnu.linkonce.t.*)
    /* .gnu.warning sections are handled specially by elf.em.  */
    *(.gnu.warning)
  }

  /* put rodata right after text so it can be extracted as a blob. */
  .rodata    ALIGN(16)     : { *(.rodata* .gnu.linkonce.r.*) }
  /* usually we shouldn't need got because global variables are forbidden
     as they will end up in RX section (not writable). For unknown reason
     clang16 for aarch64 would put symbol addresses in got. We can still
     merge this section but currently we do not allow it (backed by unittests) */
  .got       ALIGN(4)     : { *(.got) }
  __parasite_end = .;
}
#include "common/macros.hh"
#include "std/string.hh"
#include "std/sys.hh"

void parasite_main() {
  const char* str = nullptr;
  /*
  asm volatile(
      "jmp inf\n"
      "name_call:\n"
      "pop %0\n"
      "jmp out\n"
      "inf:\n"
      "call name_call\n"
      ".asciz \""
      "1234"
      "\"\n"
      "out:\n"
      : "=r"(str)
      :);
    */
  STR_LITERAL(str, "this binary is infected\\n\\0\\0\\0");
  write(1, str, strlen(str));
}

extern void parasite_main();
// Move _start() to the beginning of the text.
int main() __attribute__((section(".text.sorted.2")));

int main() {
  parasite_main();
#if defined(__x86_64__)
  asm volatile(
      "pop %rbx\n"  // undo main's frame
      "pop %rbx\n"
      "pop %rbx\n"

      "pop %rsp\n"
      "pop %r12\n"
      "pop %r11\n"
      "pop %rdi\n"
      "pop %rdx\n"
      "pop %rcx\n"
      "pop %rax\n"

      "nop\n"
      "nop\n"
      "nop\n"
      "nop\n"
      "nop\n"
      "nop\n"
      "nop\n"
      "nop\n");
#elif defined(__aarch64__)
  asm volatile(
      "ldr	x30, [sp], #16\n"  // undo the main's frame.
      "ldp x0, x1, [sp], #16\n"    // restore x0
                                   // ".inst 0xd4200000\n"
      "nop\n");
#endif

  return 0;
}
#pragma once

#include <sys/mman.h>

namespace vt {
void* mmap(void* addr, size_t length, int prot, int flags, int fd,
           off_t offset);
int munmap(void* addr, size_t length);
}  // namespace vt
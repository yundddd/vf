#pragma once

#include <sys/mman.h>

namespace vf {
void* mmap(void* addr, size_t length, int prot, int flags, int fd,
           off_t offset);
int munmap(void* addr, size_t length);
}  // namespace vf
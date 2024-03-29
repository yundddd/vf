#pragma once

#include <sys/mount.h>

namespace vf {
int mount(const char* src, const char* tgt, const char* fst,
          unsigned long flags, const void* data);
int umount2(const char* path, int flags);
}  // namespace vf
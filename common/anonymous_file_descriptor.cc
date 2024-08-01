#include "common/anonymous_file_descriptor.hh"
#include <memory>
#include "common/macros.hh"
#include "nostdlib/stdlib.hh"
#include "nostdlib/string.hh"
#include "nostdlib/sys/mman.hh"

namespace vf::common {
namespace {
struct ProcFileName {
  char name[64] = {};
};
}  // namespace

AnonymousFileDescriptor::AnonymousFileDescriptor(const char* name, int flags,
                                                 size_t size)
    : FileDescriptor(vf::memfd_create(name, flags)) {
  mapping_ = vf::common::Mmap<PROT_WRITE>(size, MAP_SHARED, handle(), 0);
  truncate(size);
}
void AnonymousFileDescriptor::execve() const {
  CHECK_TRUE(valid());
  const auto prefix = STR_LITERAL("/proc/self/fd/");
  constexpr size_t prefix_len = 14;
  auto buffer = std::make_unique<ProcFileName>();
  vf::memcpy(buffer->name, (void*)prefix, prefix_len);
  vf::itoa_r(handle(), buffer->name + prefix_len);
  vf::execve(buffer->name, nullptr, nullptr);
}

}  // namespace vf::common
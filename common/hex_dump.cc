#include "common/hex_dump.hh"
#include "nostdlib/ctype.hh"
#include "nostdlib/stdio.hh"

namespace vf::common {

void hex_dump(const void* ptr, size_t buflen) {
  auto buf = static_cast<const unsigned char*>(ptr);
  size_t i, j;
  for (i = 0; i < buflen; i += 16) {
    vf::printf("%06x: ", i);
    for (j = 0; j < 16; j++) {
      if (i + j < buflen) {
        vf::printf("%02x ", buf[i + j]);
      } else {
        vf::printf("   ");
      }
    }
    vf::printf(" ");
    for (j = 0; j < 16; j++) {
      if (i + j < buflen) {
        vf::printf("%c", vf::isprint(buf[i + j]) ? buf[i + j] : '.');
      }
    }
    vf::printf("\n");
  }
}

}  // namespace vf::common
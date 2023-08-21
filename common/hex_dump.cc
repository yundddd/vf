#include "common/hex_dump.hh"
#include "nostdlib/stdio.hh"
 #include "nostdlib/ctype.hh"

namespace vt::common {

void hex_dump(const void* ptr, size_t buflen) {
  auto buf = static_cast<const unsigned char*>(ptr);
  size_t i, j;
  for (i = 0; i < buflen; i += 16) {
    vt::printf("%06x: ", i);
    for (j = 0; j < 16; j++) {
      if (i + j < buflen) {
        vt::printf("%02x ", buf[i + j]);
      } else {
        vt::printf("   ");
      }
    }
    vt::printf(" ");
    for (j = 0; j < 16; j++) {
      if (i + j < buflen) {
        vt::printf("%c", vt::isprint(buf[i + j]) ? buf[i + j] : '.');
      }
    }
    vt::printf("\n");
  }
}

}  // namespace vt::common
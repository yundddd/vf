
#include "common/hex_dump.hh"
#include "std/stdio.hh"

namespace vt::common {

void hex_dump(const void* ptr, size_t buflen) {
  auto buf = static_cast<const unsigned char*>(ptr);
  int i, j;
  for (i = 0; i < buflen; i += 16) {
    printf("%06x: ", i);
    for (j = 0; j < 16; j++) {
      if (i + j < buflen) {
        printf("%02x ", buf[i + j]);
      } else {
        printf("   ");
      }
    }
    printf(" ");
    for (j = 0; j < 16; j++) {
      if (i + j < buflen) {
        printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
      }
    }
    printf("\n");
  }
}

}  // namespace vt::common
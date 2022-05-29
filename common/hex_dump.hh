#pragma once
#include <sstream>
#include "fmt/core.h"
#include "glog/logging.h"

namespace vt {
namespace common {
void hex_dump(const void* ptr, size_t buflen) {
  auto buf = static_cast<const unsigned char*>(ptr);
  std::stringstream ss;
  ss << "Dumping address " << fmt::format("{:p}\n", ptr);
  for (size_t i = 0, j = 0; i < buflen; i += 16) {
    ss << fmt::format("{:06x}: ", i);
    for (j = 0; j < 30; j++) {
      if (i + j < buflen) {
        ss << fmt::format("{:02x} ", buf[i + j]);
      } else {
        ss << "   ";
      }
    }
    ss << " ";
    for (j = 0; j < 30; j++) {
      if (i + j < buflen) {
        ss << fmt::format("{:c}", isprint(buf[i + j]) ? buf[i + j] : '.');
      }
    }
    ss << std::endl;
  }
  LOG(INFO) << ss.str();
}

}  // namespace common
}  // namespace vt
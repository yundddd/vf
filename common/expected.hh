#pragma once
#include "expected.hpp"

namespace vt::common {

template <typename T, typename E>
using expected = nonstd::expected<T, E>;

template <typename E>
auto make_unexpected(E&& e) {
  return nonstd::make_unexpected<E>(std::forward<E>(e));
}

}  // namespace vt::common
#pragma once
#include "nostdlib/unistd.hh"

#define CHECK_FAIL() vf::exit(-1)

#define CHECK_TRUE(cond) \
  if (!(cond)) {         \
    CHECK_FAIL();        \
  }

#define CHECK_FALSE(cond) CHECK_TRUE(!!cond)

#define CHECK_NE(a, b)         \
  if (a == b) {                \
    [[unlikely]] CHECK_FAIL(); \
  }
#define CHECK_EQ(a, b)         \
  if (a != b) {                \
    [[unlikely]] CHECK_FAIL(); \
  }
#define CHECK_LT(a, b)         \
  if (a >= b) {                \
    [[unlikely]] CHECK_FAIL(); \
  }
#define CHECK_LE(a, b)         \
  if (a > b) {                 \
    [[unlikely]] CHECK_FAIL(); \
  }
#define CHECK_GT(a, b) CHECK_LE(b, a)
#define CHECK_GE(a, b) CHECK_LT(b, a)
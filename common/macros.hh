#pragma once
#define MAKE_NON_COPYABLE(class_name)     \
  class_name(const class_name&) = delete; \
  class_name& operator=(const class_name&) = delete;

#define MAKE_NON_MOVABLE(class_name) \
  class_name(class_name&&) = delete; \
  class_name& operator=(class_name&&) = delete;

#define MAKE_COPYABLE(class_name)          \
  class_name(const class_name&) = default; \
  class_name& operator=(const class_name&) = default;

#define MAKE_MOVABLE(class_name)      \
  class_name(class_name&&) = default; \
  class_name& operator=(class_name&&) = default;

#define MAKE_NON_COPYABLE_AND_NON_MOVABLE(class_name) \
  MAKE_NON_COPYABLE(class_name);                      \
  MAKE_NON_MOVABLE(class_name);

#define MAKE_COPYABLE_AND_MOVABLE(class_name) \
  MAKE_COPYABLE(class_name);                  \
  MAKE_MOVABLE(class_name);

#define ELF_PAGE_SZ64 0x200000
#define ELF_PAGE_SZ32 0x1000

#define CHECK_FAIL() ;;
#define CHECK_NE(a, b)         \
  if (a == b) {                \
    [[unlikely]] CHECK_FAIL(); \
  };
#define CHECK_EQ(a, b)         \
  if (a != b) {                \
    [[unlikely]] CHECK_FAIL(); \
  };
  
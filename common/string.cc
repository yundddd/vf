#include "std/string.hh"
#include "common/macros.hh"
#include "common/string.hh"
#include "std/stdlib.hh"
#include "std/utility.hh"

namespace vt::common {

String::String() {
  Data = local_buf();
  Data[0] = 0;
}

String::String(const String& rhs) : String() { set(rhs); }

String::String(const char* rhs) : String() { set(rhs); }

String::String(String&& rhs) : String() { *this = vt::move(rhs); }

String::~String() {
  if (!is_using_local_buf()) {
    free(Data);
  }
}

bool String::operator==(const char* rhs) const {
  return strcmp(c_str(), rhs) == 0;
}

bool String::operator==(const String& rhs) const {
  return strcmp(c_str(), rhs.c_str()) == 0;
}

String& String::operator=(const char* rhs) {
  set(rhs);
  return *this;
}

String& String::operator=(const String& rhs) {
  set(rhs);
  return *this;
}

String& String::operator=(String&& rhs) {
  if (this == &rhs) {
    return *this;
  }
  if (rhs.length() <= ksmall_buffer_size) {
    *this = rhs;
  } else {
    if (!is_using_local_buf()) {
      vt::swap(Data, rhs.Data);
    } else {
      Data = rhs.Data;
      rhs.Data = rhs.small_buff;
    }
    Capacity = rhs.Capacity;
  }
  return *this;
}

String String::operator+(const char* rhs) const {
  String ret(*this);
  ret += rhs;
  return ret;
}

String String::operator+(const String& rhs) const {
  String ret(*this);
  ret += rhs;
  return ret;
}

String& String::operator+=(const char* rhs) {
  append(rhs);
  return *this;
}

String& String::operator+=(const String& rhs) {
  append(rhs.c_str());
  return *this;
}

String& String::operator+=(char c) {
  append(c);
  return *this;
}

size_t String::length() const { return strlen(Data); }

void String::set(const char* src) {
  // We allow set(nullptr) or via = operator to clear the String.
  if (src == nullptr) {
    clear();
    return;
  }
  auto src_len = strlen(src) + 1;
  if (Capacity <= src_len) {
    reserve_discard(src_len + 1);  // reserve for null terminator.
  }
  memcpy(Data, src, src_len + 1);  // copy the null terminator.
}

void String::set(const char* src, const char* src_end) {
  CHECK_TRUE(src != nullptr && src_end >= src);
  int buf_len = (int)(src_end - src) + 1;
  if ((int)Capacity < buf_len) reserve_discard(buf_len);
  memcpy(Data, src, (size_t)(buf_len - 1));
  Data[buf_len - 1] = 0;
}

void String::set(const String& src) { set(src.c_str()); }

void String::clear() { Data[0] = '\0'; }

// Reserve memory, preserving the current of the buffer
void String::reserve(int new_capacity) {
  if (new_capacity <= Capacity) return;

  char* new_data;
  new_data = (char*)malloc((size_t)new_capacity * sizeof(char));

  auto cur_len = length();
  strncpy(new_data, Data, cur_len);

  new_data[cur_len] = 0;

  free(Data);

  Data = new_data;
  Capacity = new_capacity;
}

// Reserve memory, discarding the current of the buffer (if we expect to be
// fully rewritten), only the requested cap is larger.
void String::reserve_discard(int new_capacity) {
  if (new_capacity <= Capacity) return;

  free(Data);

  Data = (char*)malloc((size_t)new_capacity * sizeof(char));
  Capacity = new_capacity;
  Data[0] = 0;
}

void String::shrink_to_fit() {
  if (is_using_local_buf()) return;
  int new_capacity = length() + 1;
  if (Capacity <= new_capacity) return;

  char* new_data = (char*)malloc((size_t)new_capacity * sizeof(char));
  memcpy(new_data, Data, (size_t)new_capacity);
  free(Data);
  Data = new_data;
  Capacity = new_capacity;
}

int String::append_from(int idx, char c) {
  int add_len = 1;
  if (Capacity < idx + add_len + 1) reserve(idx + add_len + 1);
  Data[idx] = c;
  Data[idx + add_len] = 0;
  return add_len;
}

int String::append_from(int idx, const char* s, const char* s_end) {
  if (!s_end) s_end = s + strlen(s);
  int add_len = (int)(s_end - s);
  if (Capacity < idx + add_len + 1) reserve(idx + add_len + 1);
  memcpy(Data + idx, (const void*)s, (size_t)add_len);
  Data[idx + add_len] = 0;  // Our source data isn't necessarily zero-terminated
  return add_len;
}

int String::append(char c) {
  int cur_len = length();
  return append_from(cur_len, c);
}

int String::append(const char* s, const char* s_end) {
  int cur_len = length();
  return append_from(cur_len, s, s_end);
}
}  // namespace vt::common
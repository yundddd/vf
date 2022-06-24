#pragma once
#include "std/std.hh"
namespace vt::common {

class String final {
 public:
  static constexpr size_t ksmall_buffer_size = 16;

  ~String();
  String();
  String(const String& rhs);
  String(const char* rhs);
  String(String&& rhs);

  String& operator=(const char* rhs);
  String& operator=(const String& rhs);
  String& operator=(String&& rhs);

  String operator+(const char* rhs) const;
  String operator+(const String& rhs) const;

  String& operator+=(const char* rhs);
  String& operator+=(const String& rhs);
  String& operator+=(char c);

  bool operator==(const char* rhs) const;
  bool operator==(const String& rhs) const;

  char* c_str() { return Data; }
  const char* c_str() const { return Data; }
  bool empty() const { return Data[0] == 0; }
  size_t length() const;
  size_t size() const { return length(); };
  size_t capacity() const { return Capacity; }

  int append(char c);
  int append(const char* s, const char* s_end = nullptr);
  int append_from(size_t idx, char c);
  int append_from(
      size_t idx, const char* s,
      const char* s_end = nullptr);  // If you know the String length or want to
                                     // append from a certain point

  void clear();
  void reserve(size_t cap);
  void reserve_discard(size_t cap);
  void shrink_to_fit();

  char& operator[](size_t i) { return Data[i]; }
  const char& operator[](size_t i) const { return Data[i]; }

 protected:
  void set(const String& src);
  void set(const char* src);
  void set(const char* src, const char* src_end);
  char* local_buf() { return small_buff; }
  const char* local_buf() const { return small_buff; }
  bool is_using_local_buf() const { return Data == local_buf(); }

  // Constructor for StrXXX variants with local buffer
  String(unsigned short local_buf_size);

 private:
  char* Data = nullptr;  // Point to LocalBuf() or heap allocated
  size_t Capacity = ksmall_buffer_size;  // Max 2 MB
  char small_buff[ksmall_buffer_size];   // small buffer optimization
};

}  // namespace vt::common
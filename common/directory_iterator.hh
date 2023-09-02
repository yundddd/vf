#pragma once
#include "common/file_descriptor.hh"

namespace vt::common {
class DirectoryIterator {
 public:
  enum class EntryType : uint8_t {
    UNKNOWN,
    FILE,
    SYMLINK,
    DIR,
  };
  struct Entry {
    EntryType type;
    const char* name = nullptr;
  };

  class Iterator {
   public:
    using value_type = Entry;
    using const_reference = const value_type&;
    using const_pointer = const value_type*;

    Iterator() = default;
    Iterator(int directory_fd);

    const_reference operator*() const { return cur_; }
    const_pointer operator->() const { return &cur_; }

    Iterator& operator++();

    bool operator==(const Iterator& other) {
      return cur_.name == other.cur_.name;
    };
    bool operator!=(const Iterator& other) { return !(*this == other); };

   private:
    bool fill();
    void consume();
    // skip the "." and ".." dir, conforming to
    // https://en.cppreference.com/w/cpp/filesystem/directory_iterator
    Iterator& skip_dots();

    int directory_fd_ = -1;
    int total_filled_ = 0;
    char buf_[4096];
    size_t buf_pos_ = 0;
    Entry cur_{};
  };

  DirectoryIterator(const char* path) : directory_fd_(path, O_RDONLY, 0) {}

  Iterator begin() { return Iterator{directory_fd_.handle()}; }
  Iterator end() { return Iterator{}; }

 private:
  common::FileDescriptor directory_fd_;
};
}  // namespace vt::common
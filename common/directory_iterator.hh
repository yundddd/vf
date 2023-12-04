#pragma once
#include <memory>
#include "common/file_descriptor.hh"
#include "common/string.hh"

namespace vf::common {
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
    const char* dir_path = nullptr;
  };

  class Iterator {
   public:
    using value_type = Entry;
    using const_reference = const value_type&;
    using const_pointer = const value_type*;

    Iterator() = default;
    Iterator(int directory_fd, const char* dir_path);

    const_reference operator*() const { return cur_; }
    const_pointer operator->() const { return &cur_; }

    Iterator& operator++();

    bool operator==(const Iterator& other) const {
      return cur_.name == other.cur_.name &&
             directory_fd_ == other.directory_fd_;
    }
    bool operator!=(const Iterator& other) const { return !(*this == other); }

   private:
    constexpr static size_t buf_size = sizeof(vf::linux_dirent64) * 8;
    bool fill();
    void consume();
    // skip the "." and ".." dir, conforming to
    // https://en.cppreference.com/w/cpp/filesystem/directory_iterator
    Iterator& skip_dots();

    int directory_fd_ = -1;

    // every 8 entries per syscall
    std::unique_ptr<std::byte[]> buf_;
    size_t buf_pos_ = 0;
    int total_filled_ = 0;
    Entry cur_{};

    const char* dir_path_ = nullptr;
  };

  DirectoryIterator(const char* path)
      : directory_fd_(path, O_RDONLY, 0), dir_path_(path) {}
  DirectoryIterator() = default;

  Iterator begin() {
    // invalid dir returns end()
    return directory_fd_.valid()
               ? Iterator{directory_fd_.handle(), dir_path_.c_str()}
               : end();
  }
  Iterator end() { return Iterator{}; }

 private:
  common::FileDescriptor directory_fd_;
  String dir_path_;
};
}  // namespace vf::common
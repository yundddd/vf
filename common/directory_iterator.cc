#include "common/directory_iterator.hh"
#include <dirent.h>
#include "nostdlib/fcntl.hh"
#include "nostdlib/unistd.hh"
namespace vf::common {

namespace {
DirectoryIterator::EntryType get_type(
    decltype(vf::linux_dirent64::d_type) type) {
  switch (type) {
    case DT_DIR:
      return DirectoryIterator::EntryType::DIR;
    case DT_LNK:
      return DirectoryIterator::EntryType::SYMLINK;
    case DT_REG:
      return DirectoryIterator::EntryType::FILE;
    default:
      return DirectoryIterator::EntryType::UNKNOWN;
  }
}
}  // namespace

DirectoryIterator::Iterator::Iterator(int directory_fd, const char* dir_path)
    : directory_fd_(directory_fd), dir_path_(dir_path) {
  if (fill()) {
    consume();
    skip_dots();
  }
}

DirectoryIterator::Iterator& DirectoryIterator::Iterator::operator++() {
  if (buf_pos_ >= total_filled_) {
    if (fill()) {
      consume();
    } else {
      // only clear what's important to mimic end()
      cur_.name = nullptr;
      directory_fd_ = -1;
      return *this;
    }
  } else {
    consume();
  }

  return skip_dots();
}

DirectoryIterator::Iterator& DirectoryIterator::Iterator::skip_dots() {
  if ((cur_.name[0] == '.' && cur_.name[1] == 0) ||
      (cur_.name[0] == '.' && cur_.name[1] == '.' && cur_.name[2] == 0)) {
    return ++(*this);
  }
  return *this;
}

bool DirectoryIterator::Iterator::fill() {
  if (!buf_) {
    buf_ = std::make_unique<std::byte[]>(buf_size);
  }
  buf_pos_ = 0;
  total_filled_ = 0;
  auto newly_filled = vf::getdents64(
      directory_fd_, reinterpret_cast<vf::linux_dirent64*>(buf_.get()),
      buf_size);
  if (newly_filled > 0) {
    total_filled_ += newly_filled;
  }
  return newly_filled > 0;
}

void DirectoryIterator::Iterator::consume() {
  auto* cur_entry =
      reinterpret_cast<vf::linux_dirent64*>(buf_.get() + buf_pos_);
  cur_ = Entry{.type = get_type(cur_entry->d_type),
               .name = cur_entry->d_name,
               .dir_path = dir_path_};
  buf_pos_ += cur_entry->d_reclen;
}
}  // namespace vf::common
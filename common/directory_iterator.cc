#include "common/directory_iterator.hh"
#include <dirent.h>
#include "nostdlib/fcntl.hh"
#include "nostdlib/unistd.hh"
namespace vt::common {

namespace {
DirectoryIterator::EntryType get_type(
    decltype(vt::linux_dirent64::d_type) type) {
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

DirectoryIterator::Iterator::Iterator(int directory_fd)
    : directory_fd_(directory_fd) {
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
      *this = {};
      return *this;
    }
  } else {
    consume();
  }

  return skip_dots();
}

DirectoryIterator::Iterator& DirectoryIterator::Iterator::skip_dots() {
  if (cur_.name[0] == '.') {
    return ++(*this);
  }
  return *this;
}

bool DirectoryIterator::Iterator::fill() {
  buf_pos_ = 0;
  total_filled_ = vt::getdents64(
      directory_fd_, reinterpret_cast<vt::linux_dirent64*>(buf_), sizeof(buf_));
  return total_filled_ > 0;
}

void DirectoryIterator::Iterator::consume() {
  auto* cur_entry = reinterpret_cast<vt::linux_dirent64*>(buf_ + buf_pos_);
  cur_ = Entry{.type = get_type(cur_entry->d_type), .name = cur_entry->d_name};
  buf_pos_ += cur_entry->d_reclen;
}
}  // namespace vt::common
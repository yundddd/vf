#pragma once
#include <stack>
#include "common/directory_iterator.hh"

namespace vf::common {
template <size_t MAX_LEVEL>
class RecursiveDirectoryIterator {
  static_assert(MAX_LEVEL > 0,
                "Cannot create RecursiveDirectoryIterator with zero depth");

 private:
  struct Storage {
    DirectoryIterator dir;
    DirectoryIterator::Iterator iter;
  };

 public:
  using Entry = DirectoryIterator::Entry;
  using EntryType = DirectoryIterator::EntryType;

  class Iterator {
   public:
    using value_type = Entry;
    using const_reference = const value_type&;
    using const_pointer = const value_type*;

    Iterator() = default;
    Iterator(std::stack<Storage>& storage, const char* path)
        : storage_(&storage) {
      prime_dir(path);
    }

    const_reference operator*() const {
      return storage_->top().iter.operator*();
    }
    const_pointer operator->() const {
      return storage_->top().iter.operator->();
    }

    Iterator& operator++() {
      if (this->operator*().type == DirectoryIterator::EntryType::DIR) {
        auto primed = prime_dir(
            (String(this->operator*().dir_path) + '/' + this->operator*().name)
                .c_str());
        if (primed) {
          if (storage_->top().iter != storage_->top().dir.end()) {
            return *this;
          } else {
            storage_->pop();
          }
        }
      }

      ++storage_->top().iter;

      while (!storage_->empty() &&
             storage_->top().iter == storage_->top().dir.end()) {
        storage_->pop();
        if (!storage_->empty()) {
          ++storage_->top().iter;
        }
      }

      if (storage_->empty()) {
        *this = {};
      }

      return *this;
    }

    bool operator==(const Iterator& other) {
      return storage_ == other.storage_;
    }

    bool operator!=(const Iterator& other) { return !(*this == other); };

   private:
    bool prime_dir(const char* path) {
      bool primed = false;
      if (storage_->size() < MAX_LEVEL) {
        primed = true;
        storage_->push({DirectoryIterator(path)});
        storage_->top().iter = storage_->top().dir.begin();
      }
      return primed;
    }

    std::stack<Storage>* storage_ = nullptr;
  };

  RecursiveDirectoryIterator(const char* path) : path_(path) {}

  Iterator begin() { return Iterator{storage_, path_}; }
  Iterator end() { return Iterator{}; }

 private:
  const char* path_ = nullptr;
  std::stack<Storage> storage_;
};
}  // namespace vf::common
#include "common/directory_iterator.hh"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <iostream>
#include <string>
#include "testing/test_support.hh"

namespace vt::common {

class DirectoryIteratorTest : public ::testing::Test {
 public:
  void SetUp() override {
    unique_dir_ = testing::get_bazel_test_dir_unique();
    for (auto&& f : test_files_) {
      write_file(unique_dir_, f);
      create_symlink_file(f, f + "_link");
    }
    create_dir(test_dirs_[0]);
    create_dir(test_dirs_[1]);

    // Write to a subdir.
    for (auto&& f : test_files_) {
      write_file(unique_dir_ + "/" + test_dirs_[0], f);
    }
  }

  void write_file(const std::string& dir, const std::string& name) {
    FileDescriptor fd((dir + "/" + name).c_str(), O_WRONLY | O_CREAT,
                      S_IRUSR | S_IWUSR);

    EXPECT_TRUE(fd.valid());
    EXPECT_NE(write(fd.handle(), "abc", 3), -1);
  }

  void create_symlink_file(const std::string& link_name,
                           const std::string& link_to) {
    EXPECT_EQ(::symlink((unique_dir_ + "/" + link_name).c_str(),
                        (unique_dir_ + "/" + link_to).c_str()),
              0);
  }

  void create_dir(const std::string& name) {
    mkdir((unique_dir_ + "/" + name).c_str(), 0700);
  }

 protected:
  std::string unique_dir_;
  std::vector<std::string> test_files_{"file1", "file2", "file3"};
  std::vector<std::string> test_link_files_{"file1_link", "file2_link",
                                            "file3_link"};
  std::vector<std::string> test_dirs_{"test_dir1", "test_dir2"};
};

TEST_F(DirectoryIteratorTest, CanIterateDir) {
  DirectoryIterator dir{unique_dir_.c_str()};

  std::vector<std::string> file_names;
  std::vector<std::string> symlink_names;
  std::vector<std::string> dir_names;

  for (auto it = dir.begin(); it != dir.end(); ++it) {
    if (it->type == DirectoryIterator::EntryType::FILE) {
      file_names.push_back(it->name);
    } else if (it->type == DirectoryIterator::EntryType::SYMLINK) {
      symlink_names.push_back(it->name);
    } else if (it->type == DirectoryIterator::EntryType::DIR) {
      dir_names.push_back(it->name);
    }
  }
  ASSERT_THAT(file_names, ::testing::UnorderedElementsAreArray(test_files_));
  ASSERT_THAT(symlink_names,
              ::testing::UnorderedElementsAreArray(test_link_files_));
  ASSERT_THAT(dir_names, ::testing::UnorderedElementsAreArray(test_dirs_));
}

TEST_F(DirectoryIteratorTest, CanIterateDirEnhancedForLoop) {
  std::vector<std::string> file_names;
  std::vector<std::string> symlink_names;
  std::vector<std::string> dir_names{};

  for (auto dir_entry : DirectoryIterator(unique_dir_.c_str())) {
    if (dir_entry.type == DirectoryIterator::EntryType::FILE) {
      file_names.push_back(dir_entry.name);
    } else if (dir_entry.type == DirectoryIterator::EntryType::SYMLINK) {
      symlink_names.push_back(dir_entry.name);
    } else if (dir_entry.type == DirectoryIterator::EntryType::DIR) {
      dir_names.push_back(dir_entry.name);
    }
  }
  ASSERT_THAT(file_names, ::testing::UnorderedElementsAreArray(test_files_));
  ASSERT_THAT(symlink_names,
              ::testing::UnorderedElementsAreArray(test_link_files_));
  ASSERT_THAT(dir_names, ::testing::UnorderedElementsAreArray(test_dirs_));
}

TEST_F(DirectoryIteratorTest, CanNestIteratorForLoop) {
  std::vector<std::string> file_names;

  for (auto dir_entry : DirectoryIterator(unique_dir_.c_str())) {
    if (dir_entry.type == DirectoryIterator::EntryType::DIR &&
        std::string(dir_entry.name) == test_dirs_[0]) {
      for (auto sub_dir_entry :
           DirectoryIterator((unique_dir_ + "/" + dir_entry.name).c_str())) {
        if (sub_dir_entry.type == DirectoryIterator::EntryType::FILE) {
          file_names.push_back(sub_dir_entry.name);
        }
      }
    }
  }
  ASSERT_THAT(file_names, ::testing::UnorderedElementsAreArray(test_files_));
}

}  // namespace vt::common
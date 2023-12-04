#include "common/directory_iterator.hh"
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <filesystem>
#include <iostream>
#include <string>
#include "common/recursive_directory_iterator.hh"
#include "testing/test_support.hh"

namespace vf::common {

struct DirEntries {
  std::vector<std::string> file_names;
  std::vector<std::string> symlink_names;
  std::vector<std::string> dir_names;
};

class DirectoryIteratorTest : public ::testing::Test {
 public:
  void SetUp() override {
    // bazel-test-dir
    //  |__ test_dir1
    //          |__ file1
    //          |__ file2
    //          |__ file3
    //  |__ file1
    //  |__ file2
    //  |__ file3
    //  |__ file1_link
    //  |__ file2_link
    //  |__ file3_link
    //  |__ test_dir2
    unique_dir_ = testing::get_bazel_test_dir_unique();
    for (auto&& f : test_files_) {
      write_file(unique_dir_ + "/" + f);
      create_symlink_file(unique_dir_ + "/" + f,
                          unique_dir_ + "/" + f + "_link");
    }
    create_dir(unique_dir_ + "/" + test_dirs_[0]);
    create_dir(unique_dir_ + "/" + test_dirs_[1]);

    // Write to a subdir.
    for (auto&& f : test_files_) {
      write_file(unique_dir_ + "/" + test_dirs_[0] + "/" + f);
    }
  }

  void write_file(const std::string& full_path) {
    FileDescriptor fd(full_path.c_str(), O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);

    EXPECT_TRUE(fd.valid()) << full_path << " failed to open";
    EXPECT_NE(write(fd.handle(), "abc", 3), -1);
  }

  void create_symlink_file(const std::string& link_file_full_path,
                           const std::string& link_to_full_path) {
    EXPECT_EQ(::symlink(link_file_full_path.c_str(), link_to_full_path.c_str()),
              0);
  }

  void create_dir(const std::string& full_path) {
    mkdir(full_path.c_str(), 0700);
  }

  template <typename IterT>
  DirEntries get_all_entries(const char* dir) {
    DirEntries ret;
    for (auto dir_entry : IterT(dir)) {
      if (dir_entry.type == DirectoryIterator::EntryType::FILE) {
        ret.file_names.push_back(dir_entry.name);
      } else if (dir_entry.type == DirectoryIterator::EntryType::SYMLINK) {
        ret.symlink_names.push_back(dir_entry.name);
      } else if (dir_entry.type == DirectoryIterator::EntryType::DIR) {
        ret.dir_names.push_back(dir_entry.name);
      }
    }
    return ret;
  }

 protected:
  std::string unique_dir_;
  std::vector<std::string> test_files_{"file1", "file2", "file3"};
  std::vector<std::string> test_link_files_{"file1_link", "file2_link",
                                            "file3_link"};
  std::vector<std::string> test_dirs_{"test_dir1", "test_dir2"};
};

TEST_F(DirectoryIteratorTest, InvalidDir) {
  DirectoryIterator dir{"abc"};
  EXPECT_EQ(dir.begin(), dir.end());
}

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
  auto ret = get_all_entries<DirectoryIterator>(unique_dir_.c_str());
  ASSERT_THAT(ret.file_names,
              ::testing::UnorderedElementsAreArray(test_files_));
  ASSERT_THAT(ret.symlink_names,
              ::testing::UnorderedElementsAreArray(test_link_files_));
  ASSERT_THAT(ret.dir_names, ::testing::UnorderedElementsAreArray(test_dirs_));
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

TEST_F(DirectoryIteratorTest, CanIterateEmptyDir) {
  auto ret = get_all_entries<DirectoryIterator>(
      (unique_dir_ + "/" + test_dirs_[1]).c_str());
  EXPECT_TRUE(ret.file_names.empty());
  EXPECT_TRUE(ret.symlink_names.empty());
  EXPECT_TRUE(ret.dir_names.empty());
}

class RecursiveDirectoryIteratorTest : public DirectoryIteratorTest {
 public:
  void SetUp() override {
    // bazel-test-dir
    //  |__ test_dir1
    //          |__ file1
    //          |__ file2
    //          |__ file3
    //          |__ test_dir2
    //               |__ file4
    //               |__ file5
    //               |__ file6
    //               |__ test_dir3

    unique_dir_ = testing::get_bazel_test_dir_unique();
    create_dir(unique_dir_ + "/" + test_dirs_[0]);
    for (auto&& f : second_level_files_) {
      write_file(unique_dir_ + "/" + test_dirs_[0] + "/" + f);
    }

    create_dir(unique_dir_ + "/" + test_dirs_[0] + "/" + test_dirs_[1]);
    create_dir(unique_dir_ + "/" + test_dirs_[0] + "/" + test_dirs_[1] + "/" +
               test_dirs_[2]);

    // Write to a subdir.
    for (auto&& f : third_level_files_) {
      write_file(unique_dir_ + "/" + test_dirs_[0] + "/" + test_dirs_[1] + "/" +
                 f);
    }
  }
  std::vector<std::string> test_dirs_{"test_dir1", "test_dir2", "test_dir3"};
  std::vector<std::string> second_level_files_{"file1", "file2", "file3"};
  std::vector<std::string> third_level_files_{"file4", "file5", "file6"};
};

TEST_F(RecursiveDirectoryIteratorTest, CanIterateOneLevel) {
  auto ret =
      get_all_entries<RecursiveDirectoryIterator<1>>(unique_dir_.c_str());

  ASSERT_TRUE(ret.file_names.empty());
  ASSERT_TRUE(ret.symlink_names.empty());
  ASSERT_THAT(ret.dir_names, ::testing::UnorderedElementsAre(test_dirs_[0]));
}

TEST_F(RecursiveDirectoryIteratorTest, CanIterateTwoLevel) {
  auto ret =
      get_all_entries<RecursiveDirectoryIterator<2>>(unique_dir_.c_str());

  std::vector<std::string> expected_files{second_level_files_.begin(),
                                          second_level_files_.end()};

  ASSERT_THAT(ret.file_names,
              ::testing::UnorderedElementsAreArray(expected_files));
  ASSERT_THAT(ret.dir_names,
              ::testing::UnorderedElementsAre(test_dirs_[0], test_dirs_[1]));
}

TEST_F(RecursiveDirectoryIteratorTest, CanIterateThreeLevel) {
  auto ret =
      get_all_entries<RecursiveDirectoryIterator<3>>(unique_dir_.c_str());

  std::vector<std::string> expected_files{second_level_files_.begin(),
                                          second_level_files_.end()};
  expected_files.insert(expected_files.end(), third_level_files_.begin(),
                        third_level_files_.end());
  ASSERT_THAT(ret.file_names,
              ::testing::UnorderedElementsAreArray(expected_files));
  ASSERT_THAT(ret.dir_names, ::testing::UnorderedElementsAre(
                                 test_dirs_[0], test_dirs_[1], test_dirs_[2]));
}

TEST_F(RecursiveDirectoryIteratorTest, CanIterateEmptyDir) {
  auto ret =
      get_all_entries<RecursiveDirectoryIterator<4>>(unique_dir_.c_str());

  std::vector<std::string> expected_files{second_level_files_.begin(),
                                          second_level_files_.end()};
  expected_files.insert(expected_files.end(), third_level_files_.begin(),
                        third_level_files_.end());

  ASSERT_THAT(ret.file_names,
              ::testing::UnorderedElementsAreArray(expected_files));
  ASSERT_THAT(ret.dir_names, ::testing::UnorderedElementsAreArray(test_dirs_));
}

}  // namespace vf::common
#include "common/file_descriptor.hh"
#include "gtest/gtest.h"
#include "testing/test_support.hh"

class FileDescriptorTest : public ::testing::Test {
 public:
  void SetUp() override {
    test_file_ =
        vt::testing::get_bazel_test_dir_unique() + std::string("/test_file");
  }

 protected:
  std::string test_file_;
};

TEST_F(FileDescriptorTest, CanReadWriteNewFile) {
  {
    vt::common::FileDescriptor fd(test_file_, O_WRONLY | O_CREAT,
                                  S_IRUSR | S_IWUSR);
    EXPECT_TRUE(fd.valid());
    ::write(fd.handle(), "abc", 3);
  }
  {
    vt::common::FileDescriptor fd(test_file_, O_RDONLY);
    EXPECT_TRUE(fd.valid());
    char buf[3];
    ::read(fd.handle(), buf, 3);
    EXPECT_EQ(buf[0], 'a');
    EXPECT_EQ(buf[1], 'b');
    EXPECT_EQ(buf[2], 'c');
  }
}

TEST_F(FileDescriptorTest, CanBeMoved) {
  vt::common::FileDescriptor fd(test_file_, O_WRONLY | O_CREAT,
                                S_IRUSR | S_IWUSR);
  EXPECT_TRUE(fd.valid());

  vt::common::FileDescriptor fd2(std::move(fd));
  EXPECT_TRUE(fd2.valid());
  EXPECT_FALSE(fd.valid());
}

TEST_F(FileDescriptorTest, FileSize) {
  vt::common::FileDescriptor fd(test_file_, O_WRONLY | O_CREAT,
                                S_IRUSR | S_IWUSR);
  EXPECT_TRUE(fd.valid());
  ::write(fd.handle(), "abc", 3);
  EXPECT_EQ(fd.file_size(), 3u);
}
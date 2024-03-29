#include "common/file_descriptor.hh"
#include <gtest/gtest.h>
#include "testing/test_support.hh"

class FileDescriptorTest : public testing::Test {
 public:
  void SetUp() override {
    test_file_ = vf::testing::get_bazel_test_dir_unique() + "/test_file";
  }
  void TearDown() override { CHECK_NE(::unlink(test_file_.c_str()), -1); }

 protected:
  std::string test_file_;
};

TEST_F(FileDescriptorTest, CanReadWrite) {
  {
    vf::common::FileDescriptor fd(test_file_.c_str(), O_WRONLY | O_CREAT,
                                  S_IRUSR | S_IWUSR);

    EXPECT_TRUE(fd.valid());
    EXPECT_NE(vf::write(fd.handle(), "abc", 3), -1);
  }
  {
    vf::common::FileDescriptor fd(test_file_.c_str(), O_RDONLY);
    EXPECT_TRUE(fd.valid());
    char buf[3];
    EXPECT_NE(vf::read(fd.handle(), buf, 3), -1);
    EXPECT_EQ(buf[0], 'a');
    EXPECT_EQ(buf[1], 'b');
    EXPECT_EQ(buf[2], 'c');
  }
}

TEST_F(FileDescriptorTest, CanBeMoved) {
  vf::common::FileDescriptor fd(test_file_.c_str(), O_WRONLY | O_CREAT,
                                S_IRUSR | S_IWUSR);
  EXPECT_TRUE(fd.valid());

  vf::common::FileDescriptor fd2(std::move(fd));
  EXPECT_TRUE(fd2.valid());
  EXPECT_FALSE(fd.valid());
}

TEST_F(FileDescriptorTest, FileSize) {
  vf::common::FileDescriptor fd(test_file_.c_str(), O_WRONLY | O_CREAT,
                                S_IRUSR | S_IWUSR);
  EXPECT_TRUE(fd.valid());
  EXPECT_NE(vf::write(fd.handle(), "abc", 3), -1);
  EXPECT_EQ(fd.file_size(), 3u);
}
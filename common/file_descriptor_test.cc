#include "common/file_descriptor.hh"
#include <gtest/gtest.h>
#include "common/anonymous_file_descriptor.hh"
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

class AnonymousFileDescriptorTest : public testing::Test {};

TEST_F(AnonymousFileDescriptorTest, Construction) {
  constexpr size_t expected_size = 4096;
  vf::common::AnonymousFileDescriptor fd("", 0, expected_size);
  EXPECT_TRUE(fd.valid());
  EXPECT_EQ(fd.file_size(), expected_size);
}

TEST_F(AnonymousFileDescriptorTest, MoveConstruction) {
  constexpr size_t expected_size = 4096;
  vf::common::AnonymousFileDescriptor fd1("", 0, expected_size);
  vf::common::AnonymousFileDescriptor fd2(std::move(fd1));
  EXPECT_TRUE(fd2.valid());
  EXPECT_FALSE(fd1.valid());
  EXPECT_NE(fd2.mutable_base(), nullptr);
  EXPECT_EQ(fd1.mutable_base(), nullptr);
}

TEST_F(AnonymousFileDescriptorTest, Truncation) {
  constexpr size_t expected_size = 4096;
  vf::common::AnonymousFileDescriptor fd("", 0, expected_size);

  EXPECT_EQ(fd.file_size(), expected_size);
  EXPECT_TRUE(fd.truncate(expected_size * 2));
  EXPECT_EQ(fd.file_size(), expected_size * 2);
}

TEST_F(AnonymousFileDescriptorTest, Writable) {
  constexpr size_t expected_size = 4096;
  vf::common::AnonymousFileDescriptor fd("", 0, expected_size);
  EXPECT_NE(fd.mutable_base(), nullptr);
  auto base = reinterpret_cast<char*>(fd.mutable_base());
  *base = 'a';
  EXPECT_EQ(*base, 'a');
  *(base + expected_size - 1) = 'b';
  EXPECT_EQ(*(base + expected_size - 1), 'b');
}
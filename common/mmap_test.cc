#include "common/mmap.hh"
#include <gtest/gtest.h>
#include "common/file_descriptor.hh"
#include "testing/test_support.hh"

class MmapTest : public testing::Test {
 public:
  void SetUp() override {
    test_file_ = vf::testing::get_bazel_test_dir_unique() + "/test_file";

    vf::common::FileDescriptor fd(test_file_.c_str(), O_WRONLY | O_CREAT,
                                  S_IRUSR | S_IWUSR);
    CHECK_TRUE(fd.valid());
    CHECK_NE(::write(fd.handle(), "abc", 3), -1);
  }
  void TearDown() override { CHECK_NE(::unlink(test_file_.c_str()), -1); }

 protected:
  std::string test_file_;
};

TEST_F(MmapTest, CanMapFileToRead) {
  vf::common::FileDescriptor fd(test_file_.c_str(), O_RDONLY);
  {
    vf::common::Mmap<PROT_READ> uut(3, MAP_PRIVATE, fd.handle(), 0);
    EXPECT_TRUE(uut.valid());
    EXPECT_EQ(uut.base()[0], std::byte{'a'});
    EXPECT_EQ(uut.base()[1], std::byte{'b'});
    EXPECT_EQ(uut.base()[2], std::byte{'c'});
  }
}

TEST_F(MmapTest, CanMapFileToWrite) {
  {
    vf::common::FileDescriptor fd(test_file_.c_str(), O_RDWR);
    vf::common::Mmap<PROT_WRITE> uut(3, MAP_SHARED, fd.handle(), 0);
    EXPECT_TRUE(uut.valid());
    uut.mutable_base()[1] = std::byte{'d'};
  }

  vf::common::FileDescriptor fd(test_file_.c_str(), O_RDONLY);

  std::byte buf[3] = {};
  EXPECT_NE(read(fd.handle(), static_cast<void*>(buf), 3), -1);
  EXPECT_EQ(buf[0], std::byte{'a'});
  EXPECT_EQ(buf[1], std::byte{'d'});
  EXPECT_EQ(buf[2], std::byte{'c'});
}

TEST_F(MmapTest, CanBeMoved) {
  vf::common::FileDescriptor fd(test_file_.c_str(), O_RDONLY);
  vf::common::Mmap<PROT_READ> uut(3, MAP_PRIVATE, fd.handle(), 0);
  vf::common::Mmap<PROT_READ> uut2(std::move(uut));
  EXPECT_FALSE(uut.valid());
  EXPECT_TRUE(uut2.valid());
}
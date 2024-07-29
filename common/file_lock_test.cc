#include "common/file_lock.hh"
#include <gtest/gtest.h>
#include "testing/test_support.hh"

class FileLockTest : public testing::Test {
 public:
  void SetUp() override {
    test_file_ = vf::testing::get_bazel_test_dir_unique() + "/test_file";
  }
  void TearDown() override { CHECK_NE(::unlink(test_file_.c_str()), -1); }

 protected:
  std::string test_file_;
};

TEST_F(FileLockTest, ConstructorCanLock) {
  vf::common::FileDescriptor fd(test_file_.c_str(), O_WRONLY | O_CREAT,
                                S_IRUSR | S_IWUSR);

  EXPECT_TRUE(fd.valid());
  EXPECT_NE(vf::write(fd.handle(), "abc", 3), -1);

  vf::common::FileLock f_lock(std::move(fd));
  EXPECT_TRUE(f_lock.is_locked());
}

TEST_F(FileLockTest, ExclusiveLock) {
  vf::common::FileDescriptor fd(test_file_.c_str(), O_WRONLY | O_CREAT,
                                S_IRUSR | S_IWUSR);

  EXPECT_TRUE(fd.valid());
  EXPECT_NE(vf::write(fd.handle(), "abc", 3), -1);

  vf::common::FileLock f_lock(std::move(fd));
  EXPECT_TRUE(f_lock.is_locked());

  {
    vf::common::FileDescriptor fd2(test_file_.c_str(), O_RDONLY,
                                   S_IRUSR | S_IWUSR);
    vf::common::FileLock f_lock2(std::move(fd2));
    EXPECT_FALSE(f_lock2.is_locked());
    EXPECT_FALSE(f_lock2.try_lock());
  }
}

TEST_F(FileLockTest, CanRelease) {
  vf::common::FileDescriptor fd(test_file_.c_str(), O_WRONLY | O_CREAT,
                                S_IRUSR | S_IWUSR);

  EXPECT_TRUE(fd.valid());
  EXPECT_NE(vf::write(fd.handle(), "abc", 3), -1);

  vf::common::FileLock f_lock(std::move(fd));
  EXPECT_TRUE(f_lock.is_locked());

  f_lock.release();
  EXPECT_FALSE(f_lock.is_locked());
}
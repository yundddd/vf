#include "common/file_descriptor.hh"
#include "testing/test.hh"
#include "testing/test_support.hh"

class FileDescriptorTest : public TestFixture {
 public:
  void Setup() override {
    test_file_ = vt::testing::get_bazel_test_dir_unique() + "/test_file";
  }
  void TearDown() override { CHECK_NE(::unlink(test_file_.c_str()), -1); }

 protected:
  vt::common::String test_file_;
};

DEFINE_TEST_F(CanReadWrite, FileDescriptorTest) {
  {
    vt::common::FileDescriptor fd(test_file_.c_str(), O_WRONLY | O_CREAT,
                                  S_IRUSR | S_IWUSR);

    EXPECT_TRUE(fd.valid());
    EXPECT_NE(::write(fd.handle(), "abc", 3), -1);
  }
  {
    vt::common::FileDescriptor fd(test_file_.c_str(), O_RDONLY);
    EXPECT_TRUE(fd.valid());
    char buf[3];
    EXPECT_NE(::read(fd.handle(), buf, 3), -1);
    EXPECT_EQ(buf[0], 'a');
    EXPECT_EQ(buf[1], 'b');
    EXPECT_EQ(buf[2], 'c');
  }
}

DEFINE_TEST_F(CanBeMoved, FileDescriptorTest) {
  vt::common::FileDescriptor fd(test_file_.c_str(), O_WRONLY | O_CREAT,
                                S_IRUSR | S_IWUSR);
  EXPECT_TRUE(fd.valid());

  vt::common::FileDescriptor fd2(vt::move(fd));
  EXPECT_TRUE(fd2.valid());
  EXPECT_FALSE(fd.valid());
}

DEFINE_TEST_F(FileSize, FileDescriptorTest) {
  vt::common::FileDescriptor fd(test_file_.c_str(), O_WRONLY | O_CREAT,
                                S_IRUSR | S_IWUSR);
  EXPECT_TRUE(fd.valid());
  EXPECT_NE(::write(fd.handle(), "abc", 3), -1);
  EXPECT_EQ(fd.file_size(), 3u);
}

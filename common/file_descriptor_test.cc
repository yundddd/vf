#include "common/file_descriptor.hh"
#include "testing/test.hh"

using namespace vt;

class FileDescriptorTest : public TestFixture {
 public:
  void Setup() override { ::unlink(test_file_); }
  void TearDown() override { ::unlink(test_file_); }

 protected:
  const char* test_file_ = "/tmp/test_file";
};

DEFINE_TEST_F(CanReadWrite, FileDescriptorTest) {
  {
    vt::common::FileDescriptor fd(test_file_, O_WRONLY | O_CREAT,
                                  S_IRUSR | S_IWUSR);
    TEST_TRUE(fd.valid());
    ::write(fd.handle(), "abc", 3);
  }
  {
    vt::common::FileDescriptor fd(test_file_, O_RDONLY);
    TEST_TRUE(fd.valid());
    char buf[3];
    ::read(fd.handle(), buf, 3);
    TEST_EQ(buf[0], 'a');
    TEST_EQ(buf[1], 'b');
    TEST_EQ(buf[2], 'c');
  }
}

DEFINE_TEST_F(CanBeMoved, FileDescriptorTest) {
  vt::common::FileDescriptor fd(test_file_, O_WRONLY | O_CREAT,
                                S_IRUSR | S_IWUSR);
  TEST_TRUE(fd.valid());

  vt::common::FileDescriptor fd2(vt::move(fd));
  TEST_TRUE(fd2.valid());
  TEST_FALSE(fd.valid());
}

DEFINE_TEST_F(FileSize, FileDescriptorTest) {
  vt::common::FileDescriptor fd(test_file_, O_WRONLY | O_CREAT,
                                S_IRUSR | S_IWUSR);
  TEST_TRUE(fd.valid());
  ::write(fd.handle(), "abc", 3);
  TEST_EQ(fd.file_size(), 3u);
}

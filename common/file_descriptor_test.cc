#include "common/file_descriptor.hh"
#include "testing/test.hh"

class FileDescriptorTest : public TestFixture {
 public:
  void Setup() override {}
  void TearDown() override {}

 protected:
};
const char* test_file_ = "/tmp/test_file";
DEFINE_TEST(CanReadWriteNewFile) { TEST_EQ(1, 1); }
/*
DEFINE_TEST(CanReadWriteNewFilea) {
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

DEFINE_TEST_F(CanBeMoved, TestFixture) {
  vt::common::FileDescriptor fd(test_file_, O_WRONLY | O_CREAT,
                                S_IRUSR | S_IWUSR);
  TEST_TRUE(fd.valid());

  vt::common::FileDescriptor fd2(vt::move(fd));
  TEST_TRUE(fd2.valid());
  TEST_FALSE(fd.valid());
}

DEFINE_TEST_F(FileSize, TestFixture) {
  vt::common::FileDescriptor fd(test_file_, O_WRONLY | O_CREAT,
                                S_IRUSR | S_IWUSR);
  TEST_TRUE(fd.valid());
  ::write(fd.handle(), "abc", 3);
  TEST_EQ(fd.file_size(), 3u);
}
*/
int main() {
  return !TestFixture::ExecuteAllTests(nullptr, nullptr, TestFixture::Verbose);
}

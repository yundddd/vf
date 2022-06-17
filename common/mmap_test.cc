#include "common/mmap.hh"
#include "common/file_descriptor.hh"
#include "testing/test.hh"

class MmapTest : public TestFixture {
 public:
  void Setup() override {
    ::unlink(test_file_);
    vt::common::FileDescriptor fd(test_file_, O_WRONLY | O_CREAT,
                                  S_IRUSR | S_IWUSR);
    TEST_TRUE(fd.valid());
    ::write(fd.handle(), "abc", 3);
  }
  void TearDown() override { ::unlink(test_file_); }

 protected:
  const char* test_file_ = "/tmp/test_file";
};

DEFINE_TEST_F(CanMapFileToRead, MmapTest) {
  vt::common::FileDescriptor fd(test_file_, O_RDONLY);
  {
    vt::common::Mmap<PROT_READ> uut(3, MAP_PRIVATE, fd.handle(), 0);
    TEST_TRUE(uut.valid());
    TEST_EQ(uut.base()[0], 'a');
    TEST_EQ(uut.base()[1], 'b');
    TEST_EQ(uut.base()[2], 'c');
  }
}

DEFINE_TEST_F(CanMapFileToWrite, MmapTest) {
  {
    vt::common::FileDescriptor fd(test_file_, O_RDWR);
    vt::common::Mmap<PROT_WRITE> uut(3, MAP_SHARED, fd.handle(), 0);
    TEST_TRUE(uut.valid());
    uut.mutable_base()[1] = 'd';
  }

  vt::common::FileDescriptor fd(test_file_, O_RDONLY);

  char buf[3];
  ::read(fd.handle(), buf, 3);
  TEST_EQ(buf[0], 'a');
  TEST_EQ(buf[1], 'd');
  TEST_EQ(buf[2], 'c');
}

DEFINE_TEST_F(CanBeMoved, MmapTest) {
  vt::common::FileDescriptor fd(test_file_, O_RDONLY);
  vt::common::Mmap<PROT_READ> uut(3, MAP_PRIVATE, fd.handle(), 0);
  vt::common::Mmap<PROT_READ> uut2(vt::move(uut));
  TEST_FALSE(uut.valid());
  TEST_TRUE(uut2.valid());
}
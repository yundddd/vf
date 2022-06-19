#include "common/string.hh"
#include "std/string.hh"
#include "std/utility.hh"
#include "testing/test.hh"

using namespace vt::common;
class StringTest : public TestFixture {
 protected:
  const char* small_literal = "abcdefg";
  const char* large_literal = "123456789abcdef123456789abcdef";
};

DEFINE_TEST_F(CanConstructEmptyString, StringTest) {
  String uut;
  EXPECT_EQ(uut.length(), 0u);
  EXPECT_TRUE(uut.empty());
  EXPECT_EQ(uut.capacity(), String::ksmall_buffer_size);
}

DEFINE_TEST_F(CanCopyConstructStringFromLiteral, StringTest) {
  String uut(small_literal);
  EXPECT_EQ(uut.capacity(), String::ksmall_buffer_size);
  EXPECT_EQ(uut.length(), strlen(small_literal));
  EXPECT_FALSE(uut.empty());
  EXPECT_EQ(uut, small_literal);
}

DEFINE_TEST_F(CanCopyStringFromLiteral, StringTest) {
  String uut;
  uut = small_literal;
  EXPECT_EQ(uut.capacity(), String::ksmall_buffer_size);
  EXPECT_EQ(uut.length(), strlen(small_literal));
  EXPECT_FALSE(uut.empty());
  EXPECT_EQ(uut, small_literal);
}

DEFINE_TEST_F(CanCopyStringFromString, StringTest) {
  String uut(small_literal);
  uut = String(large_literal);
  EXPECT_NE(uut.capacity(), String::ksmall_buffer_size);
  EXPECT_EQ(uut.length(), strlen(large_literal));
  EXPECT_FALSE(uut.empty());
  EXPECT_EQ(uut, large_literal);
}

DEFINE_TEST_F(CanModifyStringOperatorBrakets, StringTest) {
  String uut(small_literal);
  uut[0] = 'd';
  uut[6] = 'd';
  EXPECT_EQ(uut.capacity(), String::ksmall_buffer_size);
  EXPECT_EQ(uut.length(), strlen(small_literal));
  EXPECT_FALSE(uut.empty());
  EXPECT_EQ(uut, "dbcdefd");
}

DEFINE_TEST_F(CanCopyConstructStringFromLiteralOnHeap, StringTest) {
  String uut(large_literal);
  EXPECT_NE(uut.capacity(), String::ksmall_buffer_size);
  EXPECT_EQ(uut.length(), strlen(large_literal));
  EXPECT_FALSE(uut.empty());
  EXPECT_EQ(uut, large_literal);
}

DEFINE_TEST_F(CanCopyStringFromLiteralOnHeap, StringTest) {
  String uut;
  uut = large_literal;
  EXPECT_NE(uut.capacity(), String::ksmall_buffer_size);
  EXPECT_EQ(uut.length(), strlen(large_literal));
  EXPECT_FALSE(uut.empty());
  EXPECT_EQ(uut, large_literal);
}

DEFINE_TEST_F(CanModifyStringOperatorBraketsOnHeap, StringTest) {
  String uut(large_literal);
  uut[0] = 'd';
  uut[6] = 'd';
  EXPECT_NE(uut.capacity(), String::ksmall_buffer_size);
  EXPECT_EQ(uut.length(), strlen(large_literal));
  EXPECT_FALSE(uut.empty());
  EXPECT_EQ(uut, "d23456d89abcdef123456789abcdef");
}

DEFINE_TEST_F(CanReserveSmallBufferSize, StringTest) {
  String uut;
  uut = small_literal;
  uut.reserve(3);
  EXPECT_EQ(uut.capacity(), String::ksmall_buffer_size);
  EXPECT_EQ(uut.length(), strlen(small_literal));
  EXPECT_FALSE(uut.empty());
  EXPECT_EQ(uut, small_literal);
}

DEFINE_TEST_F(CanReserveLargeBufferSize, StringTest) {
  String uut;
  uut = small_literal;
  uut.reserve(32);
  EXPECT_EQ(uut.capacity(), 32);
  EXPECT_EQ(uut.length(), strlen(small_literal));
  EXPECT_FALSE(uut.empty());
  EXPECT_EQ(uut, small_literal);
}

DEFINE_TEST_F(CanReserveDiscardSmallBuffer, StringTest) {
  String uut;
  uut = small_literal;
  uut.reserve_discard(3);
  EXPECT_EQ(uut.capacity(), String::ksmall_buffer_size);
  EXPECT_EQ(uut.length(), strlen(small_literal));
  EXPECT_FALSE(uut.empty());
}

DEFINE_TEST_F(CanReserveDiscardSmallBufferLarger, StringTest) {
  String uut;
  uut = small_literal;
  uut.reserve_discard(17);
  EXPECT_EQ(uut.capacity(), 17);
  EXPECT_EQ(uut.length(), 0);
  EXPECT_TRUE(uut.empty());
}

DEFINE_TEST_F(CanReserveDiscardOnHeap, StringTest) {
  String uut(large_literal);
  uut.reserve_discard(17);
  EXPECT_NE(uut.capacity(), 17);
  EXPECT_EQ(uut.length(), strlen(large_literal));
  EXPECT_FALSE(uut.empty());
}

DEFINE_TEST_F(CanReserveDiscardOnLarger, StringTest) {
  String uut(large_literal);
  uut.reserve_discard(4096);
  EXPECT_EQ(uut.capacity(), 4096);
  EXPECT_EQ(uut.length(), 0);
  EXPECT_TRUE(uut.empty());
}

DEFINE_TEST_F(CanMoveConstructFromSmallString, StringTest) {
  String small(small_literal);
  String uut(vt::move(small));
  EXPECT_EQ(uut.capacity(), String::ksmall_buffer_size);
  EXPECT_EQ(uut.length(), strlen(small_literal));
  EXPECT_FALSE(uut.empty());
  EXPECT_EQ(uut, small_literal);
}

DEFINE_TEST_F(CanMoveConstructFromLargeString, StringTest) {
  String large(large_literal);
  String uut(vt::move(large));
  EXPECT_NE(uut.capacity(), String::ksmall_buffer_size);
  EXPECT_EQ(uut.length(), strlen(large_literal));
  EXPECT_FALSE(uut.empty());
  EXPECT_EQ(uut, large_literal);
}

DEFINE_TEST_F(LargeStringCanMoveConstructFromLargeString, StringTest) {
  const char* kAnotherLiteral = "123123123123123123123123123123123123";
  String large(kAnotherLiteral);
  String uut(vt::move(large));
  EXPECT_NE(uut.capacity(), String::ksmall_buffer_size);
  EXPECT_EQ(uut.length(), strlen(kAnotherLiteral));
  EXPECT_FALSE(uut.empty());
  EXPECT_EQ(uut, kAnotherLiteral);
}

DEFINE_TEST_F(LargeStringCanMoveAssignFromSmallString, StringTest) {
  String uut(large_literal);
  String small(small_literal);
  uut = vt::move(small);
  EXPECT_NE(uut.capacity(), String::ksmall_buffer_size);
  EXPECT_EQ(uut.length(), strlen(small_literal));
  EXPECT_FALSE(uut.empty());
  EXPECT_EQ(uut, small_literal);
}

DEFINE_TEST_F(SmallStringCanMoveAssignFromSmallString, StringTest) {
  const char* kAnotherLiteral = "123";
  String uut(kAnotherLiteral);
  String small(small_literal);
  uut = vt::move(small);
  EXPECT_EQ(uut.capacity(), String::ksmall_buffer_size);
  EXPECT_EQ(uut.length(), strlen(small_literal));
  EXPECT_FALSE(uut.empty());
  EXPECT_EQ(uut, small_literal);
}
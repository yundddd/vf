#include "common/string.hh"
#include <gtest/gtest.h>

using namespace vt::common;
class StringTest : public testing::Test {
 protected:
  const char* small_literal = "abcdefg";
  const char* large_literal = "123456789abcdef123456789abcdef";
};

TEST_F(StringTest, CanConstructEmptyString) {
  String uut;
  EXPECT_EQ(uut.length(), 0u);
  EXPECT_TRUE(uut.empty());
  EXPECT_EQ(uut.capacity(), String::ksmall_buffer_size);
}

TEST_F(StringTest, CanCopyConstructStringFromLiteral) {
  String uut(small_literal);
  EXPECT_EQ(uut.capacity(), String::ksmall_buffer_size);
  EXPECT_EQ(uut.length(), strlen(small_literal));
  EXPECT_FALSE(uut.empty());
  EXPECT_EQ(uut, small_literal);
}

TEST_F(StringTest, CanCopyStringFromLiteral) {
  String uut;
  uut = small_literal;
  EXPECT_EQ(uut.capacity(), String::ksmall_buffer_size);
  EXPECT_EQ(uut.length(), strlen(small_literal));
  EXPECT_FALSE(uut.empty());
  EXPECT_EQ(uut, small_literal);
}

TEST_F(StringTest, CanCopyStringFromString) {
  String uut(small_literal);
  uut = String(large_literal);
  EXPECT_NE(uut.capacity(), String::ksmall_buffer_size);
  EXPECT_EQ(uut.length(), strlen(large_literal));
  EXPECT_FALSE(uut.empty());
  EXPECT_EQ(uut, large_literal);
}

TEST_F(StringTest, CanModifyStringOperatorBrakets) {
  String uut(small_literal);
  uut[0] = 'd';
  uut[6] = 'd';
  EXPECT_EQ(uut.capacity(), String::ksmall_buffer_size);
  EXPECT_EQ(uut.length(), strlen(small_literal));
  EXPECT_FALSE(uut.empty());
  EXPECT_EQ(uut, "dbcdefd");
}

TEST_F(StringTest, CanCopyConstructStringFromLiteralOnHeap) {
  String uut(large_literal);
  EXPECT_NE(uut.capacity(), String::ksmall_buffer_size);
  EXPECT_EQ(uut.length(), strlen(large_literal));
  EXPECT_FALSE(uut.empty());
  EXPECT_EQ(uut, large_literal);
}

TEST_F(StringTest, CanCopyStringFromLiteralOnHeap) {
  String uut;
  uut = large_literal;
  EXPECT_NE(uut.capacity(), String::ksmall_buffer_size);
  EXPECT_EQ(uut.length(), strlen(large_literal));
  EXPECT_FALSE(uut.empty());
  EXPECT_EQ(uut, large_literal);
}

TEST_F(StringTest, CanModifyStringOperatorBraketsOnHeap) {
  String uut(large_literal);
  uut[0] = 'd';
  uut[6] = 'd';
  EXPECT_NE(uut.capacity(), String::ksmall_buffer_size);
  EXPECT_EQ(uut.length(), strlen(large_literal));
  EXPECT_FALSE(uut.empty());
  EXPECT_EQ(uut, "d23456d89abcdef123456789abcdef");
}

TEST_F(StringTest, CanReserveSmallBufferSize) {
  String uut;
  uut = small_literal;
  uut.reserve(3);
  EXPECT_EQ(uut.capacity(), String::ksmall_buffer_size);
  EXPECT_EQ(uut.length(), strlen(small_literal));
  EXPECT_FALSE(uut.empty());
  EXPECT_EQ(uut, small_literal);
}

TEST_F(StringTest, CanReserveLargeBufferSize) {
  String uut;
  uut = small_literal;
  uut.reserve(32);
  EXPECT_EQ(uut.capacity(), 32);
  EXPECT_EQ(uut.length(), strlen(small_literal));
  EXPECT_FALSE(uut.empty());
  EXPECT_EQ(uut, small_literal);
}

TEST_F(StringTest, CanReserveDiscardSmallBuffer) {
  String uut;
  uut = small_literal;
  uut.reserve_discard(3);
  EXPECT_EQ(uut.capacity(), String::ksmall_buffer_size);
  EXPECT_EQ(uut.length(), strlen(small_literal));
  EXPECT_FALSE(uut.empty());
}

TEST_F(StringTest, CanReserveDiscardSmallBufferLarger) {
  String uut;
  uut = small_literal;
  uut.reserve_discard(17);
  EXPECT_EQ(uut.capacity(), 17);
  EXPECT_EQ(uut.length(), 0);
  EXPECT_TRUE(uut.empty());
}

TEST_F(StringTest, CanReserveDiscardOnHeap) {
  String uut(large_literal);
  uut.reserve_discard(17);
  EXPECT_NE(uut.capacity(), 17);
  EXPECT_EQ(uut.length(), strlen(large_literal));
  EXPECT_FALSE(uut.empty());
}

TEST_F(StringTest, CanReserveDiscardOnLarger) {
  String uut(large_literal);
  uut.reserve_discard(4096);
  EXPECT_EQ(uut.capacity(), 4096);
  EXPECT_EQ(uut.length(), 0);
  EXPECT_TRUE(uut.empty());
}

TEST_F(StringTest, CanMoveConstructFromSmallString) {
  String small(small_literal);
  String uut(std::move(small));
  EXPECT_EQ(uut.capacity(), String::ksmall_buffer_size);
  EXPECT_EQ(uut.length(), strlen(small_literal));
  EXPECT_FALSE(uut.empty());
  EXPECT_EQ(uut, small_literal);
}

TEST_F(StringTest, CanMoveConstructFromLargeString) {
  String large(large_literal);
  String uut(std::move(large));
  EXPECT_NE(uut.capacity(), String::ksmall_buffer_size);
  EXPECT_EQ(uut.length(), strlen(large_literal));
  EXPECT_FALSE(uut.empty());
  EXPECT_EQ(uut, large_literal);
}

TEST_F(StringTest, LargeStringCanMoveConstructFromLargeString) {
  const char* kAnotherLiteral = "123123123123123123123123123123123123";
  String large(kAnotherLiteral);
  String uut(std::move(large));
  EXPECT_NE(uut.capacity(), String::ksmall_buffer_size);
  EXPECT_EQ(uut.length(), strlen(kAnotherLiteral));
  EXPECT_FALSE(uut.empty());
  EXPECT_EQ(uut, kAnotherLiteral);
}

TEST_F(StringTest, LargeStringCanMoveAssignFromSmallString) {
  String uut(large_literal);
  String small(small_literal);
  uut = std::move(small);
  EXPECT_NE(uut.capacity(), String::ksmall_buffer_size);
  EXPECT_EQ(uut.length(), strlen(small_literal));
  EXPECT_FALSE(uut.empty());
  EXPECT_EQ(uut, small_literal);
}

TEST_F(StringTest, SmallStringCanMoveAssignFromSmallString) {
  const char* kAnotherLiteral = "123";
  String uut(kAnotherLiteral);
  String small(small_literal);
  uut = std::move(small);
  EXPECT_EQ(uut.capacity(), String::ksmall_buffer_size);
  EXPECT_EQ(uut.length(), strlen(small_literal));
  EXPECT_FALSE(uut.empty());
  EXPECT_EQ(uut, small_literal);
}
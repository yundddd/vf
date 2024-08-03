#include "common/macros.hh"
#include "nostdlib/string.hh"
#include "nostdlib/sys/socket.hh"
#include "nostdlib/unistd.hh"

// This is a sample virus that could phone home by writing to a udp socket.
// use the following command to test:
//   nc -kluvw 0 5000
int main() {
  const char* str = STR_LITERAL("phone home\n");

  int sockfd = 0;
  struct sockaddr_in serv_addr {};

  if ((sockfd = vf::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    return 0;
  }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(5000);
  // 127.0.0.1 binary form in network order.
  serv_addr.sin_addr.s_addr = vf::inet_addr(127, 0, 0, 1);

  if (vf::sendto(sockfd, str, vf::strlen(str), 0, (struct sockaddr*)&serv_addr,
                 sizeof(serv_addr)) == -1) {
    return 0;
  }

  return 0;
}
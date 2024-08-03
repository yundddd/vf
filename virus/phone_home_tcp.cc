#include "common/macros.hh"
#include "nostdlib/string.hh"
#include "nostdlib/sys/socket.hh"
#include "nostdlib/unistd.hh"

// This is a sample virus that could phone home by writing to a udp socket.
// use the following command to test:
//   nc -kl 5000
int main() {
  const char* str = STR_LITERAL("phone home\n");

  int sockfd = 0;
  struct sockaddr_in serv_addr {};

  if ((sockfd = vf::socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    return 0;
  }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(5000);
  // 127.0.0.1 binary form in network order.
  serv_addr.sin_addr.s_addr = vf::inet_addr(127, 0, 0, 1);

  if (vf::connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) <
      0) {
    return 0;
  }

  vf::write(sockfd, str, vf::strlen(str));

  return 0;
}
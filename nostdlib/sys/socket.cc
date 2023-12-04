#include "nostdlib/sys/socket.hh"
#include <asm/unistd.h>
#include <fcntl.h>
#include "nostdlib/arch.hh"

namespace vf {
int socket(int fd, int type, int domain) {
  return my_syscall3(__NR_socket, fd, type, domain);
}

int sendto(int fd, const void* buf, size_t len, int flags,
           struct sockaddr* addr, socklen_t addrlen) {
  return my_syscall6(__NR_sendto, fd, buf, len, flags, addr, addrlen);
}

int recvfrom(int fd, void* buf, size_t len, int flags, struct sockaddr* addr,
             socklen_t* addrlen) {
  return my_syscall6(__NR_recvfrom, fd, buf, len, flags, addr, addrlen);
}

int bind(int fd, struct sockaddr* addr, socklen_t len) {
  return my_syscall3(__NR_bind, fd, addr, len);
}

int listen(int fd, int backlog) {
  return my_syscall2(__NR_listen, fd, backlog);
}

int accept(int fd, struct sockaddr* addr, socklen_t* len) {
  return my_syscall3(__NR_accept, fd, addr, len);
}

int connect(int fd, struct sockaddr* addr, socklen_t len) {
  return my_syscall3(__NR_connect, fd, addr, len);
}

in_addr_t inet_addr(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
  return (static_cast<uint32_t>(d) << 24) | (static_cast<uint32_t>(c) << 16) |
         (static_cast<uint32_t>(b) << 8) | a;
}

}  // namespace vf
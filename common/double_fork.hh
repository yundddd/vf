#pragma once

#include "nostdlib/sys/wait.hh"
#include "nostdlib/unistd.hh"

namespace vf::common {
// A helper function that can perform work asynchronously in a grandchild
// process to avoid:
// - blocking wait with waitpid
// - creating zombie processes
// This is achieved by forking a child that forks a grandchild to do the long
// running work. The parent will perform a short blocking wait, until the child
// forks the grandchild, to cleanup process table. When the child dies, the
// cleanup responsibility for grandchild is transferred to process 1, thus
// avoiding zombie.
template <typename Work>
void double_fork(Work&& work) {
  auto child_pid = vf::fork();
  // If we are child then perform propagation.
  if (!child_pid) {
    // create a grandchild that performs the work.
    auto grandchild_pid = vf::fork();
    if (!grandchild_pid) {
      // perform work in grandchild process.
      work();
    }
    // child exits and transfers cleanup to process 1.
    exit(0);
  }

  // This wait should be very quick, as the child will exit right after forking
  // a grandchild.
  vf::waitpid(child_pid, nullptr, 0);
}
}  // namespace vf::common
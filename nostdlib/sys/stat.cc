#include "nostdlib/sys/stat.hh"
#include <asm/unistd.h>
#include <fcntl.h>
#include "nostdlib/arch.hh"

namespace vf {
namespace {

int sys_chmod(const char* path, mode_t mode) {
#ifdef __NR_fchmodat
  return my_syscall4(__NR_fchmodat, AT_FDCWD, path, mode, 0);
#elif defined(__NR_chmod)
  return my_syscall2(__NR_chmod, path, mode);
#else
#error Neither __NR_fchmodat nor __NR_chmod defined, cannot implement sys_chmod()
#endif
}

int sys_fchmod(int fd, mode_t mode) {
  return my_syscall2(__NR_fchmod, fd, mode);
}

int sys_fstat(int fd, struct stat* buf) {
  sys_stat_struct stat;
  long ret = my_syscall2(__NR_fstat, fd, &stat);

  buf->st_dev = stat.st_dev;
  buf->st_ino = stat.st_ino;
  buf->st_mode = stat.st_mode;
  buf->st_nlink = stat.st_nlink;
  buf->st_uid = stat.st_uid;
  buf->st_gid = stat.st_gid;
  buf->st_rdev = stat.st_rdev;
  buf->st_size = stat.st_size;
  buf->st_blksize = stat.st_blksize;
  buf->st_blocks = stat.st_blocks;
  buf->st_atime = stat.sys_st_atime;
  buf->st_mtime = stat.sys_st_mtime;
  buf->st_ctime = stat.sys_st_ctime;
  return ret;
}

int sys_mkdir(const char* path, mode_t mode) {
#ifdef __NR_mkdirat
  return my_syscall3(__NR_mkdirat, AT_FDCWD, path, mode);
#elif defined(__NR_mkdir)
  return my_syscall2(__NR_mkdir, path, mode);
#else
#error Neither __NR_mkdirat nor __NR_mkdir defined, cannot implement sys_mkdir()
#endif
}

long sys_mknod(const char* path, mode_t mode, dev_t dev) {
#ifdef __NR_mknodat
  return my_syscall4(__NR_mknodat, AT_FDCWD, path, mode, dev);
#elif defined(__NR_mknod)
  return my_syscall3(__NR_mknod, path, mode, dev);
#else
#error Neither __NR_mknodat nor __NR_mknod defined, cannot implement sys_mknod()
#endif
}

int sys_stat(const char* path, struct stat* buf) {
  struct sys_stat_struct stat;
  long ret;

#ifdef __NR_newfstatat
  /* only solution for arm64 */
  ret = my_syscall4(__NR_newfstatat, AT_FDCWD, path, &stat, 0);
#elif defined(__NR_stat)
  ret = my_syscall2(__NR_stat, path, &stat);
#else
#error Neither __NR_newfstatat nor __NR_stat defined, cannot implement sys_stat()
#endif
  buf->st_dev = stat.st_dev;
  buf->st_ino = stat.st_ino;
  buf->st_mode = stat.st_mode;
  buf->st_nlink = stat.st_nlink;
  buf->st_uid = stat.st_uid;
  buf->st_gid = stat.st_gid;
  buf->st_rdev = stat.st_rdev;
  buf->st_size = stat.st_size;
  buf->st_blksize = stat.st_blksize;
  buf->st_blocks = stat.st_blocks;
  buf->st_atime = stat.sys_st_atime;
  buf->st_mtime = stat.sys_st_mtime;
  buf->st_ctime = stat.sys_st_ctime;
  return ret;
}

mode_t sys_umask(mode_t mode) { return my_syscall1(__NR_umask, mode); }

}  // namespace

int chmod(const char* path, mode_t mode) { return sys_chmod(path, mode); }
int fchmod(int fd, mode_t mode) { return sys_fchmod(fd, mode); }
int fstat(int fd, struct stat* buf) { return sys_fstat(fd, buf); }
int mkdir(const char* path, mode_t mode) { return sys_mkdir(path, mode); }
int mknod(const char* path, mode_t mode, dev_t dev) {
  return sys_mknod(path, mode, dev);
}
int stat(const char* path, struct stat* buf) { return sys_stat(path, buf); }
mode_t umask(mode_t mode) { return sys_umask(mode); }

}  // namespace vf
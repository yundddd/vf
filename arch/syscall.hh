#pragma once
//#include <linux/dirent.h>
//#include <linux/fcntl.h>
//#include <linux/time.h>
//#include <linux/types.h>
#include <linux/unistd.h>

namespace vt::arch {

#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

#define PAGE_SIZE 4096

struct dirent
  {
 	long		d_ino;
    unsigned short int d_reclen; /* Length of the whole `struct dirent'.  */
    unsigned char d_type;	/* File type, possibly unknown.  */
    unsigned char d_namlen;	/* Length of the file name.  */

    /* Only this member is in the POSIX standard.  */
    char d_name[1];		/* File name (actually longer).  */
  };
#if 0
struct stat {
  dev_t st_dev; /* Device.  */
  unsigned short int __pad1;
  ino_t st_ino;     /* File serial number.  */
  mode_t st_mode;   /* File mode.  */
  nlink_t st_nlink; /* Link count.  */
  uid_t st_uid;     /* User ID of the file's owner. */
  gid_t st_gid;     /* Group ID of the file's group.*/
  dev_t st_rdev;    /* Device number, if device.  */
  unsigned short int __pad2;
  off_t st_size;                /* Size of file, in bytes.  */
  unsigned long int st_blksize; /* Optimal block size for I/O.  */
  unsigned long int st_blocks;  /* Number of 512-byte blocks allocated.
                                 */
  time_t st_atime;              /* Time of last access.  */
  unsigned long int __unused1;
  time_t st_mtime; /* Time of last modification.  */
  unsigned long int __unused2;
  time_t st_ctime; /* Time of last status change.  */
  unsigned long int __unused3;
  unsigned long int __unused4;
  unsigned long int __unused5;
};
#endif

//time_t time(time_t* t);
unsigned long brk(unsigned long brk);
//int fstat(int, fd, struct stat* buf);
//int unlink(const char* pathname);
//int fchmod(int filedes, mode_t mode);
//int fchown(int fd, uid_t owner, gid_t group);
int rename(const char* oldpath, const char* newpath);
//int getdents(uint, fd, struct dirent*, dirp, uint, count);
int open(const char* file, int flag, int mode);
int close(int fd);
//off_t lseek(int filedes, off_t offset, int whence);
long read(int fd, void* buf, unsigned long count);
long write(int fd, const void* buf, unsigned long count);
}  // namespace vt::arch
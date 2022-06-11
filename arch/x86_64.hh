#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/dirent.h>
#include <linux/time.h>
#include <linux/fcntl.h>
#include <elf.h>

struct stat {
	dev_t st_dev;                     /* Device.  */
	unsigned short int __pad1;
	ino_t st_ino;                     /* File serial number.  */
	mode_t st_mode;                   /* File mode.  */
	nlink_t st_nlink;                 /* Link count.  */
	uid_t st_uid;                     /* User ID of the file's owner. */
	gid_t st_gid;                     /* Group ID of the file's group.*/
	dev_t st_rdev;                    /* Device number, if device.  */
	unsigned short int __pad2;
	off_t st_size;                    /* Size of file, in bytes.  */
	unsigned long int st_blksize;       /* Optimal block size for I/O.  */
	unsigned long int st_blocks;        /* Number of 512-byte blocks allocated.
 */
	time_t st_atime;                  /* Time of last access.  */
	unsigned long int __unused1;
	time_t st_mtime;                  /* Time of last modification.  */
	unsigned long int __unused2;
	time_t st_ctime;                  /* Time of last status change.  */
	unsigned long int __unused3;
	unsigned long int __unused4;
	unsigned long int __unused5;
};

/*
	Remember, we cant use libc even for things like open, close etc

	New __syscall macros are made so not to use errno which are just
	modified _syscall routines from asm/unistd.h
*/

#define __syscall1(type,name,type1,arg1) \
type name(type1 arg1) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
	: "=a" (__res) \
	: "0" (__NR_##name),"b" ((long)(arg1))); \
	return (type) __res; \
}

#define __syscall2(type,name,type1,arg1,type2,arg2) \
type name(type1 arg1,type2 arg2) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
	: "=a" (__res) \
	: "0" (__NR_##name),"b" ((long)(arg1)),"c" ((long)(arg2))); \
	return (type) __res; \
}

#define __syscall3(type,name,type1,arg1,type2,arg2,type3,arg3) \
type name(type1 arg1,type2 arg2,type3 arg3) \
{ \
long __res; \
__asm__ volatile ("int $0x80" \
	: "=a" (__res) \
	: "0" (__NR_##name),"b" ((long)(arg1)),"c" ((long)(arg2)), \
		"d" ((long)(arg3))); \
	return (type) __res; \
}

__syscall1(time_t, time, time_t *, t);
__syscall1(unsigned long, brk, unsigned long, brk);
__syscall2(int, fstat, int, fd, struct stat *, buf);
__syscall1(int, unlink, const char *, pathname);
__syscall2(int, fchmod, int, filedes, mode_t, mode);
__syscall3(int, fchown, int, fd, uid_t, owner, gid_t, group);
__syscall2(int, rename, const char *, oldpath, const char *, newpath);
__syscall3(int, getdents, uint, fd, struct dirent *, dirp, uint, count);
__syscall3(int, open, const char *, file, int, flag, int, mode);
__syscall1(int, close, int, fd);
__syscall3(off_t, lseek, int, filedes, off_t, offset, int, whence);
__syscall3(ssize_t, read, int, fd, void *, buf, size_t, count);
__syscall3(ssize_t, write, int, fd, const void *, buf, size_t, count);

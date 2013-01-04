#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include "os.h"

/* TODO: truncate and perhaps O_CREAT too */
static
int translate_open_flags(int flags)
{
	if (flags & ~(FILE_FLAG_READ | FILE_FLAG_WRITE))
		return -1;
	if (flags == 0)
		return -1;
	if (flags == FILE_FLAG_READ)
		return O_RDONLY;
	if (flags == FILE_FLAG_WRITE)
		return O_WRONLY | O_APPEND;
	return O_RDWR | O_APPEND;
}

file_fd_handle raw_file_open(const char *path, int flags, int *error)
{
	int rv = open(path, translate_open_flags(flags));
	if (rv < 0 && error)
		*error = errno;
	return (file_fd_handle)rv;
}

int raw_file_close(file_fd_handle fd)
{
	int rv = close((int)fd);
	if (rv < 0)
		return errno;
	return 0;
}

int raw_file_write(file_fd_handle fd, void *_buf, size_t *nbyte)
{
	size_t left = *nbyte;
	char *buf = _buf;
	int rv;

	while (left > 0) {
		rv = write((int)fd, buf, left);
		if (rv < 0) {
			if (errno == EINTR)
				continue;
			*nbyte = buf - (char *)_buf;
			return errno;
		}
		assert(rv != 0);
		left -= rv;
		buf += rv;
	}

	*nbyte = buf - (char *)_buf;
	return 0;
}

int raw_file_pread(file_fd_handle fd, void *buf, size_t *nbyte, int64_t offset)
{
	ssize_t rv = pread((int)fd, buf, *nbyte, (off_t)offset);
	if (rv < 0)
		return errno;
	*nbyte = (size_t)rv;
	return 0;
}

char *raw_file_error_message(int error, char *buf, int bufsize)
{
	assert(bufsize > 0);
	buf[0] = 0;
	strerror_r(error, buf, bufsize);
	return buf;
}

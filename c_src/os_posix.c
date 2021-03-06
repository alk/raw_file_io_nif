#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include <erl_nif.h>
#include <erl_driver.h>

#include "os.h"

#define O_UNSUPPORTED (~0)
#ifndef O_DIRECT
#define O_DIRECT O_UNSUPPORTED
#endif
#ifndef O_SYNC
#define O_SYNC O_UNSUPPORTED
#endif
#ifndef O_DSYNC
#define O_DSYNC O_UNSUPPORTED
#endif

static
int translate_open_flags(int flags)
{
	int rv;

	if ((flags & (FILE_FLAG_READ | FILE_FLAG_APPEND)) == 0)
		return -1;
	if (flags == FILE_FLAG_READ) {
		rv = O_RDONLY;
	} else if (flags == FILE_FLAG_APPEND) {
		rv = O_WRONLY | O_APPEND;
	} else {
		rv = O_RDWR | O_APPEND;
	}
	if (flags & ~FILE_FLAG_ALL)
		return -1;
	if (flags & FILE_FLAG_TRUNCATE)
		rv |= O_TRUNC;
	if (flags & FILE_FLAG_CREAT)
		rv |= O_CREAT;
	if (flags & FILE_FLAG_EXCL)
		rv |= O_EXCL;
 	if (flags & FILE_FLAG_DIRECT)
		rv |= O_DIRECT;
	if (flags & FILE_FLAG_DATASYNC)
		rv |= O_DSYNC;
	if (flags & FILE_FLAG_SYNC)
		rv |= O_SYNC;
	if (rv == O_UNSUPPORTED)
		return -1;
	return rv;
}

file_fd_handle raw_file_open(const char *path, int flags, int *error)
{
	int openflags = translate_open_flags(flags);
	int rv;
	if (openflags == -1) {
		*error = EINVAL;
		return -1;
	}
	rv = open(path, openflags);
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
	ssize_t rv;

	if (offset < 0)
		rv = read((int)fd, buf, *nbyte);
	else
		rv = pread((int)fd, buf, *nbyte, (off_t)offset);

	if (rv < 0)
		return errno;

	*nbyte = (size_t)rv;
	return 0;
}

int raw_file_fsync(file_fd_handle fd)
{
	int rv = fsync((int)fd);
	return (rv < 0) ? errno : 0;
}

int raw_file_size(file_fd_handle fd, int64_t *size)
{
	struct stat st;
	int rv;

	rv = fstat((int)fd, &st);
	if (rv)
		return errno;
	*size = (int64_t)st.st_size;
	return 0;
}

int raw_file_truncate(file_fd_handle fd, int64_t new_size)
{
	int rv;

	rv = ftruncate((int)fd, (off_t)new_size);
	if (rv)
		return errno;
	return 0;
}

char *raw_file_error_message(int error)
{
	return erl_errno_id(error);
}

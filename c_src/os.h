#ifndef OS_H
#define OS_H

#include <stdint.h>

#define FILE_FLAG_READ 1
/* it's actually combination of O_WRITE and O_APPEND */
#define FILE_FLAG_APPEND 2
#define FILE_FLAG_TRUNCATE 16
#define FILE_FLAG_CREAT 32
#define FILE_FLAG_EXCL 64
#define FILE_FLAG_DIRECT 256
#define FILE_FLAG_DATASYNC 1024
#define FILE_FLAG_SYNC 2048

#define FILE_FLAG_ALL (FILE_FLAG_READ|FILE_FLAG_APPEND|			\
		       FILE_FLAG_TRUNCATE|FILE_FLAG_CREAT|FILE_FLAG_CREAT| \
		       FILE_FLAG_EXCL|FILE_FLAG_DIRECT|			\
		       FILE_FLAG_DATASYNC|FILE_FLAG_SYNC)

typedef intptr_t file_fd_handle;

file_fd_handle raw_file_open(const char *path, int flags, int *error);
int raw_file_close(file_fd_handle fd);

int raw_file_write(file_fd_handle fd, void *buf, size_t *nbyte);
int raw_file_pread(file_fd_handle fd, void *buf, size_t *nbyte, int64_t offset);
int raw_file_fsync(file_fd_handle fd);

char *raw_file_error_message(int error);

#endif

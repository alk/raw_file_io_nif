#ifndef OS_H
#define OS_H

#include <stdint.h>

#define FILE_FLAG_READ 1
#define FILE_FLAG_WRITE 2
#define FILE_FLAG_TRUNCATE 4

typedef intptr_t file_fd_handle;

file_fd_handle raw_file_open(const char *path, int flags, int *error);
int raw_file_close(file_fd_handle fd);

int raw_file_write(file_fd_handle fd, void *buf, size_t *nbyte);
int raw_file_pread(file_fd_handle fd, void *buf, size_t *nbyte, int64_t offset);

char *raw_file_error_message(int error, char *buf, int bufsize);

#endif

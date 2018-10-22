#ifndef SYS_WRITE_H
#define SYS_WRITE_H

struct iovec {
  void  *iov_base;
  uint64_t iov_len;
};

int64_t sys_write(int fildes, void *buf, uint64_t nbyte);
int64_t sys_writev(int fildes, const struct iovec *iov, int iovcnt);

#endif

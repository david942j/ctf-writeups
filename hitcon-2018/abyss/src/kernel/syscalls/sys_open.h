#ifndef SYS_OPEN_H
#define SYS_OPEN_H

#define AT_FDCWD -100

int sys_open(const char *path);
int sys_openat(int fildes, const char *path);
int sys_access(const char *path, int mode);

#endif

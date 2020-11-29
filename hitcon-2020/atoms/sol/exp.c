#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <linux/atoms.h>

#define DEV "/dev/atoms"
#define N 1024
static int fds[N];

static unsigned long long k_heap, k_data, k_stack;

static void *call_mmap(void *arg) {
  int fd = (int) arg;

  for (int i = 0; i < 1000; i++) {
    mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    usleep(10);
  }
  return NULL;
}

static void test() {
  int fd = open(DEV, O_RDWR);
  assert(fd >= 0);
  pthread_t pid;
  assert(pthread_create(&pid, NULL, call_mmap, (void*)fd) == 0);
  for (int i = 0; i < 1000; i++) {
    ioctl(fd, ATOMS_INFO, 0);
    usleep(10);
  }
  pthread_join(pid, NULL);
}

int main(int argc, char *argv[], char *envp[]) {
  test();
  return 0;
}

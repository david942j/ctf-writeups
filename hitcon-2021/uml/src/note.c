#include <stdio.h>
#include <stdlib.h>
#include <sys/sendfile.h>
#include <unistd.h>

#define CHECK(cond) do { if (!(cond)) exit(1); } while (0)

static void *readn(int fd, size_t sz) {
  void *ptr = malloc(sz);
  size_t off = 0;
  CHECK(ptr);
  while (sz) {
    ssize_t n = read(fd, ptr + off, sz);
    CHECK(n > 0);
    sz -= n;
    off += n;
  }
  return ptr;
}

static void work() {
  puts("Name of note?");
  char s[32] = {}, fname[40];
  CHECK(scanf("%30s", s) == 1);

  CHECK(s[0] != '.');
  sprintf(fname, "/tmp/%s", s);
  const char *mode;
  if (access(fname, F_OK)) mode = "w+";
  else if (access(fname, W_OK)) mode = "r";
  else mode = "r+";
  FILE *f = fopen(fname, mode);
  CHECK(f);

  while (1) {
    puts("1. Write the note\n"
         "2. Read the note\n"
         "3. I'm good\n"
         "Choose one:");
    int choose;
    CHECK(scanf("%d", &choose) == 1);
    if (choose == 3) break;
    int sz;
    puts("Size?");
    CHECK(scanf("%d", &sz) == 1);
    CHECK(sz > 0 && sz <= 0x10000);
    if (choose == 1) {
      void *ptr = readn(0, sz);
      CHECK(fwrite(ptr, 1, sz, f) == sz);
      rewind(f);
      free(ptr);
    } else if (choose == 2) {
      void *ptr = readn(fileno(f), sz);
      CHECK(write(1, ptr, sz) == sz);
      free(ptr);
    }
  }
  fclose(f);
}

int main() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  work();
  return 0;
}

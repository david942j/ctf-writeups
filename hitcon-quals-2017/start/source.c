#include <stdio.h>
#include <unistd.h>
#include <string.h>

int main() {
  alarm(10);
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  char s[16];
  while(read(0, s, 217)) {
    if(strncmp(s, "exit\n", 5) == 0) break;
    puts(s);
  }
  return 0;
}

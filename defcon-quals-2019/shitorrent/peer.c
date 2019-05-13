#include <stdio.h>
int main(int argc, char *argv[]) {
  char s[100];
  read(0, s, 16);
  if(strstr(argv[0], "lis") != NULL)
    write(1, "meow", 4);
  else
    write(1, "TORADMIN", 8);
  return 0;
}

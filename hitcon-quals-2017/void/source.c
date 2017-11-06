#include <stdio.h>
char s[100];
static void t() __attribute__((destructor));
int main() {
  scanf("%s", s);
  printf("hitcon{%s}\n", s);
  return 0;
}

static void t() {}

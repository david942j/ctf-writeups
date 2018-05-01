#include <stdio.h>
#include <time.h>
#include <stdlib.h>

int main() {
  srand(time(NULL));
  printf("%d\n", rand() & 0xfffff000);
  return 0;
}

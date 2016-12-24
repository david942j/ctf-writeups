#include <cstdio>
#include <cstdlib>
int main() {
  unsigned int seed;
  scanf("%u", &seed);
  srand(seed);
  for(int i=0;i<5;i++)
    printf("%d ",rand()%6969+1000);
  puts("");
  return 0;
}

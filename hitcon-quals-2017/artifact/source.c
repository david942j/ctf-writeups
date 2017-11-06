#include <linux/seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <unistd.h>
void install_seccomp() {
  unsigned char s[] = {
    32,0,0,0,4,0,0,0,21,0,0,16,62,0,0,192,32,0,0,0,32,0,0,0,7,0,0,0,0,0,0,0,32,0,0,0,0,0,0,0,21,0,13,0,0,0,0,0,21,0,12,0,1,0,0,0,21,0,11,0,5,0,0,0,21,0,10,0,8,0,0,0,21,0,1,0,9,0,0,0,21,0,0,3,10,0,0,0,135,0,0,0,0,0,0,0,84,0,0,0,1,0,0,0,21,0,4,5,1,0,0,0,29,0,4,0,11,0,0,0,21,0,3,0,12,0,0,0,21,0,2,0,60,0,0,0,21,0,1,0,231,0,0,0,6,0,0,0,0,0,0,0,6,0,0,0,0,0,255,127
  };
  struct A { unsigned short len; unsigned char *s; } a;
  a.len = sizeof(s) / 8;
  a.s = s;
  prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  if(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &a)) { perror("prctl"); exit(1); }
}
void init() {
  alarm(120);
  setvbuf(stdout, 0, 2, 0);
  install_seccomp();
}
void menu() {
  puts("-----> Safe Memo <-----");
  puts("1. show");
  puts("2. memo");
  puts("3. exit");
  puts("Choice?");
}
int main() {
  init();
  unsigned long long memo[200] = {};
  while(1) {
    menu();
    int n, idx = 0;
    scanf("%d", &n);
    if(n != 1 && n != 2) break;
    puts("Idx?");
    scanf("%d", &idx);
    if(n == 1) printf("Here it is: %lld\n", memo[idx]);
    else {
      puts("Give me your number:");
      scanf("%lld", &memo[idx]);
    }
  }
  return 0;
}

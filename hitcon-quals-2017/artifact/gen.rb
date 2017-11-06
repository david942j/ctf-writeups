#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'seccomp-tools/asm/asm'
bpf = SeccompTools::Asm.asm(<<-EOS)
  A = arch
  A == 0xc000003e ? next : kill
  A = args[2]
  X = A
  A = sys_number
  A == read ? allow : next
  A == write ? allow : next
  A == fstat ? allow : next
  A == lseek ? allow : next
  A == mmap ? check_arg2 : next
  A == mprotect ? check_arg2 : end_of_check
check_arg2:
  A = X
  A &= 1
  A == 1 ? kill : allow
end_of_check:
  A == X ? allow : next
  A == brk ? allow : next
  A == exit ? allow : next
  A == exit_group ? allow : next
kill:
  return KILL
allow:
  return ALLOW
EOS
bpf.gsub!("\x1d\x00\x04\x00\x00\x00\x00\x00","\x1d\x00\x04\x00\x0b\x00\x00\x00")
print bpf
source_tpl = <<EOS
#include <linux/seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <unistd.h>
void install_seccomp() {
  unsigned char s[] = {
    #{bpf.bytes.join(',')}
  };
  struct A { unsigned short len; unsigned char *s; } a;
  a.len = sizeof(s) / 8;
  a.s = s;
  prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  if(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &a)) { perror("prctl"); exit(1); }
}
void init() {
  alarm(60);
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
    if(n == 1) printf("Here it is: %lld\\n", memo[idx]);
    else {
      puts("Give me your number:");
      scanf("%lld", &memo[idx]);
    }
  }
  return 0;
}
EOS
IO.binwrite('source.c', source_tpl)
`make source && strip source`

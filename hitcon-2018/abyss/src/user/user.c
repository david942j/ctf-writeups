#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct Machine {
  int top, stk[1024];
  unsigned char s[1024];
  int ip;
  int vars[26];
} machine;

#define s machine.s
#define top machine.top
#define stk machine.stk
#define ip machine.ip
#define vars machine.vars

void push(int v) {
  if(top >= 1024) return;
  stk[top++] = v;
}

int pop() { if(top == 0) return 0; return stk[--top]; }

int pick(int idx) {
  if(idx < 0 || idx >= top) return 0;
  return stk[top - idx - 1];
}

void dup_() { push(pick(0)); }
void pop_() { pop(); }
void swap_() { int tmp = stk[top-1]; stk[top-1] = stk[top-2]; stk[top-2] = tmp; }
void rot() { int tmp = stk[top - 3]; stk[top-3] = stk[top-2]; stk[top-2] = stk[top-1]; stk[top-1] = tmp; }
void pick_() { push(pick(pop())); ip++; }
void add() { push(pop() + pop()); }
void minus() { push(-pop() + pop()); }
void mul() { push(pop() * pop()); }
void div_() { int d = pop(); push(pop() / d); }
void neg() { push(-pop()); }
void and_() { push(pop() & pop()); }
void or_() { push(pop() | pop()); }
void not_() { push(~pop()); }
void gt() { push(-(pop() < pop())); }
void eql() { push(-(pop() == pop())); }
void store() { int r = pop(); if(0 <= r && r < 26) vars[r] = pop(); }
void fetch() { int r = pop(); if(0 <= r && r < 26) push(vars[r]); }
/* void read_() { char c; read(0, &c, 1); push(c); } */
void write_() { char c = pop(); write(1, &c, 1); }
void writed() { int v = pop(); printf("%d\n", v); }

int fetch_int() {
  int now = 0;
  while(isdigit(s[ip])) {
    now = now * 10 + s[ip] - '0';
    ip++;
  }
  --ip;
  return now;
}

void *commands(char c) {
  switch(c) {
   /* Stack commands */
  case '$': return dup_;
  case '%': return pop_;
  case '\\': return swap_;
  case '@': return rot;
  case 0xc3: return pick_;
  /* Arithmetic */
  case '+': return add;
  case '-': return minus;
  case '*': return mul;
  case '/': return div_;
  case '_': return neg;
  case '&': return and_;
  case '|': return or_;
  case '~' : return not_;
  /* Comparison */
  case '>': return gt;
  case '=': return eql;
  /* Lambda and Control Flows*/
  /* not implemented */
  /* names */
  case ':': return store;
  case ';': return fetch;
  /* I/O */
  /* case '^': return read_, */
  case ',': return write_;
  case '.': return writed;
  default: return NULL;
  }
}

void work() {
  int n = strlen((char*)s);
  ip = 0;
  while(ip < n) {
    if(isdigit(s[ip]))
      push(fetch_int());
    else if('a' <= s[ip] && s[ip] <= 'z')
      push(s[ip] - 'a');
    else if(commands(s[ip]))
      ((void(*)())commands(s[ip]))();
    ++ip;
  }
}

int main() {
  setbuf(stdin, 0);
  setbuf(stdout, 0);
  puts("Once you get into the Abyss, you have no choice but keep going down.");

  if(scanf("%1024s", s) != 1) return 1;
  work();
  return 0;
}

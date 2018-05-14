#include <stdio.h>
#include <string.h>

const int N = 0x6033d8;
int dp[N+2];
void trace(int now) {
  if(now == 0) return;
  trace(dp[now]);
  printf("%d\n", now - dp[now]);
}
int main() {
  int ary[]={
    208980,
    209000,
    210000,
    222000,
    223000,
    226000,
    227000,
    231036,
    232038,
    237000,
    238029,
    243000,
    244000,
    247000,
    247000,
    251000,
    252000,
    257000};
  memset(dp, -1, sizeof(dp));
  dp[0] = 0;
  for(int i=0;i<sizeof(ary)/sizeof(ary[0]);i++) {
    for(int j = 0;j+ary[i]<=N;j++) if(dp[j]!=-1 && dp[j+ary[i]] == -1){
      dp[j+ary[i]] = j;
    }
    if(dp[N]!=-1) break;
  }
  trace(N);
}

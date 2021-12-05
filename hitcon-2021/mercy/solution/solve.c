#include <stdint.h>
#include <stdio.h>

int main() {
  int t[9] = {
    0x4062ee8,
    0x441d6a8,
    0x69edf0e,
    0x7885b66,
    0x40ff43f,
    0x6f30d11,
    0x624e22d,
    0x183716f,
    0x0c7a45e,
  };
#define N 27
  uint16_t out[N];
  for (int i = 0; i < N; i += 3) {
    out[i + 0] = (t[i / 3] >> 9) & 0x1ff;
    out[i + 1] = (t[i / 3] >> 18) & 0x1ff;
    out[i + 2] = (t[i / 3]) & 0x1ff;
  }
  static uint16_t S[512];
  int i;
  for (i = 0; i < 512; i++)
    S[i] = i;
#define KLEN 9
  static uint16_t key[KLEN] = { 299, 98, 188, 156, 59, 52, 273, 137, 324 };
  uint16_t j = 0;
  for (i = 0; i < 512; i++) {
    j = (j + S[i] + key[i % KLEN]) % 512;
    S[i] ^= S[j] ^= S[i] ^= S[j];
  }
  uint16_t flag[N + 1] = {};
  j = 0;
  for (i = 0; i < N; i++) {
    j += S[i]; j %= 512;
    S[i] ^= S[j] ^= S[i] ^= S[j];
    uint16_t prev = i == 0 ? 0 : out[i - 1];
    flag[i] = ((out[i] - prev + 512) % 512) ^ S[(S[i] + S[j]) % 512];
  }
  /* for (int i = 0; i < N; i++) */
  /*   printf("%x ", flag[i]); */
  /* puts(""); */
  for (int i = 0; i < N; i++)
    printf("%c", flag[i]);
  return 0;
}

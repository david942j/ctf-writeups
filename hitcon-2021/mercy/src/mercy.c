#include <stdio.h>
#include <string.h>

#define FLAG_AT 0x04010000

#define false 0
#define true 1
typedef unsigned char uint8_t;

static bool check(uint8_t *flag) {
#define N 27
  static uint8_t S[512];
  int i;
  for (i = 0; i < 512; i++)
    S[i] = i;
  uint8_t j = 0;
#define KLEN 9
  static uint8_t key[KLEN] = { 299, 98, 188, 156, 59, 52, 273, 137, 324 };
  for (i = 0; i < 512; i++) {
    j = (j + S[i] + key[i % KLEN]) % 512;
    S[i] ^= S[j] ^= S[i] ^= S[j];
  }
  j = 0;
  uint8_t out[N], prev = 0;
  for (i = 0; i < N; i++) {
    j += S[i];
    S[i] ^= S[j] ^= S[i] ^= S[j];
    uint8_t t = S[i] + S[j];
    out[i] = (flag[i] ^ S[t]) + prev;
    prev = out[i];
  }
  /* for (i = 0; i < N; i += 3) printf("0x%x\n", *(int *)(out + i)); */
  if (*(int *)(out + 24) != 0x0c7a45e) return false;
  if (*(int *)(out + 3) != 0x441d6a8) return false;
  if (*(int *)(out + 18) != 0x624e22d) return false;
  if (*(int *)(out + 15) != 0x6f30d11) return false;
  if (*(int *)(out + 12) != 0x40ff43f) return false;
  if (*(int *)(out + 0) != 0x4062ee8) return false;
  if (*(int *)(out + 21) != 0x183716f) return false;
  if (*(int *)(out + 6) != 0x69edf0e) return false;
  if (*(int *)(out + 9) != 0x7885b66) return false;
  return true;
}

int main() {
  if (check(FLAG_AT))
    printf("Nice job: %s", FLAG_AT);
  else
    printf("NO\n");
  return 0;
}

#include <stdint.h>
#include <stdio.h>

struct chal {
  uint32_t k[4], delta, v[2];
};

void decrypt(const struct chal *chal, uint32_t *out) {
  uint32_t v0=chal->v[0], v1=chal->v[1], sum = chal->delta * 32;
  const uint32_t k0=chal->k[0], k1 = chal->k[1], k2=chal->k[2], k3=chal->k[3];

  for (int i = 0; i < 32; i++) {
    v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
    v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
    sum -= chal->delta;
  }
  out[0] = v0; out[1] = v1;
}

int main() {
  static struct chal part[4] = {
    {
      .delta = 0x51fdd41a,
      .k = {0x69a33fff, 0x468932dc, 0x2b0b575b, 0x1e8b51cc},
      .v = {0x152ceed2, 0xd6046dc3},
    },
    {
      .delta = 0x5c37a6db,
      .k = {0x32e57ab6, 0x7785df55, 0x688620f9, 0x8df954f3},
      .v = {0x4a9d3ffd, 0xbb541082},
    },
    {
      .delta = 0xb4f0b4fb,
      .k = {0xaca81571, 0x2c19574f, 0x1bd1fc38, 0x14220605},
      .v = {0x632a4f78, 0xa9cb93d},
    },
    {
      .delta = 0xd3c45f8c,
      .k = {0x33f33fe0, 0xf9de7e36, 0xe9ab109d, 0x8d4f04b2},
      .v = {0x58aae351, 0x92012a14},
    }
  };
  uint32_t res[9] = {};
  for (int i = 0; i < 4; i++)
    decrypt(&part[i], &res[i * 2]);
  printf("%s\n", res);
  return 0;
}

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
void aes_x86_128_encrypt_block(unsigned char *plaintext, unsigned char *ciphertext, unsigned char *round_keys)
{
	/* load the data */
	asm("movdqu (%0), %%xmm15" :: "r"(plaintext));
	/* load the round keys */
	asm("movdqu (%0), %%xmm0" :: "r"(round_keys));
	asm("movdqu (%0), %%xmm1" :: "r"(round_keys + 16));
	asm("movdqu (%0), %%xmm2" :: "r"(round_keys + 32));
	asm("movdqu (%0), %%xmm3" :: "r"(round_keys + 48));
	asm("movdqu (%0), %%xmm4" :: "r"(round_keys + 64));
	asm("movdqu (%0), %%xmm5" :: "r"(round_keys + 80));
	asm("movdqu (%0), %%xmm6" :: "r"(round_keys + 96));
	asm("movdqu (%0), %%xmm7" :: "r"(round_keys + 112));
	asm("movdqu (%0), %%xmm8" :: "r"(round_keys + 128));
	asm("movdqu (%0), %%xmm9" :: "r"(round_keys + 144));
	asm("movdqu (%0), %%xmm10" :: "r"(round_keys + 160));
	/* ...and do the rounds with them */
	asm("pxor %xmm0, %xmm15; \
	     aesenc %xmm1, %xmm15;\
	     aesenc %xmm2, %xmm15;\
	     aesenc %xmm3, %xmm15;\
	     aesenc %xmm4, %xmm15;\
	     aesenc %xmm5, %xmm15;\
	     aesenc %xmm6, %xmm15;\
	     aesenc %xmm7, %xmm15;\
	     aesenc %xmm8, %xmm15;\
	     aesenc %xmm9, %xmm15;\
	     aesenclast %xmm10, %xmm15;");
	/* copy the data out of xmm15 */
	asm("movdqu %%xmm15, (%0)" :: "r"(ciphertext));
}
void aes_x86_128_decrypt_block(unsigned char *ciphertext, unsigned char *plaintext, unsigned char *dec_round_keys)
{
	/* load the data */
	asm("movdqu (%0), %%xmm15" :: "r"(ciphertext));
	/* load the round keys */
	asm("movdqu (%0), %%xmm10" :: "r"(dec_round_keys + 160));
	asm("movdqu (%0), %%xmm9" :: "r"(dec_round_keys + 144));
	asm("movdqu (%0), %%xmm8" :: "r"(dec_round_keys + 128));
	asm("movdqu (%0), %%xmm7" :: "r"(dec_round_keys + 112));
	asm("movdqu (%0), %%xmm6" :: "r"(dec_round_keys + 96));
	asm("movdqu (%0), %%xmm5" :: "r"(dec_round_keys + 80));
	asm("movdqu (%0), %%xmm4" :: "r"(dec_round_keys + 64));
	asm("movdqu (%0), %%xmm3" :: "r"(dec_round_keys + 48));
	asm("movdqu (%0), %%xmm2" :: "r"(dec_round_keys + 32));
	asm("movdqu (%0), %%xmm1" :: "r"(dec_round_keys + 16));
	asm("movdqu (%0), %%xmm0" :: "r"(dec_round_keys));
	/* ...and do the rounds with them */
	asm("pxor %xmm10, %xmm15; \
	     aesdec %xmm9, %xmm15;\
	     aesdec %xmm8, %xmm15;\
	     aesdec %xmm7, %xmm15;\
	     aesdec %xmm6, %xmm15;\
	     aesdec %xmm5, %xmm15;\
	     aesdec %xmm4, %xmm15;\
	     aesdec %xmm3, %xmm15;\
	     aesdec %xmm2, %xmm15;\
	     aesdec %xmm1, %xmm15;\
	     aesdeclast %xmm0, %xmm15;");
	/* copy the data out of xmm15 */
	asm("movdqu %%xmm15, (%0)" :: "r"(plaintext));
}
void aes_x86_128_key_inv_transform(unsigned char *round_keys, unsigned char *dec_round_keys) {
  /* call the inversion instruction on most of the keys */
  asm(" \
    mov %0, %%rdx;                 \
    mov %1, %%rax;                 \
    movdqu (%%rdx), %%xmm1;        \
    movdqu %%xmm1, (%%rax);        \
    add $0x10, %%rdx;              \
    add $0x10, %%rax;              \
    \
    mov $9, %%ecx;                 \
    repeat:                        \
    movdqu (%%rdx), %%xmm1;    \
    aesimc %%xmm1, %%xmm1;     \
    movdqu %%xmm1, (%%rax);    \
    add $0x10, %%rdx;          \
    add $0x10, %%rax;          \
    loop repeat;                   \
    \
    movdqu (%%rdx), %%xmm1;        \
    movdqu %%xmm1, (%%rax);        \
    " :: "r"(round_keys), "r"(dec_round_keys) : "rdx", "rax");
}
int main() {
  unsigned char plaintext[] = "code_in_BuildID!";
  assert(strlen(plaintext) == 16);
  unsigned char roundkeys[] = {72, 193, 253, 3, 232, 7, 254, 255, 255, 72, 133, 237, 116, 32, 49, 219, 15, 31, 132, 0, 0, 0, 0, 0, 76, 137, 234, 76, 137, 246, 68, 137,
    255, 65, 255, 20, 220, 72, 131, 195, 1, 72, 57, 221, 117, 234, 72, 131, 196, 8, 91, 93, 65, 92, 65, 93, 65, 94, 65, 95, 195, 144, 102, 46,
    15, 31, 132, 0, 0, 0, 0, 0, 243, 195, 0, 0, 72, 131, 236, 8, 72, 131, 196, 8, 195, 0, 0, 0, 1, 0, 2, 0, 37, 115, 0, 104, 105, 116, 99, 111,
     110, 123, 37, 115, 125, 10, 0, 0, 1, 27, 3, 59, 64, 0, 0, 0, 7, 0, 0, 0, 188, 253, 255, 255, 140, 0, 0, 0, 204, 253, 255, 255, 180, 0, 0,
     0, 236, 253, 255, 255, 92, 0, 0, 0, 28, 255, 255, 255, 204, 0, 0, 0, 87, 255, 255, 255, 236, 0, 0, 0, 108, 255, 255, 255, 12, 1, 0, 0, 220,
      255, 255, 255, 84, 1, 0, 0};
  unsigned char ciphertext[]= "aaaaaaaaaaaaaaaa";
  unsigned char dk[180]= {};
  aes_x86_128_encrypt_block(plaintext, ciphertext, roundkeys);
  memset(plaintext, 0, sizeof(plaintext));
  aes_x86_128_key_inv_transform(roundkeys, dk);
  for(int i=0;i<16;i++)
    printf("%02x", ciphertext[i]);
  puts("");
  aes_x86_128_decrypt_block(ciphertext, plaintext, dk);
  printf("--%s--\n", plaintext);

  return 0;
}

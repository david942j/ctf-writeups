#include <cstdio>
void swap(int &a, int &b) {
  int tmp = a;
  a=b;b=tmp;
}
int magics[] = { 0x1660F4CA, 0x712FB7DC, 0xF37DEA3D, 0x17A82EC8, 0xCE473A2E, 0x10E38533, 0x5D85B14F, 0x8405B087,
 0x898FCAFC, 0xBD1736F4, 0x89F18DE1, 0xE4373F5B, 0xD1EF2627, 0xDAB1DF6A, 0x8F0463F0, 0x225079D7,
 0xD066D44D, 0x12CCE0E1, 0x04E5FB3A, 0xCA6224DA, 0x95D4C533, 0x8181A84D, 0xBAF32044, 0x44267739,
 0x6B61BDF7, 0x251D846C, 0x765F7338, 0x572BE0D1, 0x369BC21B, 0x82BA23F6, 0x4F72F6AA, 0x1867B1D3};
/*
 * ABCDEFGHIJKLMNOP
 * 'ABCDEFGHIJKLMNOP'.chars.map{|c|[c,"\x00"]}.flatten.join.unpack("L*")
 * [4325441, 4456515, 4587589, 4718663, 4849737, 4980811, 5111885, 5242959]
 * 4DB308DC 68016200 34EEED82 95540C2A 0A379DC2 66FE0230 B0526B4C F64AF6E2
 D2A6EA99 52A59D36 CC8275AF D95914DA D2A6EA99 52A59D36 CC8275AF D95914DA
 * */
int input[]= {4325441, 4456515, 4587589, 4718663, 4849737, 4980811, 5111885, 5242959,0,0,0,0,0,0,0,0,0,0,0};
int __ROL4__(unsigned int a, int b) {
  if(b==0)return a;
   return (a << b) | (a>>(32-b));
}
int alala(int *input, int *magic)
{
  int *input_0; // esi@1
  int in3; // edi@2
  int in2; // eax@2
  int in1; // ebx@2
  int _ii; // edx@2
  int v7; // ecx@4
  int v8; // edi@4
  int v9; // eax@4
  int v10; // ST0C_4@4
  signed int v11; // kr00_4@4
  int v12; // edx@4
  int v13; // edi@4
  int v14; // edx@4
  int v15; // eax@4
  bool v16; // sf@4
  int v17; // [sp+14h] [bp-10h]@4
  signed int block; // [sp+1Ch] [bp-8h]@1
  unsigned int ii; // [sp+20h] [bp-4h]@2

  input_0 = input + 0;
  block = 4;
  do
  {
    *(input_0) -= 0x7FAF076D;
    input_0[2] += 0x642805B4;
    in3 = input_0[3];                            // 4 in a group
    in2 = input_0[2];
    in1 = input_0[1];
    _ii = 124;
    ii = 124;
    while ( 1 )                                 // 16 times
    {
      v7 = *(input_0);
      input_0[3] = in2;
      *(input_0) = in3;
      v8 = in2;
      v9 = __ROL4__(in2 * (2 * in2 + 1), 8);
      v17 = v8;
      v10 = v9;
      input_0[1] = v7;
      v11 = _ii - 4;
      v12 = *(input_0);
      input_0[2] = in1;
      v13 = __ROL4__(v7 * (2 * v7 + 1), 8);
      v14 = __ROL4__(v12 - magic[v11 / 4], 32 - (v9 & 0x1F));
      *(input_0) = v13 ^ v14;
      v15 = __ROL4__(in1 - magic[ii >> 2], 32 - (v13 & 0x1F));
      in2 = v10 ^ v15;
      _ii = ii - 8;
      v16 = ((ii - 8) & 0x80000000) != 0;
      input_0[2] = in2;
      ii -= 8;
      if ( v16 )
        break;
      in1 = v7;
      in3 = v17;
    }
    input_0[1] -= 0x5BF76637;
    input_0[3] -= 0x4748DA7A;
    input_0 += 4;
    --block;
  }
  while ( block );
  return in2;
}
#define rol __ROL4__
void encrypt(int *input, int *magic) {
  int *in0 = input;
  int block = 4;
  while(block--) {
    int &a=in0[0],&b=in0[1],&c=in0[2],&d=in0[3];
    b += 0x5BF76637;
    d += 0x4748DA7A;
    for(int r=1;r<=16;r++) {
      int t=rol(b*(2*b+1), 8);
      int u=rol(d*(2*d+1), 8);
      a = rol(a^t, (u&0x1f)) + magic[2*r-2];
      c = rol(c^u, (t&0x1f)) + magic[2*r-1];
      // a,b,c,d = b,c,d,a;
      swap(a,b);
      swap(b,c);
      swap(c,d);
    }
    a += 0x7FAF076D;
    c -= 0x642805B4;
    in0 += 4;
  }
}
int target[]={0x9177ff5c, 0xc61a547e, 0x34f6d232, 0xa8b69214, 0x8a56f10b, 0x5782f79a, 0xba473fde, 0x963b0022, 0xbcdb6eb3, 0x6ca1c42f, 0xf03f31d2, 0x803ad769, 0x5ae56b35, 0x17ceb0c5, 0x5d72a4e6, 0xde477f40};
int xorkey[]={0xA9E8C7AF, 0x5E75758F, 0x5E9D3D51, 0x1D8E88AD, 0x70F2787F, 0x9F12E1E3, 0xD98E11AF, 0xDB54DF2F,
  0xD51B11C1, 0x829EB212, 0x860B121B, 0xB8266044, 0x73209C4D, 0xABC2A3AF, 0xEBDC17B8, 0xE64DC322};
int main() {
  printf("%lu\n",sizeof(magics));
  alala(input, magics);
  for(int i=0;i<16;i++)
    printf("%x ", (unsigned int)input[i]);
  puts("");
  encrypt(input, magics);
  for(int i=0;i<16;i++)
    printf("%x ", (unsigned int)input[i]);
  puts("");
  for(int i=0;i<16;i++) {
    target[i] ^= xorkey[i];
  }
  encrypt(target, magics);
  for(int i=0;i<16;i++)
    printf("%x ", (unsigned int)target[i]);
  puts("");
  for(int i=0;i<16;i++)
    printf("%c%c", target[i]&0xff, target[i]>>16);
  puts("");
}

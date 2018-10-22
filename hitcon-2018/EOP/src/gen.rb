#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'securerandom'
require 'pwn'        # https://github.com/peter50216/pwntools-ruby

# {{{ cpp tpl
tpl = <<-'CPP'
#include <bits/stdc++.h>
#include <err.h>
#include <exception>
#include <unistd.h>
#include <stdint.h>

using namespace std;

#define FLAG_LEN 16 * 3
uint8_t p[16], c[16];
uint32_t A,B,C,D,T0,T1;

struct Twofish_key {
  uint32_t K[64];
  uint32_t s[4][256];
} key = {
  .K = {%<key_k>s},
  .s = {
    {%<key_s0>s},
    {%<key_s1>s},
    {%<key_s2>s},
    {%<key_s3>s}
  }
}, *xkey = &key;

class Base {
public:
  virtual void what() const {}
};

%<all_classes>s

Base *arr[%<n>d];

void init() {
  %<all_init>s
}

void gogo(int s) {
  try {
    throw arr[s];
  } catch(const Base* e) {
    e->what();
  }
}

void no() {
  puts("NO");
  exit(0);
}

unsigned char output[FLAG_LEN + 1]; 
unsigned char ans[FLAG_LEN] = {%<ans>s};
unsigned char flag[FLAG_LEN + 1]; 

int main() {
  init();
  scanf("%%49s", flag);
  if(strlen((char*) flag) != FLAG_LEN) no();
  for(int i = 0; i < FLAG_LEN; i += 16) {
    int now = %<start>d;
    memcpy(p, flag + i, 16);
    while(1) {
      try {
        gogo(now);
      } catch(int err) {
        if(err == %<end>d) break;
        now = err;
      }
    }
    memcpy(output + i, c, 16);
  }
#ifdef DEBUG
  write(1, output, FLAG_LEN);
#endif
  if(memcmp(output, ans, FLAG_LEN) == 0)
    printf("Great! Here's the flag: hitcon{%%s}\n", flag);
  else no();
  return 0;
}
CPP
# }}}

class_tpl = <<-CLASS
class %<name>s: public Base {
public:
  void what() const override {
    try {
      throw exception();
    } catch(...) {
      %<instruction>s
      throw %<next>d;
    }
  }
};
CLASS

# {{{ insts
insts = <<-EOS.lines
  for(int i = 0; i < 16; i++) p[i] ^= c[i];
  A = ( (uint32_t)((p)[0]) | (uint32_t)((p)[1])<< 8 | (uint32_t)((p)[2])<<16 | (uint32_t)((p)[3])<<24 )^xkey->K[ 0];
  B = ( (uint32_t)((p+ 4)[0]) | (uint32_t)((p+ 4)[1])<< 8 | (uint32_t)((p+ 4)[2])<<16 | (uint32_t)((p+ 4)[3])<<24 )^xkey->K[1+0];
  C = ( (uint32_t)((p+ 8)[0]) | (uint32_t)((p+ 8)[1])<< 8 | (uint32_t)((p+ 8)[2])<<16 | (uint32_t)((p+ 8)[3])<<24 )^xkey->K[2+0];
  D = ( (uint32_t)((p+12)[0]) | (uint32_t)((p+12)[1])<< 8 | (uint32_t)((p+12)[2])<<16 | (uint32_t)((p+12)[3])<<24 )^xkey->K[3+0];

  T0 = (xkey->s[0][((((A)) >> 8*(0)) & 0xff)]^xkey->s[1][((((A)) >> 8*(1)) & 0xff)]^xkey->s[2][((((A)) >> 8*(2)) & 0xff)]^xkey->s[3][((((A)) >> 8*(3)) & 0xff)]);
  T1 = (xkey->s[0][((((B)) >> 8*(3)) & 0xff)]^xkey->s[1][((((B)) >> 8*(0)) & 0xff)]^xkey->s[2][((((B)) >> 8*(1)) & 0xff)]^xkey->s[3][((((B)) >> 8*(2)) & 0xff)]);
  C ^= T0+T1+xkey->K[8+2*(2*(0))];
  C = ( ((C))<<(32-(1)) | (((C)) & ( (((uint32_t)2)<<31) - 1 )) >> (32-(32-(1))) );
  D = ( (D)<<(1) | ((D) & ( (((uint32_t)2)<<31) - 1 )) >> (32-(1)) );
  D ^= T0+2*T1+xkey->K[8+2*(2*(0))+1];
  T0 = (xkey->s[0][((((C)) >> 8*(0)) & 0xff)]^xkey->s[1][((((C)) >> 8*(1)) & 0xff)]^xkey->s[2][((((C)) >> 8*(2)) & 0xff)]^xkey->s[3][((((C)) >> 8*(3)) & 0xff)]);
  T1 = (xkey->s[0][((((D)) >> 8*(3)) & 0xff)]^xkey->s[1][((((D)) >> 8*(0)) & 0xff)]^xkey->s[2][((((D)) >> 8*(1)) & 0xff)]^xkey->s[3][((((D)) >> 8*(2)) & 0xff)]);
  A ^= T0+T1+xkey->K[8+2*(2*(0)+1)];
  A = ( ((A))<<(32-(1)) | (((A)) & ( (((uint32_t)2)<<31) - 1 )) >> (32-(32-(1))) );
  B = ( (B)<<(1) | ((B) & ( (((uint32_t)2)<<31) - 1 )) >> (32-(1)) );
  B ^= T0+2*T1+xkey->K[8+2*(2*(0)+1)+1];
  T0 = (xkey->s[0][((((A)) >> 8*(0)) & 0xff)]^xkey->s[1][((((A)) >> 8*(1)) & 0xff)]^xkey->s[2][((((A)) >> 8*(2)) & 0xff)]^xkey->s[3][((((A)) >> 8*(3)) & 0xff)]);
  T1 = (xkey->s[0][((((B)) >> 8*(3)) & 0xff)]^xkey->s[1][((((B)) >> 8*(0)) & 0xff)]^xkey->s[2][((((B)) >> 8*(1)) & 0xff)]^xkey->s[3][((((B)) >> 8*(2)) & 0xff)]);
  C ^= T0+T1+xkey->K[8+2*(2*(1))];
  C = ( ((C))<<(32-(1)) | (((C)) & ( (((uint32_t)2)<<31) - 1 )) >> (32-(32-(1))) );
  D = ( (D)<<(1) | ((D) & ( (((uint32_t)2)<<31) - 1 )) >> (32-(1)) );
  D ^= T0+2*T1+xkey->K[8+2*(2*(1))+1];
  T0 = (xkey->s[0][((((C)) >> 8*(0)) & 0xff)]^xkey->s[1][((((C)) >> 8*(1)) & 0xff)]^xkey->s[2][((((C)) >> 8*(2)) & 0xff)]^xkey->s[3][((((C)) >> 8*(3)) & 0xff)]);
  T1 = (xkey->s[0][((((D)) >> 8*(3)) & 0xff)]^xkey->s[1][((((D)) >> 8*(0)) & 0xff)]^xkey->s[2][((((D)) >> 8*(1)) & 0xff)]^xkey->s[3][((((D)) >> 8*(2)) & 0xff)]);
  A ^= T0+T1+xkey->K[8+2*(2*(1)+1)];
  A = ( ((A))<<(32-(1)) | (((A)) & ( (((uint32_t)2)<<31) - 1 )) >> (32-(32-(1))) );
  B = ( (B)<<(1) | ((B) & ( (((uint32_t)2)<<31) - 1 )) >> (32-(1)) );
  B ^= T0+2*T1+xkey->K[8+2*(2*(1)+1)+1];
  T0 = (xkey->s[0][((((A)) >> 8*(0)) & 0xff)]^xkey->s[1][((((A)) >> 8*(1)) & 0xff)]^xkey->s[2][((((A)) >> 8*(2)) & 0xff)]^xkey->s[3][((((A)) >> 8*(3)) & 0xff)]);
  T1 = (xkey->s[0][((((B)) >> 8*(3)) & 0xff)]^xkey->s[1][((((B)) >> 8*(0)) & 0xff)]^xkey->s[2][((((B)) >> 8*(1)) & 0xff)]^xkey->s[3][((((B)) >> 8*(2)) & 0xff)]);
  C ^= T0+T1+xkey->K[8+2*(2*(2))];
  C = ( ((C))<<(32-(1)) | (((C)) & ( (((uint32_t)2)<<31) - 1 )) >> (32-(32-(1))) );
  D = ( (D)<<(1) | ((D) & ( (((uint32_t)2)<<31) - 1 )) >> (32-(1)) );
  D ^= T0+2*T1+xkey->K[8+2*(2*(2))+1];
  T0 = (xkey->s[0][((((C)) >> 8*(0)) & 0xff)]^xkey->s[1][((((C)) >> 8*(1)) & 0xff)]^xkey->s[2][((((C)) >> 8*(2)) & 0xff)]^xkey->s[3][((((C)) >> 8*(3)) & 0xff)]);
  T1 = (xkey->s[0][((((D)) >> 8*(3)) & 0xff)]^xkey->s[1][((((D)) >> 8*(0)) & 0xff)]^xkey->s[2][((((D)) >> 8*(1)) & 0xff)]^xkey->s[3][((((D)) >> 8*(2)) & 0xff)]);
  A ^= T0+T1+xkey->K[8+2*(2*(2)+1)];
  A = ( ((A))<<(32-(1)) | (((A)) & ( (((uint32_t)2)<<31) - 1 )) >> (32-(32-(1))) );
  B = ( (B)<<(1) | ((B) & ( (((uint32_t)2)<<31) - 1 )) >> (32-(1)) );
  B ^= T0+2*T1+xkey->K[8+2*(2*(2)+1)+1];
  T0 = (xkey->s[0][((((A)) >> 8*(0)) & 0xff)]^xkey->s[1][((((A)) >> 8*(1)) & 0xff)]^xkey->s[2][((((A)) >> 8*(2)) & 0xff)]^xkey->s[3][((((A)) >> 8*(3)) & 0xff)]);
  T1 = (xkey->s[0][((((B)) >> 8*(3)) & 0xff)]^xkey->s[1][((((B)) >> 8*(0)) & 0xff)]^xkey->s[2][((((B)) >> 8*(1)) & 0xff)]^xkey->s[3][((((B)) >> 8*(2)) & 0xff)]);
  C ^= T0+T1+xkey->K[8+2*(2*(3))];
  C = ( ((C))<<(32-(1)) | (((C)) & ( (((uint32_t)2)<<31) - 1 )) >> (32-(32-(1))) );
  D = ( (D)<<(1) | ((D) & ( (((uint32_t)2)<<31) - 1 )) >> (32-(1)) );
  D ^= T0+2*T1+xkey->K[8+2*(2*(3))+1];
  T0 = (xkey->s[0][((((C)) >> 8*(0)) & 0xff)]^xkey->s[1][((((C)) >> 8*(1)) & 0xff)]^xkey->s[2][((((C)) >> 8*(2)) & 0xff)]^xkey->s[3][((((C)) >> 8*(3)) & 0xff)]);
  T1 = (xkey->s[0][((((D)) >> 8*(3)) & 0xff)]^xkey->s[1][((((D)) >> 8*(0)) & 0xff)]^xkey->s[2][((((D)) >> 8*(1)) & 0xff)]^xkey->s[3][((((D)) >> 8*(2)) & 0xff)]);
  A ^= T0+T1+xkey->K[8+2*(2*(3)+1)];
  A = ( ((A))<<(32-(1)) | (((A)) & ( (((uint32_t)2)<<31) - 1 )) >> (32-(32-(1))) );
  B = ( (B)<<(1) | ((B) & ( (((uint32_t)2)<<31) - 1 )) >> (32-(1)) );
  B ^= T0+2*T1+xkey->K[8+2*(2*(3)+1)+1];
  T0 = (xkey->s[0][((((A)) >> 8*(0)) & 0xff)]^xkey->s[1][((((A)) >> 8*(1)) & 0xff)]^xkey->s[2][((((A)) >> 8*(2)) & 0xff)]^xkey->s[3][((((A)) >> 8*(3)) & 0xff)]);
  T1 = (xkey->s[0][((((B)) >> 8*(3)) & 0xff)]^xkey->s[1][((((B)) >> 8*(0)) & 0xff)]^xkey->s[2][((((B)) >> 8*(1)) & 0xff)]^xkey->s[3][((((B)) >> 8*(2)) & 0xff)]);
  C ^= T0+T1+xkey->K[8+2*(2*(4))];
  C = ( ((C))<<(32-(1)) | (((C)) & ( (((uint32_t)2)<<31) - 1 )) >> (32-(32-(1))) );
  D = ( (D)<<(1) | ((D) & ( (((uint32_t)2)<<31) - 1 )) >> (32-(1)) );
  D ^= T0+2*T1+xkey->K[8+2*(2*(4))+1];
  T0 = (xkey->s[0][((((C)) >> 8*(0)) & 0xff)]^xkey->s[1][((((C)) >> 8*(1)) & 0xff)]^xkey->s[2][((((C)) >> 8*(2)) & 0xff)]^xkey->s[3][((((C)) >> 8*(3)) & 0xff)]);
  T1 = (xkey->s[0][((((D)) >> 8*(3)) & 0xff)]^xkey->s[1][((((D)) >> 8*(0)) & 0xff)]^xkey->s[2][((((D)) >> 8*(1)) & 0xff)]^xkey->s[3][((((D)) >> 8*(2)) & 0xff)]);
  A ^= T0+T1+xkey->K[8+2*(2*(4)+1)];
  A = ( ((A))<<(32-(1)) | (((A)) & ( (((uint32_t)2)<<31) - 1 )) >> (32-(32-(1))) );
  B = ( (B)<<(1) | ((B) & ( (((uint32_t)2)<<31) - 1 )) >> (32-(1)) );
  B ^= T0+2*T1+xkey->K[8+2*(2*(4)+1)+1];
  T0 = (xkey->s[0][((((A)) >> 8*(0)) & 0xff)]^xkey->s[1][((((A)) >> 8*(1)) & 0xff)]^xkey->s[2][((((A)) >> 8*(2)) & 0xff)]^xkey->s[3][((((A)) >> 8*(3)) & 0xff)]);
  T1 = (xkey->s[0][((((B)) >> 8*(3)) & 0xff)]^xkey->s[1][((((B)) >> 8*(0)) & 0xff)]^xkey->s[2][((((B)) >> 8*(1)) & 0xff)]^xkey->s[3][((((B)) >> 8*(2)) & 0xff)]);
  C ^= T0+T1+xkey->K[8+2*(2*(5))];
  C = ( ((C))<<(32-(1)) | (((C)) & ( (((uint32_t)2)<<31) - 1 )) >> (32-(32-(1))) );
  D = ( (D)<<(1) | ((D) & ( (((uint32_t)2)<<31) - 1 )) >> (32-(1)) );
  D ^= T0+2*T1+xkey->K[8+2*(2*(5))+1];
  T0 = (xkey->s[0][((((C)) >> 8*(0)) & 0xff)]^xkey->s[1][((((C)) >> 8*(1)) & 0xff)]^xkey->s[2][((((C)) >> 8*(2)) & 0xff)]^xkey->s[3][((((C)) >> 8*(3)) & 0xff)]);
  T1 = (xkey->s[0][((((D)) >> 8*(3)) & 0xff)]^xkey->s[1][((((D)) >> 8*(0)) & 0xff)]^xkey->s[2][((((D)) >> 8*(1)) & 0xff)]^xkey->s[3][((((D)) >> 8*(2)) & 0xff)]);
  A ^= T0+T1+xkey->K[8+2*(2*(5)+1)];
  A = ( ((A))<<(32-(1)) | (((A)) & ( (((uint32_t)2)<<31) - 1 )) >> (32-(32-(1))) );
  B = ( (B)<<(1) | ((B) & ( (((uint32_t)2)<<31) - 1 )) >> (32-(1)) );
  B ^= T0+2*T1+xkey->K[8+2*(2*(5)+1)+1];
  T0 = (xkey->s[0][((((A)) >> 8*(0)) & 0xff)]^xkey->s[1][((((A)) >> 8*(1)) & 0xff)]^xkey->s[2][((((A)) >> 8*(2)) & 0xff)]^xkey->s[3][((((A)) >> 8*(3)) & 0xff)]);
  T1 = (xkey->s[0][((((B)) >> 8*(3)) & 0xff)]^xkey->s[1][((((B)) >> 8*(0)) & 0xff)]^xkey->s[2][((((B)) >> 8*(1)) & 0xff)]^xkey->s[3][((((B)) >> 8*(2)) & 0xff)]);
  C ^= T0+T1+xkey->K[8+2*(2*(6))];
  C = ( ((C))<<(32-(1)) | (((C)) & ( (((uint32_t)2)<<31) - 1 )) >> (32-(32-(1))) );
  D = ( (D)<<(1) | ((D) & ( (((uint32_t)2)<<31) - 1 )) >> (32-(1)) );
  D ^= T0+2*T1+xkey->K[8+2*(2*(6))+1];
  T0 = (xkey->s[0][((((C)) >> 8*(0)) & 0xff)]^xkey->s[1][((((C)) >> 8*(1)) & 0xff)]^xkey->s[2][((((C)) >> 8*(2)) & 0xff)]^xkey->s[3][((((C)) >> 8*(3)) & 0xff)]);
  T1 = (xkey->s[0][((((D)) >> 8*(3)) & 0xff)]^xkey->s[1][((((D)) >> 8*(0)) & 0xff)]^xkey->s[2][((((D)) >> 8*(1)) & 0xff)]^xkey->s[3][((((D)) >> 8*(2)) & 0xff)]);
  A ^= T0+T1+xkey->K[8+2*(2*(6)+1)];
  A = ( ((A))<<(32-(1)) | (((A)) & ( (((uint32_t)2)<<31) - 1 )) >> (32-(32-(1))) );
  B = ( (B)<<(1) | ((B) & ( (((uint32_t)2)<<31) - 1 )) >> (32-(1)) );
  B ^= T0+2*T1+xkey->K[8+2*(2*(6)+1)+1];
  T0 = (xkey->s[0][((((A)) >> 8*(0)) & 0xff)]^xkey->s[1][((((A)) >> 8*(1)) & 0xff)]^xkey->s[2][((((A)) >> 8*(2)) & 0xff)]^xkey->s[3][((((A)) >> 8*(3)) & 0xff)]);
  T1 = (xkey->s[0][((((B)) >> 8*(3)) & 0xff)]^xkey->s[1][((((B)) >> 8*(0)) & 0xff)]^xkey->s[2][((((B)) >> 8*(1)) & 0xff)]^xkey->s[3][((((B)) >> 8*(2)) & 0xff)]);
  C ^= T0+T1+xkey->K[8+2*(2*(7))];
  C = ( ((C))<<(32-(1)) | (((C)) & ( (((uint32_t)2)<<31) - 1 )) >> (32-(32-(1))) );
  D = ( (D)<<(1) | ((D) & ( (((uint32_t)2)<<31) - 1 )) >> (32-(1)) );
  D ^= T0+2*T1+xkey->K[8+2*(2*(7))+1];
  T0 = (xkey->s[0][((((C)) >> 8*(0)) & 0xff)]^xkey->s[1][((((C)) >> 8*(1)) & 0xff)]^xkey->s[2][((((C)) >> 8*(2)) & 0xff)]^xkey->s[3][((((C)) >> 8*(3)) & 0xff)]);
  T1 = (xkey->s[0][((((D)) >> 8*(3)) & 0xff)]^xkey->s[1][((((D)) >> 8*(0)) & 0xff)]^xkey->s[2][((((D)) >> 8*(1)) & 0xff)]^xkey->s[3][((((D)) >> 8*(2)) & 0xff)]);
  A ^= T0+T1+xkey->K[8+2*(2*(7)+1)];
  A = ( ((A))<<(32-(1)) | (((A)) & ( (((uint32_t)2)<<31) - 1 )) >> (32-(32-(1))) );
  B = ( (B)<<(1) | ((B) & ( (((uint32_t)2)<<31) - 1 )) >> (32-(1)) );
  B ^= T0+2*T1+xkey->K[8+2*(2*(7)+1)+1];

  C ^= xkey->K[ 4];
  D ^= xkey->K[1+4];
  A ^= xkey->K[2+4];
  B ^= xkey->K[3+4];
  (c)[0] = (uint8_t)(((C) ) & 0xff);
  (c)[1] = (uint8_t)(((C) >> 8) & 0xff);
  (c)[2] = (uint8_t)(((C) >> 16) & 0xff);
  (c)[3] = (uint8_t)(((C) >> 24) & 0xff);
  (c+ 4)[0] = (uint8_t)(((D) ) & 0xff);
  (c+ 4)[1] = (uint8_t)(((D) >> 8) & 0xff);
  (c+ 4)[2] = (uint8_t)(((D) >> 16) & 0xff);
  (c+ 4)[3] = (uint8_t)(((D) >> 24) & 0xff);
  (c+8)[0] = (uint8_t)(((A) ) & 0xff);
  (c+8)[1] = (uint8_t)(((A) >> 8) & 0xff);
  (c+8)[2] = (uint8_t)(((A) >> 16) & 0xff);
  (c+8)[3] = (uint8_t)(((A) >> 24) & 0xff);
  (c+12)[0] = (uint8_t)(((B) ) & 0xff);
  (c+12)[1] = (uint8_t)(((B) >> 8) & 0xff);
  (c+12)[2] = (uint8_t)(((B) >> 16) & 0xff);
  (c+12)[3] = (uint8_t)(((B) >> 24) & 0xff);
EOS
# }}}

def rand_class_name
  loop do
    h = SecureRandom.hex(5)
    return h if h =~ /^[a-f]/
  end
end

class_names = Array.new(insts.size) { rand_class_name }
v = Array.new(insts.size + 1) { |i| i }.shuffle

all_classes = class_names.zip(insts).map.with_index { |(name, inst), idx|
  format(class_tpl, name: name, instruction: inst, next: v[idx + 1])
}
all_classes.shuffle!
init = class_names.map.with_index { |name, i| "arr[#{v[i]}] = new #{name};" }
init.shuffle!

# IO.binwrite('key', Array.new(5) { 64.times.map{ '0x' + SecureRandom.hex(4) + 'u' }.join(',') }.join("\n"))
key = IO.binread('key').lines

source = format(tpl,
                all_classes: all_classes.join("\n"),
                n: insts.size + 1,
                all_init: init.join("\n"),
                start: v[0],
                end: v[-1],
                key_k: key[0],
                key_s0: key[1],
                key_s1: key[2],
                key_s2: key[3],
                key_s3: key[4],
                ans: '4f6fa787e9518764382a46e54f219e1ccd65e19a4fcfde5209bf53c4b0957531ac2ff4971da59a02a8ffae2eb970cc02'.unhex.bytes.map{|v| '0x%02x' % v}.join(',')
               );
IO.binwrite('eop.cpp', source);

flag = %q[~Exc3p7i0n-Ori3n7ed-Pr0grammin9~RoO0cks!!\o^_^o/]
(p flag.size; fail) if flag.size != 48
IO.binwrite('flag', flag)

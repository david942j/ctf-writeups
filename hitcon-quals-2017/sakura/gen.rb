#!/usr/bin/env ruby
# encoding: ascii-8bit

brd1 = <<EOS.split.map(&:chars)
xxxxxxxxxx
xxxxxx92xx
x17x378192
x29618xx81
xx89x92xxx
xxx81x12xx
xxxx31x12x
x37xx29341
x192837x12
xxx19xxxxx
EOS

brd2 = <<EOS.split.map(&:chars)
xxxxxxxxxx
xx41xxxx91
xx638x4683
x71x9837xx
x936x915xx
x8216x2843
xxx498x931
xxx3792x62
x7128x172x
x92xxxx91x
EOS

brd3 = <<EOS.split.map(&:chars)
xxxxxxxxxx
xxxx14x65x
xx41835792
x125x13x73
x76x72x86x
xx948x512x
xx57x18x86
x48x49x538
x17863294x
xx31x74xxx
EOS

brd4 = <<EOS.split.map(&:chars)
xxxxxxxxxx
x63xxxxxxx
x82xxx52xx
xx1246735x
x96387xx17
x87xxxxx95
x25xx95634
xx4396128x
xxx25xxx68
xxxxxxxx76
EOS

brd5 = <<EOS.split.map(&:chars)
xxxxxxxxxx
xxx8172xxx
xxx7394xxx
x956xx16xx
x8739xx38x
xx847x186x
xx95xx2473
xxx98xx791
xxxx9215xx
xxxx7139xx
EOS

brd6 = <<EOS.split.map(&:chars)
xxxxxxxxxx
xx271x49xx
xx89641275
x91xx53x37
x86xxx26xx
xx53xxx36x
xxx52xxx51
x85x69xx85
x73615284x
xxx35x123x
EOS

def gen(brd)
  fail if brd.size != 10 || brd[0].size != 10
  res = []
  brd.size.times do |i|
    brd[0].size.times do |j|
      next if brd[i][j] != 'x'
      # row constraint
      if brd[i][j+1] && brd[i][j+1] != 'x'
        off = 1.step.find { |jj| brd[i][j + jj].nil? || brd[i][j + jj] == 'x' }
        entries = (1...off).map { |o| [i, j+o] }
        res << [entries.size, entries, entries.inject(0) { |s, (i,j)| s + brd[i][j].to_i }]
      end
      # column constraint
      if brd[i + 1] && brd[i + 1][j] != 'x'
        off = 1.step.find { |ii| brd[i + ii].nil? || brd[i + ii][j] == 'x' }
        entries = (1...off).map { |o| [i + o, j] }
        res << [entries.size, entries, entries.inject(0) { |s, (i,j)| s + brd[i][j].to_i }]
      end
    end
  end
  res
end

collect = []
[[brd1, 0, 0], [brd2, 0, 1], [brd3, 1, 0], [brd6, 1, 1]].each do |brd, dx, dy|
  collect.concat(gen(brd).map { |sz,entries,v| [sz, entries.map{|i, j| [i + dx * 10, j + dy * 10]}, v] })
end
gen(brd1)
gen(brd2)
gen(brd3)
gen(brd4)
gen(brd5)
gen(brd6)

z=[
  [brd1, brd2],
  [brd3, brd6]
]
big = Array.new(20){|i| Array.new(20) {|j|
 z[i/10][j/10][i%10][j%10] 
}}

def gen_source(collect)
  head = <<-EOS
#include <array>
#include <algorithm>
#include <unistd.h>
#include <cstring>
#include <openssl/sha.h>
using namespace std;
unsigned char memo[20][20];
bool check(char s[][20]) {
memset(memo, '0', sizeof(memo));
EOS
  str = StringIO.new
  str.puts(head)
  collect.each_with_index do |(n, entries, sum), idx|
    str.puts("array<pair<int,int>, #{n}> ary#{idx} = {");
    entries.each do |e|
      str.puts("  pair<int,int>({#{e[0]}, #{e[1]}}),")
    end
    str.puts("};")
  end
  str.puts("int sum;bool ok = true;int mask;")
  collect.each_with_index do |(n, entries, sum), idx|
    str.puts(<<-EOS)
        sum = 0;
        mask = 0;
        for(auto pr: ary#{idx}) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != #{sum}) ok = false;
    EOS
  end
  tail = <<-EOS
  return ok;
}
char s[20][20];
void sha() {
  unsigned char digest[SHA256_DIGEST_LENGTH];
  SHA256((unsigned char*)memo, sizeof(memo), digest);    
  for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    printf("%02x", (unsigned int)digest[i]);
}
int main() {
  for(int i=0;i<20;i++)
    read(0, s[i], 20);
  if(check(s)) {
    printf("hitcon{");
    sha();
    puts("}");
  }
  return 0;
}
  EOS
  str.puts(tail)
  str.string
end

fail if collect.map{|_,v,_|v}.flatten(1).group_by(&:itself).values.map(&:size).uniq != [2]

if ARGV.include?('--source')
  IO.binwrite('source.c', gen_source(collect))
  `g++ source.c -std=c++11 -o sakura -lcrypto && strip sakura`
end

if ARGV.include?('--sol')
  puts big.map(&:join).join("") # .gsub('x', ' ')
end
# p collect


# hitcon{6c0d62189adfd27a12289890d5b89c0dc8098bc976ecc3f6d61ec0429cccae61}

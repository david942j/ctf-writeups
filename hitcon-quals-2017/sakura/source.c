#include <array>
#include <algorithm>
#include <unistd.h>
#include <cstring>
#include <openssl/sha.h>
using namespace std;
unsigned char memo[20][20];
bool check(char s[][20]) {
memset(memo, '0', sizeof(memo));
array<pair<int,int>, 2> ary0 = {
  pair<int,int>({1, 6}),
  pair<int,int>({2, 6}),
};
array<pair<int,int>, 2> ary1 = {
  pair<int,int>({1, 7}),
  pair<int,int>({2, 7}),
};
array<pair<int,int>, 2> ary2 = {
  pair<int,int>({2, 1}),
  pair<int,int>({3, 1}),
};
array<pair<int,int>, 3> ary3 = {
  pair<int,int>({2, 2}),
  pair<int,int>({3, 2}),
  pair<int,int>({4, 2}),
};
array<pair<int,int>, 2> ary4 = {
  pair<int,int>({2, 4}),
  pair<int,int>({3, 4}),
};
array<pair<int,int>, 2> ary5 = {
  pair<int,int>({1, 6}),
  pair<int,int>({1, 7}),
};
array<pair<int,int>, 3> ary6 = {
  pair<int,int>({2, 5}),
  pair<int,int>({3, 5}),
  pair<int,int>({4, 5}),
};
array<pair<int,int>, 2> ary7 = {
  pair<int,int>({2, 8}),
  pair<int,int>({3, 8}),
};
array<pair<int,int>, 2> ary8 = {
  pair<int,int>({2, 9}),
  pair<int,int>({3, 9}),
};
array<pair<int,int>, 2> ary9 = {
  pair<int,int>({2, 1}),
  pair<int,int>({2, 2}),
};
array<pair<int,int>, 6> ary10 = {
  pair<int,int>({2, 4}),
  pair<int,int>({2, 5}),
  pair<int,int>({2, 6}),
  pair<int,int>({2, 7}),
  pair<int,int>({2, 8}),
  pair<int,int>({2, 9}),
};
array<pair<int,int>, 3> ary11 = {
  pair<int,int>({3, 3}),
  pair<int,int>({4, 3}),
  pair<int,int>({5, 3}),
};
array<pair<int,int>, 5> ary12 = {
  pair<int,int>({3, 1}),
  pair<int,int>({3, 2}),
  pair<int,int>({3, 3}),
  pair<int,int>({3, 4}),
  pair<int,int>({3, 5}),
};
array<pair<int,int>, 2> ary13 = {
  pair<int,int>({4, 6}),
  pair<int,int>({5, 6}),
};
array<pair<int,int>, 2> ary14 = {
  pair<int,int>({3, 8}),
  pair<int,int>({3, 9}),
};
array<pair<int,int>, 2> ary15 = {
  pair<int,int>({4, 2}),
  pair<int,int>({4, 3}),
};
array<pair<int,int>, 2> ary16 = {
  pair<int,int>({4, 5}),
  pair<int,int>({4, 6}),
};
array<pair<int,int>, 2> ary17 = {
  pair<int,int>({5, 4}),
  pair<int,int>({6, 4}),
};
array<pair<int,int>, 3> ary18 = {
  pair<int,int>({5, 7}),
  pair<int,int>({6, 7}),
  pair<int,int>({7, 7}),
};
array<pair<int,int>, 2> ary19 = {
  pair<int,int>({5, 3}),
  pair<int,int>({5, 4}),
};
array<pair<int,int>, 2> ary20 = {
  pair<int,int>({5, 6}),
  pair<int,int>({5, 7}),
};
array<pair<int,int>, 3> ary21 = {
  pair<int,int>({6, 5}),
  pair<int,int>({7, 5}),
  pair<int,int>({8, 5}),
};
array<pair<int,int>, 3> ary22 = {
  pair<int,int>({6, 8}),
  pair<int,int>({7, 8}),
  pair<int,int>({8, 8}),
};
array<pair<int,int>, 2> ary23 = {
  pair<int,int>({7, 1}),
  pair<int,int>({8, 1}),
};
array<pair<int,int>, 2> ary24 = {
  pair<int,int>({7, 2}),
  pair<int,int>({8, 2}),
};
array<pair<int,int>, 2> ary25 = {
  pair<int,int>({6, 4}),
  pair<int,int>({6, 5}),
};
array<pair<int,int>, 2> ary26 = {
  pair<int,int>({6, 7}),
  pair<int,int>({6, 8}),
};
array<pair<int,int>, 2> ary27 = {
  pair<int,int>({7, 6}),
  pair<int,int>({8, 6}),
};
array<pair<int,int>, 2> ary28 = {
  pair<int,int>({7, 9}),
  pair<int,int>({8, 9}),
};
array<pair<int,int>, 2> ary29 = {
  pair<int,int>({7, 1}),
  pair<int,int>({7, 2}),
};
array<pair<int,int>, 2> ary30 = {
  pair<int,int>({8, 3}),
  pair<int,int>({9, 3}),
};
array<pair<int,int>, 5> ary31 = {
  pair<int,int>({7, 5}),
  pair<int,int>({7, 6}),
  pair<int,int>({7, 7}),
  pair<int,int>({7, 8}),
  pair<int,int>({7, 9}),
};
array<pair<int,int>, 2> ary32 = {
  pair<int,int>({8, 4}),
  pair<int,int>({9, 4}),
};
array<pair<int,int>, 6> ary33 = {
  pair<int,int>({8, 1}),
  pair<int,int>({8, 2}),
  pair<int,int>({8, 3}),
  pair<int,int>({8, 4}),
  pair<int,int>({8, 5}),
  pair<int,int>({8, 6}),
};
array<pair<int,int>, 2> ary34 = {
  pair<int,int>({8, 8}),
  pair<int,int>({8, 9}),
};
array<pair<int,int>, 2> ary35 = {
  pair<int,int>({9, 3}),
  pair<int,int>({9, 4}),
};
array<pair<int,int>, 5> ary36 = {
  pair<int,int>({1, 12}),
  pair<int,int>({2, 12}),
  pair<int,int>({3, 12}),
  pair<int,int>({4, 12}),
  pair<int,int>({5, 12}),
};
array<pair<int,int>, 2> ary37 = {
  pair<int,int>({1, 13}),
  pair<int,int>({2, 13}),
};
array<pair<int,int>, 2> ary38 = {
  pair<int,int>({1, 18}),
  pair<int,int>({2, 18}),
};
array<pair<int,int>, 2> ary39 = {
  pair<int,int>({1, 19}),
  pair<int,int>({2, 19}),
};
array<pair<int,int>, 2> ary40 = {
  pair<int,int>({1, 12}),
  pair<int,int>({1, 13}),
};
array<pair<int,int>, 2> ary41 = {
  pair<int,int>({2, 14}),
  pair<int,int>({3, 14}),
};
array<pair<int,int>, 4> ary42 = {
  pair<int,int>({2, 16}),
  pair<int,int>({3, 16}),
  pair<int,int>({4, 16}),
  pair<int,int>({5, 16}),
};
array<pair<int,int>, 2> ary43 = {
  pair<int,int>({1, 18}),
  pair<int,int>({1, 19}),
};
array<pair<int,int>, 5> ary44 = {
  pair<int,int>({2, 17}),
  pair<int,int>({3, 17}),
  pair<int,int>({4, 17}),
  pair<int,int>({5, 17}),
  pair<int,int>({6, 17}),
};
array<pair<int,int>, 3> ary45 = {
  pair<int,int>({2, 12}),
  pair<int,int>({2, 13}),
  pair<int,int>({2, 14}),
};
array<pair<int,int>, 3> ary46 = {
  pair<int,int>({3, 11}),
  pair<int,int>({4, 11}),
  pair<int,int>({5, 11}),
};
array<pair<int,int>, 4> ary47 = {
  pair<int,int>({2, 16}),
  pair<int,int>({2, 17}),
  pair<int,int>({2, 18}),
  pair<int,int>({2, 19}),
};
array<pair<int,int>, 2> ary48 = {
  pair<int,int>({3, 15}),
  pair<int,int>({4, 15}),
};
array<pair<int,int>, 2> ary49 = {
  pair<int,int>({3, 11}),
  pair<int,int>({3, 12}),
};
array<pair<int,int>, 4> ary50 = {
  pair<int,int>({3, 14}),
  pair<int,int>({3, 15}),
  pair<int,int>({3, 16}),
  pair<int,int>({3, 17}),
};
array<pair<int,int>, 5> ary51 = {
  pair<int,int>({4, 13}),
  pair<int,int>({5, 13}),
  pair<int,int>({6, 13}),
  pair<int,int>({7, 13}),
  pair<int,int>({8, 13}),
};
array<pair<int,int>, 3> ary52 = {
  pair<int,int>({4, 11}),
  pair<int,int>({4, 12}),
  pair<int,int>({4, 13}),
};
array<pair<int,int>, 3> ary53 = {
  pair<int,int>({4, 15}),
  pair<int,int>({4, 16}),
  pair<int,int>({4, 17}),
};
array<pair<int,int>, 4> ary54 = {
  pair<int,int>({5, 14}),
  pair<int,int>({6, 14}),
  pair<int,int>({7, 14}),
  pair<int,int>({8, 14}),
};
array<pair<int,int>, 5> ary55 = {
  pair<int,int>({5, 18}),
  pair<int,int>({6, 18}),
  pair<int,int>({7, 18}),
  pair<int,int>({8, 18}),
  pair<int,int>({9, 18}),
};
array<pair<int,int>, 3> ary56 = {
  pair<int,int>({5, 19}),
  pair<int,int>({6, 19}),
  pair<int,int>({7, 19}),
};
array<pair<int,int>, 4> ary57 = {
  pair<int,int>({5, 11}),
  pair<int,int>({5, 12}),
  pair<int,int>({5, 13}),
  pair<int,int>({5, 14}),
};
array<pair<int,int>, 4> ary58 = {
  pair<int,int>({5, 16}),
  pair<int,int>({5, 17}),
  pair<int,int>({5, 18}),
  pair<int,int>({5, 19}),
};
array<pair<int,int>, 2> ary59 = {
  pair<int,int>({6, 15}),
  pair<int,int>({7, 15}),
};
array<pair<int,int>, 3> ary60 = {
  pair<int,int>({6, 13}),
  pair<int,int>({6, 14}),
  pair<int,int>({6, 15}),
};
array<pair<int,int>, 3> ary61 = {
  pair<int,int>({6, 17}),
  pair<int,int>({6, 18}),
  pair<int,int>({6, 19}),
};
array<pair<int,int>, 2> ary62 = {
  pair<int,int>({7, 16}),
  pair<int,int>({8, 16}),
};
array<pair<int,int>, 2> ary63 = {
  pair<int,int>({8, 11}),
  pair<int,int>({9, 11}),
};
array<pair<int,int>, 4> ary64 = {
  pair<int,int>({7, 13}),
  pair<int,int>({7, 14}),
  pair<int,int>({7, 15}),
  pair<int,int>({7, 16}),
};
array<pair<int,int>, 2> ary65 = {
  pair<int,int>({8, 12}),
  pair<int,int>({9, 12}),
};
array<pair<int,int>, 2> ary66 = {
  pair<int,int>({7, 18}),
  pair<int,int>({7, 19}),
};
array<pair<int,int>, 2> ary67 = {
  pair<int,int>({8, 17}),
  pair<int,int>({9, 17}),
};
array<pair<int,int>, 4> ary68 = {
  pair<int,int>({8, 11}),
  pair<int,int>({8, 12}),
  pair<int,int>({8, 13}),
  pair<int,int>({8, 14}),
};
array<pair<int,int>, 3> ary69 = {
  pair<int,int>({8, 16}),
  pair<int,int>({8, 17}),
  pair<int,int>({8, 18}),
};
array<pair<int,int>, 2> ary70 = {
  pair<int,int>({9, 11}),
  pair<int,int>({9, 12}),
};
array<pair<int,int>, 2> ary71 = {
  pair<int,int>({9, 17}),
  pair<int,int>({9, 18}),
};
array<pair<int,int>, 2> ary72 = {
  pair<int,int>({11, 4}),
  pair<int,int>({12, 4}),
};
array<pair<int,int>, 4> ary73 = {
  pair<int,int>({11, 5}),
  pair<int,int>({12, 5}),
  pair<int,int>({13, 5}),
  pair<int,int>({14, 5}),
};
array<pair<int,int>, 2> ary74 = {
  pair<int,int>({11, 7}),
  pair<int,int>({12, 7}),
};
array<pair<int,int>, 8> ary75 = {
  pair<int,int>({11, 8}),
  pair<int,int>({12, 8}),
  pair<int,int>({13, 8}),
  pair<int,int>({14, 8}),
  pair<int,int>({15, 8}),
  pair<int,int>({16, 8}),
  pair<int,int>({17, 8}),
  pair<int,int>({18, 8}),
};
array<pair<int,int>, 8> ary76 = {
  pair<int,int>({12, 2}),
  pair<int,int>({13, 2}),
  pair<int,int>({14, 2}),
  pair<int,int>({15, 2}),
  pair<int,int>({16, 2}),
  pair<int,int>({17, 2}),
  pair<int,int>({18, 2}),
  pair<int,int>({19, 2}),
};
array<pair<int,int>, 2> ary77 = {
  pair<int,int>({11, 4}),
  pair<int,int>({11, 5}),
};
array<pair<int,int>, 2> ary78 = {
  pair<int,int>({12, 3}),
  pair<int,int>({13, 3}),
};
array<pair<int,int>, 2> ary79 = {
  pair<int,int>({11, 7}),
  pair<int,int>({11, 8}),
};
array<pair<int,int>, 2> ary80 = {
  pair<int,int>({12, 6}),
  pair<int,int>({13, 6}),
};
array<pair<int,int>, 2> ary81 = {
  pair<int,int>({12, 9}),
  pair<int,int>({13, 9}),
};
array<pair<int,int>, 8> ary82 = {
  pair<int,int>({12, 2}),
  pair<int,int>({12, 3}),
  pair<int,int>({12, 4}),
  pair<int,int>({12, 5}),
  pair<int,int>({12, 6}),
  pair<int,int>({12, 7}),
  pair<int,int>({12, 8}),
  pair<int,int>({12, 9}),
};
array<pair<int,int>, 2> ary83 = {
  pair<int,int>({13, 1}),
  pair<int,int>({14, 1}),
};
array<pair<int,int>, 3> ary84 = {
  pair<int,int>({13, 1}),
  pair<int,int>({13, 2}),
  pair<int,int>({13, 3}),
};
array<pair<int,int>, 2> ary85 = {
  pair<int,int>({13, 5}),
  pair<int,int>({13, 6}),
};
array<pair<int,int>, 2> ary86 = {
  pair<int,int>({14, 4}),
  pair<int,int>({15, 4}),
};
array<pair<int,int>, 2> ary87 = {
  pair<int,int>({13, 8}),
  pair<int,int>({13, 9}),
};
array<pair<int,int>, 2> ary88 = {
  pair<int,int>({14, 7}),
  pair<int,int>({15, 7}),
};
array<pair<int,int>, 2> ary89 = {
  pair<int,int>({14, 1}),
  pair<int,int>({14, 2}),
};
array<pair<int,int>, 2> ary90 = {
  pair<int,int>({14, 4}),
  pair<int,int>({14, 5}),
};
array<pair<int,int>, 2> ary91 = {
  pair<int,int>({15, 3}),
  pair<int,int>({16, 3}),
};
array<pair<int,int>, 2> ary92 = {
  pair<int,int>({14, 7}),
  pair<int,int>({14, 8}),
};
array<pair<int,int>, 2> ary93 = {
  pair<int,int>({15, 6}),
  pair<int,int>({16, 6}),
};
array<pair<int,int>, 3> ary94 = {
  pair<int,int>({15, 2}),
  pair<int,int>({15, 3}),
  pair<int,int>({15, 4}),
};
array<pair<int,int>, 3> ary95 = {
  pair<int,int>({15, 6}),
  pair<int,int>({15, 7}),
  pair<int,int>({15, 8}),
};
array<pair<int,int>, 4> ary96 = {
  pair<int,int>({16, 5}),
  pair<int,int>({17, 5}),
  pair<int,int>({18, 5}),
  pair<int,int>({19, 5}),
};
array<pair<int,int>, 2> ary97 = {
  pair<int,int>({16, 9}),
  pair<int,int>({17, 9}),
};
array<pair<int,int>, 2> ary98 = {
  pair<int,int>({16, 2}),
  pair<int,int>({16, 3}),
};
array<pair<int,int>, 2> ary99 = {
  pair<int,int>({17, 1}),
  pair<int,int>({18, 1}),
};
array<pair<int,int>, 2> ary100 = {
  pair<int,int>({16, 5}),
  pair<int,int>({16, 6}),
};
array<pair<int,int>, 2> ary101 = {
  pair<int,int>({17, 4}),
  pair<int,int>({18, 4}),
};
array<pair<int,int>, 2> ary102 = {
  pair<int,int>({16, 8}),
  pair<int,int>({16, 9}),
};
array<pair<int,int>, 2> ary103 = {
  pair<int,int>({17, 7}),
  pair<int,int>({18, 7}),
};
array<pair<int,int>, 2> ary104 = {
  pair<int,int>({17, 1}),
  pair<int,int>({17, 2}),
};
array<pair<int,int>, 2> ary105 = {
  pair<int,int>({17, 4}),
  pair<int,int>({17, 5}),
};
array<pair<int,int>, 2> ary106 = {
  pair<int,int>({18, 3}),
  pair<int,int>({19, 3}),
};
array<pair<int,int>, 3> ary107 = {
  pair<int,int>({17, 7}),
  pair<int,int>({17, 8}),
  pair<int,int>({17, 9}),
};
array<pair<int,int>, 2> ary108 = {
  pair<int,int>({18, 6}),
  pair<int,int>({19, 6}),
};
array<pair<int,int>, 8> ary109 = {
  pair<int,int>({18, 1}),
  pair<int,int>({18, 2}),
  pair<int,int>({18, 3}),
  pair<int,int>({18, 4}),
  pair<int,int>({18, 5}),
  pair<int,int>({18, 6}),
  pair<int,int>({18, 7}),
  pair<int,int>({18, 8}),
};
array<pair<int,int>, 2> ary110 = {
  pair<int,int>({19, 2}),
  pair<int,int>({19, 3}),
};
array<pair<int,int>, 2> ary111 = {
  pair<int,int>({19, 5}),
  pair<int,int>({19, 6}),
};
array<pair<int,int>, 5> ary112 = {
  pair<int,int>({11, 12}),
  pair<int,int>({12, 12}),
  pair<int,int>({13, 12}),
  pair<int,int>({14, 12}),
  pair<int,int>({15, 12}),
};
array<pair<int,int>, 2> ary113 = {
  pair<int,int>({11, 13}),
  pair<int,int>({12, 13}),
};
array<pair<int,int>, 2> ary114 = {
  pair<int,int>({11, 14}),
  pair<int,int>({12, 14}),
};
array<pair<int,int>, 4> ary115 = {
  pair<int,int>({11, 16}),
  pair<int,int>({12, 16}),
  pair<int,int>({13, 16}),
  pair<int,int>({14, 16}),
};
array<pair<int,int>, 2> ary116 = {
  pair<int,int>({11, 17}),
  pair<int,int>({12, 17}),
};
array<pair<int,int>, 3> ary117 = {
  pair<int,int>({11, 12}),
  pair<int,int>({11, 13}),
  pair<int,int>({11, 14}),
};
array<pair<int,int>, 2> ary118 = {
  pair<int,int>({11, 16}),
  pair<int,int>({11, 17}),
};
array<pair<int,int>, 2> ary119 = {
  pair<int,int>({12, 15}),
  pair<int,int>({13, 15}),
};
array<pair<int,int>, 2> ary120 = {
  pair<int,int>({12, 18}),
  pair<int,int>({13, 18}),
};
array<pair<int,int>, 2> ary121 = {
  pair<int,int>({12, 19}),
  pair<int,int>({13, 19}),
};
array<pair<int,int>, 8> ary122 = {
  pair<int,int>({12, 12}),
  pair<int,int>({12, 13}),
  pair<int,int>({12, 14}),
  pair<int,int>({12, 15}),
  pair<int,int>({12, 16}),
  pair<int,int>({12, 17}),
  pair<int,int>({12, 18}),
  pair<int,int>({12, 19}),
};
array<pair<int,int>, 2> ary123 = {
  pair<int,int>({13, 11}),
  pair<int,int>({14, 11}),
};
array<pair<int,int>, 2> ary124 = {
  pair<int,int>({13, 11}),
  pair<int,int>({13, 12}),
};
array<pair<int,int>, 2> ary125 = {
  pair<int,int>({13, 15}),
  pair<int,int>({13, 16}),
};
array<pair<int,int>, 2> ary126 = {
  pair<int,int>({13, 18}),
  pair<int,int>({13, 19}),
};
array<pair<int,int>, 2> ary127 = {
  pair<int,int>({14, 17}),
  pair<int,int>({15, 17}),
};
array<pair<int,int>, 2> ary128 = {
  pair<int,int>({14, 11}),
  pair<int,int>({14, 12}),
};
array<pair<int,int>, 2> ary129 = {
  pair<int,int>({15, 13}),
  pair<int,int>({16, 13}),
};
array<pair<int,int>, 2> ary130 = {
  pair<int,int>({14, 16}),
  pair<int,int>({14, 17}),
};
array<pair<int,int>, 5> ary131 = {
  pair<int,int>({15, 18}),
  pair<int,int>({16, 18}),
  pair<int,int>({17, 18}),
  pair<int,int>({18, 18}),
  pair<int,int>({19, 18}),
};
array<pair<int,int>, 2> ary132 = {
  pair<int,int>({15, 12}),
  pair<int,int>({15, 13}),
};
array<pair<int,int>, 4> ary133 = {
  pair<int,int>({16, 14}),
  pair<int,int>({17, 14}),
  pair<int,int>({18, 14}),
  pair<int,int>({19, 14}),
};
array<pair<int,int>, 2> ary134 = {
  pair<int,int>({15, 17}),
  pair<int,int>({15, 18}),
};
array<pair<int,int>, 2> ary135 = {
  pair<int,int>({16, 19}),
  pair<int,int>({17, 19}),
};
array<pair<int,int>, 2> ary136 = {
  pair<int,int>({17, 11}),
  pair<int,int>({18, 11}),
};
array<pair<int,int>, 2> ary137 = {
  pair<int,int>({16, 13}),
  pair<int,int>({16, 14}),
};
array<pair<int,int>, 2> ary138 = {
  pair<int,int>({17, 12}),
  pair<int,int>({18, 12}),
};
array<pair<int,int>, 2> ary139 = {
  pair<int,int>({17, 15}),
  pair<int,int>({18, 15}),
};
array<pair<int,int>, 2> ary140 = {
  pair<int,int>({16, 18}),
  pair<int,int>({16, 19}),
};
array<pair<int,int>, 2> ary141 = {
  pair<int,int>({17, 11}),
  pair<int,int>({17, 12}),
};
array<pair<int,int>, 2> ary142 = {
  pair<int,int>({17, 14}),
  pair<int,int>({17, 15}),
};
array<pair<int,int>, 2> ary143 = {
  pair<int,int>({18, 13}),
  pair<int,int>({19, 13}),
};
array<pair<int,int>, 2> ary144 = {
  pair<int,int>({18, 16}),
  pair<int,int>({19, 16}),
};
array<pair<int,int>, 2> ary145 = {
  pair<int,int>({17, 18}),
  pair<int,int>({17, 19}),
};
array<pair<int,int>, 2> ary146 = {
  pair<int,int>({18, 17}),
  pair<int,int>({19, 17}),
};
array<pair<int,int>, 8> ary147 = {
  pair<int,int>({18, 11}),
  pair<int,int>({18, 12}),
  pair<int,int>({18, 13}),
  pair<int,int>({18, 14}),
  pair<int,int>({18, 15}),
  pair<int,int>({18, 16}),
  pair<int,int>({18, 17}),
  pair<int,int>({18, 18}),
};
array<pair<int,int>, 2> ary148 = {
  pair<int,int>({19, 13}),
  pair<int,int>({19, 14}),
};
array<pair<int,int>, 3> ary149 = {
  pair<int,int>({19, 16}),
  pair<int,int>({19, 17}),
  pair<int,int>({19, 18}),
};
int sum;bool ok = true;int mask;
        sum = 0;
        mask = 0;
        for(auto pr: ary0) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 17) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary1) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 3) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary2) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 3) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary3) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 24) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary4) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 4) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary5) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 11) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary6) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 24) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary7) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 17) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary8) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 3) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary9) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 8) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary10) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 30) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary11) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 23) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary12) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 26) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary13) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 3) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary14) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 9) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary15) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 17) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary16) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 11) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary17) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 4) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary18) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 6) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary19) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 9) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary20) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 3) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary21) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 6) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary22) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 7) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary23) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 4) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary24) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 16) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary25) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 4) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary26) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 3) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary27) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 16) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary28) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 3) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary29) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 10) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary30) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 3) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary31) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 19) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary32) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 17) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary33) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 30) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary34) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 3) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary35) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 10) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary36) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 16) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary37) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 4) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary38) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 17) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary39) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 4) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary40) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 5) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary41) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 17) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary42) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 10) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary43) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 10) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary44) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 35) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary45) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 17) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary46) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 24) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary47) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 21) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary48) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 17) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary49) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 8) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary50) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 27) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary51) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 16) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary52) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 18) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary53) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 15) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary54) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 30) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary55) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 16) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary56) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 6) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary57) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 17) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary58) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 17) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary59) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 17) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary60) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 21) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary61) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 13) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary62) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 3) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary63) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 16) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary64) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 21) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary65) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 3) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary66) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 8) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary67) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 16) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary68) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 18) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary69) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 10) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary70) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 11) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary71) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 10) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary72) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 9) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary73) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 10) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary74) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 13) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary75) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 44) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary76) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 44) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary77) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 5) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary78) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 6) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary79) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 11) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary80) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 8) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary81) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 5) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary82) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 39) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary83) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 8) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary84) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 8) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary85) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 4) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary86) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 15) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary87) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 10) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary88) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 9) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary89) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 13) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary90) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 9) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary91) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 11) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary92) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 14) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary93) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 13) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary94) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 21) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary95) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 8) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary96) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 20) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary97) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 14) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary98) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 12) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary99) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 5) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary100) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 9) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary101) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 10) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary102) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 14) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary103) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 14) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary104) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 12) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary105) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 13) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary106) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 9) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary107) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 16) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary108) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 6) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary109) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 40) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary110) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 4) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary111) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 11) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary112) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 22) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary113) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 16) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary114) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 7) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary115) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 10) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary116) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 11) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary117) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 10) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary118) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 13) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary119) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 9) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary120) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 10) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary121) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 12) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary122) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 42) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary123) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 17) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary124) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 10) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary125) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 8) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary126) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 10) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary127) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 9) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary128) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 14) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary129) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 8) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary130) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 8) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary131) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 26) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary132) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 8) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary133) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 14) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary134) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 9) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary135) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 6) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary136) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 15) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary137) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 7) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary138) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 8) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary139) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 14) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary140) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 6) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary141) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 13) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary142) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 15) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary143) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 9) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary144) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 3) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary145) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 13) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary146) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 10) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary147) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 36) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary148) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 8) ok = false;
        sum = 0;
        mask = 0;
        for(auto pr: ary149) {
          memo[pr.first][pr.second] = s[pr.first][pr.second];
          int v = s[pr.first][pr.second] - '0';
          if(v < 1 || v > 9) ok = false;
          if(mask & (1 << v)) ok = false;
          mask |= 1 << v;
          sum += v;
        }
        if(sum != 6) ok = false;
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

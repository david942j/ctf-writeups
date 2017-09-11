#!/usr/bin/env ruby
# encoding: ascii-8bit

N = 512
file = 'dump_y'
ystar = IO.binread(file).split.map(&:to_f)
e = []
N.times do |i|
  N.times do |j|
    e << ystar[i * N + j] if i + j >= N / 2
  end
end
280.upto(280) do |len|
  value = IO.binread("values/#{format('%02d', len)}.dump").split.map(&:to_i)
  result = ''
  0.upto(8 * len - 1) do |v|
    sym = [0] * v + value.dup + [0] * (len * 8 - 1 - v)
    result << (sym.zip(e[0, sym.size]).reduce(0.0) { |s, (a, b)| s + a * b } < 0 ? '0' : '1')
  end
  p result.scan(/.{8}/).map { |v| v.to_i(2) }.pack("C*")
end

# Dear CTFers, We are holding Tokyo Westerns CTF 3rd 2017 from September 2nd to September 4th. This is a security competition hosted by Tokyo Westerns. We would like to invite you to this CTF. P.S. This is my present for you. TWCTF{Spr34d_Sp3ctrum_1s_m0r3_u53fu1_f0r_st3g4n0gr4phy}.

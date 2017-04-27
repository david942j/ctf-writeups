#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pry'
require 'pwn'        # https://github.com/peter50216/ruby-pwntools

def dec
  require 'openssl'
  msg = '80dc59ce81e30bcd02198059b556731597ce5cf597481229ac9b2d523516c83e0f65896ce3b51cc2eb5b120adca55ed8'
  msg = [msg].pack("H*")
  cipher = OpenSSL::Cipher.new('AES-128-ECB').decrypt
  cipher.padding = 0
  cipher.key = "\xff" * 16
  msg_bob = cipher.update(msg) + cipher.final
#{{{
   measure = [-1, -1, 1, -1, 1, -1, 1, -1, -1, -1, 1, 1, -1, -1, 1, -1, -1, -1, -1, -1, -1, 1, -1, -1, -1, 1, 1, 1, -1, -1, -1, -1, -1, 1, -1, 1, 1, 1, -1, 1, -1, 1, -1, -1, -1, 1, -1, -1, -1, 1, -1, 1, -1, 1, -1, -1, -1, 1, 1, -1, 1, -1, 1, 1, 1, -1, -1, -1, -1, 1, 1, -1, 1, 1, -1, -1, -1, -1, 1, 1, -1, -1, 1, 1, -1, 1, 1, -1, 1, 1, -1, 1, -1, 1, 1, 1, -1, 1, 1, 1, -1, 1, -1, -1, 1, -1, 1, -1, 1, -1, -1, 1, -1, 1, 1, 1, 1, 1, -1, -1, 1, -1, 1, -1, 1, -1, -1, -1, -1, -1, 1, -1, -1, 1, 1, -1, 1, 1, 1, -1, 1, 1, 1, 1, 1, -1, 1, -1, 1, -1, -1, -1, -1, 1, 1, 1, -1, 1 , 1, -1, 1, 1, 1, 1, 1, -1, 1, -1, -1, 1, -1, 1, -1, -1, 1, 1, 1, -1, 1, 1, -1, -1, 1, 1, -1, 1, -1, 1, -1, -1, 1, 1, 1, -1, -1, 1, 1, -1, 1, 1, 1, 1, -1, -1, -1, 1, -1, -1, 1, -1, 1, -1, 1, -1, 1, 1, -1, 1, 1, -1, -1, -1, 1, -1, 1, 1, 1, 1, 1, -1, -1, 1, 1, 1, 1, -1, 1, -1, -1 , 1, -1, -1, 1, 1, -1, -1, 1, -1, -1, 1, -1, -1, 1, -1, -1, -1, 1, -1, -1, -1, 1, 1, 1, 1, 1, 1, -1, -1, 1, 1, -1, 1, 1, 1, 1, -1, -1, 1, 1 , 1, 1, -1, -1, 1, 1, -1, 1, 1, 1, -1, 1, 1, -1, 1, -1, -1, 1, -1, -1, -1, 1, 1, -1, -1, 1, 1, 1, 1, 1, 1, 1, -1, -1, 1, 1, 1, -1, 1, 1, -1 , 1, 1, 1, -1, -1, -1, -1, -1, -1, 1, 1, 1, 1, 1, -1, 1, 1, -1, 1, 1, -1, 1, 1, -1, 1, 1, -1, -1, 1, 1, -1, 1, -1, 1, -1, -1, -1, -1, 1, 1,   1, 1, -1, -1, -1, 1, 1, -1, -1, 1, 1, 1, -1, -1, -1, -1, -1, 1, 1, 1, -1, 1, -1, -1, -1, -1, 1, 1, -1, 1, -1, 1, -1, -1, 1, -1, 1, 1, 1, -1, -1, 1, 1, 1, -1, 1, 1, -1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, 1, 1, -1, 1, 1, -1, 1, -1, -1, -1, -1, -1, 1, 1, -1, 1, 1, 1, 1, 1, 1, -1 , -1, -1, -1, 1, -1, 1, -1, -1, 1, -1, 1, -1, -1, 1, -1, 1, -1, 1, 1, 1, 1, -1, -1, 1, -1, -1, 1, 1, 1, -1, 1, 1, -1, -1, -1, -1, 1, 1, 1,  1, 1, 1, -1, 1, 1, 1, 1, -1, 1, 1, -1, 1, -1, 1, 1, 1, -1, -1, 1, 1, -1, 1, 1, 1, -1, -1, -1, -1, 1, 1, 1, -1, 1, 1, -1, 1, 1, -1, 1, -1, 1 , -1, -1, 1, -1, -1, 1, -1, -1, -1, -1, 1, -1, -1, 1, 1, 1, 1, 1, -1, 1, -1, -1, -1, -1, -1, 1, 1, -1, 1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 1, -1, 1, -1, -1, 1, 1, -1, 1, -1, 1, 1, 1, 1, 1, -1, -1, -1, -1, 1, 1, 1, 1, -1, -1, 1, -1, 1, 1, 1, 1, 1, -1, -1, 1, -1, -1, 1 , -1]
  alice_in_z=[0, 2, 6, 7, 9, 13, 17, 18, 19, 20, 21, 22, 24, 25, 26, 27, 28, 31, 36, 38, 40, 42, 43, 44, 46, 47, 50, 51, 55, 61, 62, 64, 66, 67, 68, 71, 72, 76, 80, 81, 83, 85, 89, 90, 93, 94, 95, 96, 98, 100, 101, 102, 105, 106, 107, 109, 110, 112, 124, 131, 132, 134, 136, 138, 139, 140, 142, 144, 145, 146, 147, 148, 149, 150, 153, 156, 158, 159, 162, 165, 168, 169, 172, 173, 175, 176, 177, 178, 183, 184, 187, 188, 189, 190, 191, 192, 193, 196, 197, 198, 200, 201, 202, 205, 206, 208, 210, 214, 215, 217, 218, 220, 221, 225, 226, 227, 237, 238, 239, 241, 246, 247,  248, 249, 252, 257, 259, 260, 261, 265, 267, 268, 269, 275, 276, 279, 280, 281, 282, 283, 286, 287, 289, 290, 291, 295, 296, 297, 298, 299, 300, 301, 302, 305, 310, 311, 312, 314, 315, 316, 319, 320, 322, 325, 326, 327, 328, 333, 335, 337, 338, 341, 342, 345, 350, 351, 352, 353, 358, 359, 361, 367, 368, 370, 372, 373, 374, 379, 381, 383, 384, 385, 390, 392, 393, 395, 396, 400, 402, 405, 406, 408, 411, 412, 414, 416, 417, 419, 420, 421, 423, 427, 428, 430, 432, 433, 434, 435, 436, 437, 438, 439, 440, 441, 442, 447, 451, 455, 456, 458, 459, 461, 462, 463, 465, 466, 469, 470, 471, 476, 481, 483, 484, 485, 487, 488, 491, 493, 494, 495, 500, 506, 507, 511, 515, 516, 518, 521, 522, 525, 527,  528, 530, 531, 533, 535, 537, 539, 540, 542, 548, 551, 555, 557, 563, 568, 570, 574, 577, 580, 584, 585, 586, 590, 592, 596, 599]
  #}}}
  p alice_in_z.size
  key = 128.times.map {|i| measure[alice_in_z[i*2+1]] == -1 ? 0 : 1}.join.scan(/.{8}/).map{|c|c.to_i(2).chr}.join
  msg = ['45b676f199a669b5fbc426f3d2d17fc2cc257d76f0bd1a9496809522f3611533'].pack("H*")
  cipher = OpenSSL::Cipher.new('AES-128-ECB').decrypt
  cipher.padding = 0
  cipher.key = key
  puts cipher.update(msg).strip + msg_bob
  exit
end
dec

host, port = 'bb8.chal.pwning.xxx', 20811
@local = false
if ARGV.empty?
  host = '127.0.0.1'; @local = true
else
  raise ArgumentError, 'host not set' if host.empty?
end
$z = Sock.new host, port
def z;$z;end
#================= Exploit Start ====================
z.recvuntil("We've provided you all the tools we can.. good luck...\n")

# mitm 600 qubits
N = 600
measure_from_alice = Array.new(N)


N.times do |i|
  # alice -> bob
  # z.recvuntil('There is a qubit on the line going to Bob, do you want to intercept (y/N)?')
  z.puts 'y'
  z.puts 'Z'
  # z.recvuntil('OK, measured ')
  # measure_from_alice[i] = z.gets.to_i
  # z.recvuntil('Shall we pass this along (N) or replace it (Y)?')
  z.puts 'Y'
  # eve -> bob All Z1
  # z.recvuntil 'In what basis should the new qubit be prepared? (Z/Y)'
  z.puts 'Z'
  # z.recvuntil('OK, using the Z basis... what should the value be? (-1/1)')
  z.puts '1'
  unless i == N - 1 # no ACK in last round
    # bob -> alice (ACK)
    # z.recvuntil('There is a qubit on the line going to Alice, do you want to intercept (y/N)?')
    z.puts 'n'
  end
end
600.times do |i|
  z.recvuntil('OK, measured ')
  measure_from_alice[i] = z.gets.to_i
end
p measure_from_alice

require 'ruby-progressbar'
pg = ProgressBar.create(title: 'Guess Phase', total: 600)
alice_in_z = []
bob_thought = []
# Guess phase
600.times do |i|
  # bob -> alice
  z.puts 'y'
  z.puts 'Z' # measure Z 
  z.puts 'Y'
  # eve -> alice All guess as Z
  z.puts 'Z'
  z.puts '-1'

  z.recvuntil('OK, measured ') # what bob guessed?
  guess = (z.gets.to_i == -1) # -1 for Z
  bob_thought << i if guess
  # alice's response of guess
  z.puts 'y'
  z.puts 'Z'
  z.recvuntil('OK, measured ')
  alice_in_z << i if (z.gets.to_i == 1) # guess of Z is correct
  z.puts 'Y'
  # eve -> bob
  z.puts 'Z'
  z.puts (guess ? '1' : '-1')
  pg.increment
end

p bob_thought
p alice_in_z

p 'size of bob thought: %d' % bob_thought.size
p 'size of alice_in_z: %d' % alice_in_z.size
# want alice_in_z >= bob_thought
fail if (bob_thought.size-1) / 2 * 2 != (alice_in_z.size-1) / 2 * 2
0.step(bob_thought.size - 1, 2) do |i|
  # bob -> eve  bob_thought[i]
  z.puts 'y'
  # don't check if bob thought is correct..
  z.puts 'Z'
  z.puts 'Y'
  # eve -> alice
  v = measure_from_alice[alice_in_z[i]]
  z.puts 'Z'
  z.puts v.to_s

  # alice -> bob
  z.puts 'n'
end

z.interact

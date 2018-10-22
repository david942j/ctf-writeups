#!/usr/bin/env ruby
# encoding: ascii-8bit
require 'pwn'        # https://github.com/peter50216/pwntools-ruby
require './twofish'

# key = "\x87\x90\xA5\xF8,,r\xCD\xC7\xD9G-\xEA}a\xE6"

tf = Twofish.new(iv: "\x00" * 16)
ciphertext = '4f6fa787e9518764382a46e54f219e1ccd65e19a4fcfde5209bf53c4b0957531ac2ff4971da59a02a8ffae2eb970cc02'.unhex
plain = tf.decrypt(ciphertext)
puts "hitcon{#{plain}}"

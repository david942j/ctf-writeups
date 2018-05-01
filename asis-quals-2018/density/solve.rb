#!/usr/bin/env ruby
# encoding: ascii-8bit

require 'base64'

data = IO.binread('short_adff30bd9894908ee5730266025ffd3787042046dd30b61a78e6cc9cadd72191')
puts Base64.strict_encode64(data)
  .gsub('++e', '{')
  .gsub('+d', '}')
  .gsub('+c', '_')

# ASIS{01d_4Nd_GoLD_ASIS_1De4_4H4t_g0e5_f0r_ls}

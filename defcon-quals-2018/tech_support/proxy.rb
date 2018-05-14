#!/usr/bin/env ruby
require 'socket'

if ARGV.length < 1
  $stderr.puts "Usage: #{$0} remoteHost:remotePort [ localPort [ localHost ] ]"
  exit 1
end
 
$remoteHost, $remotePort = ARGV.shift.split(":")
puts "target address: #{$remoteHost}:#{$remotePort}"
localPort = ARGV.shift || $remotePort
localHost = ARGV.shift
 
$blockSize = 1024
 
server = TCPServer.open(localHost, localPort)
 
port = server.addr[1]
addrs = server.addr[2..-1].uniq
 
puts "*** listening on #{addrs.collect{|a|"#{a}:#{port}"}.join(' ')}"
 
# abort on exceptions, otherwise threads will be silently killed in case
# of unhandled exceptions
Thread.abort_on_exception = true
 
# have a thread just to process Ctrl-C events on Windows
# (although Ctrl-Break always works)
Thread.new { loop { sleep 1 } }

def blacklist(s)
  if s[8] && !([2, 3, 5].include?(s[8].ord))
    puts "\e[1;32mignore #{s[8].ord}\e[0m"
    return true
  end
  IO.read('black').split.each do |w|
    if s[Regexp.new(w, 'n')]
      puts "\e[1;32mblack #{w}\e[0m"
      return true
    end
  end
  false
end
 
def connThread(local)
  port, name = local.peeraddr[1..2]
  puts "*** receiving from #{name}:#{port}"
 
  # open connection to remote server
  remote = TCPSocket.new($remoteHost, $remotePort)
   
  # start reading from both ends
  loop do
    ready = select([local, remote], nil, nil)
    if ready[0].include? local
      # local -> remote
      data = local.recv($blockSize)
      # data = data[1..-1] if @trim && data[0, 2] == '+$'
      @trim = true if data == "+$QStartNoAckMode#b0"
      @b1 = true if data == "+$Z0,401745,1#48"
      s = "send #{data.inspect}"
      puts s
      open('proxy.log', 'a'){|f| f.puts s}
      exit if !ARGV.include?('safe') && !data.start_with?('+$qSupported:multiprocess+;swbreak+;hw') &&
        data != '+$vMustReplyEmpty#3a' &&
        data != '+$QStartNoAckMode#b0' &&
        data != '+$?#3f' &&
        data != '+$qXfer:threads:read::0,fff#03' &&
        data != '+$qXfer:exec-file:read:19ef:0,fff#bf' &&
        !data.start_with?('+$vFile:open:6d') &&
        !data.start_with?('+$vFile:pread') &&
        !data.start_with?('+$Z0,') &&
        data != '+$c#63' &&
        data != '' &&
        !data.start_with?('+$z0,') &&
        data != '+$g#67' &&
        !data.start_with?('+$vKill') &&
        !data.start_with?('+$m7fffff') &&
        !data.start_with?('+$mdeadbeef,')
      if data.empty?
        puts "local end closed connection"
        break
      end
      remote.write(data)
    end
    if ready[0].include? remote
      # remote -> local
      data = remote.recv($blockSize)
      if data.start_with?('$60ba4efa0')
        puts 'hook!!!!!'
        data = "$f4bf96b0*5150**32c7cb680*\"00d03360*)e1f*\"7f0* a0e1f*\"7f0* 60e1f*\"7f0*\"37fff7ff7f0*!10**6c040*(a0aeb5f7ff7f0* 200740*'60e4f*\"7f0*@451740*'46020* 330*\"2b0*}0*}0* 7f030*(f* 0*H414141414141414141414141414141410*Nf**0*}0*;414141414141414141414141414141410*}0*}0*Z801f0* f*,0037fff7ff7f0*}0*}0*}0*}0*}0*K#f9"
      end
      s = "recv #{data.inspect}"
      puts s
      open('proxy.log', 'a'){|f| f.puts s}
      if data.empty?
        puts "remote end closed connection"
        break
      end
      local.write(data)
    end
  end
   
  local.close
  remote.close
   
  puts "*** done with #{name}:#{port}"
end
 
loop do
  Thread.start(server.accept) { |local| connThread(local) }
end

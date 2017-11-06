all: source
source: source.c
	cc source.c -o source
patch: patch.rb
	./patch.rb source
	mv source.patch void
test: patch.rb
	cat flag | ./patched
	ruby -e 'puts "h"*30' | ./patched
	ruby -e 'puts "z"*30' | ./patched

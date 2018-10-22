all: eop

eop: gen.rb
	env ruby gen.rb
	g++ -std=c++11 eop.cpp -o eop -Wall
	strip eop

test: eop
	./eop < flag

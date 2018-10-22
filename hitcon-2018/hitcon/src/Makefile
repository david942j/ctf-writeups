all: hitcon

hitcon: hitcon.cpp
	g++ -o hitcon hitcon.cpp -lpthread

release: hitcon
	mv hitcon ../release
	cp papers.txt ../release
	cp /lib/x86_64-linux-gnu/libc.so.6 ../release

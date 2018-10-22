all: groot

CFLAGS := -O2 -std=c++11 -Wall -Wl,-z,relro,-z,now
groot: groot.cpp
	g++ groot.cpp $(CFLAGS) -o groot
	strip groot
debug: groot.cpp
	g++ groot.cpp $(CFLAGS) -DDEBUG -o groot -g

release: groot
	mv groot ../release/

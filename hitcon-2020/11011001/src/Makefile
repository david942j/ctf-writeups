all: chal

chal: chal.cpp
	$(CXX) -o $@ $^ -O3 -lssl -lcrypto
	strip -s $@

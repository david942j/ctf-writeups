all: exp

exp: exp.c
	$(CC) -o exp -static exp.c -I../src/linux/include/uapi/ -lpthread
	strip -s exp

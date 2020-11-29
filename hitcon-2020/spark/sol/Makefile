all: exp

exp: exp.c
	$(CC) -o exp -static exp.c -I../src/linux/include/uapi/ -lpthread -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast
	strip -s exp

all: vuln backdoor run_exploit

vuln: vuln.c
	$(CC) -o vuln vuln.c -fno-stack-protector -Wl,-z,execstack
	strip -s vuln

backdoor: backdoor.c
	diet $(CC) -o backdoor backdoor.c -static
	ruby -e "s=IO.binread('backdoor');s[0x18d+1]=(0x0e-5).chr;IO.binwrite('backdoor', s)"
	strip -s backdoor

run_exploit: run_exploit.c
	$(CC) -o $@ $^ -Os
	strip -s $@

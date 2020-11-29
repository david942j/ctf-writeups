all: release

release: src
	mkdir -p release/chal
	cp src/exploit.py release/
	cp src/vuln.c release/chal/
	cp src/vuln release/chal/
	cp src/backdoor.c release/
	cp src/backdoor release/
	tar cvzf revenge_of_pwn.tar.gz release/

src: .PHONY
	$(MAKE) -C src/

clean: .PHONY
	$(RM) -r release/chal release/backdoor release/backdoor.c release/exploit.py \
		src/vuln src/backdoor src/run_exploit

.PHONY:

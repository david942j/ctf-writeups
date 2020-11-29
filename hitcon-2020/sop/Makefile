all: src release

src: .PHONY
	$(MAKE) -C src

sol: .PHONY
	$(MAKE) -C sol

release: src .PHONY
	mkdir -p release
	cp src/sop release/
	cp src/sop_bytecode release/
	tar cvzf sop.tar.gz release/
	rm -rf release/

clean: .PHONY
	$(RM) src/sop src/sop_bytecode sol/decrypt

.PHONY:

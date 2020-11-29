PARENT := time_machine

all: release

src: .PHONY
	$(MAKE) -C src/

release: src .PHONY
	mkdir -p release/
	cp src/$(PARENT) release/
	cp src/server.rb release/
	tar cvzf tenet.tar.gz release/

sol: release .PHONY
	sol/gen.rb | release/server.rb

clean:
	$(RM) -r release src/$(PARENT)

.PHONY:

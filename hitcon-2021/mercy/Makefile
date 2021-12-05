CC=cLEMENCy/neat/neatcc/ncc
LD=cLEMENCy/neat/neatld/nld
LIBC=cLEMENCy/neat/neatlibc
BIN=mercy

all: $(BIN)

$(BIN): src/$(BIN).c
	$(CC) -I$(LIBC) src/$(BIN).c -o $(BIN).o
	$(LD) -f -o release/$(BIN).bin -L $(LIBC) -lc src/$(BIN).o
	chmod -x release/$(BIN).bin
	$(RM) release/*.map src/*.o

run: $(BIN)
	cLEMENCy/cLEMENCy-emu/clemency-emu-debug-team release/$(BIN).bin -L 4000 &
	python2 cLEMENCy/cLEMENCy-emu/connect.py

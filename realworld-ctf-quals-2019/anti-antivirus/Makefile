# Add -DNEEDS_STRCHRNUL to end of CFLAGS if necessary
CFLAGS	= -ggdb3 -O0 -march=native -std=gnu99 -Wall
LDFLAGS	= $(CFLAGS)
LDLIBS = -lz
RARAS	= ./rarvmtools/raras
RARLD	= ./rarvmtools/rarld

%.ri: %.rs
	cpp -Irarvmtools/stdlib < $< > $@

%.ro: %.ri
	$(RARAS) -o $@ $<

%.rar: %.ro
	$(RARLD) $< > $@

all:   exp.rar

all: cord_exp tpu_exp

cord_exp: cord_exp.c
	$(CC) -o cord_exp -static cord_exp.c
	strip cord_exp
tpu_exp: tpu_exp.c
	$(CXX) -o tpu_exp -static tpu_exp.c
	strip tpu_exp

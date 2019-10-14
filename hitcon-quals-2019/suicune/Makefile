release: build fast
	src/fast $(FLAG) $(KEY) > release/output

BUILD_FLAGS := --progress --release --no-debug

build: src/suicune.cr
	crystal build $(BUILD_FLAGS) -o release/suicune src/suicune.cr

fast: src/fast.cr
	crystal build $(BUILD_FLAGS) -o src/fast src/fast.cr

solution: sol/solve.cr
	crystal build $(BUILD_FLAGS) -o sol/solve sol/solve.cr
	time sol/solve < release/output

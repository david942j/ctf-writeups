all: test_ioctl run_tests

test_ioctl: test_ioctl.c
	$(CXX) test_ioctl.c -o test_ioctl -I../src/linux/include/uapi/ -static

run_tests: run_tests.c
	$(CXX) run_tests.c -o run_tests -static

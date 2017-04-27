#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

int width, height;
char *buf;

void plot(int x, int y, char c);
void draw();

int main() {
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
	alarm(100);
	puts("Let's draw a picture!");
	fputs("How big? ", stdout);
	scanf(" %d x %d", &width, &height);
	buf = calloc(width, height);
	if(buf == NULL) {
		perror("malloc");
		return -1;
	}
	char c;
	while(1) {
		fputs("> ", stdout);
		int x, y;
		if(scanf(" %d , %d , %c", &x, &y, &c) != 3)
			break;
		plot(x, y, c);
	}
	if(scanf(" quit%c", &c) != 1)
		draw();
	puts("Bye!");
	free(buf);
	return 0;
}

char *get(size_t x, size_t y) {
	return &buf[x * height + y];
}

void plot(int x, int y, char c) {
	if(x >= width || y >= height) {
		puts("out of bounds!");
		return;
	}
	char *ptr = get(x, y);
	if(*ptr != 0)
		printf("overwriting %c!\n", *ptr);
	else
		*ptr = c;
}

void draw() {
	int x, y;
	char c;
	for(y = height-1; y >= 0; y--) {
		for(x = 0; x < width; x++) {
			c = *get(x, y);
			if(c == 0)
				c = ' ';
			if(putchar(c) != c)
				return;
		}
		putchar('\n');
	}
}

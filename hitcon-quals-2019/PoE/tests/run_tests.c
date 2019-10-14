#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char s[4096];

pid_t pcreate(int fds[2], const char *cmd) {
  /* Spawn a process from pfunc, returning it's pid. The fds array passed will
   * be filled with two descriptors: fds[0] will read from the child process,
   * and fds[1] will write to it.
   * Similarly, the child process will receive a reading/writing fd set (in
   * that same order) as arguments.
   */
  pid_t pid;
  int pipes[4];

  pipe(&pipes[0]);
  pipe(&pipes[2]);

  if ((pid = fork()) > 0) {
    fds[0] = pipes[0];
    fds[1] = pipes[3];
    close(pipes[1]);
    close(pipes[2]);
    return pid;

  } else {
    close(pipes[0]);
    close(pipes[3]);

    dup2(pipes[2], 0);
    dup2(pipes[1], 1);
    execl("/bin/sh", "sh", "-c", cmd, NULL);

    err(2, "execl");
  }
}

FILE *eout;
bool check = false;
int cur_line = 1;
int error_cnt = 0;

void readuntilprompt(FILE *po) {
  bool stop = false;
  static char buf[4096];
  while (1) {
    if (!fgets(s, sizeof(s), po))
      err(1, "Process reach EOF");
    if (strcmp(s, "-------------------\n") == 0)
      stop = true;
    else if (!stop && check) {
      if (!fgets(buf, sizeof(buf), eout)) {
	fprintf(stderr, "Warning: eout reaches EOF\n");
	buf[0] = 0;
      }
      if (strcmp(buf, s) != 0) {
	fprintf(stderr, "Mismatch at line %d!\nExpected: \"%s\"\nOutput: \"%s\"", cur_line, buf, s);
	error_cnt++;
      }
      cur_line++;
    }
    /* fprintf(stderr, "[I] %s", s); */
    if (strcmp(s, "[q]uit\n") == 0) {
      s[fread(s, 1, strlen(">>> "), po)] = 0;
      /* fprintf(stderr, "[I] %s", s); */
      break;
    }
  }
}

int main(int argc, char *argv[]) {
  if (argc != 4) {
    fprintf(stderr, "Usage: %s <program> <in> <expected_out>\n", argv[0]);
    return 1;
  }
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  int fds[2];
  pid_t pid = pcreate(fds, argv[1]);
  if (pid == -1)
    err(1, "pcreate");
  FILE *in = fopen(argv[2], "r");
  if (!in)
    err(1, "fopen %s", argv[2]);
  eout = fopen(argv[3], "r");
  if (!eout)
    err(1, "fopen %s", argv[3]);
  FILE *po = fdopen(fds[0], "r");
  if (!po)
    err(1, "fdopen %d\n", fds[0]);
  FILE *pi = fdopen(fds[1], "w");
  if (!pi)
    err(1, "fdopen %d\n", fds[1]);
  readuntilprompt(po);
  check = true;
  while (fgets(s, sizeof(s), in)) {
    int n = strlen(s);
    if (fwrite(s, 1, n, pi) != n)
      err(1, "fwrite");
    fflush(pi);
    readuntilprompt(po);
  }

  fclose(pi);
  fclose(po);
  fclose(in);
  fclose(eout);
  if (error_cnt == 0)
    puts("All passed!");
  else
    printf("%d lines different\n", error_cnt);

  return 0;
}

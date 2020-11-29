#include <err.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

/* #define debug(...) fprintf(stderr, __VA_ARGS__) */

#ifndef debug
#define debug(...)
#endif

#define PTRACE(r, p, a, d) do { if (ptrace(r, p, a, d) != 0) err(1, "ptrace"); } while (0)

#define LIMIT 4096

#define SC (0xdead0000u + 0x80)
#define COOKIE_AT 0x2170000u

static pid_t pid;
static int steps = 0;
static unsigned long long record[LIMIT];

static unsigned long long cookie;

static void clear_cookie_at() {
  for (size_t at = COOKIE_AT; at < COOKIE_AT + 0x1000; at += 8)
    PTRACE(PTRACE_POKEDATA, pid, at, 0);
}

static void clear_regs() {
  struct user_regs_struct regs = {
    .rip = SC,
    .cs = 0x33,
    .ss = 0x2b,
  };
  PTRACE(PTRACE_SETREGS, pid, NULL, &regs);
  struct user_fpregs_struct fregs = {};
  PTRACE(PTRACE_SETFPREGS, pid, NULL, &fregs);
}

static void kill_wait_exit() {
  kill(pid, SIGKILL);
  wait(NULL);
  _exit(1);
}

static void fail(const char *msg) {
  printf("Failed - %s\n", msg);
  kill_wait_exit();
}

static void error(const char *msg) {
  printf("%s failed - contact admin\n", msg);
  kill_wait_exit();
}

static void inverse() {
  clear_regs();
  for (int i = steps - 1; i >= 0; i--) {
    struct user_regs_struct regs;
    PTRACE(PTRACE_GETREGS, pid, NULL, &regs);
    regs.rip = record[i];
    PTRACE(PTRACE_SETREGS, pid, NULL, &regs);
    PTRACE(PTRACE_SINGLESTEP, pid, 0, 0);

    int status = 0;
    int res = wait(&status);
    if (WIFEXITED(status)) {
      puts("exit too early..");
      _exit(1);
    }
    int sig = WSTOPSIG(status);
    if (sig != SIGTRAP)
      fail("Child dead..");
  }
}

static unsigned long long getpc() {
  struct user_regs_struct regs;
  PTRACE(PTRACE_GETREGS, pid, NULL, &regs);
  return regs.rip;
}

static bool is_syscall(unsigned long long *rax) {
  struct user_regs_struct regs;
  PTRACE(PTRACE_GETREGS, pid, NULL, &regs);
  long ins = ptrace(PTRACE_PEEKDATA, pid, regs.rip, NULL);
  if ((ins & 0xffff) != 0x050f && (ins & 0xffff) != 0x340f)
    return false;
  *rax = regs.rax;
  return true;
}

static bool seg_changed() {
  struct user_regs_struct regs;
  PTRACE(PTRACE_GETREGS, pid, NULL, &regs);
  return regs.cs != 0x33 || regs.ss != 0x2b;
}

static void skip(unsigned long long step) {
  struct user_regs_struct regs;
  PTRACE(PTRACE_GETREGS, pid, NULL, &regs);
  regs.rip += step;
  PTRACE(PTRACE_SETREGS, pid, NULL, &regs);
}

static void put_cookie() {
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0)
    error("open urandom");
  if (sizeof(cookie) != read(fd, &cookie, sizeof(cookie)))
    error("read urandom");
  PTRACE(PTRACE_POKEDATA, pid, COOKIE_AT, cookie);
  debug("Put cookie 0x%016lx\n", cookie);
}

static bool check_cookie_gone() {
  unsigned long long val = 0;
  for (size_t at = COOKIE_AT; at < COOKIE_AT + 0x1000; at += 8)
    val |= ptrace(PTRACE_PEEKDATA, pid, at, NULL);
  debug("Cookie after forwards: 0x%llx\n", val);
  return val == 0;
}

static bool check_cookie_back() {
  unsigned long long val = ptrace(PTRACE_PEEKDATA, pid, COOKIE_AT, NULL);
  debug("Cookie after backwards: 0x%016lx\n", val);
  return val == cookie;
}

static bool success() {
  puts("Perfect.");
  system("cat flag");
}

static void check_maps() {
#if 0
  char buf[30];
  sprintf(buf, "cat /proc/%u/maps", pid);
  system(buf);

  struct user_regs_struct regs;
  PTRACE(PTRACE_GETREGS, pid, NULL, &regs);
  debug("RSP = %#llx\n", regs.rsp);
#endif
}

// returns true if the program calls SYS_exit
static bool check_state() {
  unsigned long long rax;

  while (is_syscall(&rax)) {
    if (rax == 60) return true;
    skip(2);
  }
  if (seg_changed()) { fail("NO."); }
  return false;
}

int main(int argc, char *argv[]) {
  if (argc != 2)
    exit(2);
  setbuf(stdout, NULL);
  pid = fork();
  if (pid == 0) {
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    execve(argv[1], NULL, NULL);
    error("execve");
  }
  PTRACE(PTRACE_ATTACH, pid, NULL, NULL);
  int status = 0;
  int res = waitpid(pid, &status, WUNTRACED);
  if (res != pid || !WIFSTOPPED(status))
    error("the first wait");

  bool start = false, end = false;
  while (true) {
    PTRACE(PTRACE_SINGLESTEP, pid, 0, 0);

    res = wait(&status);
    // should never happen..
    if (WIFEXITED(status))
      break;
    int sig = WSTOPSIG(status);
    if (sig != SIGTRAP) {
      debug("child got unexpected signal %d\n", sig);
      fail("Child dead unexpectedly.");
    }
    if (steps >= LIMIT)
      fail("Too many steps.");
    if (!start && getpc() == SC) {
      start = true;
      check_maps();
      clear_regs();
      clear_cookie_at();
      put_cookie();
    }
    if (start) {
      if (check_state()) {
        end = true;
        break;
      }
      record[steps++] = getpc();
    }
  }
  if (!end)
    fail("...?");
  debug("exiting after %d single-steps\n", steps);
  if (!check_cookie_gone())
    fail("Please swallow the cookie.");
  inverse();
  if (!check_cookie_back())
    fail("You should vomit the cookie out.");
  success();
  return 0;
}

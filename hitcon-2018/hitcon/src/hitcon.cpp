#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>

void contact() {
  puts("Error, contact admin");
  exit(127);
}

const int PN = 9;

struct Paper {
  char *author;
  char *title;
  char *content;
  Paper() {}
  Paper(char *a, char *t, char *c): author(a), title(t), content(c) {}

  void show() const {
    printf("Author: %s\nTitle: %s\n\n", author, title);
  }
} papers[PN + 1];

char *readline(FILE *f) {
  char buf[1000];
  if(!fgets(buf, sizeof(buf), f)) contact();
  int n = strlen(buf);
  if(buf[n-1] == '\n') buf[n-1] = 0;
  return strdup(buf);
}

void init_papers() {
  FILE *f = fopen("papers.txt", "rb");
  if(f == NULL) contact();
  papers[0].author = (char*) "TBD";
  char buf;
  for(int i = 1; i <= PN; i++) {
    char *a = readline(f);
    char *t = readline(f);
    char *c = readline(f);
    /* seprator */
    fread(&buf, 1, 1, f);
    papers[i] = Paper(a, t, c);
    // fprintf(stderr, "%s: %d, %u\n", papers[i].author, strlen(papers[i].content), 3000000 % strlen(papers[i].content));
  }
}

void welcome() {
  puts(R"MSG(Honey Island Taiwan CONference is coming!

We have accepted many papers, please help us schedule the agenda!
)MSG");
}

void show_papers() {
  for(int i = 1; i <= PN; i++)
    printf("%d:  Author: %s\n    Title: %s\n\n", i, papers[i].author, papers[i].title);
}

char matching[PN + 1];
int cur_time;
const int BUFLEN = 100;
char buf[BUFLEN + 1] = {};

#define ALIGN(s) (int)(5+strlen(s)/2), s, (int)(5-strlen(s)/2), ""
#define AT(i) ALIGN(papers[matching[i]].author)

void show_agenda() {
  printf(R"STR(
----------------------------------------
| %*s%*s | %*s%*s | %*s%*s |
----------------------------------------
| %*s%*s | %*s%*s | %*s%*s |
----------------------------------------
| %*s%*s | %*s%*s | %*s%*s |
----------------------------------------
| %*s%*s | %*s%*s | %*s%*s |
----------------------------------------
)STR",
    ALIGN("R0"), ALIGN("R1"), ALIGN("R2"),
    AT(1), AT(2), AT(3),
    AT(4), AT(5), AT(6),
    AT(7), AT(8), AT(9)
    );
}

bool schedule_ok() {
  int cnt[PN+1] = {};
  for(int i = 1; i <= PN; i++)
    if(matching[i] == 0) return false;
    else ++cnt[matching[i]];
  for(int i = 1; i <= PN; i++)
    if(cnt[i] != 1) return false;
  return true;
}

void schedule() {
  int x = -1, y = -1;
  show_agenda();
  while(scanf("%d%d", &x, &y) == 2) {
    if(x <= 0 || x > PN || y < 0 || y > PN) break;
    matching[x] = y;
    if(schedule_ok()) break;
    show_agenda();
  }
}

thread_local int my_id = -1, room_id = -1;
thread_local int remain_time = 0;
thread_local Paper *paper = NULL;
thread_local char tname[32];
thread_local char tbuf[BUFLEN + 12];

#define AN 1000

struct Audience {
  int room;
  bool angry;
  // ~Audience() {}
  virtual void putchar(char c) {}
  virtual void puts(const char *s) {}
  virtual void choose() { room = rand() % 3; }
  virtual char* ask() { return NULL; }
  virtual void readn(char *buf, int len) {}
} *aud[AN];

struct NiceAudience: public Audience {
  void choose() override {
    int best[3] = {}, btop = 0;
    for(int i = 0; i < 3; i++) {
      char *name = papers[matching[cur_time * 3 + i + 1]].author;
      if(!strcmp(name, "Orange") || !strcmp(name, "Angelboy") || !strcmp(name, "david942j")) best[btop++] = i;
    }
    if(btop == 0) room = rand() % 3;
    else {
      if(btop > 1) { angry = true; room = best[rand() % btop]; }
      else room = best[0];
    }
  }

  char* ask() override {
    static const char *ans[] = {
      "Could you explain what's heap overflow?\n",
      "So.. how could I become the best hacker?\n",
      "Do you have a girl friend?\n",
    };
    return (char*) ans[rand() % (sizeof(ans) / sizeof(char*))];
  }
};

struct You: public NiceAudience {
  void putchar(char c) override {
    ::putchar(c);
  }

  void puts(const char *s) override {
    ::puts(s);
  }
  void choose() override {
    printf("This is the %s talk!\n", cur_time == 0 ? "first" : cur_time == 1 ? "second" : "last");
    puts("Which room you'd like to go?");
    for(int i = 0; i < 3; i++) {
      const Paper *paper = &papers[matching[cur_time * 3 + i + 1]];
      printf("%d. %s: %s\n", i, paper->author, paper->title);
    }
    scanf("%d", &room);
    getchar();
  }
  char* ask() override {
    memset(buf, 0, sizeof(buf));
    read(0, buf, sizeof(buf) - 1);
    return buf;
  }

  void readn(char *buf, int len) override {
    int l = read(0, buf, len - 1);
    if(l <= 0) _exit(2);
    buf[l] = 0;
    char *c = strchr(buf, '\n');
    if(c) *c = 0;
  }
};

void set_variables(Paper *_paper) {
  remain_time = 3 * 1000000;
  paper = _paper;
  for(int i = 1; i <= PN; i++)
    if(paper ==  &papers[i])
      my_id = i;
  for(int i = 0 ; i < 3; i++)
    if(matching[cur_time * 3  + i + 1] == my_id)
      room_id = i;
}

#define TWORK(work) for(int i = 0; i < AN; i++) \
    if(aud[i]->room == room_id) \
    do { work; } while(0);

void a_putchar(char c) {
  TWORK(aud[i]->putchar(c));
}

void a_puts(const char *s) {
  TWORK(aud[i]->puts(s));
}

void do_talk() {
  int len = strlen(paper->content);
  const int gap = remain_time / len;
  for(int i = 0; i < len; i++) {
    a_putchar(paper->content[i]);
    usleep(gap);
    remain_time -= gap;
  }
  a_putchar('\n');
}

bool times_up() {
  return remain_time <= 0;
}

void response(Audience *a, char *q) {
  char *s = stpcpy(tbuf, "So your question is: ");
  strncpy(s, q, strlen(q) - 1);
  TWORK({
  aud[i]->puts(tbuf);
  aud[i]->puts("This is a good question,");
  aud[i]->puts("but I don't have enough time to answer you now.");
  aud[i]->puts("May I know your name please?");
  if(aud[i] == a) aud[i]->readn(tname, sizeof(tname));
  aud[i]->puts("OK, let's discuss about it later.\n");
  });
  sleep(1);
}

void qa_time() {
  if(times_up()) return;
  a_puts("Any questions?");
  TWORK({
    char *q = aud[i]->ask();
    if(q == NULL || strcmp(q, "no\n") == 0) continue;
    response(aud[i], q); return;
    });
}

void* talk(void *varg) {
  set_variables((Paper*) varg);
  do_talk();
  qa_time();
  sprintf(tbuf, "I'm %s, thanks for listening!\n", paper->author);
  TWORK(aud[i]->puts(tbuf));
  return NULL;
}

void init_audience() {
  for(int i = 0; i < AN - 3; i++)
    aud[i] = new Audience;
  for(int i = AN - 3; i < AN - 1; i++)
    aud[i] = new NiceAudience;
  aud[AN - 1] = new You;
}

void start() {
  if(!schedule_ok()) { puts("ಠ_ಠ?"); return; }
  init_audience();
  /* create three threads */
  pthread_t thread_id[3];
  for(cur_time = 0; cur_time < 3; cur_time++) {
    for(int i = 0; i < AN; i++)
      aud[i]->choose();
    for(int i = 0; i < 3; i++)
      pthread_create(&thread_id[i], NULL, talk, (void*) &papers[matching[cur_time * 3 + i + 1]]);
    for(int i = 0; i < 3; i++)
      pthread_join(thread_id[i], NULL);
    for(int i = 0; i < AN; i++)
      if(aud[i]->angry) {
        puts("Oh no! Audience are angry! We hosted a bad conference :((");
        exit(0);
      }
  }
  puts("HITCON 2018 is end! See you next year!");
}

void menu() {
  puts(R"MENU(1.  Show papers
2.  Show agenda
3.  Schedule)MENU");
  if(schedule_ok()) puts("4.  Start");
  puts("-1. Exit");
}

void setup() {
  setbuf(stdout, NULL);
  setbuf(stdin, NULL);
  int seed, fd = open("/dev/urandom", 0);
  if(fd < 0) _exit(1);
  read(fd, &seed, 4);
  close(fd);
  srand(seed);
}

int main() {
  setup();
  init_papers();
  welcome();
  while(1) {
    menu();
    int choice;
    if(scanf("%d", &choice) != 1) break;
    switch(choice) {
    case 1: show_papers(); break;
    case 2: show_agenda(); break;
    case 3: schedule(); break;
    case 4: start(); return 0;
    case -1: puts("No HITCON this year Q_Q?"); return 0;
    }
  }
  return 0;
}

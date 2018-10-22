#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define FOR(i, n) for(int i=0;i<(n);i++)

char cmd[100] = {};
#define MAX_ARGC 3
bool get_cmd(char **in_ptr, int *n_ptr) {
  printf("$ ");
  if(!fgets(cmd, sizeof(cmd), stdin)) return false;
  /* cmd.split(" ") */
  char dlim[] = " \t\n\v\f\r";
  char *ptr = strtok(cmd, dlim);
  int n = 0;
  while(ptr != NULL) {
    in_ptr[n++] = ptr;
    if(n >= MAX_ARGC) break;
    ptr = strtok(NULL, dlim);
  }
  *n_ptr = n;
  return true;
}

/* A file node */
struct Node {
#define T_FILE 1
#define T_DIR 2
#define T_LINK 4
  int type;
  Node *parent;
  Node *child, *brother;
  char *name, *content;
  Node() {
    type = 0;
    parent = child = brother = NULL;
    name = content = NULL;
  }

  void remove() {
    Node *c = child;
    while(c) {
      Node *next_c = c->brother;
      c->remove();
      c = next_c;
    }
    if(name) free(name);
    if(content) free(content);
    delete this;
  }

  void unlink() {
    if(parent->child == this) {
      /* ok I'm the first child */
      parent->child = brother;
    }
    else {
      Node *s = parent->child;
      while(s->brother != this) s = s->brother;
      s->brother = brother;
    }
  }

  /* file node */
  Node(Node *par, char *s, char *c) {
    setfile();
    add_to_parent(par);
    name = s;
    content = c;
  }

  Node(Node *par, char *s) {
    setdir();
    add_to_parent(par);
    name = s;
    content = NULL;
  }

  void add_to_parent(Node *par) {
    parent = par;
    brother = par->child;
    par->child = this;
  }

  void ls() {
    if(isfile()) {
      puts(name);
      return;
    }
    Node *c = child;
    printf("\e[38;5;153m.\t..\e[0m\t");
    while(c) {
      if(c->isdir()) printf("\e[38;5;153m");
      printf("%s\e[0m\t", c->name);
      c = c->brother;
    }
    puts("\n");
  }

  Node *find_by_name(char *s) {
    Node *c = child;
    while(c) {
      if(strcmp(c->name, s) == 0)
        return c;
      c = c->brother;
    }
    return NULL;
  }

  bool is_ancestor_of(Node *c) {
    do {
      if(c == this || c->parent == this) return true;
      c = c->parent;
    } while(!c->is_root());
    return false;
  }

  void fullpath() {
    if(is_root()) {
      printf("%s", name);
      return;
    }
    this->parent->fullpath();
    printf("%s/", name);
  }

  void setdir() {
    type = T_DIR;
  }

  void setfile() {
    type = T_FILE;
  }

  void setlink() {
    type = T_FILE | T_LINK;
  }

  bool isdir() { return type & T_DIR; }
  bool isfile() { return type & T_FILE; }
  bool islink() { return type & T_LINK; }
  bool is_root() { return this == this->parent; }
};

Node *new_file(Node *parent, const char* name, const char* content) {
  return new Node(parent, strdup(name), strdup(content));
}

Node *new_dir(Node *parent, const char* name) {
  return new Node(parent, strdup(name));
}

Node *new_link(Node *parent, const char* name, const char *target) {
  Node *n = new Node(parent, strdup(name), strdup(target));
  n->setlink();
  return n;
}

struct FS {
// {{{ init
  void init() {
    root.parent = &root; /* rock! */
    root.name = strdup("/");
    root.setdir();

    Node *etc = new_dir(&root, "etc");
    new_file(etc, "passwd", R"passwd(root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
)passwd");
    Node *bin = new_dir(&root, "bin");
#define HANDLE(name) new_file(bin, #name, "\177ELF")
    HANDLE(ls);
    HANDLE(cat);
    HANDLE(rm);
    HANDLE(mkdir);
    HANDLE(mv);
    HANDLE(touch);
    HANDLE(ln);
    HANDLE(id);
#undef HANDLE
    new_dir(&root, "dev");
    new_dir(&root, "boot");
    new_dir(&root, "lib");
    new_dir(&root, "root");
    Node *proc = new_dir(&root, "proc");
    new_file(new_dir(proc, "self"), "maps", R"maps(5578f660d000-5578f6615000 r-xp 00000000 fd:00 9044035                    /bin/cat
5578f6814000-5578f6815000 r--p 00007000 fd:00 9044035                    /bin/cat
5578f6815000-5578f6816000 rw-p 00008000 fd:00 9044035                    /bin/cat
7ffff6fca000-7ffff6feb000 rw-p 00000000 00:00 0                          [stack]
7ffff6ff1000-7ffff6ff3000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
)maps");
    new_dir(&root, "tmp");

    Node *home = new_dir(&root, "home");
    Node *user_home = new_dir(home, "groot");
    new_file(user_home, ".bashrc", "alias ls='ls -a --color=tty'\n");
    new_file(user_home, "flag", "No flag here, what are you expecting?\n");

    cwd = user_home;
  }
// }}}

  void chdir(Node *n) {
    cwd = n;
  }

  Node root;
  Node *cwd;
} fs;

void init() {
  setbuf(stdout, NULL);
  setbuf(stdin, NULL);
#ifndef DEBUG
  alarm(60);
#else
  alarm(6000);
#endif
  fs.init();
}

#define CHECK_ARGC(low, up) do { \
  if(argc < low) { printf("%s: too few arguments\n", argv[0]); return; } \
  else if(argc > up) { printf("%s: too many arguments\n", argv[0]); return; } \
}while(0)

#define NULL_NODE(n, s) if(n == NULL) { \
    printf("%s: %s: No such file or directory\n", argv[0], s); \
    return; \
  }

Node *resolve_path(const char *path, bool last_follow_link = true, Node *start = NULL, int dep = 0) {
  if(dep > 1000) { puts("Too many levels of symbolic links"); exit(0); }
  char *saveptr;
  char *s = strtok_r(strdup(path), "/", &saveptr);
  Node *now = fs.cwd;
  if(start != NULL) now = start;
  /* absolute path, let's start from root */
  if(path[0] == '/') now = &fs.root;
  while(s != NULL) {
    if(strcmp(s, ".") == 0);
    else if(strcmp(s, "..") == 0) now = now->parent;
    else now = now->find_by_name(s);

    if(now == NULL) return NULL;

    s = strtok_r(NULL, "/", &saveptr);
    if(now->islink()) {
      if(s != NULL || last_follow_link) {
        now = resolve_path(now->content, true, now->parent, dep + 1);
        if(now == NULL) return NULL;
      }
    }
  }
  return now;
}

void handle_ls(int argc, char *argv[]) {
  CHECK_ARGC(1, 2);
  Node *n;
  if(argc == 1) n = fs.cwd;
  else n = resolve_path(argv[1], false);
  NULL_NODE(n, argv[1]);

  n->ls();
}

void handle_cat(int argc, char *argv[]) {
  CHECK_ARGC(2, 2);

  Node *n = resolve_path(argv[1]);
  NULL_NODE(n, argv[1]);
  if(n->isdir()) { printf("%s: %s: Is a directory\n", argv[0], argv[1]); return; }
  printf("%s", n->content);
}

void handle_cd(int argc, char *argv[]) {
  CHECK_ARGC(2, 2);

  Node *n = resolve_path(argv[1]);
  NULL_NODE(n, argv[1]);
  if(!n->isdir()) { printf("%s: %s: Not a directory\n", argv[0], argv[1]); return; }
  fs.chdir(n);
}

void handle_rm(int argc, char *argv[]) {
  CHECK_ARGC(2, 2);

  Node *n = resolve_path(argv[1], false);
  NULL_NODE(n, argv[1]);
  /* check node to be removed is not an ancestor of cwd */
  if(n->is_ancestor_of(fs.cwd)) {
    printf("%s: %s: Cannot remove current directory\n", argv[0], argv[1]);
    return;
  }

  n->unlink();
  n->remove();
}

#define CHECK_FILENAME(s) if(strchr(s, '/') || strcmp(s, ".") == 0 || strcmp(s, "..") == 0) { \
  printf("%s: %s: Invalid filename\n", argv[0], s); \
  return; \
}

#define CHECK_EXISTS(s) if(fs.cwd->find_by_name(s)) { \
  printf("%s: %s: Already exists\n", argv[0], s); \
  return; \
}

void handle_mv(int argc, char *argv[]) {
  CHECK_ARGC(3, 3);
  Node *a = resolve_path(argv[1], false), *b = resolve_path(argv[2], false);
  Node *tar_dir = NULL;
  char *filename = NULL;
  NULL_NODE(a, argv[1]);

  if(b == NULL) {
    char *last = strrchr(argv[2], '/');
    if(last == NULL) {
      // argv[2] contains filename only
      tar_dir = a->parent;
      CHECK_FILENAME(argv[2]);
      filename = strdup(argv[2]);
    }
    else {
      *last = '\0';
      tar_dir = resolve_path(argv[2]);
      NULL_NODE(tar_dir, argv[2]);
      CHECK_FILENAME(last + 1);
      filename = strdup(last + 1);
    }
  }
  else if(b->isdir())
    tar_dir = b;
  else {
    printf("%s: %s: Already exists\n", argv[0], argv[2]);
    return;
  }

  if(a->is_ancestor_of(tar_dir)) {
    printf("%s: cannot move '%s' to a subdirectory of itself, '%s'\n", argv[0], argv[1], argv[2]);
    return;
  }

  a->unlink();
  a->brother = tar_dir->child;
  a->parent = tar_dir;
  tar_dir->child = a;
  if(filename) {
    free(a->name);
    a->name = filename;
  }
}

void handle_mkfile(int argc, char *argv[]) {
  CHECK_ARGC(2, 2);
  CHECK_FILENAME(argv[1]);
  CHECK_EXISTS(argv[1]);

  char content[100] = {};
  printf("Content? ");
  if(read(0, content, sizeof(content) - 1) <= 0) exit(1);
  new_file(fs.cwd, argv[1], content);
}

void handle_mkdir(int argc, char *argv[]) {
  CHECK_ARGC(2, 2);
  CHECK_FILENAME(argv[1]);
  CHECK_EXISTS(argv[1]);

  new_dir(fs.cwd, argv[1]);
}

void handle_touch(int argc, char *argv[]) {
  CHECK_ARGC(2, 2);
  CHECK_FILENAME(argv[1]);
  /* do nothing */
  if(fs.cwd->find_by_name(argv[1])) return;
  new_file(fs.cwd, argv[1], "");
}

void handle_pwd(int argc, char *argv[]) {
  CHECK_ARGC(1, 1);
  fs.cwd->fullpath();
  puts("");
}

void handle_ln(int argc, char *argv[]) {
  CHECK_ARGC(3, 3);
  CHECK_FILENAME(argv[2]);
  CHECK_EXISTS(argv[2]);

  new_link(fs.cwd, argv[2], argv[1]);
}

void handle_id(int argc, char *argv[]) {
  CHECK_ARGC(1, 1);
  puts("uid=1000(groot) gid=1000(groot) groups=1000(groot)");
}

void handle_exit(int _argc, char *_argv[]) {
  puts("Bye!");
  exit(0);
}

#define HANDLE(name) if(!strcmp(in[0], #name)) { \
      handle_##name(n, in); \
      continue; \
    }

int main(int argc, char *argv[]) {
  init();
  char **in = (char**) malloc(sizeof(char*) * MAX_ARGC);
  int n = 0;

  while(get_cmd(in, &n)) {
    HANDLE(ls);
    HANDLE(cat);
    HANDLE(cd);
    HANDLE(rm);
    HANDLE(mv);
    HANDLE(mkdir);
    HANDLE(mkfile);
    HANDLE(touch);
    HANDLE(pwd);
    HANDLE(ln);
    HANDLE(id);
    HANDLE(exit);
    printf("%s: %s: not found\n", argv[0], in[0]);
  }
  return 0;
}

#undef HANDLE

#include <err.h>
#include <fcntl.h>
#include <malloc.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/cord.h>

/* #define DEBUG */
typedef uint32_t u32;

#define delete __delete

#define IOCTL(cmd, arg) do { \
    int ret = ioctl(devfd, cmd, arg); \
    if (ret < 0) \
      err(1, NULL); \
  } while (0)

#define ASSIGN_IOCTL(S, cmd, arg) \
    int ret = ioctl(devfd, cmd, arg); \
    if (ret < 0) \
      err(1, NULL); \
    S = ret

#define CORD_DEVICE_NAME "/dev/cord"

#define INVALID_CID ((u32) -1)
struct Tab {
  u32 len;
  u32 cid;
  bool dirty;
  char *cache;

  void remove_cache() {
    if (!dirty) {
      dirty = true;
      free(cache);
    }
  }
#ifdef DEBUG
  void dump() {
    fprintf(stderr, "cid: %u, len: %u\n", cid, len);
    if (dirty) fprintf(stderr, "dirty\n");
    else {
      fprintf(stderr, "cache: %p, size=%lu\n", cache, malloc_usable_size(cache));
    }
  }
#endif
};

struct Tab *alloc_tab() {
  struct Tab *ret = (Tab *)malloc(sizeof(*ret));
  if (!ret)
    errx(1, NULL);
  ret->len = 0;
  ret->cid = INVALID_CID;
  ret->cache = NULL;
  ret->dirty = true;
  return ret;
}

struct Editor {
  struct Tab **tabs;
  int tab_cnt;
  int cur_tab;
  int devfd;
  struct Tab *clip;

  void init() {
    devfd = open(CORD_DEVICE_NAME, O_RDWR|O_CLOEXEC);
    if (devfd < 0)
      err(1, "open");
    IOCTL(CORD_SET_DATA_WIDTH, 1);
    cur_tab = 0;
    new_tab();
  }

  void hw_version(int *v) const {
    ASSIGN_IOCTL(*v, CORD_GET_DEVICE_VERSION, 0);
  }

  void new_tab() {
    tabs = (Tab **)realloc(tabs, (tab_cnt + 1) * sizeof(*tabs));
    if (!tabs)
      errx(1, NULL);
    tabs[tab_cnt] = alloc_tab();
    cur_tab = tab_cnt;
    tab_cnt++;
  }

  void select(int n) {
    if (n >= tab_cnt)
      return;
    cur_tab = n;
  }

#define CHECK_RANGE do { \
    if (tabs[cur_tab]->cid == INVALID_CID) \
      return; \
    if (idx >= tabs[cur_tab]->len) \
      return; \
    if (n == 0 || n > tabs[cur_tab]->len) \
      return; \
    if (idx > tabs[cur_tab]->len - n) \
      return; \
  } while(0)

  void insert(u32 idx, u32 n, char text[]) {
    struct Tab *tab = tabs[cur_tab];
    if (idx > tab->len)
      return;
    struct cord_new_data cmd = {
      .n = n,
      .data = text,
    };
    ASSIGN_IOCTL(int cid, CORD_NEW_DATA, &cmd);
    if (tab->cid != INVALID_CID) {
      __paste(tab->cid, idx, cid);
      tab->len += n;
      tab->remove_cache();
    }
    else {
      tab->cid = cid;
      tab->len = n;
      tab->cache = (char*)malloc(n);
      memcpy(tab->cache, text, n);
      tab->dirty = false;
    }
  }

  inline void __paste(u32 cid1, u32 idx, u32 cid2) {
    struct cord_paste cmd = {
      .cid_d = cid1,
      .cur = idx,
      .cid_s = cid2,
    };
    IOCTL(CORD_PASTE, &cmd);
  }

  void paste(u32 idx) {
    if (!clip)
      return;
    struct Tab *tab = tabs[cur_tab];
    if (idx > tab->len)
      return;
    if (tab->cid == INVALID_CID) {
      memcpy(tab, clip, sizeof(*clip));
      free(clip);
      clip = NULL;
      return;
    }
    __paste(tab->cid, idx, clip->cid);
    tab->len += clip->len;
    tab->remove_cache();
    clip->remove_cache();
    free(clip);
    clip = NULL;
  }

  void cut(u32 idx, u32 n) {
    CHECK_RANGE;
    struct Tab *tab = tabs[cur_tab];
    if (!clip) {
      clip = (struct Tab *)malloc(sizeof(*clip));
      clip->dirty = true;
    }
    if (idx == 0 && n == tab->len) {
      memcpy(clip, tab, sizeof(*clip));
      tab->cid = INVALID_CID;
      tab->len = 0;
      tab->dirty = true;
      return;
    }
    struct cord_cut cmd = {
      .cid = tab->cid,
      .cur = idx,
      .len = n
    };

    ASSIGN_IOCTL(clip->cid, CORD_CUT, &cmd);
    clip->len = n;
    /* if (!tab->dirty) { */
    /*   clip->cache = (char*)malloc(n); */
    /*   clip->dirty = false; */
    /*   memcpy(clip->cache, tab->cache + idx, n); */
    /* } */
    tab->len -= n;
    tab->remove_cache();
  }

  void replace(u32 idx, u32 n, int chr) {
    CHECK_RANGE;
    struct cord_cover cmd = {
      .cid = tabs[cur_tab]->cid,
      .cur = idx,
      .len = n,
      .val = (unsigned)chr,
    };
    IOCTL(CORD_COVER, &cmd);
    struct Tab *tab = tabs[cur_tab];
    if (!tab->dirty) {
      for (int i = idx, j = 0; j < n; j++, i++)
        tab->cache[i] = (char) chr;
    }
  }

  void reverse(u32 idx, u32 n) {
    CHECK_RANGE;
    struct cord_reverse cmd = {
      .cid = tabs[cur_tab]->cid,
      .cur = idx,
      .len = n,
    };
    IOCTL(CORD_REVERSE, &cmd);
    struct Tab *tab = tabs[cur_tab];
    if (!tab->dirty) {
      for (int i = 0; i < n / 2; i++) {
        char tmp = tab->cache[i + idx];
        tab->cache[i + idx] = tab->cache[n - i - 1 + idx];
        tab->cache[n - i - 1 + idx] = tmp;
      }
    }
  }

  void delete(u32 idx, u32 n) {
    cut(idx, n);
    IOCTL(CORD_DELETE, clip->cid);
    clip->remove_cache();
    free(clip);
    clip = NULL;
  }

  void display(u32 idx, u32 n) {
    CHECK_RANGE;
    struct Tab *tab = tabs[cur_tab];

    if (!tab->dirty) {
      write(1, tab->cache + idx, n);
      puts("");
      return;
    }
    void *d = malloc(n);
    struct cord_display cmd = {
      .cid = tabs[cur_tab]->cid,
      .cur = idx,
      .len = n,
      .data = d,
    };
    IOCTL(CORD_DISPLAY, &cmd);
    write(1, d, n);
    puts("");
    free(d);
  }

  void release() {
    close(devfd);
    devfd = -1;
  }
} editor;

void init() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  editor.init();
}

void get_version(int *major, int *minor) {
  int version;
  editor.hw_version(&version);
  *major = version >> 8;
  *minor = version & 0xff;
}

void welcome() {
  int major, minor;
  get_version(&major, &minor);
  printf(R"WELCOME(
  Luna - the Legendary Ultra Note Accelerator
                version %d.%d
                by david942j
)WELCOME", major, minor);
}

void menu() {
  printf(
    "-------------------\n"
    "[i]nsert INDEX TEXT\n"
    "[n]ewtab\n"
    "[s]elect TAB\n"
    "[d]isplay INDEX LENGTH\n"
    "[c]ut INDEX LENGTH\n"
    "[p]aste INDEX\n"
    "[r]eplace INDEX LENGTH CHAR\n"
    "[R]everse INDEX LENGTH\n"
    "[D]elete INDEX LENGTH\n"
    "[q]uit\n"
    ">>> "
  );
}

bool handle() {
  static char text[256];
  int idx = 0;
  int n = 0;

#ifdef DEBUG
  if (editor.clip) {
    fprintf(stderr, "clip:\n");
    editor.clip->dump();
  }
  fprintf(stderr, "cur:\n");
  editor.tabs[editor.cur_tab]->dump();
#endif

  menu();

  char c = 'q';
  if (scanf("%c", &c) != 1)
    return false;

  switch (c) {
  case 'i':
    if (scanf("%d", &idx) != 1)
      return false;
    if (idx < 0)
      return false;
    getchar(); // the space
    n = read(0, text, sizeof(text)) - 1; // -1 for \n
    if (n <= 0)
      return false;
    editor.insert(idx, n, text);
    printf("Done.\n");
    return true;
  case 'n':
    editor.new_tab();
    printf("Switched to new tab %d.\n", editor.cur_tab);
    break;
  case 'r':
    if (scanf("%d%d", &idx, &n) != 2)
      return false;
    if (idx < 0 || n <= 0)
      return false;
    getchar(); // space
    editor.replace(idx, n, getchar());
    printf("Done.\n");
    break;
  case 'R':
    if (scanf("%d%d", &idx, &n) != 2)
      return false;
    if (idx < 0 || n <= 0)
      return false;
    editor.reverse(idx, n);
    printf("Done.\n");
    break;
  case 's':
    if (scanf("%d", &n) != 1)
      return false;
    if (n < 0)
      return false;
    editor.select(n);
    printf("Switched to tab %d.\n", editor.cur_tab);
    break;
  case 'c':
    if (scanf("%d%d", &idx, &n) != 2)
      return false;
    if (idx < 0 || n <= 0)
      return false;
    editor.cut(idx, n);
    printf("Done.\n");
    break;
  case 'p':
    if (scanf("%d", &idx) != 1)
      return false;
    if (idx < 0)
      return false;
    editor.paste(idx);
    printf("Done.\n");
    break;
  case 'd':
    if (scanf("%d%d", &idx, &n) != 2)
      return false;
    if (idx < 0 || n <= 0 || n >= 256)
      return false;
    editor.display(idx, n);
    break;
  case 'D':
    if (scanf("%d%d", &idx, &n) != 2)
      return false;
    if (idx < 0 || n <= 0)
      return false;
    editor.delete(idx, n);
    printf("Done.\n");
    break;
  case 'q':
    getchar();
    return false;
  default:
    getchar();
    return true;
  }

  getchar();
  return true;
}

static void __attribute__((destructor)) release() {
  editor.release();
}

int main() {
  init();
  welcome();
  while(handle());
  puts("Bye bye");
  return 0;
}

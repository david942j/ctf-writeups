#include <assert.h>
#include <fcntl.h>
#include <errno.h>
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

#define assert_errno(statement, val) \
  do { \
    assert(statement < 0); \
    assert(errno == val); \
  } while(0)

#define assert_content(cid, s) \
  do { \
    const int n = strlen(s); \
    void *d = malloc(n); \
    assert_ok(display(cid, 0, n, d)); \
    assert_ok(memcmp(d, s, n)); \
    free(d); \
  } while (0)

#define assert_inval(s) assert_errno(s, EINVAL)
#define assert_fault(s) assert_errno(s, EFAULT)
#define assert_ok(s) assert((s) == 0)

#define DEVICE_NAME "/dev/cord"

typedef unsigned int uint;

int fd;

void setup() {
  fd = open(DEVICE_NAME, O_RDWR);
  assert(fd >= 0);
}

void test_version() {
  assert(ioctl(fd, CORD_GET_DEVICE_VERSION) == 0xd901);
}

void test_set_data_width() {
  assert_inval(ioctl(fd, CORD_SET_DATA_WIDTH, 0));
  assert_ok(   ioctl(fd, CORD_SET_DATA_WIDTH, 1));
  assert_ok(   ioctl(fd, CORD_SET_DATA_WIDTH, 2));
  assert_inval(ioctl(fd, CORD_SET_DATA_WIDTH, 3));
  assert_ok(   ioctl(fd, CORD_SET_DATA_WIDTH, 4));
  assert_inval(ioctl(fd, CORD_SET_DATA_WIDTH, 5));
  assert_inval(ioctl(fd, CORD_SET_DATA_WIDTH, 6));
  assert_inval(ioctl(fd, CORD_SET_DATA_WIDTH, 7));
  assert_ok(   ioctl(fd, CORD_SET_DATA_WIDTH, 8));
  assert_inval(ioctl(fd, CORD_SET_DATA_WIDTH, 9));
  assert_inval(ioctl(fd, CORD_SET_DATA_WIDTH, -1));
}

static inline int set_width(int w) {
  return ioctl(fd, CORD_SET_DATA_WIDTH, w);
};

static inline int new_data(uint n, void *data) {
  struct cord_new_data cmd = {
    .n = n,
    .data = data,
  };

  return ioctl(fd, CORD_NEW_DATA, &cmd);
}

static inline int display(uint cid, uint cur, uint len, void *data) {
  struct cord_display cmd = {
    .cid = cid,
    .cur = cur,
    .len = len,
    .data = data
  };

  return ioctl(fd, CORD_DISPLAY, &cmd);
}

static inline int cut(uint cid, uint cur, uint len) {
  struct cord_cut cmd = {
    .cid = cid,
    .cur = cur,
    .len = len,
  };

  return ioctl(fd, CORD_CUT, &cmd);
}

static inline int paste(uint cid, uint cur, uint cid2) {
  struct cord_paste cmd = {
    .cid_d = cid,
    .cur = cur,
    .cid_s = cid2,
  };

  return ioctl(fd, CORD_PASTE, &cmd);
}

#define delete __delete
static inline int delete(uint cid) {
  return ioctl(fd, CORD_DELETE, cid);
}

static inline int reverse(uint cid, uint cur, uint len) {
  struct cord_reverse cmd = {
    .cid = cid,
    .cur = cur,
    .len = len,
  };

  return ioctl(fd, CORD_REVERSE, &cmd);
}

static inline int cover(uint cid, uint cur, uint len, ulong val) {
  struct cord_cover cmd = {
    .cid = cid,
    .cur = cur,
    .len = len,
    .val = val,
  };

  return ioctl(fd, CORD_COVER, &cmd);
}

void test_new_data() {
  char data[17] = "ABCDEFGHIJKLMNOP";

  assert_ok(set_width(1));
  assert_fault(ioctl(fd, CORD_NEW_DATA, NULL));
  assert_inval(new_data(256, data));
  assert_fault(new_data(16, (void *) 0x1337));

  /* first success, should have cid = 0 */
  assert(new_data(16, data) == 0);
  assert(new_data(1, data) == 1);
  assert(new_data(16, data) == 2);

  for (int i = 3; i < 256; i++)
    assert(new_data(1, data) == i);
  assert_errno(new_data(1, data), EMFILE);
  for (int i = 0; i < 256; i++)
    assert_ok(delete(i));
}

void test_display() {
  char data[17] = "ABCDEFGHIJKLMNOP";
  void *d = malloc(16);
  void *l1 = malloc(256), *l2 = malloc(1);
  int cid;

  assert_ok(set_width(1));
  cid = new_data(16, data);
  assert(cid >= 0);
  assert_ok(display(cid, 0, 16, d));
  assert_ok(memcmp(d, data, 16));

  assert_inval(display(cid, 1, 16, d));

  assert_ok(display(cid, 8, 7, d));
  assert_ok(memcmp(d, data + 8, 7));

  assert((cid = new_data(255, l1)) >= 0);
  assert_ok(paste(cid, 0, new_data(1, l2)));
  /* display > 255 should fail */
  assert_inval(display(cid, 0, 256, l1));
  assert_ok(display(cid, 0, 255, l1));

  assert_ok(set_width(4));
  cid = new_data(4, data);
  assert(cid >= 0);
  assert_ok(display(cid, 0, 4, d));
  assert_ok(memcmp(d, data, 16));

  assert_inval(display(cid, 4, 1, d));

  assert_ok(display(cid, 2, 1, d));
  assert_ok(memcmp(d, data + 8, 4));

  free(d); free(l1); free(l2);
}

void test_display_stress() {
  const int n = 255;
  const int w = 8;
  void *d = malloc(n * w);
  void *s = malloc(n * w);
  int cid;
  int fd = open("/dev/urandom", O_RDONLY);

  assert_ok(set_width(w));
  assert(fd >= 0);
  assert(read(fd, d, n * w) == n * w);
  close(fd);
  assert((cid = new_data(n, d)) >= 0);

  for (int i = 1; i <= 255; i++) /* stress on queues */
	assert_ok(display(cid, 0, i, s));
  assert_ok(memcmp(d, s, n * w));
  assert_ok(paste(cid, 0, new_data(1, d)));
  assert_inval(display(cid, 0, 256, s));
  assert_ok(display(cid, 1, 255, s));
  assert_ok(memcmp(d, s, n * w));

  free(d); free(s);
}

void test_cut_paste() {
  char data1[17] = "ABCDEFGHIJKLMNOP";
  char data2[17] = "0123456789";
  void *d = malloc(26);
  int c1, c2, c3, c4;

  assert_ok(set_width(1));
  c1 = new_data(16, data1);
  c2 = new_data(10, data2);
  assert(c1 >= 0 && c2 >= 0);
  assert_inval(cut(c1, 0, 16));
  assert_inval(cut(c1, 1, 16));
  c3 = cut(c1, 1, 3);
  assert(c3 >= 0);
  assert_inval(cut(c1, 1, 13));
  c4 = cut(c1, 1, 12);
  assert(c4 >= 0);
  assert_inval(paste(c1, 2, c4)); // c1 has only one byte
  assert_ok(paste(c1, 0, c4));
  assert_content(c1 ,"EFGHIJKLMNOPA");
  assert_inval(paste(c1, 13, c4)); // c4 should be destroyed
  assert_ok(paste(c1, 13, c3));
  assert_content(c1, "EFGHIJKLMNOPABCD");

  assert_ok(paste(c2, 2, c1)); // move whole c1 into c2
  assert_inval(display(c1, 0, 1, d)); // c1 should be destroyed
  assert_content(c2, "01EFGHIJKLMNOPABCD23456789");

  free(d);
}

void test_delete() {
  char data[17] = "ABCDEFGHIJKLMNOP";
  int c1, c2;

  assert_ok(set_width(1));
  c1 = new_data(16, data);
  assert(c1 >= 0);
  assert_ok(delete(c1));
  assert_inval(display(c1, 0, 1, data));
  c1 = new_data(16, data);
  assert(c1 >= 0);
  c2 = cut(c1, 0, 2);
  assert(c2 >= 0);
  assert_ok(delete(c2));
  assert_inval(paste(c1, 0, c2));
}

void test_reverse() {
  char data[17] = "ABCDEFGHIJKLMNOP";
  int c1, c2;

  assert_ok(set_width(1));
  assert((c1 = new_data(16, data)) >= 0);
  assert_ok(reverse(c1, 0, 4)); // DCBA
  assert_ok(reverse(c1, 3, 5)); // DCBHGFEA
  assert_ok(reverse(c1, 0, 16)); // PONMLKJIAEFGHBCD
  assert_inval(reverse(c1, 1, 16));
  assert((c2 = cut(c1, 1, 3)) >= 0); // ONM
  assert_ok(reverse(c2, 0, 3)); // MNO
  assert_ok(paste(c1, 1, c2));
  assert_content(c1, "PMNOLKJIAEFGHBCD");
}

void test_cover() {
  char data[17] = "ABCDEFGHIJKLMNOP";
  int c1, c2;

  assert_ok(set_width(1));
  assert((c1 = new_data(16, data)) >= 0);
  assert_inval(cover(c1, 0, 17, 'z'));
  assert_ok(cover(c1, 0, 3, '0')); // 000
  assert_ok(cover(c1, 2, 4, '1')); // 001111
  assert_ok(reverse(c1, 4, 4)); // 0011HG11
  assert_content(c1, "0011HG11IJKLMNOP");

  assert_ok(cover(c1, 0, 16, 's'));
  assert((c2 = cut(c1, 3, 3)) >= 0);
  assert_content(c2, "sss");

  assert_inval(cover(c1, 0, 14, 's'));
  assert_ok(cover(c2, 1, 2, 0xdeadbeefu));
  assert_content(c2, "s\xef\xef");
}

void test_invalid_merge() {
  char data[17] = "ABCDEFGHIJKLMNOP";
  int c1, c2;

  assert_ok(set_width(1));
  assert((c1 = new_data(16, data)) >= 0);
  assert_ok(set_width(8));
  assert((c2 = new_data(16, data)) >= 0);
  assert_inval(paste(c1, 0, c2));
}

void run_tests() {
  setup();
  test_version();
  test_set_data_width();
  test_new_data();
  test_display();
  test_display_stress();
  test_cut_paste();
  test_delete();
  test_reverse();
  test_cover();
  test_invalid_merge();
}

int main() {
  run_tests();
  puts("All tests passed");
  return 0;
}

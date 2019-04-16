// g++     tree.cpp libsplaid.so.1  -o tree -Wall -O3
// ./tree 2438 secrets.zip.enc 74
#include <cstdint>
#include <bits/stdc++.h>
using namespace std;

extern "C" {
  struct SPNode {
    SPNode* parent;
    SPNode* left;
    SPNode* right;
    int64_t cnt;
  };
  struct Context {
    SPNode* root;
    unsigned int (*compare)(SPNode*, SPNode*);
    void (*push)(SPNode*);
    unsigned int (*compare_i)(int64_t, SPNode*);
  };
  struct Tree {
    SPNode nodes[511];
    Context context;
  };
  struct Node {
    bool is_leaf, is_inner;
    int leaf_id;
    SPNode spnode;
    Node(): is_leaf(false), is_inner(false), leaf_id(-1) {}
  };

  struct SPNodeInt {
    uint16_t parent, left, right;
    SPNodeInt(): parent(0), left(0), right(0) {}
  };

  struct State {
    bool invalid;
    int inner_count, leaf_count;
    uint64_t leaf_mask[8];
    Node *root;
    State(): invalid(false), inner_count(0), leaf_count(0) {
      // memset(leaf_mask, 0, sizeof(leaf_mask));
    }
  };
  int64_t sp_init(Context* a1, void* a2, void* a3, void (*push)(SPNode*));
  void sp_select(Context* ctx, SPNode* sp_node);
}

Node *newnode(SPNode *par) {
  Node *node = new Node;
  node->spnode.parent = par;
  node->spnode.left = node->spnode.right = nullptr;
  return node;
}

void set_inner(State *s, Node *n) {
  if(n->is_inner == false) {
    if(++s->inner_count > 255) s->invalid = true;
    n->is_inner = true;
  }
}

bool has_leaf(State *s, int id) {
  assert(id >= 0 && id < 256);
  return (s->leaf_mask[id / 64] >> (id % 64) ) & 1;

}

void set_leafbit(State *s, int id) {
  assert(id >= 0 && id < 256);
  s->leaf_mask[id / 64] |= 1LL << (id % 64);
}

void set_leaf(State *s, Node *n, int id) {
  if(id == -1) {
    if(n->is_leaf == false) {
      if(++s->leaf_count > 256) s->invalid = true;
      n->is_leaf = true;
      n->leaf_id = id;
    }
  }
  else {
    if(n->is_leaf == false) {
      // if leaf exists and not n -> invalid
      if(has_leaf(s, id)) s->invalid = true;
      else set_leafbit(s, id);
      if(++s->leaf_count > 256) s->invalid = true;
      n->is_leaf = true;
      n->leaf_id = id;
    }
    else {
      if(n->leaf_id != -1 && n->leaf_id != id) s->invalid = true;
      if(!has_leaf(s, id)) set_leafbit(s, id);
      n->leaf_id = id;
    }
  }
}
#define SP2NODE(sp) ((Node*)((uint8_t*)sp - offsetof(Node, spnode)))

Node *copy(Node *r) {
  Node *n = newnode(nullptr);
  n->is_leaf = r->is_leaf;
  n->is_inner = r->is_inner;
  n->leaf_id = r->leaf_id;
  if(r->spnode.left) {
    n->spnode.left = &(copy(SP2NODE(r->spnode.left))->spnode);
    n->spnode.left->parent = &(n->spnode);
  }
  if(r->spnode.right) {
    n->spnode.right = &(copy(SP2NODE(r->spnode.right))->spnode);
    n->spnode.right->parent = &(n->spnode);
  }
  return n;
}

State *copy(State *s) {
  State *c = new State;
  c->root = copy(s->root);
  memcpy(c->leaf_mask, s->leaf_mask, sizeof(s->leaf_mask));
  c->inner_count = s->inner_count;
  c->leaf_count = s->leaf_count;
  return c;
}

void nop(SPNode*) {}

string inject(Tree* tree, unsigned char byte) {
  string out;
  SPNode *root = &tree->nodes[0];
  SPNode *node = root+byte+255;
  SPNode *parent = node->parent;
  while (parent) {
    SPNode* left = parent->left;
    // SPNode* right = parent->right;
    if (left != node) {
      parent->left = parent->right;
      parent->right = left;
      out += "1";
    } else {
      out += "0";
    }
    node = parent;
    parent = parent->parent;
  }
  sp_select(&tree->context, ((SPNode*)(root+byte+255))->parent);
  return out;
}

void readfile(const char filename[], uint8_t * &out, size_t &n) {
  FILE *f = fopen(filename, "rb");
  fseek(f, 0, 2);
  n = ftell(f);
  rewind(f);
  out = new uint8_t [n];
  fread(out, n, 1, f);
  fclose(f);
}

Tree* initTree() {
  Tree *tree = new Tree;
  sp_init(&tree->context, 0, 0, nop);
  tree->context.root = &tree->nodes[0];
  return tree;
}

void completTree(Tree *tree) {
  SPNode *sp = tree->nodes;
  for (int i = 0; i < 511; i++) {
    if (i > 0)
      sp[i].parent = &sp[(i - 1) / 2];
    sp[i].left = 2 * i + 1 < 511 ? &sp[2 * i + 1] : nullptr;
    sp[i].right = 2 * i + 2 < 511 ? &sp[2 * i + 2] : nullptr;
  }
}

int data_len = 0;
unsigned char* readData() {
  FILE *f = fopen("e.zip", "rb");
  fseek(f, 0, 2);
  data_len = ftell(f);
  rewind(f);
  unsigned char *data = new unsigned char[data_len];
  fread(data, data_len, 1, f);
  fclose(f);
  return data;
}

string genTesting() {
  Tree *tree = initTree();
  completTree(tree);
  string out;
  // char key[] = "this_is_the_private_key_for_testing";
  // char key[] = "meow";
  // int keylen = strlen(key);
  uint8_t *key; size_t keylen;
  readfile("pusheen.txt", key, keylen);
  keylen--; // remove \n
  for (uint32_t i=0; i<keylen; i++) {
    inject(tree, key[i]);
  }
  unsigned char *data = readData();
  size_t max_dep = 0;
  for (int i=0; i<data_len; i++) {
    string res = inject(tree, data[i]);
    max_dep = max(max_dep, res.length());
    std::reverse(res.begin(), res.end());
    cout << i << ": " << res.length() << " " << res << endl;
    out += res;
  }
  cout << "max depth = " << max_dep << endl;
  // max depth = 31
  return out;
}

void test() {
  string output = genTesting();
  // cout << output << endl;
  // for(int i=0;i<output.length();i+=8) {
  //   unsigned int t = 0;
  //   for(int j=0;j<8 && i+j < output.length();j++)
  //     t = t * 2 + output[i+j] - '0';
  //   printf("%02x", t);
  // }
}

int bitof(const uint8_t *d, int i) {
  return (d[i/8] >> (7-(i%8)))&1;
}

void read_enc(const char filename[], uint8_t * &out, size_t &n) {
  readfile(filename, out, n);
  out += 4; // skip magic header
  n -= 8; // skip magic & crc
  n *= 8;
  // remove the last 1
  while(bitof(out, n - 1) == 0) --n;
  --n;
}

#define MAX_DEP 40

enum RES {
  IMPOSSIBLE,
  NOT_LEAF,
  OK
};

Context CC;

RES go(State *s, const uint8_t *data, int offset, int len, int leaf_id) {
  Node *cur = s->root;
  // assert(cur->is_leaf == false);

  for(int i=0;i<len;i++) {
    int b = bitof(data, offset + i);
    if(b == 0) {
      if(cur->spnode.left == nullptr) { // not create yet
        cur->spnode.left = &(newnode(&cur->spnode)->spnode);
      }
      // assert(cur->spnode.left->parent == &cur->spnode);
      cur = SP2NODE(cur->spnode.left);
    }
    else {
      Node *par = cur;
      if(cur->spnode.right == nullptr) { // not create yet
        cur->spnode.right = &(newnode(&cur->spnode)->spnode);
      }
      // assert(cur->spnode.right->parent == &cur->spnode);
      cur = SP2NODE(cur->spnode.right);
      swap(par->spnode.right, par->spnode.left);
    }
    if(i != len - 1) {
      if(cur->is_leaf) return IMPOSSIBLE;
      set_inner(s, cur);
      if(s->invalid) return IMPOSSIBLE;
    }
  }
  if(cur->is_inner) return NOT_LEAF;
  set_leaf(s, cur, leaf_id);
  if(s->invalid) return IMPOSSIBLE;
  SPNode *tmp = cur->spnode.parent;
  sp_select(&CC, tmp);
  s->root = SP2NODE(tmp);
  return OK;
}

void release(Node *n) {
  if(n->spnode.left) release(SP2NODE(n->spnode.left));
  if(n->spnode.right) release(SP2NODE(n->spnode.right));
  delete n;
}
void release(State *s) {
  release(s->root);
  delete s;
}

#define DANNY_START 76
int danny_start = DANNY_START;
#define FLAG_FILE "flag-cypress.txt"
int known_byte(int index) {
  static uint8_t *ans = nullptr;
  static size_t aa = 0;
  if(ans == nullptr) {
    readfile("danny.zip", ans, aa);
    ans += danny_start;
    aa -= danny_start;
    aa = min(aa, 5000lu);
  }
  if(index < (int)aa) return ans[index];
  return -1;
}
int dfs(Node *r, int id) {
  if(r->leaf_id == id) return 0;
  int val = -1;
  if(r->spnode.left) {
    val = dfs(SP2NODE(r->spnode.left), id);
    if(val != -1) return val + 1;
  }
  if(r->spnode.right) {
    val = dfs(SP2NODE(r->spnode.right), id);
    if(val != -1) return val + 1;
  }
  return -1;
}

int find_dep(State *s, int id) {
  if(id == -1) return -1;
  if(!has_leaf(s, id)) return -1;
  return dfs(s->root, id);
}

int get_candidate_len(uint32_t i) {
  static const int cand[] = {13, 14, 15, 12, 11, 16, 10, 17, 9, 18, 19, 8, 20, 1, 7, 21, 2, 22, 6, 5, 3, 4, 23};
  if(i < sizeof(cand)/sizeof(cand[0])) return cand[i];
  return i + 1;
}

// plain zip contains < 9000 byte
#define PLAIN_MAX_LENGTH 9000
int bitlen[PLAIN_MAX_LENGTH];
int offset_ = 825;

bool nice = false;
clock_t start;
uint8_t *data;
void set_child(Node *r, int lr, SPNode *to) {
  if(lr == 0) {
    r->spnode.left = to;
  }
  else r->spnode.right = to;
  if(to != nullptr)
    to->parent = &(r->spnode);
}

bool antizig(State *s, Node *r) {
  if(r->spnode.right == nullptr) return false;

  Node *p = SP2NODE(r->spnode.right);
  if(p->spnode.left == nullptr) return false;

  assert(p->spnode.left != nullptr);
  SPNode *god = r->spnode.parent;
  set_child(r, 1, p->spnode.left);
  set_child(p, 0, &(r->spnode));
  if(god != nullptr)
    set_child(SP2NODE(god), 0, &(p->spnode));
  else
    p->spnode.parent = god;

  if(god == nullptr) s->root = p;
  return true;
}

bool antizigzig(State *s, Node *r) {
  if(r->spnode.right == nullptr) return false;

  Node *p = SP2NODE(r->spnode.right);
  if(p->is_leaf) return false;
  assert(p->spnode.left != nullptr && p->spnode.right != nullptr);
  Node *g = SP2NODE(p->spnode.right);
  if(g->is_leaf) return false;
  SPNode *god = r->spnode.parent; // can be null? // no
  assert(god != nullptr);
  set_child(r, 1, p->spnode.left);
  set_child(p, 0, &(r->spnode));
  set_child(p, 1, g->spnode.left);
  set_child(g, 0, &(p->spnode));

  if(god != nullptr)
    set_child(SP2NODE(god), 0, &(g->spnode));
  if(god == nullptr) s->root = g;
  return true;
}

// swap left-right according to bitstream
void flip(State *s, int st, int len) {
  SPNode *r = &(s->root->spnode);
  for(int i = st; i < st + len; i++) {
    if(bitof(data, i) == 1) {
      swap(r->left, r->right);
      r = r->right;
    }
    else r = r->left;
    assert(r != nullptr);
  }
  assert(SP2NODE(r)->is_leaf);
}
void travel(Node *r ) {
  if(r->spnode.left) travel(SP2NODE(r->spnode.left));
  if(r->spnode.right) travel(SP2NODE(r->spnode.right));
  if(r->spnode.left == nullptr || r->spnode.right == nullptr) {
    assert(r->is_leaf && r->spnode.right == r->spnode.left);
  }
}
bool back(State *s, int st , int len) {
  Node *r = s->root;
  if(len == 1) return true;
  if(!antizig(s, r)) return false;
  if(len & 1) {
    if(!antizig(s, r)) return false;
  }
  for(int j=3;j<len;j+=2)
    if(!antizigzig(s, r)) return false;
  flip(s, st, len);
  return true;
}
int go_back(State *s, int n, int end)  {
  // travel(s->root);
  for(int i = n-1;i>=16;i--) { // the first few bytes may wrong, don't trust them.
    int len = bitlen[i], st = end - len;
    printf("%d %d\n", i, len);
    end = st;
    assert(SP2NODE(s->root->spnode.left)->leaf_id == known_byte(i));
    assert(SP2NODE(s->root->spnode.left)->is_leaf);
    assert(len > 0);
    if(len == 1)
      assert(bitof(data, st) == 0);
    bool ok = back(s, st, len);
    assert(ok);
  }
  // assert(end == offset_);
  assert(SP2NODE(s->root->spnode.left)->is_leaf);
  return end;
}

char bb[PLAIN_MAX_LENGTH];
void search2(State *s, int now, int end) {
  if(!SP2NODE(s->root->spnode.left)->is_leaf) return;
  bb[now] = SP2NODE(s->root->spnode.left)->leaf_id;
  int AA = 1;
  if (bb[now] == 'n' || bb[now] == 's') AA = 2;
  if(bb[now] != 0 && now >= AA) {
    int i;
    for(i=0;i<AA;i++) if (bb[now - i - 1] != bb[now]) break;
    if(i == AA) return;
  }
  static int mm = INT_MAX;
  if(mm > end) { 
    mm = end; printf("%d %d\n", now, end);
  }
  if(end == 0) {
    FILE * f = fopen("result/decrypt.data", "wb");
    for(int i=now;i>=0;i--)
      fwrite(&bb[i], 1, 1, f);
    fclose(f);
    puts("YES!");
    exit(0);
  }
  for(int i=0;i<MAX_DEP;i++) {
    int len = get_candidate_len(i);
    int st = end - len;
    if((len == 1) ^ (bitof(data, st) != 1)) continue;
    State *tmp = copy(s);
    if(!back(tmp, st, len)) { release(tmp); continue; }
    search2(tmp, now + 1, st);
    release(tmp);
  }
}

void search(State *s, int plain_bytes, int now, int remain_len) {
  // static int mmax = 0;
  // if(mmax < plain_bytes) { mmax = plain_bytes; printf("%d %d %d\n", plain_bytes, remain_len, s->leaf_count);
  //   for(int i=0;i<plain_bytes;i++)
  //     printf("(%d: %d) ", i, bitlen[i]);
  //   puts("");
  // }

  int id = known_byte(plain_bytes);
  if(id == -1) {
    printf("%d %d\n", offset_, danny_start);
    printf("%d %d\n", s->inner_count, s->leaf_count);
    puts("Success!");
    // for(int i=0;i<plain_bytes;i++)
    //   printf("%d\n", bitlen[i]);
    int e = go_back(s, plain_bytes, now);
    search2(s, 0, e);
    exit(0);
    return;
  }
  int h = min(remain_len, MAX_DEP);
  if(bitof(data, now) == 0) { // iff two same input bytes can start with 0
    int pid = known_byte(plain_bytes - 1);
    if(pid != id) return; // fast fail
  }
  // if the target leaf is known, we should calc the length directly.
  // bad but, usually fast enough.
  int dep = find_dep(s, id);
  if(dep != -1) {
    int len = dep;
    State *tmp = copy(s);
    RES res = go(tmp, data, now, len, id);
    if(res == OK) {
      bitlen[plain_bytes] = len;
      search(tmp, plain_bytes + 1, now + len, remain_len - len);
    }
    release(tmp);
    return;
  }
  for(int len=1;len<=h;len++) {
    State *tmp = copy(s);
    RES res = go(tmp, data, now, len, id);
    if(res == IMPOSSIBLE) { release(tmp); break; } // the path go through a known-leaf node
    if(res == NOT_LEAF) { release(tmp); continue; } // the path stops on a known-inner node
    bitlen[plain_bytes] = len;
    search(tmp, plain_bytes + 1, now + len, remain_len - len);
    release(tmp);
  }
}
char *enc_path = "secrets.zip.enc";
void solve() {
  sp_init(&CC, 0, 0, nop);
  uint8_t *out;
  size_t n;
  read_enc(enc_path, out, n);
  if(bitof(out, offset_) == 0) return;
  State *s = new State;
  memset(s->leaf_mask, 0, sizeof(s->leaf_mask));
  s->root = newnode(nullptr);
  set_inner(s, s->root);
  data = out;
  search(s, 0, offset_, n - offset_);
}

int main(int argc, char *argv[]) {
  // test(); exit(0);
  if(argc != 4) return 1;
  offset_ = atoi(argv[1]);
  if(argc >= 3)
    enc_path = argv[2];
  if(argc >= 4)
    danny_start = atoi(argv[3]);
  // offset_ = 2450;
  // offset_ = 2545;
  solve();
  return 0;
}

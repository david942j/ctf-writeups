// {{{ by david942j
#include <bits/stdc++.h>

#define mpr std::make_pair
#define lg(x) (31-__builtin_clz(x))
#define lgll(x) (63-__builtin_clzll(x))
#define __count __builtin_popcount
#define __countll __builtin_popcountll
#define X first
#define Y second
#define mst(x) memset(x,0,sizeof(x))
#define mst1(x) memset(x,-1,sizeof(x))
#define ALL(c) (c).begin(),(c).end()
#define FOR(i,n) for(int i=0;i<n;i++)
#define FOR1(i,n) for(int i=1;i<=n;i++)
#define FORit(it,c) for(auto it=(c).begin();it!=(c).end();++it)
#define pb push_back
#define RI(x) scanf("%d",&x)
#define RID(x) int x;RI(x)
using namespace std;

typedef long long LL;
typedef double LD;
typedef vector<int> VI;
typedef std::pair<int,int> PII;
template<class T>inline void maz(T &a,T b){if(a<b)a=b;}
template<class T>inline void miz(T &a,T b){if(a>b)a=b;}
template<class T>inline T abs(T a){return a>0?a:-a;}

#ifdef DAVID942J
template<typename T>
void _dump( const char* s, T&& head ) { cerr<<s<<"="<<head<<endl; }

template<typename T, typename... Args>
void _dump( const char* s, T&& head, Args&&... tail ) {
    int c=0;
    while ( *s!=',' || c!=0 ) {
        if ( *s=='(' || *s=='[' || *s=='{' ) c++;
        if ( *s==')' || *s==']' || *s=='}' ) c--;
        cerr<<*s++;
    }
    cerr<<"="<<head<<", ";
    _dump(s+1,tail...);
}

#define dump(...) do { \
    fprintf(stderr, "%s:%d - ", __PRETTY_FUNCTION__, __LINE__); \
    _dump(#__VA_ARGS__, __VA_ARGS__); \
} while (0)

template<typename Iter>
ostream& _out( ostream &s, Iter b, Iter e ) {
    s<<"[";
    for ( auto it=b; it!=e; it++ ) s<<(it==b?"":" ")<<*it;
    s<<"]";
    return s;
}

template<typename A, typename B>
ostream& operator <<( ostream &s, const pair<A,B> &p ) { return s<<"("<<p.first<<","<<p.second<<")"; }
template<typename T>
ostream& operator <<( ostream &s, const vector<T> &c ) { return _out(s,ALL(c)); }
template<typename T, size_t N>
ostream& operator <<( ostream &s, const array<T,N> &c ) { return _out(s,ALL(c)); }
template<typename T>
ostream& operator <<( ostream &s, const set<T> &c ) { return _out(s,ALL(c)); }
template<typename A, typename B>
ostream& operator <<( ostream &s, const map<A,B> &c ) { return _out(s,ALL(c)); }
#else
#define dump(...)
#endif

template<typename T>
void _R( T &x ) { cin>>x; }
void _R( int &x ) { scanf("%d",&x); }
void _R( long long &x ) { scanf("%" PRId64,&x); }
void _R( double &x ) { scanf("%lf",&x); }
void _R( char &x ) { scanf(" %c",&x); }
void _R( char *x ) { scanf("%s",x); }

void R() {}
template<typename T, typename... U>
void R( T& head, U&... tail ) {
    _R(head);
    R(tail...);
}

template<typename T>
void _W( const T &x ) { cout<<x; }
void _W( const int &x ) { printf("%d",x); }
template<typename T>
void _W( const vector<T> &x ) {
    for ( auto i=x.cbegin(); i!=x.cend(); i++ ) {
        if ( i!=x.cbegin() ) putchar(' ');
        _W(*i);
    }
}

void W() {}
template<typename T, typename... U>
void W( const T& head, const U&... tail ) {
    _W(head);
    putchar(sizeof...(tail)?' ':'\n');
    W(tail...);
}

#define FILEIO(name) do {\
    freopen(name ".in","r",stdin); \
    freopen(name ".out","w",stdout); \
} while (0)

// }}} end of default code

const int N=100010, INF=1e9;
const LD EPS=1e-7;
int n, m;
#include <inttypes.h>

#define __int64 long long
#define __int8 char
#define __int16 short

#define __fastcall

#define LOBYTE(c) ((c))
#define LODWORD(c) (c)

// {{{ xor_ith_lala
void __fastcall xor_ith_lala(__int16 offset, unsigned __int8 *dst, const unsigned char *lala) {
  unsigned __int8 *end; // rcx
  const unsigned char *ith_lala; // rdx
  __int64 i; // rax

  end = dst + 16;
  ith_lala = &lala[16 * offset & 0xFF0];
  do
  {
    i = 0LL;
    do
    {
      dst[i] ^= ith_lala[i];
      ++i;
    }
    while ( i != 4 );
    dst += 4;
    ith_lala += 4;
  }
  while ( dst != end );
}
// }}}

void do_encrypt(unsigned char *lala, unsigned char *plain, unsigned __int64 len, unsigned char *magic_256) {
  // {{{ vars
  int tmp4; // er14
  int c27; // er15
  unsigned char *lala_; // r9
  unsigned char *magic_256_; // r13
  unsigned char *plain_; // r12
  signed int offset; // eax
  __int64 i_; // rbx
  int chr; // edi
  unsigned char *__lala__ = lala; // r9
  int off; // er11
  unsigned __int64 tmp; // rdx
  unsigned __int8 *to_xor_; // r10
  __int64 j; // rax
  __int64 idx; // rcx
  unsigned __int8 v18; // al
  unsigned __int8 *to_xor_ptr; // rsi
  unsigned __int8 v20; // dl
  unsigned __int8 v21; // dl
  unsigned __int8 v22; // dl
  unsigned __int8 v23; // al
  unsigned __int8 v24; // dl
  unsigned __int64 tmp2; // rax
  int tmp3; // ecx
  int v27; // eax
  int tmp5; // ecx
  int tmp6; // eax
  int tmp7; // eax
  int tmp8; // eax
  int tmp9; // edi
  int tmp10; // eax
  int tmp11; // eax
  unsigned __int8 *__to_xor__; // r8
  // unsigned __int8 *__end_of_to_xor__; // r10
  // int __off__; // er11
  __int64 k; // rax
  unsigned __int8 v39; // al
  unsigned __int8 v40; // dl
  unsigned __int8 v41; // dl
  unsigned __int8 v42; // dl
  unsigned __int8 v43; // al
  unsigned __int8 v44; // dl
  signed __int64 l; // rax
  char cnt; // dl
  __int64 offset_; // rdx
  unsigned int i; // [rsp+Ch] [rbp-6Ch]
  unsigned __int64 len_; // [rsp+18h] [rbp-60h]
  unsigned __int8 to_xor[16]; // [rsp+28h] [rbp-50h]
  // }}}

  lala_ = lala;
  magic_256_ = magic_256;
  plain_ = plain;
  len_ = len;
  i = 0;
  offset = 16;
  while ( 1 )
  {
    i_ = i;
    if ( i >= len_ )
      break;
    if ( offset == 16 )
    {
      chr = 0;
      memcpy(to_xor, &lala_[240], 16);
      // *(_OWORD *)to_xor = *((_OWORD *)lala_ + 15);
      xor_ith_lala(0, to_xor, lala_);
      off = 1;
      do
      {
        // tmp = (unsigned __int64)&to_xor[4];
        to_xor_ = to_xor;
        do
        {
          j = 0LL;
          do
          {
            idx = to_xor_[4 * j];
            to_xor_[4 * j++] = magic_256_[idx];
          }
          while ( j != 4 );
          ++to_xor_;
        }
        while ( &to_xor[4] != to_xor_ );
        v18 = to_xor[1];
        to_xor_ptr = to_xor;
        LOBYTE(c27) = 27;
        to_xor[1] = to_xor[5];
        to_xor[5] = to_xor[9];
        v20 = to_xor[13];
        to_xor[13] = v18;
        to_xor[9] = v20;
        v21 = to_xor[10];
        to_xor[10] = to_xor[2];
        to_xor[2] = v21;
        v22 = to_xor[14];
        to_xor[14] = to_xor[6];
        v23 = to_xor[3];
        to_xor[6] = v22;
        to_xor[3] = to_xor[15];
        to_xor[15] = to_xor[11];
        v24 = to_xor[7];
        to_xor[7] = v23;
        to_xor[11] = v24;
        do
        {
          LOBYTE(tmp) = *to_xor_ptr;
          LOBYTE(idx) = to_xor_ptr[1];
          to_xor_ptr += 4;
          LOBYTE(chr) = *(to_xor_ptr - 1) ^ *(to_xor_ptr - 2);
          tmp3 = tmp ^ idx;
          LOBYTE(tmp2) = tmp3;
          LOBYTE(tmp4) = tmp3;
          tmp3 *= 2;
          LOBYTE(tmp2) = (unsigned __int8)tmp2 >> 7;
          tmp4 ^= chr;
          v27 = tmp3 ^ c27 * tmp2;
          LOBYTE(tmp3) = tmp;
          LOBYTE(tmp) = *(to_xor_ptr - 1) ^ tmp;
          tmp5 = tmp4 ^ tmp3;
          tmp6 = tmp5 ^ v27;
          LOBYTE(tmp5) = *(to_xor_ptr - 2) ^ *(to_xor_ptr - 3);
          *(to_xor_ptr - 4) = tmp6;
          LOBYTE(tmp6) = tmp5;
          tmp5 *= 2;
          LOBYTE(tmp6) = (unsigned __int8)tmp6 >> 7;
          tmp7 = tmp5 ^ c27 * tmp6;
          LOBYTE(tmp5) = *(to_xor_ptr - 3);
          LODWORD(idx) = tmp4 ^ tmp5;
          tmp8 = idx ^ tmp7;
          *(to_xor_ptr - 3) = tmp8;
          LOBYTE(tmp8) = chr;
          tmp9 = 2 * chr;
          LOBYTE(tmp8) = (unsigned __int8)tmp8 >> 7;
          tmp10 = tmp9 ^ c27 * tmp8;
          LOBYTE(tmp9) = *(to_xor_ptr - 2);
          chr = tmp4 ^ tmp9;
          LOBYTE(tmp4) = *(to_xor_ptr - 1) ^ tmp4;
          tmp11 = chr ^ tmp10;
          *(to_xor_ptr - 2) = tmp11;
          LOBYTE(tmp11) = (unsigned __int8)tmp >> 7;
          LODWORD(tmp2) = c27 * tmp11;
          LODWORD(tmp) = tmp4 ^ tmp2 ^ 2 * tmp;
          *(to_xor_ptr - 1) = tmp;
        }
        while ( &to_xor[16] != to_xor_ptr );
        chr = off;
        xor_ith_lala(off, to_xor, __lala__);
        // off = __off__ + 1;                      // off++
        off++;
      }
      while ( off != 14 );
      __to_xor__ = to_xor;
      do
      {
        k = 0LL;
        do
        {
          __to_xor__[4 * k] = magic_256_[__to_xor__[4 * k]];
          ++k;
        }
        while ( k != 4 );
        ++__to_xor__;
      }
      while ( &to_xor[4] != __to_xor__ );
      v39 = to_xor[1];
      to_xor[1] = to_xor[5];
      to_xor[5] = to_xor[9];
      v40 = to_xor[13];
      to_xor[13] = v39;
      to_xor[9] = v40;
      v41 = to_xor[10];
      to_xor[10] = to_xor[2];
      to_xor[2] = v41;
      v42 = to_xor[14];
      to_xor[14] = to_xor[6];
      v43 = to_xor[3];
      to_xor[6] = v42;
      to_xor[3] = to_xor[15];
      to_xor[15] = to_xor[11];
      v44 = to_xor[7];
      to_xor[7] = v43;
      to_xor[11] = v44;
      xor_ith_lala(14, to_xor, __lala__);
      l = 15LL;
      while ( 1 )
      {
        cnt = lala_[l + 240];
        if ( cnt != -1 )
          break;
        lala_[l-- + 240] = 0;
        if ( l == -1 )
          break;
      }
      if (l != -1)
        lala_[l + 240] = cnt + 1;
      offset = 0;
    }
    offset_ = offset;
    ++i;
    ++offset;
    assert(offset_ < 16);
    plain_[i_] ^= to_xor[offset_];
  }
}

unsigned char *readfile(const char *filename, int len) {
  unsigned char *buf = new unsigned char[len];
  FILE *f = fopen(filename, "r");
  fread(buf, 1, len, f);
  fclose(f);
  return buf;
}

static unsigned target[6] = {
0x1e, 0x60, 0x48, 0xa9, 0x39, 0xc7
};

void random_string(char *str, int len) {
  FOR(i, len)
    str[i] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"[rand() % 62];
}

unsigned char lagi[16] = {
0xE4,0xB8,0xC7,0x5A,0xCC,0xB8,0x77,0xDA,0xB0,0xF5,0xA6,0xF0,0xA7,0xAA,0x0E,0x67
};

unsigned char table11[11] = {
'r',
0xFE,
0xFD,
0xFB,
0xF7,
0xEF,
0xDF,
0xBF,
0x7F,
0xE4,
0xC9,
};

void __fastcall lalalei(unsigned __int8 *out_string, char *random_string, unsigned char *lagi, unsigned char *magic_256)
{
  __int64 v4; // rax
  unsigned __int8 *out_string_; // rax
  unsigned int v6; // er11
  __int64 v7; // r10
  __int64 v8; // r9
  __int64 v9; // r8
  __int64 v10; // rsi
  char v11; // bp
  unsigned __int8 v12; // r10
  unsigned __int8 v13; // r9
  unsigned __int8 v14; // r8
  unsigned __int8 v15; // si

  v4 = 0LL;
  do
  {
    out_string[v4] = random_string[v4];
    out_string[v4 + 1] = random_string[v4 + 1];
    out_string[v4 + 2] = random_string[v4 + 2];
    out_string[v4 + 3] = random_string[v4 + 3];
    v4 += 4LL;
  }
  while ( v4 != 32 );
  out_string_ = out_string;
  v6 = 8;
  do
  {
    v7 = out_string_[28];
    v8 = out_string_[29];
    v9 = out_string_[30];
    v10 = out_string_[31];
    if ( v6 & 7 )
    {
      if ( (v6 & 7) == 4 )
      {
        LOBYTE(v7) = magic_256[v7];
        LOBYTE(v8) = magic_256[v8];
        LOBYTE(v9) = magic_256[v9];
        LOBYTE(v10) = magic_256[v10];
      }
    }
    else
    {
      v11 = magic_256[v8];
      LOBYTE(v8) = magic_256[v9];
      LOBYTE(v9) = magic_256[v10];
      LOBYTE(v10) = magic_256[v7];
      LOBYTE(v7) = table11[v6 >> 3] ^ v11;
    }
    v12 = *out_string_ ^ v7;
    v13 = out_string_[1] ^ v8;
    ++v6;
    v14 = out_string_[2] ^ v9;
    v15 = out_string_[3] ^ v10;
    out_string_ += 4;
    out_string_[28] = v12;
    out_string_[29] = v13;
    out_string_[30] = v14;
    out_string_[31] = v15;
  }
  while ( v6 != 60 );
  memcpy(out_string + 240, lagi, 16);
}

#define N 10

void work(unsigned char *out, int time, unsigned char *magic, const unsigned char *plain, int len) {
  unsigned char lala[256];
  char random_str[32];

  srand(time);
  random_string(random_str, 32);
  lalalei(lala, random_str, lagi, magic);

  memcpy(out, plain, len);
  do_encrypt(lala, out, len, magic);
}

int find_time(unsigned char *magic, unsigned char *plain) {
  unsigned char out[N];
  for(int i = 1550000000; i < 1559669818; i++) {
    if (i % 3600 == 0)
      printf("-- %d\n", i);
    work(out, i, magic, plain, N);
    bool ok = true;
    FOR(i, 6) if (target[i] != out[i]) { ok = false; break; }
    if (ok) {
      printf(">>> %d\n", i);
      FOR(i, N) printf("%02x ", out[i]);
      puts("");
      return i;
    }
  }
}

int main() {
  FOR(i, 11) table11[i] = ~table11[i];
  unsigned char *magic = readfile("magic", 256);
  unsigned char *plain = readfile("src.cpp", N);
  // find_time(magic, plain);
  int ans = 1552365754;
  unsigned char src[5144]; src[5143] = 0;
  work(src, ans, magic, readfile("challenge/temp.bin", 5143), 5143);
  puts((char*)src);
  return 0;
}

// fb{RandumbNumbers}

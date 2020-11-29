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

#include <openssl/sha.h>
const int N=20;

typedef unsigned int u32;

static void convert(u32 brd[]) {
  FOR(i, N)
    cin >> brd[i];
}

static inline bool three(u32 val) {
  // 001100
  FOR(_, N - 2) {
    if ((val & 7) == 7 || (val & 7) == 0)
      return false;
    val >>= 1;
  }
  return true;
}

static inline u32 colval(u32 brd[], int j) {
    u32 val = 0;
    FOR(i, N) val |= ((brd[i] >> j) & 1) << i;
    return val;
}

static bool check(u32 brd[]) {
  FOR(i, N)
    if (brd[i] & 0xfff00000u)
      return false;
  static pair<u32, u32> ary[N] = {
    {0b10000001000000000010, 0b00000001000000000000},
    {0b00101001000001100101, 0b00101001000001100001},
    {0b00000000000000000000, 0b00000000000000000000},
    {0b00010110110001000000, 0b00010110110000000000},
    {0b00100000100100000101, 0b00000000100000000101},
    {0b00010000001000100000, 0b00000000001000100000},
    {0b10011000100001101000, 0b10000000100001100000},
    {0b00100001000100000010, 0b00100001000000000000},
    {0b00000000010010010001, 0b00000000010010000001},
    {0b00110001000101000000, 0b00000001000000000000},
    {0b00000000100000000001, 0b00000000000000000000},
    {0b01100000010000000101, 0b00000000010000000000},
    {0b00001100100001100000, 0b00000000000001100000},
    {0b00000000010100001000, 0b00000000010000000000},
    {0b01000000100100000000, 0b00000000100000000000},
    {0b00010010001000010011, 0b00010000000000000011},
    {0b01000010100011000000, 0b00000000100001000000},
    {0b00001000010000001100, 0b00000000000000001100},
    {0b01000011010100000000, 0b00000010000000000000},
    {0b10000001000001011010, 0b00000001000000000000},
  };
  FOR(i, N)
    if ((brd[i] & ary[i].X) != ary[i].Y)
      return false;
  // 2. No more than two similar numbers next to or below each other are allowed.
  FOR(i, N)
    if (!three(brd[i]))
      return false;
  FOR(j, N)
    if (!three(colval(brd, j)))
      return false;
  // 3. Each row and each column should contain an equal number of zeros and ones.
  FOR(i, N)
    if (__count(brd[i]) != N / 2)
      return false;
  FOR(j, N)
    if (__count(colval(brd, j)) != N / 2)
      return false;
  // 4. Each row is unique and each column is unique.
  FOR(a, N)
    FOR(b, a)
      if (brd[a] == brd[b])
        return false;
  FOR(a, N)
    FOR(b, a)
      if (colval(brd, a) == colval(brd, b))
        return false;
  return true;
}

static void print_flag(u32 brd[]) {
  cout << "Congratulations!" << endl;
  SHA256_CTX context;
  SHA256_Init(&context);
  SHA256_Update(&context, (unsigned char*)brd, N * sizeof(u32));
  unsigned char h[SHA256_DIGEST_LENGTH];
  SHA256_Final(h, &context);
  cout << "Here's your gift: hitcon{";
  FOR(i, SHA256_DIGEST_LENGTH)
    cout << setfill('0') << setw(2) <<  right << hex << (unsigned int) h[i];
  cout << "}" << endl;
}

int main() {
  u32 brd[N] = {};
  convert(brd);
  if (check(brd))
    print_flag(brd);
  else cout << "Zzz.." << endl;
  return 0;
}


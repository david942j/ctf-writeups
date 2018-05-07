//by david942j
// {{{
#include <cstdio>
#include <cstring>
#include <set>
#include <map>
#include <ctime>
#include <vector>
#include <algorithm>
#include <iostream>
#include <cmath>
#include <deque>
#include <cassert>
#include <queue>
#include <stack>
#include <cstdlib>
// #ifndef DAVID
// #include <bits/stdc++.h>
// #endif
#define openfile(s) freopen(s".in","r",stdin);freopen(s".out","w",stdout)
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
#define FORit(it,c) for(__typeof(c.begin()) it=c.begin();it!=c.end();++it)
#define pb push_back
#define RI(x) scanf("%d",&x)
#define RID(x) int x;RI(x)

#define IOS do {ios_base::sync_with_stdio(false); cin.tie(0); }while(0)
using namespace std;
template<typename T>
void _R( T &x ) { cin>>x; }
void _R( int &x ) { scanf("%d",&x); }
#ifdef PRId64
void _R( long long &x ) { scanf("%" PRId64,&x); }
#else
void _R( long long &x) {cin >> x;}
#endif
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
#ifdef DAVID
#define debug(format, ...) fprintf(stderr, format, ##__VA_ARGS__)
#else
#define debug(...)
#endif
#define caset RID(T);FOR1(cas,T)
typedef long long LL;
typedef double LD;
typedef vector<int> VI;
typedef std::pair<int,int> PII;
template<class T>inline void maz(T &a,T b){if(a<b)a=b;}
template<class T>inline void miz(T &a,T b){if(a>b)a=b;}
template<class T>inline T abs(T a){return a>0?a:-a;}
// }}}

const int N=5010;
const int lgN = 17;
const LL INF = 1LL << 61;
const int MOD = 1e9+7;
int n,m;
int p;
int pp[N], food[N];
LL dis[N][N];
void upd(LL &a, LL b) {
  if(a==-1 || a>b) a=b; 
}
typedef pair<long long, long long> pll;
#define PB pb
#define SZ(c) ((c).size())
struct CostFlow {
  static const int MXN = N * 2 + 2;
  struct Edge {
    int v, r;
    long long f, c;
  };
  int n, s, t, prv[MXN], prvL[MXN], inq[MXN];
  long long dis[MXN], fl, cost;
  vector<Edge> E[MXN];
  void init(int _n, int _s, int _t) {
    assert(n < MXN);
    n = _n; s = _s; t = _t;
    for (int i=0; i<n; i++) E[i].clear();
    fl = cost = 0;
  }
  void add_edge(int u, int v, long long f, long long c) {
    E[u].PB({v, SZ(E[v])  , f,  c});
    E[v].PB({u, SZ(E[u])-1, 0, -c});
  }
  pll flow() {
    while (true) {
      for (int i=0; i<n; i++) {
        dis[i] = INF;
        inq[i] = 0;
      }
      dis[s] = 0;
      queue<int> que;
      que.push(s);
      while (!que.empty()) {
        int u = que.front(); que.pop();
        inq[u] = 0;
        for (int i=0; i<SZ(E[u]); i++) {
          int v = E[u][i].v;
          long long w = E[u][i].c;
          if (E[u][i].f > 0 && dis[v] > dis[u] + w) {
            prv[v] = u; prvL[v] = i;
            dis[v] = dis[u] + w;
            if (!inq[v]) {
              inq[v] = 1;
              que.push(v);
            }
          }
        }
      }
      if (dis[t] == INF) break;
      long long tf = INF;
      for (int v=t, u, l; v!=s; v=u) {
        u=prv[v]; l=prvL[v];
        tf = min(tf, E[u][l].f);
      }
      for (int v=t, u, l; v!=s; v=u) {
        u=prv[v]; l=prvL[v];
        E[u][l].f -= tf;
        E[v][E[u][l].r].f += tf;
      }
      cost += tf * dis[t];
      fl += tf;
    }
    return {fl, cost};
  }
}flow;
void floyd() {
  FOR(k, n)
    FOR(i, n)
    if(dis[i][k] != -1)
      FOR(j,n)
        if(dis[k][j] != -1) {
          upd(dis[i][j], dis[i][k] + dis[k][j]);
        }
}
pll best() {
  LL m = INF;
  int id=-1;
  FOR(i, n) {
    LL total = 0;
    FOR(j, n) if(dis[i][j] == -1 && food[j]) {total=INF;break;} else total += dis[i][j] * food[j];
    if(total < m){id = i; m = total;}
  }
  return mpr(id, m);
}

void solve() {
  floyd();
  // 0 1~n n+1~2n 2n+1
  const int t = 2 * n + 1;
  flow.init(2*n+2, 0, t);
  FOR(i, n)
    if(pp[i] > 0)
      flow.add_edge(0, i+1, pp[i], 0);
  FOR(i, n)
    if(food[i] > 0)
      flow.add_edge(i+n+1, t, food[i], 0);
  FOR(i, n)FOR(j, n)if(pp[i] &&food[j] && dis[i][j] != -1)
    flow.add_edge(i+1, j+n+1, n, dis[i][j]);
  auto ans = flow.flow();
  assert(ans.X == p);
  auto z = best();
  W(z.X, ans.Y + z.Y);
}
int main() {
  R(n,m,p);
  assert(n < N);
  FOR(i, p) {
    RID(x);
    pp[x]++;
  }
  FOR(i, p) {
    RID(x);
    food[x]++;
  }
  FOR(i, n)FOR(j, n) dis[i][j] = -1;
  FOR(i, n) dis[i][i]=0;
  while(m--) {
    int x,y;
    long long d;
    R(x,y, d);
    upd(dis[x][y], d);
    upd(dis[y][x], d);
  }
  solve();
  return 0;
}

/*
7 6 3
2
1
3
5
6
0
0 1 25239
0 2 50478
1 5 16826
2 6 25239
3 5 25239
3 6 16826
 */

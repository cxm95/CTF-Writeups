#include <cstdio>
#include <iostream>
#include <cstring>
using namespace std;
const int maxn = 100;
const int maxv = 0x6033E0 + 5;
const int INF = 0x3f3f3f3f;
int dp[maxv];
int v, n;
int f[maxn];
int cnt[maxn];
int path[maxv];
int mp[maxv];
int main()
{
    scanf("%d", &v);
        scanf("%d", &n);
        for (int i = 1; i <= n; i++) {
            scanf("%d", &f[i]);
            mp[f[i]] = i;
        }
        memset(cnt, 0, sizeof(cnt));
        dp[0] = 0;
        for (int i = 1; i <= v; i++)
            dp[i] = INF;
        for (int i = 1; i <= n; i++) {
            for (int c = f[i]; c <= v; c++) {
                if (dp[c - f[i]] + 1 <= dp[c]) {
                    path[c] = c - f[i];
                    dp[c] = dp[c - f[i]] + 1;
                }
            }
        }
        if (dp[v] == INF) {
            printf("-1\n");
            return 1;
        }
        int i = v;
        if (dp[v] > 0) {
            while (i != 0) {
                cnt[mp[i - path[i]]]++;
                i = path[i];
            }
        }
        printf("\'");
        for (int i = 1; i <= n; i++) {
            printf("%d\',\'", cnt[i]);
        }
    printf("\nEnd.\n");
    return 0;
}
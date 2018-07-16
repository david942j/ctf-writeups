### Vulnerability

No lock at all in main thread, everywhere has race condition on `account->orders`.

While the only useful bug is while switching to real account, all orders in `account->orders` will be freed,
and the third child thread will free all closed orders as well, leads to *double-free*.

### Exploit

1. Do trading to earn some exp
2. Enable GC mode
3. Switch to real account, and wait 3s on the `change leverage?` query
    - wait 3s for triggering double free
4. Order multiple times and set volume to `0x604070`, which is located at GOT
5. Properly set the `malloc`ed chunk on GOT s.t. `got.atoi` points to `plt.printf + 6`
6. Input `%17$p` to leak libc base
7. Use the `set_takeprofit` function to reset `got.atoi` into `libc_system`
8. Shellllllllllll

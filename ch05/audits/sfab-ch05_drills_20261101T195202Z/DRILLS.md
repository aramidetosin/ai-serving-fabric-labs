# Rail drills

- Lab: `sfab-ch05`; labs repo commit `ebc79b42ed8e7c27efd526eb0362447cb260e449`; UTC 2026-11-01T19:52:02Z; host tick 10000; passes: 3

## dark-switch: rail-sw1 dark, rails 1, 3, 5, 7

Answered of sent, by when each request was sent (host clock; the cut and the restore are the KLISH sessions). Return: seconds from the restore's session start to the first answered request.

| Pass | Row | Expect | Before | Dark | Reached the far node | Far node replied | ARP while dark | After | Return (s) | Guest log replies | Guest log unreachable |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | `same-1` | dark | 48 of 48 | 0 of 130 | 0 | 0 | 0 | 86 of 102 | 6.295 | 152 | 0 |
| 1 | `same-2` | answered | 48 of 48 | 135 of 135 | 135 | 135 | - | 103 of 103 | 0.146 | 319 | 0 |
| 1 | `same-3` | dark | 48 of 48 | 0 of 130 | 0 | 0 | 0 | 85 of 102 | 6.503 | 151 | 0 |
| 1 | `same-4` | answered | 48 of 48 | 135 of 135 | 135 | 135 | - | 103 of 103 | 0.13 | 319 | 0 |
| 1 | `same-5` | dark | 48 of 48 | 0 of 130 | 0 | 0 | 0 | 90 of 102 | 6.52 | 156 | 0 |
| 1 | `same-6` | answered | 48 of 48 | 135 of 135 | 135 | 135 | - | 103 of 103 | 0.131 | 319 | 0 |
| 1 | `same-7` | dark | 48 of 48 | 0 of 119 | 0 | 0 | 6 | 81 of 81 | 7.419 | 147 | 30 |
| 1 | `same-8` | answered | 48 of 48 | 135 of 135 | 135 | 135 | - | 103 of 103 | 0.146 | 319 | 0 |
| 1 | `cross-2-1` | dark | 48 of 48 | 0 of 130 | 0 | 0 | 0 | 86 of 102 | 6.303 | 152 | 0 |
| 1 | `cross-1-2` | dark | 48 of 48 | 0 of 130 | 130 | 130 | 0 | 86 of 102 | 6.303 | 152 | 0 |
| 1 | `cross-2-4` | answered | 48 of 48 | 135 of 135 | 135 | 135 | - | 103 of 103 | 0.158 | 319 | 0 |
| 2 | `same-1` | dark | 48 of 48 | 0 of 63 | 0 | 0 | 17 | 95 of 95 | 7.033 | 161 | 60 |
| 2 | `same-2` | answered | 48 of 48 | 134 of 134 | 134 | 134 | - | 104 of 104 | 0.126 | 321 | 0 |
| 2 | `same-3` | dark | 48 of 48 | 0 of 82 | 0 | 0 | 13 | 90 of 90 | 7.097 | 156 | 50 |
| 2 | `same-4` | answered | 48 of 48 | 134 of 134 | 134 | 134 | - | 104 of 104 | 0.125 | 321 | 0 |
| 2 | `same-5` | dark | 48 of 48 | 0 of 41 | 0 | 0 | 21 | 86 of 86 | 6.788 | 153 | 80 |
| 2 | `same-6` | answered | 48 of 48 | 134 of 134 | 134 | 134 | - | 104 of 104 | 0.138 | 321 | 0 |
| 2 | `same-7` | dark | 48 of 48 | 0 of 119 | 0 | 0 | 5 | 97 of 97 | 6.586 | 164 | 20 |
| 2 | `same-8` | answered | 48 of 48 | 134 of 134 | 134 | 134 | - | 104 of 104 | 0.133 | 321 | 0 |
| 2 | `cross-2-1` | dark | 48 of 48 | 0 of 63 | 0 | 0 | 17 | 95 of 95 | 7.033 | 161 | 21 |
| 2 | `cross-1-2` | dark | 48 of 48 | 0 of 129 | 129 | 129 | 0 | 87 of 104 | 6.68 | 153 | 0 |
| 2 | `cross-2-4` | answered | 48 of 48 | 134 of 134 | 134 | 134 | - | 104 of 104 | 0.183 | 321 | 0 |
| 3 | `same-1` | dark | 48 of 48 | 0 of 63 | 0 | 0 | 17 | 92 of 92 | 7.07 | 158 | 60 |
| 3 | `same-2` | answered | 48 of 48 | 134 of 134 | 134 | 134 | - | 103 of 103 | 0.13 | 319 | 0 |
| 3 | `same-3` | dark | 48 of 48 | 0 of 85 | 0 | 0 | 12 | 84 of 84 | 6.705 | 150 | 50 |
| 3 | `same-4` | answered | 48 of 48 | 134 of 134 | 134 | 134 | - | 103 of 103 | 0.13 | 319 | 0 |
| 3 | `same-5` | dark | 48 of 48 | 0 of 45 | 0 | 0 | 20 | 93 of 93 | 6.815 | 159 | 70 |
| 3 | `same-6` | answered | 48 of 48 | 134 of 134 | 134 | 134 | - | 103 of 103 | 0.157 | 319 | 0 |
| 3 | `same-7` | dark | 48 of 48 | 0 of 117 | 0 | 0 | 6 | 81 of 81 | 7.21 | 147 | 30 |
| 3 | `same-8` | answered | 48 of 48 | 134 of 134 | 134 | 134 | - | 103 of 103 | 0.139 | 319 | 0 |
| 3 | `cross-2-1` | dark | 48 of 48 | 0 of 63 | 0 | 0 | 17 | 92 of 92 | 7.07 | 158 | 21 |
| 3 | `cross-1-2` | dark | 48 of 48 | 0 of 129 | 129 | 129 | 0 | 84 of 102 | 6.669 | 150 | 0 |
| 3 | `cross-2-4` | answered | 48 of 48 | 134 of 134 | 134 | 134 | - | 103 of 103 | 0.163 | 319 | 0 |

Every pass agrees on which rows went dark.

Pass 1 (`pass1/dark-switch/analysis.txt`):

```
pass 1 dark-switch: rail-sw1 dark (rails 1, 3, 5, 7); shut session 2.73 s, dark 27.10 s, restore session 2.84 s (host clock)
row          expect       before      dark  arrived  replied   arp     after  return s  guest rx  unreach
same-1       dark        48/48      0/130         0        0     0   86/102      6.295       152        0
same-2       answered    48/48    135/135       135      135     -  103/103      0.146       319        0
same-3       dark        48/48      0/130         0        0     0   85/102      6.503       151        0
same-4       answered    48/48    135/135       135      135     -  103/103       0.13       319        0
same-5       dark        48/48      0/130         0        0     0   90/102       6.52       156        0
same-6       answered    48/48    135/135       135      135     -  103/103      0.131       319        0
same-7       dark        48/48      0/119         0        0     6   81/81       7.419       147       30
same-8       answered    48/48    135/135       135      135     -  103/103      0.146       319        0
cross-2-1    dark        48/48      0/130         0        0     0   86/102      6.303       152        0
cross-1-2    dark        48/48      0/130       130      130     0   86/102      6.303       152        0
cross-2-4    answered    48/48    135/135       135      135     -  103/103      0.158       319        0

before, dark, after: answered of the requests that left the source's container port (host clock; a reply over 1000 ms counts as lost); arrived, replied: dark requests seen at the far node's port and its replies leaving it; arp: ARP requests for the far address on the dead rail while dark (from the source on a dead request rail, from the far node on a dead reply rail); guest rx: replies the guest's ping counted; unreach: its Destination Host Unreachable lines
```

Pass 2 (`pass2/dark-switch/analysis.txt`):

```
pass 2 dark-switch: rail-sw1 dark (rails 1, 3, 5, 7); shut session 2.91 s, dark 26.92 s, restore session 3.01 s (host clock)
row          expect       before      dark  arrived  replied   arp     after  return s  guest rx  unreach
same-1       dark        48/48      0/63          0        0    17   95/95       7.033       161       60
same-2       answered    48/48    134/134       134      134     -  104/104      0.126       321        0
same-3       dark        48/48      0/82          0        0    13   90/90       7.097       156       50
same-4       answered    48/48    134/134       134      134     -  104/104      0.125       321        0
same-5       dark        48/48      0/41          0        0    21   86/86       6.788       153       80
same-6       answered    48/48    134/134       134      134     -  104/104      0.138       321        0
same-7       dark        48/48      0/119         0        0     5   97/97       6.586       164       20
same-8       answered    48/48    134/134       134      134     -  104/104      0.133       321        0
cross-2-1    dark        48/48      0/63          0        0    17   95/95       7.033       161       21
cross-1-2    dark        48/48      0/129       129      129     0   87/104       6.68       153        0
cross-2-4    answered    48/48    134/134       134      134     -  104/104      0.183       321        0

before, dark, after: answered of the requests that left the source's container port (host clock; a reply over 1000 ms counts as lost); arrived, replied: dark requests seen at the far node's port and its replies leaving it; arp: ARP requests for the far address on the dead rail while dark (from the source on a dead request rail, from the far node on a dead reply rail); guest rx: replies the guest's ping counted; unreach: its Destination Host Unreachable lines
```

Pass 3 (`pass3/dark-switch/analysis.txt`):

```
pass 3 dark-switch: rail-sw1 dark (rails 1, 3, 5, 7); shut session 2.89 s, dark 26.94 s, restore session 2.79 s (host clock)
row          expect       before      dark  arrived  replied   arp     after  return s  guest rx  unreach
same-1       dark        48/48      0/63          0        0    17   92/92        7.07       158       60
same-2       answered    48/48    134/134       134      134     -  103/103       0.13       319        0
same-3       dark        48/48      0/85          0        0    12   84/84       6.705       150       50
same-4       answered    48/48    134/134       134      134     -  103/103       0.13       319        0
same-5       dark        48/48      0/45          0        0    20   93/93       6.815       159       70
same-6       answered    48/48    134/134       134      134     -  103/103      0.157       319        0
same-7       dark        48/48      0/117         0        0     6   81/81        7.21       147       30
same-8       answered    48/48    134/134       134      134     -  103/103      0.139       319        0
cross-2-1    dark        48/48      0/63          0        0    17   92/92        7.07       158       21
cross-1-2    dark        48/48      0/129       129      129     0   84/102      6.669       150        0
cross-2-4    answered    48/48    134/134       134      134     -  103/103      0.163       319        0

before, dark, after: answered of the requests that left the source's container port (host clock; a reply over 1000 ms counts as lost); arrived, replied: dark requests seen at the far node's port and its replies leaving it; arp: ARP requests for the far address on the dead rail while dark (from the source on a dead request rail, from the far node on a dead reply rail); guest rx: replies the guest's ping counted; unreach: its Destination Host Unreachable lines
```

The verdict so far (`verdict.txt`; the run's own RESULT line follows it there):

== RESULT: 153 passed, 0 failed, 3 known platform limitation(s), 0 skipped

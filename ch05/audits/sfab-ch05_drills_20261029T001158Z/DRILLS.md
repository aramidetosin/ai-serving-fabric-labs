# Rail drills

- Lab: `sfab-ch05`; labs repo commit `ad2f14ffba532ff5d8be0be16301f9fbc625f55f` (with uncommitted changes); UTC 2026-10-29T00:11:58Z; host tick 10000; passes: 3

## dark-switch: rail-sw1 dark, rails 1, 3, 5, 7

Answered of sent, by when each request was sent (host clock; the cut and the restore are the KLISH sessions). Return: seconds from the restore's session start to the first answered request.

| Pass | Row | Expect | Before | Dark | Reached the far node | Far node replied | ARP while dark | After | Return (s) | Guest log replies | Guest log unreachable |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | `same-1` | dark | 45 of 45 | 0 of 127 | 0 | 0 | 6 | 86 of 86 | 4.98 | 142 | 20 |
| 1 | `same-2` | answered | 45 of 45 | 138 of 138 | 138 | 138 | - | 99 of 99 | 0.035 | 299 | 0 |
| 1 | `same-3` | dark | 45 of 45 | 0 of 68 | 0 | 0 | 17 | 83 of 83 | 5.62 | 139 | 60 |
| 1 | `same-4` | answered | 45 of 45 | 138 of 138 | 138 | 138 | - | 98 of 98 | 0.051 | 298 | 0 |
| 1 | `same-5` | dark | 45 of 45 | 0 of 110 | 0 | 0 | 9 | 87 of 87 | 5.556 | 143 | 30 |
| 1 | `same-6` | answered | 45 of 45 | 138 of 138 | 138 | 138 | - | 98 of 98 | 0.035 | 298 | 0 |
| 1 | `same-7` | dark | 45 of 45 | 0 of 87 | 0 | 0 | 13 | 79 of 79 | 5.245 | 135 | 50 |
| 1 | `same-8` | answered | 45 of 45 | 138 of 138 | 138 | 138 | - | 98 of 98 | 0.035 | 298 | 0 |
| 1 | `cross-2-1` | dark | 45 of 45 | 0 of 127 | 0 | 0 | 6 | 86 of 86 | 4.98 | 142 | 9 |
| 1 | `cross-1-2` | dark | 45 of 45 | 0 of 137 | 137 | 137 | 0 | 82 of 99 | 4.795 | 138 | 0 |
| 1 | `cross-2-4` | answered | 45 of 45 | 138 of 138 | 138 | 138 | - | 98 of 98 | 0.043 | 298 | 0 |
| 2 | `same-1` | dark | 45 of 45 | 0 of 74 | 0 | 0 | 16 | 91 of 91 | 4.781 | 147 | 50 |
| 2 | `same-2` | answered | 45 of 45 | 139 of 139 | 139 | 139 | - | 97 of 97 | 0.189 | 298 | 0 |
| 2 | `same-3` | dark | 45 of 45 | 0 of 74 | 0 | 0 | 16 | 77 of 77 | 5.615 | 133 | 60 |
| 2 | `same-4` | answered | 45 of 45 | 138 of 138 | 138 | 138 | - | 98 of 98 | 0.045 | 298 | 0 |
| 2 | `same-5` | dark | 45 of 45 | 0 of 114 | 0 | 0 | 8 | 81 of 81 | 5.718 | 137 | 30 |
| 2 | `same-6` | answered | 45 of 45 | 138 of 138 | 138 | 138 | - | 98 of 98 | 0.045 | 298 | 0 |
| 2 | `same-7` | dark | 45 of 45 | 0 of 92 | 0 | 0 | 13 | 75 of 75 | 6.079 | 131 | 50 |
| 2 | `same-8` | answered | 45 of 45 | 138 of 138 | 138 | 138 | - | 98 of 98 | 0.045 | 298 | 0 |
| 2 | `cross-2-1` | dark | 45 of 45 | 0 of 74 | 0 | 0 | 16 | 93 of 93 | 4.781 | 149 | 18 |
| 2 | `cross-1-2` | dark | 45 of 45 | 0 of 139 | 139 | 96 | 12 | 85 of 98 | 3.942 | 142 | 0 |
| 2 | `cross-2-4` | answered | 45 of 45 | 139 of 139 | 139 | 139 | - | 97 of 97 | 0.19 | 298 | 0 |
| 3 | `same-1` | dark | 45 of 45 | 0 of 77 | 0 | 0 | 15 | 90 of 90 | 5.163 | 146 | 50 |
| 3 | `same-2` | answered | 45 of 45 | 138 of 138 | 138 | 138 | - | 98 of 98 | 0.203 | 299 | 0 |
| 3 | `same-3` | dark | 45 of 45 | 0 of 77 | 0 | 0 | 16 | 90 of 90 | 5.227 | 146 | 50 |
| 3 | `same-4` | answered | 45 of 45 | 137 of 137 | 137 | 137 | - | 99 of 99 | 0.035 | 299 | 0 |
| 3 | `same-5` | dark | 45 of 45 | 0 of 94 | 0 | 0 | 12 | 86 of 86 | 4.843 | 142 | 40 |
| 3 | `same-6` | answered | 45 of 45 | 137 of 137 | 137 | 137 | - | 98 of 98 | 0.043 | 298 | 0 |
| 3 | `same-7` | dark | 45 of 45 | 0 of 77 | 0 | 0 | 15 | 89 of 89 | 5.419 | 145 | 50 |
| 3 | `same-8` | answered | 45 of 45 | 137 of 137 | 137 | 137 | - | 98 of 98 | 0.043 | 298 | 0 |
| 3 | `cross-2-1` | dark | 45 of 45 | 0 of 77 | 0 | 0 | 15 | 90 of 90 | 5.163 | 146 | 18 |
| 3 | `cross-1-2` | dark | 45 of 45 | 0 of 138 | 138 | 98 | 11 | 84 of 98 | 4.363 | 140 | 0 |
| 3 | `cross-2-4` | answered | 45 of 45 | 138 of 138 | 138 | 138 | - | 98 of 98 | 0.203 | 299 | 0 |

Every pass agrees on which rows went dark.

Pass 1 (`pass1/dark-switch/analysis.txt`):

```
pass 1 dark-switch: rail-sw1 dark (rails 1, 3, 5, 7); shut session 1.26 s, dark 28.67 s, restore session 1.22 s (host clock)
row          expect       before      dark  arrived  replied   arp     after  return s  guest rx  unreach
same-1       dark        45/45      0/127         0        0     6   86/86        4.98       142       20
same-2       answered    45/45    138/138       138      138     -   99/99       0.035       299        0
same-3       dark        45/45      0/68          0        0    17   83/83        5.62       139       60
same-4       answered    45/45    138/138       138      138     -   98/98       0.051       298        0
same-5       dark        45/45      0/110         0        0     9   87/87       5.556       143       30
same-6       answered    45/45    138/138       138      138     -   98/98       0.035       298        0
same-7       dark        45/45      0/87          0        0    13   79/79       5.245       135       50
same-8       answered    45/45    138/138       138      138     -   98/98       0.035       298        0
cross-2-1    dark        45/45      0/127         0        0     6   86/86        4.98       142        9
cross-1-2    dark        45/45      0/137       137      137     0   82/99       4.795       138        0
cross-2-4    answered    45/45    138/138       138      138     -   98/98       0.043       298        0

before, dark, after: answered of the requests that left the source's container port (host clock; a reply over 1000 ms counts as lost); arrived, replied: dark requests seen at the far node's port and its replies leaving it; arp: ARP requests for the far address on the dead rail while dark (from the source on a dead request rail, from the far node on a dead reply rail); guest rx: replies the guest's ping counted; unreach: its Destination Host Unreachable lines
```

Pass 2 (`pass2/dark-switch/analysis.txt`):

```
pass 2 dark-switch: rail-sw1 dark (rails 1, 3, 5, 7); shut session 1.21 s, dark 28.72 s, restore session 1.24 s (host clock)
row          expect       before      dark  arrived  replied   arp     after  return s  guest rx  unreach
same-1       dark        45/45      0/74          0        0    16   91/91       4.781       147       50
same-2       answered    45/45    139/139       139      139     -   97/97       0.189       298        0
same-3       dark        45/45      0/74          0        0    16   77/77       5.615       133       60
same-4       answered    45/45    138/138       138      138     -   98/98       0.045       298        0
same-5       dark        45/45      0/114         0        0     8   81/81       5.718       137       30
same-6       answered    45/45    138/138       138      138     -   98/98       0.045       298        0
same-7       dark        45/45      0/92          0        0    13   75/75       6.079       131       50
same-8       answered    45/45    138/138       138      138     -   98/98       0.045       298        0
cross-2-1    dark        45/45      0/74          0        0    16   93/93       4.781       149       18
cross-1-2    dark        45/45      0/139       139       96    12   85/98       3.942       142        0
cross-2-4    answered    45/45    139/139       139      139     -   97/97        0.19       298        0

before, dark, after: answered of the requests that left the source's container port (host clock; a reply over 1000 ms counts as lost); arrived, replied: dark requests seen at the far node's port and its replies leaving it; arp: ARP requests for the far address on the dead rail while dark (from the source on a dead request rail, from the far node on a dead reply rail); guest rx: replies the guest's ping counted; unreach: its Destination Host Unreachable lines
```

Pass 3 (`pass3/dark-switch/analysis.txt`):

```
pass 3 dark-switch: rail-sw1 dark (rails 1, 3, 5, 7); shut session 1.29 s, dark 28.64 s, restore session 1.24 s (host clock)
row          expect       before      dark  arrived  replied   arp     after  return s  guest rx  unreach
same-1       dark        45/45      0/77          0        0    15   90/90       5.163       146       50
same-2       answered    45/45    138/138       138      138     -   98/98       0.203       299        0
same-3       dark        45/45      0/77          0        0    16   90/90       5.227       146       50
same-4       answered    45/45    137/137       137      137     -   99/99       0.035       299        0
same-5       dark        45/45      0/94          0        0    12   86/86       4.843       142       40
same-6       answered    45/45    137/137       137      137     -   98/98       0.043       298        0
same-7       dark        45/45      0/77          0        0    15   89/89       5.419       145       50
same-8       answered    45/45    137/137       137      137     -   98/98       0.043       298        0
cross-2-1    dark        45/45      0/77          0        0    15   90/90       5.163       146       18
cross-1-2    dark        45/45      0/138       138       98    11   84/98       4.363       140        0
cross-2-4    answered    45/45    138/138       138      138     -   98/98       0.203       299        0

before, dark, after: answered of the requests that left the source's container port (host clock; a reply over 1000 ms counts as lost); arrived, replied: dark requests seen at the far node's port and its replies leaving it; arp: ARP requests for the far address on the dead rail while dark (from the source on a dead request rail, from the far node on a dead reply rail); guest rx: replies the guest's ping counted; unreach: its Destination Host Unreachable lines
```

The verdict so far (`verdict.txt`; the run's own RESULT line follows it there):

== RESULT: 154 passed, 0 failed, 3 known platform limitation(s), 0 skipped

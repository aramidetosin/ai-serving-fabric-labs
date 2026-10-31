# Serving drills

- Lab: `sfab-ch06`; labs repo commit `39786511f9876ee9998dd48ca53d91efaf83680d`; UTC 2026-10-28T21:25:55Z
- Every time is the lab host's clock; passes: 3

## dark-switch: serve-dark on rail-sw1, copies out chat-c

| Pass | Shut session | Restore session | Whole after restore | Service | Server left (after the cut) | Back (after the restore) |
|---|---|---|---|---|---|---|
| 1 | 3.209 s | 3.779 s | 17.915 s | chat (chat-c-server-0) | 4.2 to 5.2 s | 16.9 to 17.9 s |
| 1 | 3.209 s | 3.779 s | 17.915 s | chat-c (chat-c-server-0) | 4.2 to 5.2 s | 16.9 to 17.9 s |
| 2 | 3.493 s | 3.921 s | 8.756 s | chat (chat-c-server-0) | 6.2 to 7.2 s | 7.7 to 8.8 s |
| 2 | 3.493 s | 3.921 s | 8.756 s | chat-c (chat-c-server-0) | 6.2 to 7.2 s | 7.7 to 8.8 s |
| 3 | 3.527 s | 3.822 s | 7.416 s | chat (chat-c-server-0) | 6.8 to 7.8 s | 6.4 to 7.4 s |
| 3 | 3.527 s | 3.822 s | 7.416 s | chat-c (chat-c-server-0) | 6.8 to 7.8 s | 6.4 to 7.4 s |

| Pass | Model | Sent | Answered | Failed | Sent while down, answered | Router retries | Slowest answer |
|---|---|---|---|---|---|---|---|
| 1 | chat | 59 | 59 | 0 | 19 of 19 | 0 | 54.883 s |
| 1 | staff | 4 | 4 | 0 | 2 of 2 | 0 | 60.195 s |
| 2 | chat | 54 | 54 | 0 | 19 of 19 | 0 | 4.128 s |
| 2 | staff | 4 | 4 | 0 | 2 of 2 | 0 | 31.666 s |
| 3 | chat | 53 | 53 | 0 | 19 of 19 | 0 | 5.953 s |
| 3 | staff | 4 | 4 | 0 | 2 of 2 | 0 | 56.144 s |

Every pass agrees on which servers left which Services.

## rail-move

```
  FAIL  the table keeps the recipe's rules (every pod of a copy on one rail, one server and a worker a copy, every address once) -> copy chat-a spans the attachments ['rail3', 'rail5']: every pod of a copy sits on one rail
  FAIL  chat-a-worker0-0 (chat copy a, worker): on k8s-gpu1, rail 5 as rail5 10.21.5.102 02:5a:fe:05:00:66, Ready -> network-status names serving/rail3 10.21.3.101; label rail=rail3
  PASS  no StatefulSet the table does not name
  FAIL  chat-a-worker0-0: ggml-rpc-server bound to its rail address 10.21.5.102:50052 -> bound to 10.21.3.101:50052
  FAIL  chat-a-worker0-0: listening on 10.21.5.102:50052 alone (ggml-rpc only on the rail; the pod's cluster interface answers nothing) -> listening on 10.21.3.101:50052
  PASS  one macvlan attachment per rail the table uses (rail3, rail4, rail5, rail6, rail7): the rail NIC as master, bridge mode, MTU 9000, the static IPAM plugin and no route
  PASS  no rail attachment the table does not use
  FAIL  in every pod the default route on eth0, and on its rail attachment only the rail's connected prefix (11 pods read on their nodes) -> chat-a-worker0-0: on rail5:
  PASS  no server or worker pod the table does not name
```

## worker-port: worker-port on rail-sw1, copies out chat-c

| Pass | Shut session | Restore session | Whole after restore | Service | Server left (after the cut) | Back (after the restore) |
|---|---|---|---|---|---|---|
| 1 | 3.748 s | 3.488 s | 7.524 s | chat (chat-c-server-0) | 6.9 to 7.9 s | 6.5 to 7.5 s |
| 1 | 3.748 s | 3.488 s | 7.524 s | chat-c (chat-c-server-0) | 6.9 to 7.9 s | 6.5 to 7.5 s |
| 2 | 3.615 s | 3.544 s | 7.863 s | chat (chat-c-server-0) | 6.2 to 7.2 s | 6.9 to 7.9 s |
| 2 | 3.615 s | 3.544 s | 7.863 s | chat-c (chat-c-server-0) | 6.2 to 7.2 s | 6.9 to 7.9 s |
| 3 | 3.685 s | 3.552 s | 16.602 s | chat (chat-c-server-0) | 5.9 to 6.9 s | 15.6 to 16.6 s |
| 3 | 3.685 s | 3.552 s | 16.602 s | chat-c (chat-c-server-0) | 5.9 to 6.9 s | 15.6 to 16.6 s |

| Pass | Model | Sent | Answered | Failed | Sent while down, answered | Router retries | Slowest answer |
|---|---|---|---|---|---|---|---|
| 1 | chat | 54 | 54 | 0 | 18 of 18 | 0 | 4.092 s |
| 1 | staff | 4 | 4 | 0 | 1 of 1 | 0 | 58.871 s |
| 2 | chat | 54 | 54 | 0 | 18 of 18 | 0 | 56.063 s |
| 2 | staff | 4 | 4 | 0 | 1 of 1 | 0 | 55.661 s |
| 3 | chat | 59 | 59 | 0 | 18 of 18 | 0 | 55.383 s |
| 3 | staff | 4 | 4 | 0 | 1 of 1 | 0 | 59.79 s |

Every pass agrees on which servers left which Services.

## Files

- `pass<N>/<drill>/`: `timeline.txt` (the host-clock moments), `endpoints.jsonl` (each read of the EndpointSlices), `records-<model>.jsonl` (each request of the gateway probe), `klish/` (the switch before, during and after), the pods and events read, `analysis.json` and `analysis.txt`
- `pass<N>/rail-move/`: the moved table, the recipe's refusal of it, and the audits against it and against the table as rendered

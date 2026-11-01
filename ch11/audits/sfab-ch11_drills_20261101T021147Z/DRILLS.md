# Drills

- Lab: `sfab-ch11`; labs repo commit `86a59ddfea6f405c4d6d70af509ef75a856ac3a8`; UTC 2026-11-01T02:11:47Z

## isolation-under-load: pass1

```
== pass 1 isolation-under-load: 8 held connection(s) a population
  PASS  pass 1 isolation-under-load x1 enterprise: 8 connection(s) from ent-client held to gw-users at 10.20.11.210:443 (llm.ai.tarnwick.example), 48 replies, every one 200
  PASS  pass 1 isolation-under-load x1 enterprise: the firewall counts 8 session(s) from enterprise destination 10.20.11.210 destination-port 443 while they are held, within the plan's bound 8 to 11
  PASS  pass 1 isolation-under-load x1 internet: 8 connection(s) from inet-client held to gw-inet at 198.51.100.10:443 (llm.ai.tarnwick.example), 48 replies, every one 200
  PASS  pass 1 isolation-under-load x1 internet: the firewall counts 8 session(s) from isp destination 198.51.100.10 destination-port 443 while they are held, within the plan's bound 8 to 11
  PASS  pass 1 isolation-under-load x1 operator: 8 connection(s) from ops-client held to gw-internal at 10.20.11.200:443 (llm.ai.tarnwick.example), 48 replies, every one 200
  PASS  pass 1 isolation-under-load x1 operator: the firewall counts 8 session(s) from operator-vpn destination 10.20.11.200 destination-port 443 while they are held, within the plan's bound 8 to 11
  PASS  pass 1 isolation-under-load x1 enterprise (ent-client): its own Gateway 10 of 10 answered 200; gw-internal 0/10 through; gw-users 10/10 allowed; gw-inet 0/10 through; admin 0/10 through
  PASS  pass 1 isolation-under-load x1 internet (inet-client): its own Gateway 10 of 10 answered 200; gw-internal 0/10 through; gw-users 0/10 through; gw-inet 10/10 allowed; staff 0/10 through; admin 0/10 through
  PASS  pass 1 isolation-under-load x1 operator (ops-client): its own Gateway 10 of 10 answered 200; gw-internal 10/10 allowed; gw-users 0/10 through; gw-inet 0/10 through; admin 10/10 allowed
== pass 1 isolation-under-load: 16 held connection(s) a population
  PASS  pass 1 isolation-under-load x2 enterprise: 16 connection(s) from ent-client held to gw-users at 10.20.11.210:443 (llm.ai.tarnwick.example), 96 replies, every one 200
  PASS  pass 1 isolation-under-load x2 enterprise: the firewall counts 16 session(s) from enterprise destination 10.20.11.210 destination-port 443 while they are held, within the plan's bound 16 to 19
  PASS  pass 1 isolation-under-load x2 internet: 16 connection(s) from inet-client held to gw-inet at 198.51.100.10:443 (llm.ai.tarnwick.example), 96 replies, every one 200
  PASS  pass 1 isolation-under-load x2 internet: the firewall counts 16 session(s) from isp destination 198.51.100.10 destination-port 443 while they are held, within the plan's bound 16 to 19
  PASS  pass 1 isolation-under-load x2 operator: 16 connection(s) from ops-client held to gw-internal at 10.20.11.200:443 (llm.ai.tarnwick.example), 96 replies, every one 200
  PASS  pass 1 isolation-under-load x2 operator: the firewall counts 16 session(s) from operator-vpn destination 10.20.11.200 destination-port 443 while they are held, within the plan's bound 16 to 19
  PASS  pass 1 isolation-under-load x2 enterprise (ent-client): its own Gateway 10 of 10 answered 200; gw-internal 0/10 through; gw-users 10/10 allowed; gw-inet 0/10 through; admin 0/10 through
  PASS  pass 1 isolation-under-load x2 internet (inet-client): its own Gateway 10 of 10 answered 200; gw-internal 0/10 through; gw-users 0/10 through; gw-inet 10/10 allowed; staff 0/10 through; admin 0/10 through
  PASS  pass 1 isolation-under-load x2 operator (ops-client): its own Gateway 10 of 10 answered 200; gw-internal 10/10 allowed; gw-users 0/10 through; gw-inet 0/10 through; admin 10/10 allowed
```

## leaked-key: pass1

```
  PASS  pass 1 leaked-key: the key Job minted batch.fb000001, a key of batch, a caller of the enterprise audience
  PASS  pass 1 leaked-key: inet-client, a client of the internet audience, through gw-inet to chat with batch.fb000001: HTTP 200 17.653 s after the mint: no network layer refuses it, the caller's key is not bound to a Gateway
  PASS  pass 1 leaked-key: the API gateway's access log names caller batch for it (2 answered line(s) of consumer batch_key_fb000001, the first at api-gateway-access.txt:139): the log says who, the Gateway says from where
  PASS  pass 1 leaked-key: after the revoke the same key refused HTTP 401, 2.41 s after it
  PASS  pass 1 leaked-key: the key Secret holds the same 3 fields and fingerprints after the drill as before, and no batch.fb000001
```

## isolation-under-load: pass2

```
== pass 2 isolation-under-load: 8 held connection(s) a population
  PASS  pass 2 isolation-under-load x1 enterprise: 8 connection(s) from ent-client held to gw-users at 10.20.11.210:443 (llm.ai.tarnwick.example), 48 replies, every one 200
  PASS  pass 2 isolation-under-load x1 enterprise: the firewall counts 8 session(s) from enterprise destination 10.20.11.210 destination-port 443 while they are held, within the plan's bound 8 to 11
  PASS  pass 2 isolation-under-load x1 internet: 8 connection(s) from inet-client held to gw-inet at 198.51.100.10:443 (llm.ai.tarnwick.example), 48 replies, every one 200
  PASS  pass 2 isolation-under-load x1 internet: the firewall counts 8 session(s) from isp destination 198.51.100.10 destination-port 443 while they are held, within the plan's bound 8 to 11
  PASS  pass 2 isolation-under-load x1 operator: 8 connection(s) from ops-client held to gw-internal at 10.20.11.200:443 (llm.ai.tarnwick.example), 48 replies, every one 200
  PASS  pass 2 isolation-under-load x1 operator: the firewall counts 8 session(s) from operator-vpn destination 10.20.11.200 destination-port 443 while they are held, within the plan's bound 8 to 11
  PASS  pass 2 isolation-under-load x1 enterprise (ent-client): its own Gateway 10 of 10 answered 200; gw-internal 0/10 through; gw-users 10/10 allowed; gw-inet 0/10 through; admin 0/10 through
  PASS  pass 2 isolation-under-load x1 internet (inet-client): its own Gateway 10 of 10 answered 200; gw-internal 0/10 through; gw-users 0/10 through; gw-inet 10/10 allowed; staff 0/10 through; admin 0/10 through
  PASS  pass 2 isolation-under-load x1 operator (ops-client): its own Gateway 10 of 10 answered 200; gw-internal 10/10 allowed; gw-users 0/10 through; gw-inet 0/10 through; admin 10/10 allowed
== pass 2 isolation-under-load: 16 held connection(s) a population
  PASS  pass 2 isolation-under-load x2 enterprise: 16 connection(s) from ent-client held to gw-users at 10.20.11.210:443 (llm.ai.tarnwick.example), 96 replies, every one 200
  PASS  pass 2 isolation-under-load x2 enterprise: the firewall counts 16 session(s) from enterprise destination 10.20.11.210 destination-port 443 while they are held, within the plan's bound 16 to 19
  PASS  pass 2 isolation-under-load x2 internet: 16 connection(s) from inet-client held to gw-inet at 198.51.100.10:443 (llm.ai.tarnwick.example), 96 replies, every one 200
  PASS  pass 2 isolation-under-load x2 internet: the firewall counts 16 session(s) from isp destination 198.51.100.10 destination-port 443 while they are held, within the plan's bound 16 to 19
  PASS  pass 2 isolation-under-load x2 operator: 16 connection(s) from ops-client held to gw-internal at 10.20.11.200:443 (llm.ai.tarnwick.example), 96 replies, every one 200
  PASS  pass 2 isolation-under-load x2 operator: the firewall counts 16 session(s) from operator-vpn destination 10.20.11.200 destination-port 443 while they are held, within the plan's bound 16 to 19
  PASS  pass 2 isolation-under-load x2 enterprise (ent-client): its own Gateway 10 of 10 answered 200; gw-internal 0/10 through; gw-users 10/10 allowed; gw-inet 0/10 through; admin 0/10 through
  PASS  pass 2 isolation-under-load x2 internet (inet-client): its own Gateway 10 of 10 answered 200; gw-internal 0/10 through; gw-users 0/10 through; gw-inet 10/10 allowed; staff 0/10 through; admin 0/10 through
  PASS  pass 2 isolation-under-load x2 operator (ops-client): its own Gateway 10 of 10 answered 200; gw-internal 10/10 allowed; gw-users 0/10 through; gw-inet 0/10 through; admin 10/10 allowed
```

## leaked-key: pass2

```
  PASS  pass 2 leaked-key: the key Job minted batch.fb000002, a key of batch, a caller of the enterprise audience
  PASS  pass 2 leaked-key: inet-client, a client of the internet audience, through gw-inet to chat with batch.fb000002: HTTP 200 17.594 s after the mint: no network layer refuses it, the caller's key is not bound to a Gateway
  PASS  pass 2 leaked-key: the API gateway's access log names caller batch for it (1 answered line(s) of consumer batch_key_fb000002, the first at api-gateway-access.txt:296): the log says who, the Gateway says from where
  PASS  pass 2 leaked-key: after the revoke the same key refused HTTP 401, 0.149 s after it
  PASS  pass 2 leaked-key: the key Secret holds the same 3 fields and fingerprints after the drill as before, and no batch.fb000002
```

## isolation-under-load: pass3

```
== pass 3 isolation-under-load: 8 held connection(s) a population
  PASS  pass 3 isolation-under-load x1 enterprise: 8 connection(s) from ent-client held to gw-users at 10.20.11.210:443 (llm.ai.tarnwick.example), 48 replies, every one 200
  PASS  pass 3 isolation-under-load x1 enterprise: the firewall counts 8 session(s) from enterprise destination 10.20.11.210 destination-port 443 while they are held, within the plan's bound 8 to 11
  PASS  pass 3 isolation-under-load x1 internet: 8 connection(s) from inet-client held to gw-inet at 198.51.100.10:443 (llm.ai.tarnwick.example), 48 replies, every one 200
  PASS  pass 3 isolation-under-load x1 internet: the firewall counts 8 session(s) from isp destination 198.51.100.10 destination-port 443 while they are held, within the plan's bound 8 to 11
  PASS  pass 3 isolation-under-load x1 operator: 8 connection(s) from ops-client held to gw-internal at 10.20.11.200:443 (llm.ai.tarnwick.example), 48 replies, every one 200
  PASS  pass 3 isolation-under-load x1 operator: the firewall counts 8 session(s) from operator-vpn destination 10.20.11.200 destination-port 443 while they are held, within the plan's bound 8 to 11
  PASS  pass 3 isolation-under-load x1 enterprise (ent-client): its own Gateway 10 of 10 answered 200; gw-internal 0/10 through; gw-users 10/10 allowed; gw-inet 0/10 through; admin 0/10 through
  PASS  pass 3 isolation-under-load x1 internet (inet-client): its own Gateway 10 of 10 answered 200; gw-internal 0/10 through; gw-users 0/10 through; gw-inet 10/10 allowed; staff 0/10 through; admin 0/10 through
  PASS  pass 3 isolation-under-load x1 operator (ops-client): its own Gateway 10 of 10 answered 200; gw-internal 10/10 allowed; gw-users 0/10 through; gw-inet 0/10 through; admin 10/10 allowed
== pass 3 isolation-under-load: 16 held connection(s) a population
  PASS  pass 3 isolation-under-load x2 enterprise: 16 connection(s) from ent-client held to gw-users at 10.20.11.210:443 (llm.ai.tarnwick.example), 96 replies, every one 200
  PASS  pass 3 isolation-under-load x2 enterprise: the firewall counts 16 session(s) from enterprise destination 10.20.11.210 destination-port 443 while they are held, within the plan's bound 16 to 19
  PASS  pass 3 isolation-under-load x2 internet: 16 connection(s) from inet-client held to gw-inet at 198.51.100.10:443 (llm.ai.tarnwick.example), 96 replies, every one 200
  PASS  pass 3 isolation-under-load x2 internet: the firewall counts 16 session(s) from isp destination 198.51.100.10 destination-port 443 while they are held, within the plan's bound 16 to 19
  PASS  pass 3 isolation-under-load x2 operator: 16 connection(s) from ops-client held to gw-internal at 10.20.11.200:443 (llm.ai.tarnwick.example), 96 replies, every one 200
  PASS  pass 3 isolation-under-load x2 operator: the firewall counts 16 session(s) from operator-vpn destination 10.20.11.200 destination-port 443 while they are held, within the plan's bound 16 to 19
  PASS  pass 3 isolation-under-load x2 enterprise (ent-client): its own Gateway 10 of 10 answered 200; gw-internal 0/10 through; gw-users 10/10 allowed; gw-inet 0/10 through; admin 0/10 through
  PASS  pass 3 isolation-under-load x2 internet (inet-client): its own Gateway 10 of 10 answered 200; gw-internal 0/10 through; gw-users 0/10 through; gw-inet 10/10 allowed; staff 0/10 through; admin 0/10 through
  PASS  pass 3 isolation-under-load x2 operator (ops-client): its own Gateway 10 of 10 answered 200; gw-internal 10/10 allowed; gw-users 0/10 through; gw-inet 0/10 through; admin 10/10 allowed
```

## leaked-key: pass3

```
  PASS  pass 3 leaked-key: the key Job minted batch.fb000003, a key of batch, a caller of the enterprise audience
  PASS  pass 3 leaked-key: inet-client, a client of the internet audience, through gw-inet to chat with batch.fb000003: HTTP 200 2.845 s after the mint: no network layer refuses it, the caller's key is not bound to a Gateway
  PASS  pass 3 leaked-key: the API gateway's access log names caller batch for it (2 answered line(s) of consumer batch_key_fb000003, the first at api-gateway-access.txt:456): the log says who, the Gateway says from where
  PASS  pass 3 leaked-key: after the revoke the same key refused HTTP 401, 2.403 s after it
  PASS  pass 3 leaked-key: the key Secret holds the same 3 fields and fingerprints after the drill as before, and no batch.fb000003
```

## Verdict

```
== pass 1, drill isolation-under-load: every population's own Gateway under held load, and every forbidden try refused
== pass 1 isolation-under-load: 8 held connection(s) a population
== pass 1 isolation-under-load: 16 held connection(s) a population
  PASS  pass 1 isolation-under-load: audit.sh --quick after the drill: RESULT: 351 passed, 0 failed, 0 known platform limitation(s), 1 skipped
== pass 1 isolation-under-load: 8 held connection(s) a population
  PASS  pass 1 isolation-under-load x1 enterprise: 8 connection(s) from ent-client held to gw-users at 10.20.11.210:443 (llm.ai.tarnwick.example), 48 replies, every one 200
  PASS  pass 1 isolation-under-load x1 enterprise: the firewall counts 8 session(s) from enterprise destination 10.20.11.210 destination-port 443 while they are held, within the plan's bound 8 to 11
  PASS  pass 1 isolation-under-load x1 internet: 8 connection(s) from inet-client held to gw-inet at 198.51.100.10:443 (llm.ai.tarnwick.example), 48 replies, every one 200
  PASS  pass 1 isolation-under-load x1 internet: the firewall counts 8 session(s) from isp destination 198.51.100.10 destination-port 443 while they are held, within the plan's bound 8 to 11
  PASS  pass 1 isolation-under-load x1 operator: 8 connection(s) from ops-client held to gw-internal at 10.20.11.200:443 (llm.ai.tarnwick.example), 48 replies, every one 200
  PASS  pass 1 isolation-under-load x1 operator: the firewall counts 8 session(s) from operator-vpn destination 10.20.11.200 destination-port 443 while they are held, within the plan's bound 8 to 11
  PASS  pass 1 isolation-under-load x1 enterprise (ent-client): its own Gateway 10 of 10 answered 200; gw-internal 0/10 through; gw-users 10/10 allowed; gw-inet 0/10 through; admin 0/10 through
  PASS  pass 1 isolation-under-load x1 internet (inet-client): its own Gateway 10 of 10 answered 200; gw-internal 0/10 through; gw-users 0/10 through; gw-inet 10/10 allowed; staff 0/10 through; admin 0/10 through
  PASS  pass 1 isolation-under-load x1 operator (ops-client): its own Gateway 10 of 10 answered 200; gw-internal 10/10 allowed; gw-users 0/10 through; gw-inet 0/10 through; admin 10/10 allowed
== pass 1 isolation-under-load: 16 held connection(s) a population
  PASS  pass 1 isolation-under-load x2 enterprise: 16 connection(s) from ent-client held to gw-users at 10.20.11.210:443 (llm.ai.tarnwick.example), 96 replies, every one 200
  PASS  pass 1 isolation-under-load x2 enterprise: the firewall counts 16 session(s) from enterprise destination 10.20.11.210 destination-port 443 while they are held, within the plan's bound 16 to 19
  PASS  pass 1 isolation-under-load x2 internet: 16 connection(s) from inet-client held to gw-inet at 198.51.100.10:443 (llm.ai.tarnwick.example), 96 replies, every one 200
  PASS  pass 1 isolation-under-load x2 internet: the firewall counts 16 session(s) from isp destination 198.51.100.10 destination-port 443 while they are held, within the plan's bound 16 to 19
  PASS  pass 1 isolation-under-load x2 operator: 16 connection(s) from ops-client held to gw-internal at 10.20.11.200:443 (llm.ai.tarnwick.example), 96 replies, every one 200
  PASS  pass 1 isolation-under-load x2 operator: the firewall counts 16 session(s) from operator-vpn destination 10.20.11.200 destination-port 443 while they are held, within the plan's bound 16 to 19
  PASS  pass 1 isolation-under-load x2 enterprise (ent-client): its own Gateway 10 of 10 answered 200; gw-internal 0/10 through; gw-users 10/10 allowed; gw-inet 0/10 through; admin 0/10 through
  PASS  pass 1 isolation-under-load x2 internet (inet-client): its own Gateway 10 of 10 answered 200; gw-internal 0/10 through; gw-users 0/10 through; gw-inet 10/10 allowed; staff 0/10 through; admin 0/10 through
  PASS  pass 1 isolation-under-load x2 operator (ops-client): its own Gateway 10 of 10 answered 200; gw-internal 10/10 allowed; gw-users 0/10 through; gw-inet 0/10 through; admin 10/10 allowed
== pass 1, drill leaked-key: an enterprise caller's key used from the internet, answered, then refused after its revoke
  PASS  pass 1 leaked-key: audit.sh --quick after the drill: RESULT: 351 passed, 0 failed, 0 known platform limitation(s), 1 skipped
  PASS  pass 1 leaked-key: the key Job minted batch.fb000001, a key of batch, a caller of the enterprise audience
  PASS  pass 1 leaked-key: inet-client, a client of the internet audience, through gw-inet to chat with batch.fb000001: HTTP 200 17.653 s after the mint: no network layer refuses it, the caller's key is not bound to a Gateway
  PASS  pass 1 leaked-key: the API gateway's access log names caller batch for it (2 answered line(s) of consumer batch_key_fb000001, the first at api-gateway-access.txt:139): the log says who, the Gateway says from where
  PASS  pass 1 leaked-key: after the revoke the same key refused HTTP 401, 2.41 s after it
  PASS  pass 1 leaked-key: the key Secret holds the same 3 fields and fingerprints after the drill as before, and no batch.fb000001
== pass 2, drill isolation-under-load: every population's own Gateway under held load, and every forbidden try refused
== pass 2 isolation-under-load: 8 held connection(s) a population
== pass 2 isolation-under-load: 16 held connection(s) a population
  PASS  pass 2 isolation-under-load: audit.sh --quick after the drill: RESULT: 351 passed, 0 failed, 0 known platform limitation(s), 1 skipped
== pass 2 isolation-under-load: 8 held connection(s) a population
  PASS  pass 2 isolation-under-load x1 enterprise: 8 connection(s) from ent-client held to gw-users at 10.20.11.210:443 (llm.ai.tarnwick.example), 48 replies, every one 200
  PASS  pass 2 isolation-under-load x1 enterprise: the firewall counts 8 session(s) from enterprise destination 10.20.11.210 destination-port 443 while they are held, within the plan's bound 8 to 11
  PASS  pass 2 isolation-under-load x1 internet: 8 connection(s) from inet-client held to gw-inet at 198.51.100.10:443 (llm.ai.tarnwick.example), 48 replies, every one 200
  PASS  pass 2 isolation-under-load x1 internet: the firewall counts 8 session(s) from isp destination 198.51.100.10 destination-port 443 while they are held, within the plan's bound 8 to 11
  PASS  pass 2 isolation-under-load x1 operator: 8 connection(s) from ops-client held to gw-internal at 10.20.11.200:443 (llm.ai.tarnwick.example), 48 replies, every one 200
  PASS  pass 2 isolation-under-load x1 operator: the firewall counts 8 session(s) from operator-vpn destination 10.20.11.200 destination-port 443 while they are held, within the plan's bound 8 to 11
  PASS  pass 2 isolation-under-load x1 enterprise (ent-client): its own Gateway 10 of 10 answered 200; gw-internal 0/10 through; gw-users 10/10 allowed; gw-inet 0/10 through; admin 0/10 through
  PASS  pass 2 isolation-under-load x1 internet (inet-client): its own Gateway 10 of 10 answered 200; gw-internal 0/10 through; gw-users 0/10 through; gw-inet 10/10 allowed; staff 0/10 through; admin 0/10 through
  PASS  pass 2 isolation-under-load x1 operator (ops-client): its own Gateway 10 of 10 answered 200; gw-internal 10/10 allowed; gw-users 0/10 through; gw-inet 0/10 through; admin 10/10 allowed
== pass 2 isolation-under-load: 16 held connection(s) a population
  PASS  pass 2 isolation-under-load x2 enterprise: 16 connection(s) from ent-client held to gw-users at 10.20.11.210:443 (llm.ai.tarnwick.example), 96 replies, every one 200
  PASS  pass 2 isolation-under-load x2 enterprise: the firewall counts 16 session(s) from enterprise destination 10.20.11.210 destination-port 443 while they are held, within the plan's bound 16 to 19
  PASS  pass 2 isolation-under-load x2 internet: 16 connection(s) from inet-client held to gw-inet at 198.51.100.10:443 (llm.ai.tarnwick.example), 96 replies, every one 200
  PASS  pass 2 isolation-under-load x2 internet: the firewall counts 16 session(s) from isp destination 198.51.100.10 destination-port 443 while they are held, within the plan's bound 16 to 19
  PASS  pass 2 isolation-under-load x2 operator: 16 connection(s) from ops-client held to gw-internal at 10.20.11.200:443 (llm.ai.tarnwick.example), 96 replies, every one 200
  PASS  pass 2 isolation-under-load x2 operator: the firewall counts 16 session(s) from operator-vpn destination 10.20.11.200 destination-port 443 while they are held, within the plan's bound 16 to 19
  PASS  pass 2 isolation-under-load x2 enterprise (ent-client): its own Gateway 10 of 10 answered 200; gw-internal 0/10 through; gw-users 10/10 allowed; gw-inet 0/10 through; admin 0/10 through
  PASS  pass 2 isolation-under-load x2 internet (inet-client): its own Gateway 10 of 10 answered 200; gw-internal 0/10 through; gw-users 0/10 through; gw-inet 10/10 allowed; staff 0/10 through; admin 0/10 through
  PASS  pass 2 isolation-under-load x2 operator (ops-client): its own Gateway 10 of 10 answered 200; gw-internal 10/10 allowed; gw-users 0/10 through; gw-inet 0/10 through; admin 10/10 allowed
== pass 2, drill leaked-key: an enterprise caller's key used from the internet, answered, then refused after its revoke
  PASS  pass 2 leaked-key: audit.sh --quick after the drill: RESULT: 351 passed, 0 failed, 0 known platform limitation(s), 1 skipped
  PASS  pass 2 leaked-key: the key Job minted batch.fb000002, a key of batch, a caller of the enterprise audience
  PASS  pass 2 leaked-key: inet-client, a client of the internet audience, through gw-inet to chat with batch.fb000002: HTTP 200 17.594 s after the mint: no network layer refuses it, the caller's key is not bound to a Gateway
  PASS  pass 2 leaked-key: the API gateway's access log names caller batch for it (1 answered line(s) of consumer batch_key_fb000002, the first at api-gateway-access.txt:296): the log says who, the Gateway says from where
  PASS  pass 2 leaked-key: after the revoke the same key refused HTTP 401, 0.149 s after it
  PASS  pass 2 leaked-key: the key Secret holds the same 3 fields and fingerprints after the drill as before, and no batch.fb000002
== pass 3, drill isolation-under-load: every population's own Gateway under held load, and every forbidden try refused
== pass 3 isolation-under-load: 8 held connection(s) a population
== pass 3 isolation-under-load: 16 held connection(s) a population
  PASS  pass 3 isolation-under-load: audit.sh --quick after the drill: RESULT: 351 passed, 0 failed, 0 known platform limitation(s), 1 skipped
== pass 3 isolation-under-load: 8 held connection(s) a population
  PASS  pass 3 isolation-under-load x1 enterprise: 8 connection(s) from ent-client held to gw-users at 10.20.11.210:443 (llm.ai.tarnwick.example), 48 replies, every one 200
  PASS  pass 3 isolation-under-load x1 enterprise: the firewall counts 8 session(s) from enterprise destination 10.20.11.210 destination-port 443 while they are held, within the plan's bound 8 to 11
  PASS  pass 3 isolation-under-load x1 internet: 8 connection(s) from inet-client held to gw-inet at 198.51.100.10:443 (llm.ai.tarnwick.example), 48 replies, every one 200
  PASS  pass 3 isolation-under-load x1 internet: the firewall counts 8 session(s) from isp destination 198.51.100.10 destination-port 443 while they are held, within the plan's bound 8 to 11
  PASS  pass 3 isolation-under-load x1 operator: 8 connection(s) from ops-client held to gw-internal at 10.20.11.200:443 (llm.ai.tarnwick.example), 48 replies, every one 200
  PASS  pass 3 isolation-under-load x1 operator: the firewall counts 8 session(s) from operator-vpn destination 10.20.11.200 destination-port 443 while they are held, within the plan's bound 8 to 11
  PASS  pass 3 isolation-under-load x1 enterprise (ent-client): its own Gateway 10 of 10 answered 200; gw-internal 0/10 through; gw-users 10/10 allowed; gw-inet 0/10 through; admin 0/10 through
  PASS  pass 3 isolation-under-load x1 internet (inet-client): its own Gateway 10 of 10 answered 200; gw-internal 0/10 through; gw-users 0/10 through; gw-inet 10/10 allowed; staff 0/10 through; admin 0/10 through
  PASS  pass 3 isolation-under-load x1 operator (ops-client): its own Gateway 10 of 10 answered 200; gw-internal 10/10 allowed; gw-users 0/10 through; gw-inet 0/10 through; admin 10/10 allowed
== pass 3 isolation-under-load: 16 held connection(s) a population
  PASS  pass 3 isolation-under-load x2 enterprise: 16 connection(s) from ent-client held to gw-users at 10.20.11.210:443 (llm.ai.tarnwick.example), 96 replies, every one 200
  PASS  pass 3 isolation-under-load x2 enterprise: the firewall counts 16 session(s) from enterprise destination 10.20.11.210 destination-port 443 while they are held, within the plan's bound 16 to 19
  PASS  pass 3 isolation-under-load x2 internet: 16 connection(s) from inet-client held to gw-inet at 198.51.100.10:443 (llm.ai.tarnwick.example), 96 replies, every one 200
  PASS  pass 3 isolation-under-load x2 internet: the firewall counts 16 session(s) from isp destination 198.51.100.10 destination-port 443 while they are held, within the plan's bound 16 to 19
  PASS  pass 3 isolation-under-load x2 operator: 16 connection(s) from ops-client held to gw-internal at 10.20.11.200:443 (llm.ai.tarnwick.example), 96 replies, every one 200
  PASS  pass 3 isolation-under-load x2 operator: the firewall counts 16 session(s) from operator-vpn destination 10.20.11.200 destination-port 443 while they are held, within the plan's bound 16 to 19
  PASS  pass 3 isolation-under-load x2 enterprise (ent-client): its own Gateway 10 of 10 answered 200; gw-internal 0/10 through; gw-users 10/10 allowed; gw-inet 0/10 through; admin 0/10 through
  PASS  pass 3 isolation-under-load x2 internet (inet-client): its own Gateway 10 of 10 answered 200; gw-internal 0/10 through; gw-users 0/10 through; gw-inet 10/10 allowed; staff 0/10 through; admin 0/10 through
  PASS  pass 3 isolation-under-load x2 operator (ops-client): its own Gateway 10 of 10 answered 200; gw-internal 10/10 allowed; gw-users 0/10 through; gw-inet 0/10 through; admin 10/10 allowed
== pass 3, drill leaked-key: an enterprise caller's key used from the internet, answered, then refused after its revoke
  PASS  pass 3 leaked-key: audit.sh --quick after the drill: RESULT: 351 passed, 0 failed, 0 known platform limitation(s), 1 skipped
  PASS  pass 3 leaked-key: the key Job minted batch.fb000003, a key of batch, a caller of the enterprise audience
  PASS  pass 3 leaked-key: inet-client, a client of the internet audience, through gw-inet to chat with batch.fb000003: HTTP 200 2.845 s after the mint: no network layer refuses it, the caller's key is not bound to a Gateway
  PASS  pass 3 leaked-key: the API gateway's access log names caller batch for it (2 answered line(s) of consumer batch_key_fb000003, the first at api-gateway-access.txt:456): the log says who, the Gateway says from where
  PASS  pass 3 leaked-key: after the revoke the same key refused HTTP 401, 2.403 s after it
  PASS  pass 3 leaked-key: the key Secret holds the same 3 fields and fingerprints after the drill as before, and no batch.fb000003
```

# Drills

- Lab: `sfab-ch08`; labs repo commit `6ed2c330e0393d082e755ddf5137a7b437b6c69f`; UTC 2026-10-31T09:56:51Z

## lease-holder-loss: pass1

```
  PASS  pass 1 lease-holder-loss: gw-inet's lease, held by k8s-ingress2 at the cut, taken by k8s-ingress1 within 3.729 s of both ports shut, 6.256 s of the cut's start (the first lease read naming it)
  PASS  pass 1 lease-holder-loss: gw-internal's lease, held by k8s-ingress2 at the cut, taken by k8s-ingress1 within 3.729 s of both ports shut, 6.256 s of the cut's start (the first lease read naming it)
  PASS  pass 1 lease-holder-loss: gw-users's lease, held by k8s-ingress2 at the cut, taken by k8s-ingress1 within 3.729 s of both ports shut, 6.256 s of the cut's start (the first lease read naming it)
  PASS  pass 1 lease-holder-loss: ent-client through gw-users: 1 of 46 echo requests lost, the gap 4.0 s from the last request answered before both ports were shut to the first sent after it that was answered (sent times, every 2 s), the slowest answer while cut 2.093 s; answered again before the ports came back
  PASS  pass 1 lease-holder-loss: ent-client's connects to 10.20.11.210:443: 4 of 186 failed, the gap 4.504 s (every 0.5 s), the slowest connect while cut 1.3 ms; connecting again before the ports came back
  PASS  pass 1 lease-holder-loss: the prediction, 2 to 4 s at the timers 3s, 1s, 200ms plus the firewall's ARP update, against the measured 4.0 s (the probe's own interval 2 s): within it
  PASS  pass 1 lease-holder-loss: ops-client through gw-internal: 1 of 48 echo requests lost, the gap 4.0 s from the last request answered before both ports were shut to the first sent after it that was answered (sent times, every 2 s), the slowest answer while cut 1.061 s; answered again before the ports came back
  PASS  pass 1 lease-holder-loss: ops-client's connects to 10.20.11.200:443: 4 of 194 failed, the gap 4.504 s (every 0.5 s), the slowest connect while cut 1.6 ms; connecting again before the ports came back
  PASS  pass 1 lease-holder-loss: the prediction, 2 to 4 s at the timers 3s, 1s, 200ms plus the firewall's ARP update, against the measured 4.0 s (the probe's own interval 2 s): within it
  PASS  pass 1 lease-holder-loss: the firewall's ARP entry for gw-inet's VIP 10.20.11.220 while k8s-ingress2 is cut names 02:5a:68:00:00:01 (recorded, not judged: no probe of the drill reaches gw-inet through the firewall)
  PASS  pass 1 lease-holder-loss: the firewall's ARP entry for gw-internal's VIP 10.20.11.200 names k8s-ingress1's bond MAC 02:5a:68:00:00:01 while k8s-ingress2 is cut (arp-during.txt)
  PASS  pass 1 lease-holder-loss: the firewall's ARP entry for gw-users's VIP 10.20.11.210 names k8s-ingress1's bond MAC 02:5a:68:00:00:01 while k8s-ingress2 is cut (arp-during.txt)
  PASS  pass 1 lease-holder-loss: apart from the gap, the model probe (chat through gw-users): 37 of 50 answered over the drill, the API gateway, router and identity provider pods on the cut node among what it lost
  PASS  pass 1 lease-holder-loss: echo's Services without an endpoint on k8s-ingress2 after the cut: echo from 1.13 s
  PASS  pass 1 lease-holder-loss: inference's Services without an endpoint on k8s-ingress2 after the cut: none read
```

## lease-holder-loss: pass2

```
  PASS  pass 2 lease-holder-loss: gw-inet's lease, held by k8s-ingress1 at the cut, taken by k8s-ingress2 within 3.503 s of both ports shut, 5.948 s of the cut's start (the first lease read naming it)
  PASS  pass 2 lease-holder-loss: gw-internal's lease, held by k8s-ingress1 at the cut, taken by k8s-ingress2 within 3.503 s of both ports shut, 5.948 s of the cut's start (the first lease read naming it)
  PASS  pass 2 lease-holder-loss: gw-users's lease, held by k8s-ingress1 at the cut, taken by k8s-ingress2 within 3.503 s of both ports shut, 5.948 s of the cut's start (the first lease read naming it)
  PASS  pass 2 lease-holder-loss: ent-client through gw-users: 1 of 46 echo requests lost, the gap 4.0 s from the last request answered before both ports were shut to the first sent after it that was answered (sent times, every 2 s), the slowest answer while cut 1.073 s; answered again before the ports came back
  PASS  pass 2 lease-holder-loss: ent-client's connects to 10.20.11.210:443: 4 of 185 failed, the gap 4.505 s (every 0.5 s), the slowest connect while cut 2.1 ms; connecting again before the ports came back
  PASS  pass 2 lease-holder-loss: the prediction, 2 to 4 s at the timers 3s, 1s, 200ms plus the firewall's ARP update, against the measured 4.0 s (the probe's own interval 2 s): within it
  PASS  pass 2 lease-holder-loss: ops-client through gw-internal: 1 of 48 echo requests lost, the gap 4.0 s from the last request answered before both ports were shut to the first sent after it that was answered (sent times, every 2 s), the slowest answer while cut 1.059 s; answered again before the ports came back
  PASS  pass 2 lease-holder-loss: ops-client's connects to 10.20.11.200:443: 4 of 193 failed, the gap 4.504 s (every 0.5 s), the slowest connect while cut 10.1 ms; connecting again before the ports came back
  PASS  pass 2 lease-holder-loss: the prediction, 2 to 4 s at the timers 3s, 1s, 200ms plus the firewall's ARP update, against the measured 4.0 s (the probe's own interval 2 s): within it
  PASS  pass 2 lease-holder-loss: the firewall's ARP entry for gw-inet's VIP 10.20.11.220 while k8s-ingress1 is cut names 02:5a:69:00:00:01 (recorded, not judged: no probe of the drill reaches gw-inet through the firewall)
  PASS  pass 2 lease-holder-loss: the firewall's ARP entry for gw-internal's VIP 10.20.11.200 names k8s-ingress2's bond MAC 02:5a:69:00:00:01 while k8s-ingress1 is cut (arp-during.txt)
  PASS  pass 2 lease-holder-loss: the firewall's ARP entry for gw-users's VIP 10.20.11.210 names k8s-ingress2's bond MAC 02:5a:69:00:00:01 while k8s-ingress1 is cut (arp-during.txt)
  PASS  pass 2 lease-holder-loss: apart from the gap, the model probe (chat through gw-users): 32 of 49 answered over the drill, the API gateway, router and identity provider pods on the cut node among what it lost
  PASS  pass 2 lease-holder-loss: echo's Services without an endpoint on k8s-ingress1 after the cut: echo from 0.718 s
  PASS  pass 2 lease-holder-loss: inference's Services without an endpoint on k8s-ingress1 after the cut: none read
```

## lease-holder-loss: pass3

```
  PASS  pass 3 lease-holder-loss: gw-inet's lease, held by k8s-ingress2 at the cut, taken by k8s-ingress1 within 2.751 s of both ports shut, 5.185 s of the cut's start (the first lease read naming it)
  PASS  pass 3 lease-holder-loss: gw-internal's lease, held by k8s-ingress2 at the cut, taken by k8s-ingress1 within 2.751 s of both ports shut, 5.185 s of the cut's start (the first lease read naming it)
  PASS  pass 3 lease-holder-loss: gw-users's lease, held by k8s-ingress2 at the cut, taken by k8s-ingress1 within 2.751 s of both ports shut, 5.185 s of the cut's start (the first lease read naming it)
  PASS  pass 3 lease-holder-loss: ent-client through gw-users: 0 of 46 echo requests lost, the gap 2.0 s from the last request answered before both ports were shut to the first sent after it that was answered (sent times, every 2 s), the slowest answer while cut 2.083 s; answered again before the ports came back
  PASS  pass 3 lease-holder-loss: ent-client's connects to 10.20.11.210:443: 3 of 187 failed, the gap 3.503 s (every 0.5 s), the slowest connect while cut 8.8 ms; connecting again before the ports came back
  PASS  pass 3 lease-holder-loss: the prediction, 2 to 4 s at the timers 3s, 1s, 200ms plus the firewall's ARP update, against the measured 2.0 s (the probe's own interval 2 s): within it
  PASS  pass 3 lease-holder-loss: ops-client through gw-internal: 0 of 48 echo requests lost, the gap 2.0 s from the last request answered before both ports were shut to the first sent after it that was answered (sent times, every 2 s), the slowest answer while cut 2.086 s; answered again before the ports came back
  PASS  pass 3 lease-holder-loss: ops-client's connects to 10.20.11.200:443: 3 of 194 failed, the gap 3.503 s (every 0.5 s), the slowest connect while cut 1.6 ms; connecting again before the ports came back
  PASS  pass 3 lease-holder-loss: the prediction, 2 to 4 s at the timers 3s, 1s, 200ms plus the firewall's ARP update, against the measured 2.0 s (the probe's own interval 2 s): within it
  PASS  pass 3 lease-holder-loss: the firewall's ARP entry for gw-inet's VIP 10.20.11.220 while k8s-ingress2 is cut names 02:5a:68:00:00:01 (recorded, not judged: no probe of the drill reaches gw-inet through the firewall)
  PASS  pass 3 lease-holder-loss: the firewall's ARP entry for gw-internal's VIP 10.20.11.200 names k8s-ingress1's bond MAC 02:5a:68:00:00:01 while k8s-ingress2 is cut (arp-during.txt)
  PASS  pass 3 lease-holder-loss: the firewall's ARP entry for gw-users's VIP 10.20.11.210 names k8s-ingress1's bond MAC 02:5a:68:00:00:01 while k8s-ingress2 is cut (arp-during.txt)
  PASS  pass 3 lease-holder-loss: apart from the gap, the model probe (chat through gw-users): 36 of 49 answered over the drill, the API gateway, router and identity provider pods on the cut node among what it lost
  PASS  pass 3 lease-holder-loss: echo's Services without an endpoint on k8s-ingress2 after the cut: echo from 0.688 s
  PASS  pass 3 lease-holder-loss: inference's Services without an endpoint on k8s-ingress2 after the cut: none read
```

## Verdict

```
== pass 1, drill lease-holder-loss: the ingress node holding the most leases cut from the pair, its leases taken by the other
  PASS  pass 1 lease-holder-loss: the lab whole whole-before (k8s-ingress1 on 2 leg(s); k8s-ingress2 on 2 leg(s); leases gw-inet k8s-ingress2, gw-internal k8s-ingress2, gw-users k8s-ingress2)
  KNOWN pass 1 lease-holder-loss: the cut node sees no loss of carrier on the virtual switch's ports; it loses its leases because it cannot renew them: L9
  PASS  pass 1 lease-holder-loss: the lab whole whole-after (k8s-ingress1 on 2 leg(s); k8s-ingress2 on 2 leg(s); leases gw-inet k8s-ingress1, gw-internal k8s-ingress1, gw-users k8s-ingress1)
  PASS  pass 1 lease-holder-loss: audit.sh --quick after the drill: RESULT: 337 passed, 0 failed, 0 known platform limitation(s), 0 skipped
  PASS  pass 1 lease-holder-loss: gw-inet's lease, held by k8s-ingress2 at the cut, taken by k8s-ingress1 within 3.729 s of both ports shut, 6.256 s of the cut's start (the first lease read naming it)
  PASS  pass 1 lease-holder-loss: gw-internal's lease, held by k8s-ingress2 at the cut, taken by k8s-ingress1 within 3.729 s of both ports shut, 6.256 s of the cut's start (the first lease read naming it)
  PASS  pass 1 lease-holder-loss: gw-users's lease, held by k8s-ingress2 at the cut, taken by k8s-ingress1 within 3.729 s of both ports shut, 6.256 s of the cut's start (the first lease read naming it)
  PASS  pass 1 lease-holder-loss: ent-client through gw-users: 1 of 46 echo requests lost, the gap 4.0 s from the last request answered before both ports were shut to the first sent after it that was answered (sent times, every 2 s), the slowest answer while cut 2.093 s; answered again before the ports came back
  PASS  pass 1 lease-holder-loss: ent-client's connects to 10.20.11.210:443: 4 of 186 failed, the gap 4.504 s (every 0.5 s), the slowest connect while cut 1.3 ms; connecting again before the ports came back
  PASS  pass 1 lease-holder-loss: the prediction, 2 to 4 s at the timers 3s, 1s, 200ms plus the firewall's ARP update, against the measured 4.0 s (the probe's own interval 2 s): within it
  PASS  pass 1 lease-holder-loss: ops-client through gw-internal: 1 of 48 echo requests lost, the gap 4.0 s from the last request answered before both ports were shut to the first sent after it that was answered (sent times, every 2 s), the slowest answer while cut 1.061 s; answered again before the ports came back
  PASS  pass 1 lease-holder-loss: ops-client's connects to 10.20.11.200:443: 4 of 194 failed, the gap 4.504 s (every 0.5 s), the slowest connect while cut 1.6 ms; connecting again before the ports came back
  PASS  pass 1 lease-holder-loss: the prediction, 2 to 4 s at the timers 3s, 1s, 200ms plus the firewall's ARP update, against the measured 4.0 s (the probe's own interval 2 s): within it
  PASS  pass 1 lease-holder-loss: the firewall's ARP entry for gw-inet's VIP 10.20.11.220 while k8s-ingress2 is cut names 02:5a:68:00:00:01 (recorded, not judged: no probe of the drill reaches gw-inet through the firewall)
  PASS  pass 1 lease-holder-loss: the firewall's ARP entry for gw-internal's VIP 10.20.11.200 names k8s-ingress1's bond MAC 02:5a:68:00:00:01 while k8s-ingress2 is cut (arp-during.txt)
  PASS  pass 1 lease-holder-loss: the firewall's ARP entry for gw-users's VIP 10.20.11.210 names k8s-ingress1's bond MAC 02:5a:68:00:00:01 while k8s-ingress2 is cut (arp-during.txt)
  PASS  pass 1 lease-holder-loss: apart from the gap, the model probe (chat through gw-users): 37 of 50 answered over the drill, the API gateway, router and identity provider pods on the cut node among what it lost
  PASS  pass 1 lease-holder-loss: echo's Services without an endpoint on k8s-ingress2 after the cut: echo from 1.13 s
  PASS  pass 1 lease-holder-loss: inference's Services without an endpoint on k8s-ingress2 after the cut: none read
== pass 2, drill lease-holder-loss: the ingress node holding the most leases cut from the pair, its leases taken by the other
  PASS  pass 2 lease-holder-loss: the lab whole whole-before (k8s-ingress1 on 2 leg(s); k8s-ingress2 on 2 leg(s); leases gw-inet k8s-ingress1, gw-internal k8s-ingress1, gw-users k8s-ingress1)
  KNOWN pass 2 lease-holder-loss: the cut node sees no loss of carrier on the virtual switch's ports; it loses its leases because it cannot renew them: L9
  PASS  pass 2 lease-holder-loss: the lab whole whole-after (k8s-ingress1 on 2 leg(s); k8s-ingress2 on 2 leg(s); leases gw-inet k8s-ingress2, gw-internal k8s-ingress2, gw-users k8s-ingress2)
  PASS  pass 2 lease-holder-loss: audit.sh --quick after the drill: RESULT: 337 passed, 0 failed, 0 known platform limitation(s), 0 skipped
  PASS  pass 2 lease-holder-loss: gw-inet's lease, held by k8s-ingress1 at the cut, taken by k8s-ingress2 within 3.503 s of both ports shut, 5.948 s of the cut's start (the first lease read naming it)
  PASS  pass 2 lease-holder-loss: gw-internal's lease, held by k8s-ingress1 at the cut, taken by k8s-ingress2 within 3.503 s of both ports shut, 5.948 s of the cut's start (the first lease read naming it)
  PASS  pass 2 lease-holder-loss: gw-users's lease, held by k8s-ingress1 at the cut, taken by k8s-ingress2 within 3.503 s of both ports shut, 5.948 s of the cut's start (the first lease read naming it)
  PASS  pass 2 lease-holder-loss: ent-client through gw-users: 1 of 46 echo requests lost, the gap 4.0 s from the last request answered before both ports were shut to the first sent after it that was answered (sent times, every 2 s), the slowest answer while cut 1.073 s; answered again before the ports came back
  PASS  pass 2 lease-holder-loss: ent-client's connects to 10.20.11.210:443: 4 of 185 failed, the gap 4.505 s (every 0.5 s), the slowest connect while cut 2.1 ms; connecting again before the ports came back
  PASS  pass 2 lease-holder-loss: the prediction, 2 to 4 s at the timers 3s, 1s, 200ms plus the firewall's ARP update, against the measured 4.0 s (the probe's own interval 2 s): within it
  PASS  pass 2 lease-holder-loss: ops-client through gw-internal: 1 of 48 echo requests lost, the gap 4.0 s from the last request answered before both ports were shut to the first sent after it that was answered (sent times, every 2 s), the slowest answer while cut 1.059 s; answered again before the ports came back
  PASS  pass 2 lease-holder-loss: ops-client's connects to 10.20.11.200:443: 4 of 193 failed, the gap 4.504 s (every 0.5 s), the slowest connect while cut 10.1 ms; connecting again before the ports came back
  PASS  pass 2 lease-holder-loss: the prediction, 2 to 4 s at the timers 3s, 1s, 200ms plus the firewall's ARP update, against the measured 4.0 s (the probe's own interval 2 s): within it
  PASS  pass 2 lease-holder-loss: the firewall's ARP entry for gw-inet's VIP 10.20.11.220 while k8s-ingress1 is cut names 02:5a:69:00:00:01 (recorded, not judged: no probe of the drill reaches gw-inet through the firewall)
  PASS  pass 2 lease-holder-loss: the firewall's ARP entry for gw-internal's VIP 10.20.11.200 names k8s-ingress2's bond MAC 02:5a:69:00:00:01 while k8s-ingress1 is cut (arp-during.txt)
  PASS  pass 2 lease-holder-loss: the firewall's ARP entry for gw-users's VIP 10.20.11.210 names k8s-ingress2's bond MAC 02:5a:69:00:00:01 while k8s-ingress1 is cut (arp-during.txt)
  PASS  pass 2 lease-holder-loss: apart from the gap, the model probe (chat through gw-users): 32 of 49 answered over the drill, the API gateway, router and identity provider pods on the cut node among what it lost
  PASS  pass 2 lease-holder-loss: echo's Services without an endpoint on k8s-ingress1 after the cut: echo from 0.718 s
  PASS  pass 2 lease-holder-loss: inference's Services without an endpoint on k8s-ingress1 after the cut: none read
== pass 3, drill lease-holder-loss: the ingress node holding the most leases cut from the pair, its leases taken by the other
  PASS  pass 3 lease-holder-loss: the lab whole whole-before (k8s-ingress1 on 2 leg(s); k8s-ingress2 on 2 leg(s); leases gw-inet k8s-ingress2, gw-internal k8s-ingress2, gw-users k8s-ingress2)
  KNOWN pass 3 lease-holder-loss: the cut node sees no loss of carrier on the virtual switch's ports; it loses its leases because it cannot renew them: L9
  PASS  pass 3 lease-holder-loss: the lab whole whole-after (k8s-ingress1 on 2 leg(s); k8s-ingress2 on 2 leg(s); leases gw-inet k8s-ingress1, gw-internal k8s-ingress1, gw-users k8s-ingress1)
  PASS  pass 3 lease-holder-loss: audit.sh --quick after the drill: RESULT: 337 passed, 0 failed, 0 known platform limitation(s), 0 skipped
  PASS  pass 3 lease-holder-loss: gw-inet's lease, held by k8s-ingress2 at the cut, taken by k8s-ingress1 within 2.751 s of both ports shut, 5.185 s of the cut's start (the first lease read naming it)
  PASS  pass 3 lease-holder-loss: gw-internal's lease, held by k8s-ingress2 at the cut, taken by k8s-ingress1 within 2.751 s of both ports shut, 5.185 s of the cut's start (the first lease read naming it)
  PASS  pass 3 lease-holder-loss: gw-users's lease, held by k8s-ingress2 at the cut, taken by k8s-ingress1 within 2.751 s of both ports shut, 5.185 s of the cut's start (the first lease read naming it)
  PASS  pass 3 lease-holder-loss: ent-client through gw-users: 0 of 46 echo requests lost, the gap 2.0 s from the last request answered before both ports were shut to the first sent after it that was answered (sent times, every 2 s), the slowest answer while cut 2.083 s; answered again before the ports came back
  PASS  pass 3 lease-holder-loss: ent-client's connects to 10.20.11.210:443: 3 of 187 failed, the gap 3.503 s (every 0.5 s), the slowest connect while cut 8.8 ms; connecting again before the ports came back
  PASS  pass 3 lease-holder-loss: the prediction, 2 to 4 s at the timers 3s, 1s, 200ms plus the firewall's ARP update, against the measured 2.0 s (the probe's own interval 2 s): within it
  PASS  pass 3 lease-holder-loss: ops-client through gw-internal: 0 of 48 echo requests lost, the gap 2.0 s from the last request answered before both ports were shut to the first sent after it that was answered (sent times, every 2 s), the slowest answer while cut 2.086 s; answered again before the ports came back
  PASS  pass 3 lease-holder-loss: ops-client's connects to 10.20.11.200:443: 3 of 194 failed, the gap 3.503 s (every 0.5 s), the slowest connect while cut 1.6 ms; connecting again before the ports came back
  PASS  pass 3 lease-holder-loss: the prediction, 2 to 4 s at the timers 3s, 1s, 200ms plus the firewall's ARP update, against the measured 2.0 s (the probe's own interval 2 s): within it
  PASS  pass 3 lease-holder-loss: the firewall's ARP entry for gw-inet's VIP 10.20.11.220 while k8s-ingress2 is cut names 02:5a:68:00:00:01 (recorded, not judged: no probe of the drill reaches gw-inet through the firewall)
  PASS  pass 3 lease-holder-loss: the firewall's ARP entry for gw-internal's VIP 10.20.11.200 names k8s-ingress1's bond MAC 02:5a:68:00:00:01 while k8s-ingress2 is cut (arp-during.txt)
  PASS  pass 3 lease-holder-loss: the firewall's ARP entry for gw-users's VIP 10.20.11.210 names k8s-ingress1's bond MAC 02:5a:68:00:00:01 while k8s-ingress2 is cut (arp-during.txt)
  PASS  pass 3 lease-holder-loss: apart from the gap, the model probe (chat through gw-users): 36 of 49 answered over the drill, the API gateway, router and identity provider pods on the cut node among what it lost
  PASS  pass 3 lease-holder-loss: echo's Services without an endpoint on k8s-ingress2 after the cut: echo from 0.688 s
  PASS  pass 3 lease-holder-loss: inference's Services without an endpoint on k8s-ingress2 after the cut: none read
```

#!/usr/bin/env python3
"""holdrun.py: chapter 10's session measurement judged (common/trace/lib-hold.sh), and HOLD.md.

    holdrun.py judge --set DIR --plan gen/tenancy.json [--factor F] [--stamp TEXT]

It reads the files the run saved in DIR and prints the result vocabulary, appending each line to
$SFAB_VERDICT:

  held          every population's N connections opened, held and answered 200 on every request,
                and its zone's session count on the firewall, read while they are held, within the
                plan's bound (N to N plus the chat request plus the plan's slack)
  chat          one chat completion per population with its own caller's key: HTTP 200
  timeouts      show session info's TCP timeouts equal the plan's, the pinned PA-VM 12.1.2's
                defaults: TCP 3,600 s, handshake 10 s, init 5 s, half closed 30 s (PAN-OS 12.1 help
                documents 120 s), time wait 15 s, and the session timeout in the discard state,
                90 s

HOLD.md holds, per zone, the counts before, while held, after the chat and after the stop, and
Little's law worked from the run's own events: the connections the zone's client opened over the
window from its first open to the stop, times the mean time each was held, over the window, gives
the sessions the zone should hold on average; the count read while held stands beside it. No rate
is printed (the repository publishes no throughput figure): the arrivals are the plan's own load. Standard
library only.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "audit"))
import tenancy as T  # noqa: E402
import vocab  # noqa: E402


def read(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def little(events: list, stop_t: float | None) -> dict:
    opens = {e["conn"]: e["t"] for e in events if e.get("event") == "open"}
    closes = {e["conn"]: e["t"] for e in events if e.get("event") == "closed"}
    spans = [closes[c] - opens[c] for c in opens if c in closes]
    if not opens:
        return {}
    t0 = min(opens.values())
    t1 = stop_t or max(closes.values(), default=t0)
    w = max(t1 - t0, 1e-6)
    lam = len(opens) / w
    t_mean = sum(spans) / len(spans) if spans else 0.0
    return {"arrivals": len(opens), "window_s": round(w, 1), "mean_hold_s": round(t_mean, 1), "predicted": round(lam * t_mean, 1)}


def judge(a) -> int:
    d = Path(a.set)
    plan = json.loads(Path(a.plan).read_text())
    hp = plan["hold"]
    factor = int(a.factor or 1)
    v = vocab.Vocab()
    v.sec(f"the held connections: {hp['n'] * factor} a population for {hp['hold_s']} s (chapter 10)")
    res = T.judge_hold(v, d, hp, "held", factor)
    v.sec("one chat completion a population, with its own caller's key")
    for r in hp["rows"]:
        if not r.get("chat"):
            continue
        st = (read(d / f"chat-{r['population']}-result.txt").split() or ["none"])[0]
        key = (read(d / f"chat-{r['population']}-key.txt").strip().splitlines() or ["no key"])[-1].split()[0]
        v.check(f"{r['population']}: {r['chat']['model']} through {r['gateway']} with {r['chat']['caller']}'s key ({key}): HTTP {st}",
                st == "200" and key.startswith(f"{r['chat']['caller']}."), f"HTTP {st}, key {key}")
    v.sec("the firewall's session timeouts (the pinned PA-VM 12.1.2's defaults)")
    got = T.session_timeouts(read(d / "session-info-held.txt"))
    for k, want in hp["timeouts"].items():
        if k not in got and k == "discard_tcp":
            v.skip(f"show session info: the session timeout in the discard state, {want} s", "the command does not print it")
            continue
        v.check(f"show session info: {k.replace('_', ' ')} {got.get(k, 'not printed')} s, the plan's {want} s", got.get(k) == want,
                f"{got.get(k, 'not printed')}")
    try:
        stop_t = float(read(d / "stopped-at.txt").strip() or 0) or None
    except ValueError:
        stop_t = None
    rows = []
    for r in hp["rows"]:
        ev = T.hold_events(read(d / f"hold-{r['population']}.jsonl"))
        counts = {t: T.session_count(read(d / f"counts-{t}-{r['population']}.txt")) for t in ("before", "held", "chat", "after")}
        rows.append((r, counts, little(ev, stop_t), res.get(r["population"]) or {}))
    write_md(d, plan, rows, factor, a.stamp, got)
    return 1 if v.counts()["fail"] else 0


def write_md(d: Path, plan: dict, rows: list, factor: int, stamp, timeouts: dict) -> None:
    try:
        run = json.loads(read(d / "RUN.json"))
    except ValueError:
        run = {}
    repo = run.get("labs_repo") or {}
    unc = " (with uncommitted changes)" if repo.get("dirty") is True else ""
    hp = plan["hold"]
    L = ["# Sessions under held connections", "",
         f"- Lab: `{plan.get('lab')}`; labs repo commit `{repo.get('commit') or 'none'}`{unc}; UTC {run.get('utc_start') or 'unknown'}",
         f"- {hp['n'] * factor} keep-alive HTTPS connections a population to its own Gateway's test backend, each used again every "
         f"{hp['every_s']} s and held {hp['hold_s']} s, plus one chat completion a population with its own caller's key"]
    if stamp:
        L.append(f"- {stamp}")
    L += ["", "| Population | Client | Zone | Filter | Before | Held | After the chat | After the stop | Bound |",
          "|---|---|---|---|---|---|---|---|---|"]
    for r, c, _l, x in rows:
        b = x.get("bound") or [r["bound"]["min"], r["bound"]["max"]]
        L.append(f"| {r['population']} | {r['client']} | {r['zone']} | `{r['filter']}` | {c['before']} | {c['held']} | {c['chat']} | "
                 f"{c['after']} | {b[0]} to {b[1]} |")
    L += ["", "## Little's law per zone", "",
          "Sessions held on average = the arrival rate x the mean time each is held, here the arrivals over the window times "
          "the mean hold, divided by the window. The arrivals are the connections the zone's client opened between its first "
          "open and the stop (the window); the mean hold is each connection's own span from open to close, both from the run's "
          "events. The arrivals are the plan's own load, not a measure of what the path can carry.", "",
          "| Zone | Arrivals | Window (s) | Mean hold (s) | Predicted sessions | Counted while held |",
          "|---|---|---|---|---|---|"]
    for r, c, lt, _x in rows:
        if lt:
            L.append(f"| {r['zone']} | {lt['arrivals']} | {lt['window_s']} | {lt['mean_hold_s']} | {lt['predicted']} | {c['held']} |")
    L += ["", "The discard timeout"
          + (f" ({timeouts['discard_tcp']} s as show session info prints it)" if "discard_tcp" in timeouts else
             f" ({hp['timeouts']['discard_tcp']} s in the plan; show session info did not print it)")
          + " applies to a session the firewall holds in the discard state. This run makes no denied attempt, and each "
          "population's filter names its zone and its own Gateway's address and port, so the counts above hold the "
          "population's own connections and its chat request alone.", ""]
    verdict = read(d / "verdict.txt")
    L += ["## Verdict", "", "```"] + [x for x in verdict.splitlines() if x.strip()] + ["```", ""]
    L += ["## Files", "", "- `hold-<population>.jsonl`: each client's events (open, reply, held, closed, done), on the client's clock",
          "- `counts-<when>-<population>.txt`: show session all with the population's filter and count yes, before, held, after the chat "
          "and after the stop", "- `sessions-after-<population>.txt`: the same filter's entries still listed after the stop, with their states "
          "(closing sessions age out by their own timeouts, so the after-the-stop count depends on when it is read)",
          "- `session-info-<when>.txt`: show session info at the same reads",
          "- `chat-<population>-result.txt`, `chat-<population>-key.txt`: the chat completion's status and the key's field and "
          "fingerprint (never the key)", "- `tenancy.json`: the plan", ""]
    (d / "HOLD.md").write_text("\n".join(L), encoding="utf-8")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="holdrun")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("judge")
    s.add_argument("--set", required=True)
    s.add_argument("--plan", required=True)
    s.add_argument("--factor", default="1")
    s.add_argument("--stamp")
    a = ap.parse_args(argv)
    return judge(a)


if __name__ == "__main__":
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    sys.exit(main())

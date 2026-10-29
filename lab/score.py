#!/usr/bin/env python3
"""Puntúa una corrida del laboratorio.
uso: score.py WORKDIR LABEL OUT_JSON
- Detección por familia: inyecciones (truth.jsonl de la corrida attack)
  con al menos una alerta del sensor (alerts.jsonl, repetición offline) con
  la misma clave (dns: cport+txid; rst: cport+sport).
- FPR limpio: eventos alertados / eventos observados en la corrida clean
  (transacciones DNS con respuesta + flujos TCP con tráfico entrante).
- Falla (exit 1) si el laboratorio no generó lo esperado: sin inyecciones,
  eventos limpios de menos, o vivo y offline no coinciden."""
import json
import os
import sys
from collections import Counter, defaultdict

W, label, out = sys.argv[1], sys.argv[2], sys.argv[3]


def jl(p):
    with open(p) as f:
        return [json.loads(x) for x in f if x.strip()]


def key(a):
    return ("dns", a["cport"], a["txid"]) if a["kind"] == "dns" else ("rst", a["cport"], a["sport"])


fatal = []
res = {"label": label}
for mode in ("clean", "attack"):
    d = os.path.join(W, mode)
    st, stl = json.load(open(os.path.join(d, "stats.json"))), json.load(open(os.path.join(d, "stats-live.json")))
    al, all_live = jl(os.path.join(d, "alerts.jsonl")), jl(os.path.join(d, "alerts-live.jsonl"))
    if sorted(map(key, al)) != sorted(map(key, all_live)):
        fatal.append(f"{mode}: alertas vivo ({len(all_live)}) != offline ({len(al)})")
    wl = jl(os.path.join(d, "workload.jsonl"))
    res[mode] = {"stats": st, "live_cpu_s": stl["cpu_s"], "live_packets": stl["packets"],
                 "alerts": len(al), "workload_dns": sum(w["kind"] == "dns" for w in wl),
                 "workload_tcp": sum(w["kind"] == "tcp" for w in wl)}
    res[mode]["_alerts"] = al

c = res["clean"]
ev = c["stats"].get("dns_events", 0) + c["stats"].get("tcp_flows", 0)
if c["stats"].get("dns_events", 0) < 0.95 * c["workload_dns"] or c["stats"].get("tcp_flows", 0) < 0.9 * c["workload_tcp"]:
    fatal.append(f"clean: eventos observados de menos ({c['stats']})")
fp_reasons = Counter(r for a in c["_alerts"] for r in a["reasons"])
res["clean_fpr"] = {"events": ev, "dns_events": c["stats"].get("dns_events", 0),
                    "tcp_flows": c["stats"].get("tcp_flows", 0), "legit_rst_flows": c["stats"].get("rst_flows", 0),
                    "false_alerts": len(c["_alerts"]), "fpr": (len(c["_alerts"]) / ev) if ev else None,
                    "by_reason": dict(fp_reasons)}

truth = jl(os.path.join(W, "attack", "truth.jsonl"))
if not truth:
    fatal.append("attack: sin inyecciones")
akeys = defaultdict(list)
for a in res["attack"]["_alerts"]:
    akeys[key(a)].append(a)
fam = defaultdict(lambda: {"injected": 0, "detected": 0, "reasons": Counter()})
tkeys = set()
for t in truth:
    k = ("dns", t["cport"], t["txid"]) if t["kind"] == "dns" else ("rst", t["cport"], t["sport"])
    tkeys.add(k)
    f = fam[t["family"]]
    f["injected"] += 1
    if akeys.get(k):
        f["detected"] += 1
        for a in akeys[k]:
            f["reasons"].update(a["reasons"])
extra = [a for a in res["attack"]["_alerts"] if key(a) not in tkeys]
tot_i = sum(f["injected"] for f in fam.values())
tot_d = sum(f["detected"] for f in fam.values())
res["detection"] = {k: {"injected": v["injected"], "detected": v["detected"],
                        "rate": v["detected"] / v["injected"], "reasons": dict(v["reasons"])}
                    for k, v in sorted(fam.items())}
res["detection_total"] = {"injected": tot_i, "detected": tot_d, "rate": tot_d / tot_i if tot_i else None}
a_ev = res["attack"]["stats"].get("dns_events", 0) + res["attack"]["stats"].get("tcp_flows", 0)
res["attack_unmatched_alerts"] = {"count": len(extra), "events_not_injected": a_ev - tot_i,
                                  "by_reason": dict(Counter(r for a in extra for r in a["reasons"]))}
for m in ("clean", "attack"):
    s = res[m]
    s["live_cpu_us_per_packet"] = 1e6 * s["live_cpu_s"] / s["live_packets"] if s["live_packets"] else None
    s["offline_cpu_us_per_packet"] = 1e6 * s["stats"]["cpu_s"] / s["stats"]["packets"] if s["stats"]["packets"] else None
    del s["_alerts"]
res["fatal"] = fatal
os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
with open(out, "w") as fh:
    json.dump(res, fh, indent=1, sort_keys=True)
print(json.dumps({"detection_total": res["detection_total"], "clean_fpr": res["clean_fpr"],
                  "detection": {k: (v["detected"], v["injected"]) for k, v in res["detection"].items()},
                  "fatal": fatal}, indent=1))
sys.exit(1 if fatal else 0)

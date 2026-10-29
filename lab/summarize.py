#!/usr/bin/env python3
"""Agrega results/lab-*.json en results/SUMMARY.md y verifica criterios.
Criterios (exit 1 si fallan): FPR limpio <= 0.5 % en cada corrida; detección
>= 95 % en cada familia salvo rst-mimic-both (punto ciego declarado: RST a
ambos lados con TTL e IPID mimetizados, sin tráfico posterior)."""
import glob
import json
import os
import sys
from collections import defaultdict

root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results")
runs = [json.load(open(f)) for f in sorted(glob.glob(os.path.join(root, "lab-*.json")))]
if not runs:
    sys.exit("FATAL: no hay results/lab-*.json")
BLIND = {"rst-mimic-both"}
fails = []
fam = defaultdict(lambda: [0, 0])
L = ["# Resultados del laboratorio", "",
     "Generado por `lab/summarize.py` desde `results/lab-*.json` (una corrida limpia + una con middlebox por archivo).", "",
     "| corrida | eventos limpios | RST legítimos | falsas alertas | FPR limpio | inyectados | detectados | detección total | alertas extra (ataque) | CPU vivo µs/paquete |",
     "|---|---|---|---|---|---|---|---|---|---|"]
for r in runs:
    c, d = r["clean_fpr"], r["detection_total"]
    L.append(f"| {r['label']} | {c['events']} | {c['legit_rst_flows']} | {c['false_alerts']} | {100*c['fpr']:.2f} % | "
             f"{d['injected']} | {d['detected']} | {100*d['rate']:.1f} % | {r['attack_unmatched_alerts']['count']} | "
             f"{r['attack']['live_cpu_us_per_packet']:.1f} |")
    if c["fpr"] > 0.005:
        fails.append(f"{r['label']}: FPR {c['fpr']:.4f} > 0.005 ({c['by_reason']})")
    if r.get("fatal"):
        fails.append(f"{r['label']}: {r['fatal']}")
    for k, v in r["detection"].items():
        fam[k][0] += v["detected"]
        fam[k][1] += v["injected"]
L += ["", "## Detección por familia (todas las corridas)", "", "| familia | detectados / inyectados | tasa | criterio |", "|---|---|---|---|"]
for k, (dd, ii) in sorted(fam.items()):
    crit = "punto ciego declarado" if k in BLIND else ">= 95 %"
    L.append(f"| {k} | {dd} / {ii} | {100*dd/ii:.1f} % | {crit} |")
    if k not in BLIND and dd / ii < 0.95:
        fails.append(f"familia {k}: {dd}/{ii} < 95 %")
tot_d = sum(v[0] for k, v in fam.items() if k not in BLIND)
tot_i = sum(v[1] for k, v in fam.items() if k not in BLIND)
all_d, all_i = sum(v[0] for v in fam.values()), sum(v[1] for v in fam.values())
L += ["", f"Total sin el punto ciego: {tot_d}/{tot_i} = {100*tot_d/tot_i:.1f} %. "
          f"Total con todas las familias: {all_d}/{all_i} = {100*all_d/all_i:.1f} %.", ""]
open(os.path.join(root, "SUMMARY.md"), "w").write("\n".join(L))
print("\n".join(L))
if fails:
    print("\n".join("FALLA: " + f for f in fails), file=sys.stderr)
    sys.exit(1)

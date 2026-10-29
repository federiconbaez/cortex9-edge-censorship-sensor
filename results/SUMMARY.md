# Resultados del laboratorio

Generado por `lab/summarize.py` desde `results/lab-*.json` (una corrida limpia + una con middlebox por archivo).

| corrida | eventos limpios | RST legítimos | falsas alertas | FPR limpio | inyectados | detectados | detección total | alertas extra (ataque) | CPU vivo µs/paquete |
|---|---|---|---|---|---|---|---|---|---|
| ci-jitter-s1 | 2000 | 182 | 0 | 0.00 % | 770 | 675 | 87.7 % | 0 | 80.1 |
| ci-jitter-s2 | 2000 | 198 | 0 | 0.00 % | 767 | 664 | 86.6 % | 1 | 89.0 |
| ci-jitter-s3 | 2000 | 182 | 0 | 0.00 % | 807 | 701 | 86.9 % | 0 | 38.0 |
| ci-none-s1 | 2000 | 182 | 0 | 0.00 % | 773 | 677 | 87.6 % | 0 | 78.5 |
| ci-none-s2 | 2000 | 198 | 0 | 0.00 % | 769 | 665 | 86.5 % | 0 | 79.5 |
| ci-none-s3 | 2000 | 182 | 0 | 0.00 % | 810 | 700 | 86.4 % | 0 | 87.8 |

## Detección por familia (todas las corridas)

| familia | detectados / inyectados | tasa | criterio |
|---|---|---|---|
| dns-copyttl | 1174 / 1174 | 100.0 % | >= 95 % |
| dns-lowttl | 1228 / 1228 | 100.0 % | >= 95 % |
| rst-copyttl | 551 / 553 | 99.6 % | >= 95 % |
| rst-lowttl | 552 / 552 | 100.0 % | >= 95 % |
| rst-mimic-both | 1 / 613 | 0.2 % | punto ciego declarado |
| rst-mimic-client | 576 / 576 | 100.0 % | >= 95 % |

Total sin el punto ciego: 4081/4083 = 100.0 %. Total con todas las familias: 4082/4696 = 86.9 %.

# Tablas de la evaluación a escala

Fuente: `data/experiments/scale_evaluation_20260929_203402.json` — 4 aplicaciones, ground truth de 5 vulnerabilidades por aplicación.

"Híbrido" es la unión de los hallazgos SAST y DAST comparada contra el ground truth: mide la cobertura combinada de ambas técnicas y no aplica el motor de correlación.

## Métricas medias por método

| Método | Precision | Recall | F1 |
|---|---|---|---|
| SAST | 0.171 | 0.500 | 0.219 |
| DAST | 0.013 | 0.050 | 0.020 |
| Híbrido | 0.158 | 0.550 | 0.203 |

## Resultados por aplicación

| Aplicación | Método | Hallazgos | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|
| OWASP Juice Shop | SAST | 17 | 2 | 15 | 3 | 0.118 | 0.400 | 0.182 |
| OWASP Juice Shop | DAST | 20 | 1 | 19 | 4 | 0.050 | 0.200 | 0.080 |
| OWASP Juice Shop | Híbrido | 37 | 3 | 34 | 2 | 0.081 | 0.600 | 0.143 |
| DVWA | SAST | 33 | 4 | 29 | 1 | 0.121 | 0.800 | 0.210 |
| DVWA | DAST | 5 | 0 | 5 | 5 | 0.000 | 0.000 | 0.000 |
| DVWA | Híbrido | 38 | 4 | 34 | 1 | 0.105 | 0.800 | 0.186 |
| NodeGoat | SAST | 5 | 2 | 3 | 3 | 0.400 | 0.400 | 0.400 |
| NodeGoat | DAST | 0 | 0 | 0 | 5 | 0.000 | 0.000 | 0.000 |
| NodeGoat | Híbrido | 5 | 2 | 3 | 3 | 0.400 | 0.400 | 0.400 |
| OWASP WebGoat | SAST | 43 | 2 | 41 | 3 | 0.046 | 0.400 | 0.083 |
| OWASP WebGoat | DAST | 0 | 0 | 0 | 5 | 0.000 | 0.000 | 0.000 |
| OWASP WebGoat | Híbrido | 43 | 2 | 41 | 3 | 0.046 | 0.400 | 0.083 |

## Prueba t de Student emparejada (gl = 3; H₁: híbrido > método individual)

| Comparación | t | p unilateral | p bilateral | Cohen's d | Significativa (p < 0.05) |
|---|---|---|---|---|---|
| F1: Híbrido vs SAST | -1.65 | 0.901 | 0.198 | -0.12 | No |
| F1: Híbrido vs DAST | 2.37 | 0.049 | 0.098 | 1.80 | Sí (unilateral) |
| Recall: Híbrido vs SAST | 1.00 | 0.196 | 0.391 | — | No |

Con n = 4 aplicaciones la potencia estadística es baja.

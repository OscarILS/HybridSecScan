# Análisis exploratorio — module_match en modo `mapped_endpoint`

> ⚠️ **ANÁLISIS EXPLORATORIO Y POST-HOC.** Diseñado DESPUÉS de observar que `module_match` valió 0 en los 221 pares reales de `real_pairs_evaluation_20261030_211257`, y evaluado sobre esas MISMAS dos aplicaciones (Flask y VAmPI). No es una validación independiente. No se reentrena el modelo ni se cambian el umbral (0.5), los pesos del motor, el umbral de correlación (0.70), los datos ni archivos de resultados existentes. El modo por defecto del sistema sigue siendo `file`.

Generado: 2026-10-30T23:37:36. Commit: `e90821a5b416bc2e91b5ece4cff24aeab3c2713a`.

## Modelo y entorno

- Versión del modelo: `1.0.0`; entrenado (pkl): `2026-10-02T00:40:12.658587`; metadata.json: `2026-10-02T00:40:08.391655`.
- n_features: 517; índice de module_match: 511; umbral clasificador: 0.5; umbral correlación: 0.7; peso RF: 0.1.
- Python: 3.11.9; scikit-learn: 1.9.0.

## Control de regresión (modo file)

OK: modo file reproduce real_pairs_evaluation_20261030_211257

## Juice Shop

Excluida: la ejecución de la Tarea 3 de Juice Shop no tiene ground truth.

## Totales — modo file (ambas apps, 221 pares)

- Positivos: 2, negativos: 219.
- Matriz: VN=219, FP=0, FN=2, VP=0; FP sobre negativos = 0/219 = 0.0000.
- Correlación (umbral 0.70): confirmados = 1, precisión = 1.0000, recall = 0.0556.

## Totales — modo mapped_endpoint (ambas apps, 221 pares)

- Positivos: 2, negativos: 219.
- Matriz: VN=219, FP=0, FN=1, VP=1; FP sobre negativos = 0/219 = 0.0000.
- Correlación (umbral 0.70): confirmados = 1, precisión = 1.0000, recall = 0.0556.

## Resultados por aplicación

## App vulnerable propia (Flask)

Fuentes: ground truth `vulnerable_app_ground_truth.json`, SAST `sast_bandit_vulnerable_20260930_095345.json`, DAST `dast_active_vulnerable_20260930_095345.json`. Hallazgos SAST = 12, DAST = 12; ground truth = 9.

### A. Clasificador — modo mapped_endpoint (umbral 0.5)

- Pares: 144 — positivos: 2, negativos: 142.

| | Pred. negativo | Pred. positivo |
|---|---|---|
| **Real negativo** | VN = 142 | FP = 0 |
| **Real positivo** | FN = 1 | VP = 1 |

- Tasa de FP sobre negativos: 0 / 142 = 0.0000 (referencia sintética: 129 / 700 = 0.1843).

Probabilidad RF (mapped) de cada par positivo:

| Ground truth | Prob. RF (mapped) | Pred. (≥0.5) | module_match | SAST | DAST |
|---|---|---|---|---|---|
| VA_002 | 0.7256 | sí | 1 | B608 vulnerable_app.py:25 → /login | SQL Injection @ /login |
| VA_009 | 0.2522 | no | 0 | B201 vulnerable_app.py:81 → /token | Error Disclosure - Debug Mode @ /deserialize |

Resumen de probabilidades RF (mapped):

| Grupo | n | Mín | Mediana | Media | Máx |
|---|---|---|---|---|---|
| Positivos | 2 | 0.2522 | 0.4889 | 0.4889 | 0.7256 |
| Negativos | 142 | 0.1020 | 0.2042 | 0.2029 | 0.4257 |

Distribución de module_match (mapped):

| Grupo | module_match = 1 | module_match = 0 |
|---|---|---|
| Positivos | 1 | 1 |
| Negativos | 1 | 141 |

### B. Comparación par a par (file vs mapped)

- Pares que cambian de module_match: **2** de 144.

Probabilidad de cada par positivo en ambos modos:

| Ground truth | mm file | mm mapped | RF file | RF mapped | Δ RF |
|---|---|---|---|---|---|
| VA_002 | 0 | 1 | 0.4725 | 0.7256 | +0.2531 |
| VA_009 | 0 | 0 | 0.2522 | 0.2522 | +0.0000 |

### C. Pares NEGATIVOS que pasan a module_match = 1: 1

| Ground truth | RF file | RF mapped | Pred. (≥0.5) | SAST | DAST |
|---|---|---|---|---|---|
| — | 0.1938 | 0.4257 | no | B301 vulnerable_app.py:42 → /deserialize | Error Disclosure - Debug Mode @ /deserialize |

### D. Motor de correlación (umbral 0.70, pesos actuales)

**Modo file** — pares confirmados: 1; correctos (corresponden a GT): 1; vulnerabilidades confirmadas: VA_002; precisión: 1.0000, recall: 0.1111.

- Confianza 0.8674 — SAST `B608 vulnerable_app.py:25 → /login` × DAST `SQL Injection @ /login` — GT: VA_002.

| Factor | Peso | Valor | Aporte |
|---|---|---|---|
| Endpoint | 0.40 | 1.0000 | 0.4000 |
| Tipo | 0.35 | 1.0000 | 0.3500 |
| Semántica | 0.10 | 0.3680 | 0.0368 |
| Random Forest | 0.10 | 0.4725 | 0.0473 |
| Severidad | 0.05 | 0.6667 | 0.0333 |

**Modo mapped_endpoint** — pares confirmados: 1; correctos (corresponden a GT): 1; vulnerabilidades confirmadas: VA_002; precisión: 1.0000, recall: 0.1111.

- Confianza 0.8927 — SAST `B608 vulnerable_app.py:25 → /login` × DAST `SQL Injection @ /login` — GT: VA_002.

| Factor | Peso | Valor | Aporte |
|---|---|---|---|
| Endpoint | 0.40 | 1.0000 | 0.4000 |
| Tipo | 0.35 | 1.0000 | 0.3500 |
| Semántica | 0.10 | 0.3680 | 0.0368 |
| Random Forest | 0.10 | 0.7256 | 0.0726 |
| Severidad | 0.05 | 0.6667 | 0.0333 |

### E. VA_002 / VA_009: confianza y supresión del RF

| GT | Conf. file | ¿conf.? | Conf. mapped | ¿conf.? | ¿cambia? | C' file (−RF) | ¿conf.? | C' mapped (−RF) | ¿conf.? |
|---|---|---|---|---|---|---|---|---|---|
| VA_002 | 0.8674 | sí | 0.8927 | sí | no | 0.8201 | sí | 0.8201 | sí |
| VA_009 | 0.5067 | no | 0.5067 | no | no | 0.4814 | no | 0.4814 | no |

### F. Hallazgos SAST sin endpoint mapeado: 4

- `B403 vulnerable_app.py:7` (endpoint: `/unknown_line_7`)
- `B404 vulnerable_app.py:8` (endpoint: `/unknown_line_8`)
- `B105 vulnerable_app.py:15` (endpoint: `/unknown_line_15`)
- `B105 vulnerable_app.py:16` (endpoint: `/unknown_line_16`)

## VAmPI (API REST vulnerable)

Fuentes: ground truth `vampi_ground_truth.json`, SAST `sast_bandit_vampi_20260930_230153.json`, DAST `dast_active_vampi_20261001_003241.json`. Hallazgos SAST = 7, DAST = 11; ground truth = 9.

### A. Clasificador — modo mapped_endpoint (umbral 0.5)

- Pares: 77 — positivos: 0, negativos: 77.

| | Pred. negativo | Pred. positivo |
|---|---|---|
| **Real negativo** | VN = 77 | FP = 0 |
| **Real positivo** | FN = 0 | VP = 0 |

- Tasa de FP sobre negativos: 0 / 77 = 0.0000 (referencia sintética: 129 / 700 = 0.1843).

Probabilidad RF (mapped) de cada par positivo:

_Sin pares positivos._

Resumen de probabilidades RF (mapped):

| Grupo | n | Mín | Mediana | Media | Máx |
|---|---|---|---|---|---|
| Positivos | 0 | — | — | — | — |
| Negativos | 77 | 0.0941 | 0.1657 | 0.1694 | 0.2638 |

Distribución de module_match (mapped):

| Grupo | module_match = 1 | module_match = 0 |
|---|---|---|
| Positivos | 0 | 0 |
| Negativos | 0 | 77 |

### B. Comparación par a par (file vs mapped)

- Pares que cambian de module_match: **0** de 77.

Probabilidad de cada par positivo en ambos modos:

| Ground truth | mm file | mm mapped | RF file | RF mapped | Δ RF |
|---|---|---|---|---|---|

### C. Pares NEGATIVOS que pasan a module_match = 1: 0

Ninguno.

### D. Motor de correlación (umbral 0.70, pesos actuales)

**Modo file** — pares confirmados: 0; correctos (corresponden a GT): 0; vulnerabilidades confirmadas: —; precisión: —, recall: 0.0000.

**Modo mapped_endpoint** — pares confirmados: 0; correctos (corresponden a GT): 0; vulnerabilidades confirmadas: —; precisión: —, recall: 0.0000.

### E. VA_002 / VA_009: confianza y supresión del RF

| GT | Conf. file | ¿conf.? | Conf. mapped | ¿conf.? | ¿cambia? | C' file (−RF) | ¿conf.? | C' mapped (−RF) | ¿conf.? |
|---|---|---|---|---|---|---|---|---|---|

### F. Hallazgos SAST sin endpoint mapeado: 6

- `B105 users.py:122` (endpoint: `/unknown_line_122`)
- `B105 users.py:124` (endpoint: `/unknown_line_124`)
- `B104 app.py:17` (endpoint: `/unknown_line_17`)
- `B105 config.py:13` (endpoint: `/unknown_line_13`)
- `B608 user_model.py:72` (endpoint: `/unknown_line_72`)
- `B311 user_model.py:86` (endpoint: `/unknown_line_86`)

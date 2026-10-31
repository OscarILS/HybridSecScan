# Evaluación del Random Forest sobre pares reales SAST–DAST

Generado: 2026-10-30T21:12:57.

Mide el clasificador Random Forest ya entrenado sobre todos los pares SAST × DAST de dos aplicaciones con ground truth (Tarea 3), etiquetados como positivos cuando ambos hallazgos corresponden a la misma vulnerabilidad del ground truth. No se reentrena ni se modifica el modelo, el umbral ni los datos.

## Modelo y entorno

- Versión del modelo: `1.0.0`
- Entrenado (pkl): `2026-10-02T00:40:12.658587`
- Entrenado (metadata.json): `2026-10-02T00:40:08.391655`
- n_features: 517; umbral de decisión: 0.5
- Python: 3.11.9; scikit-learn: 1.9.0

## Control de consistencia obligatorio

| Vulnerabilidad | Prob. RF esperada | Prob. RF observada | Confianza total | ¿OK? |
|---|---|---|---|---|
| VA_002 | 0.472 | 0.4725 | 0.8674 | ✅ |
| VA_009 | 0.25 | 0.2522 | 0.5067 | ✅ |

## Juice Shop (excluida)

La ejecución de la Tarea 3 de OWASP Juice Shop no tiene archivo de ground truth asociado (no existe un `correlation_evaluation_juiceshop_*`), por lo que no se pueden etiquetar pares positivos/negativos y queda fuera de esta evaluación.

## Totales (ambas aplicaciones)

- Pares: **221** — positivos: **2**, negativos: **219**.

| | Pred. negativo | Pred. positivo |
|---|---|---|
| **Real negativo** | VN = 219 | FP = 0 |
| **Real positivo** | FN = 2 | VP = 0 |

- Tasa de falsos positivos (pares reales): 0 / 219 = 0.0000.
- Referencia holdout sintético independiente: 129 / 700 = 0.1843 (fuente: `holdout_evaluation_20261001_223335.json`).

## Resultados por aplicación

## App vulnerable propia (Flask)

Fuentes: ground truth `vulnerable_app_ground_truth.json`, SAST `sast_bandit_vulnerable_20260930_095345.json`, DAST `dast_active_vulnerable_20260930_095345.json`.

- Hallazgos: SAST = 12, DAST = 12 (esperado 12 × 12; coincide).
- Pares (SAST × DAST): **144** — positivos: **2**, negativos: **142**.

### 2. Matriz de confusión (umbral 0.5)

| | Pred. negativo | Pred. positivo |
|---|---|---|
| **Real negativo** | VN = 142 | FP = 0 |
| **Real positivo** | FN = 2 | VP = 0 |

### 3. Tasa de falsos positivos sobre los negativos

- Pares reales: FP / negativos = 0 / 142 = 0.0000.

### 4. Probabilidad RF de cada par positivo

| Ground truth | Prob. RF | Pred. (≥0.5) | module_match | SAST | DAST |
|---|---|---|---|---|---|
| VA_002 | 0.4725 | no | 0 | B608 vulnerable_app.py:25 → /login | SQL Injection @ /login |
| VA_009 | 0.2522 | no | 0 | B201 vulnerable_app.py:81 → /token | Error Disclosure - Debug Mode @ /deserialize |

### 5. Resumen de probabilidades RF

| Grupo | n | Mín | Mediana | Media | Máx |
|---|---|---|---|---|---|
| Positivos | 2 | 0.2522 | 0.3624 | 0.3624 | 0.4725 |
| Negativos | 142 | 0.1020 | 0.2033 | 0.2012 | 0.2937 |

### 6. Distribución de module_match

| Grupo | module_match = 1 | module_match = 0 |
|---|---|---|
| Positivos | 0 | 2 |
| Negativos | 0 | 142 |

### Métricas complementarias (inestables con pocos positivos)

- n_positivos = 2. Precisión = —, Recall = 0.0000, F1 = —.

### Ambigüedades registradas: 0

Ninguna: ningún hallazgo ni par coincide con más de una vulnerabilidad del ground truth.

## VAmPI (API REST vulnerable)

Fuentes: ground truth `vampi_ground_truth.json`, SAST `sast_bandit_vampi_20260930_230153.json`, DAST `dast_active_vampi_20261001_003241.json`.

- Hallazgos: SAST = 7, DAST = 11 (esperado 7 × 11; coincide).
- Pares (SAST × DAST): **77** — positivos: **0**, negativos: **77**.

### 2. Matriz de confusión (umbral 0.5)

| | Pred. negativo | Pred. positivo |
|---|---|---|
| **Real negativo** | VN = 77 | FP = 0 |
| **Real positivo** | FN = 0 | VP = 0 |

### 3. Tasa de falsos positivos sobre los negativos

- Pares reales: FP / negativos = 0 / 77 = 0.0000.

### 4. Probabilidad RF de cada par positivo

_No hay pares positivos (ninguna vulnerabilidad fue detectada por ambas técnicas)._

### 5. Resumen de probabilidades RF

| Grupo | n | Mín | Mediana | Media | Máx |
|---|---|---|---|---|---|
| Positivos | 0 | — | — | — | — |
| Negativos | 77 | 0.0941 | 0.1657 | 0.1694 | 0.2638 |

### 6. Distribución de module_match

| Grupo | module_match = 1 | module_match = 0 |
|---|---|---|
| Positivos | 0 | 0 |
| Negativos | 0 | 77 |

### Métricas complementarias (inestables con pocos positivos)

- n_positivos = 0. Precisión = —, Recall = —, F1 = —.

### Ambigüedades registradas: 0

Ninguna: ningún hallazgo ni par coincide con más de una vulnerabilidad del ground truth.

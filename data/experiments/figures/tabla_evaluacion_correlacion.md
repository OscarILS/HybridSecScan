# Evaluación del motor de correlación contra ground truth

Precisión = hallazgos correctos / hallazgos; recall = vulnerabilidades encontradas / total. Los pesos de la confianza son una decisión de diseño (backend/correlation_engine.py, CONFIDENCE_WEIGHTS). Cada aplicación es un caso de estudio: los resultados ilustran el comportamiento del sistema, no permiten generalizar.

## App vulnerable propia (Flask)

Ground truth: 9 vulnerabilidades (`vulnerable_app_ground_truth.json`). Hallazgos: `sast_bandit_vulnerable_20260930_095345.json`, `dast_active_vulnerable_20260930_095345.json`. Umbral de correlación: 0.7.

| Método | Hallazgos | Correctos | Incorrectos | Vulnerabilidades encontradas | Precisión | Recall | F1 |
|---|---|---|---|---|---|---|---|
| SAST (Bandit) | 12 | 9 | 3 | 8 de 9 | 0.750 | 0.889 | 0.814 |
| DAST (escáner activo) | 12 | 3 | 9 | 3 de 9 | 0.250 | 0.333 | 0.286 |
| Unión SAST+DAST | 24 | 12 | 12 | 9 de 9 | 0.500 | 1.000 | 0.667 |
| Correlación (pares confirmados) | 1 | 1 | 0 | 1 de 9 | 1.000 | 0.111 | 0.200 |

### Detección por categoría OWASP API Top 10 (2023)

| Categoría | Vulnerabilidades | SAST | DAST | Unión | Correlación |
|---|---|---|---|---|---|
| API2:2023 | 2 (VA_001, VA_008) | 2 | 0 | 2 | 0 |
| API8:2023 | 7 (VA_002, VA_003, VA_004, VA_005, VA_006, VA_007, VA_009) | 6 | 3 | 7 | 1 |

Vulnerabilidades detectadas por ambas técnicas (las únicas que el correlador puede confirmar): 2 (VA_002, VA_009). Confirmadas por el correlador: 1 (VA_002).

| Confianza | SAST | DAST | Vulnerabilidad del ground truth |
|---|---|---|---|
| 0.867 | B608 vulnerable_app.py:25 | SQL Injection @ /login | VA_002 |

### Desglose de la confianza (vulnerabilidades detectadas por ambas técnicas)

- **VA_002**: SAST B608 vulnerable_app.py:25 → /login; DAST SQL Injection @ /login — confirmada.
- **VA_009**: SAST B201 vulnerable_app.py:81 → /token; DAST Error Disclosure - Debug Mode @ /deserialize — no confirmada (< 0.7).

| Factor | Peso | VA_002 (valor → aporte) | VA_009 (valor → aporte) |
|---|---|---|---|
| Similitud de endpoint | 0.40 | 1.000 → 0.400 | 0.091 → 0.036 |
| Tipo de vulnerabilidad | 0.35 | 1.000 → 0.350 | 1.000 → 0.350 |
| Similitud semántica | 0.10 | 0.368 → 0.037 | 0.451 → 0.045 |
| Probabilidad del Random Forest | 0.10 | 0.472 → 0.047 | 0.252 → 0.025 |
| Similitud de severidad | 0.05 | 0.667 → 0.033 | 1.000 → 0.050 |
| **Confianza total** | 1.00 | **0.867** | **0.507** |

Aporte = peso × valor. Similitud semántica calculada con embeddings.

## VAmPI (API REST vulnerable)

Ground truth: 9 vulnerabilidades (`vampi_ground_truth.json`). Hallazgos: `sast_bandit_vampi_20260930_230153.json`, `dast_active_vampi_20261001_003241.json`. Umbral de correlación: 0.7.

| Método | Hallazgos | Correctos | Incorrectos | Vulnerabilidades encontradas | Precisión | Recall | F1 |
|---|---|---|---|---|---|---|---|
| SAST (Bandit) | 7 | 2 | 5 | 2 de 9 | 0.286 | 0.222 | 0.250 |
| DAST (escáner activo) | 11 | 2 | 9 | 2 de 9 | 0.182 | 0.222 | 0.200 |
| Unión SAST+DAST | 18 | 4 | 14 | 4 de 9 | 0.222 | 0.444 | 0.296 |
| Correlación (pares confirmados) | 0 | 0 | 0 | 0 de 9 | 0.000 | 0.000 | 0.000 |

### Detección por categoría OWASP API Top 10 (2023)

| Categoría | Vulnerabilidades | SAST | DAST | Unión | Correlación |
|---|---|---|---|---|---|
| API1:2023 | 2 (VAMPI_002, VAMPI_003) | 0 | 0 | 0 | 0 |
| API2:2023 | 2 (VAMPI_006, VAMPI_009) | 1 | 0 | 1 | 0 |
| API3:2023 | 2 (VAMPI_004, VAMPI_005) | 0 | 1 | 1 | 0 |
| API4:2023 | 2 (VAMPI_007, VAMPI_008) | 0 | 1 | 1 | 0 |
| API8:2023 | 1 (VAMPI_001) | 1 | 0 | 1 | 0 |

Vulnerabilidades detectadas por ambas técnicas (las únicas que el correlador puede confirmar): 0 (—). Confirmadas por el correlador: 0 (—).

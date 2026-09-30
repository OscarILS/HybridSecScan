# Evaluación del motor de correlación (caso de estudio)

Aplicación: `ProgramasPruebas/vulnerable_app.py` — ground truth de 9 vulnerabilidades (`vulnerable_app_ground_truth.json`). Hallazgos: `sast_bandit_vulnerable_20260930_095345.json`, `dast_active_vulnerable_20260930_095345.json`. Umbral de correlación: 0.7.

| Método | Hallazgos | Correctos | Incorrectos | Vulnerabilidades encontradas | Precisión | Recall | F1 |
|---|---|---|---|---|---|---|---|
| SAST (Bandit) | 12 | 9 | 3 | 8 de 9 | 0.750 | 0.889 | 0.814 |
| DAST (escáner activo) | 12 | 3 | 9 | 3 de 9 | 0.250 | 0.333 | 0.286 |
| Unión SAST+DAST | 24 | 12 | 12 | 9 de 9 | 0.500 | 1.000 | 0.667 |
| Correlación (pares confirmados) | 1 | 1 | 0 | 1 de 9 | 1.000 | 0.111 | 0.200 |

Vulnerabilidades detectadas por ambas técnicas (las únicas que el correlador puede confirmar): 2 (VA_002, VA_009). Confirmadas por el correlador: 1 (VA_002).

## Correlaciones

| Confianza | SAST | DAST | Vulnerabilidad del ground truth |
|---|---|---|---|
| 0.884 | B608 línea 25 | SQL Injection @ /login | VA_002 |

## Desglose de la confianza (vulnerabilidades detectadas por ambas técnicas)

- **VA_002**: SAST B608 línea 25 → /login; DAST SQL Injection @ /login — confirmada.
- **VA_009**: SAST B201 línea 81 → /token; DAST Error Disclosure - Debug Mode @ /deserialize — no confirmada (< 0.7).

| Factor | Peso | VA_002 (valor → aporte) | VA_009 (valor → aporte) |
|---|---|---|---|
| Similitud de endpoint | 0.40 | 1.000 → 0.400 | 0.091 → 0.036 |
| Tipo de vulnerabilidad | 0.35 | 1.000 → 0.350 | 1.000 → 0.350 |
| Similitud semántica | 0.10 | 0.368 → 0.037 | 0.451 → 0.045 |
| Probabilidad del Random Forest | 0.10 | 0.643 → 0.064 | 0.413 → 0.041 |
| Similitud de severidad | 0.05 | 0.667 → 0.033 | 1.000 → 0.050 |
| **Confianza total** | 1.00 | **0.884** | **0.523** |

Aporte = peso × valor. Similitud semántica calculada con embeddings. Los pesos son una decisión de diseño (backend/correlation_engine.py, CONFIDENCE_WEIGHTS).

Precisión = hallazgos correctos / hallazgos; recall = vulnerabilidades encontradas / total. Caso de estudio con una sola aplicación: los resultados ilustran el comportamiento del correlador, no permiten generalizar.

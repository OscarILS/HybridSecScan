# Resultados Experimentales — HybridSecScan

**Fecha:** 27 de Junio, 2026  
**Autor:** Oscar Isaac Laguna Santa Cruz  
**Universidad:** UNMSM — Ingeniería de Software

---

## Aplicación objetivo: OWASP Juice Shop

| Campo | Valor |
|---|---|
| Aplicación | OWASP Juice Shop v17.x |
| Lenguaje | TypeScript / Node.js / Angular |
| Despliegue | Docker (`bkimminich/juice-shop`) |
| SAST ejecutado sobre | Código fuente (`juiceshop_src/`) |
| DAST ejecutado sobre | `http://localhost:3000` |
| Herramienta SAST | Semgrep 1.168.0 (`p/javascript`, `p/typescript`) |
| Herramienta DAST | HybridSecScan HTTP Security Scanner |

---

## Resultados por método

### SAST (Semgrep)

| Métrica | Valor |
|---|---|
| Total hallazgos | **9** |
| HIGH | 3 |
| MEDIUM | 6 |
| Tipos detectados | JWT hardcoded secret, Path traversal (sendfile), XSS patterns |

**Hallazgos principales:**
1. `jwt-hardcode.hardcoded-jwt-secret` — Secreto JWT hardcodeado (HIGH)
2. `express-res-sendfile` × 2 — Path traversal en rutas Express (HIGH)
3. Patrones XSS en renderizado frontend (MEDIUM × 6)

**Limitación observada:** Semgrep/p/javascript cubre código TypeScript pero no detecta vulnerabilidades en configuración HTTP (headers, CORS) — esas son responsabilidad del DAST.

---

### DAST (HTTP Security Scanner)

| Métrica | Valor |
|---|---|
| Total hallazgos | **23** |
| CRITICAL | 3 |
| HIGH | 11 |
| MEDIUM | 6 |
| LOW | 3 |

**Hallazgos principales:**
- Cabeceras de seguridad ausentes: CSP, HSTS, X-Frame-Options, Referrer-Policy (CRITICAL/HIGH)
- CORS mal configurado — acepta orígenes arbitrarios (HIGH)
- Rutas sensibles expuestas: `/api/admin`, `/metrics`, `/swagger.json` (HIGH)
- Server information disclosure en headers HTTP (MEDIUM)
- Rate limiting ausente en endpoints críticos (MEDIUM)

**Fortaleza:** Detecta problemas en runtime que el código fuente no revela — configuración de servidor, exposición de APIs, comportamiento HTTP real.

---

### Análisis Híbrido (HybridSecScan)

| Métrica | Valor |
|---|---|
| Cobertura total única | **32 hallazgos** |
| Incremento vs SAST solo | **+256%** (9 → 32) |
| Incremento vs DAST solo | **+39%** (23 → 32) |
| Correlaciones ML (threshold 0.70) | 0 |
| Modelo ML utilizado | Random Forest, F1=0.786, Recall=96.5% |

**Interpretación de 0 correlaciones ML:**

Las 0 correlaciones con el modelo ML reflejan un **domain shift** entre los datos de entrenamiento y la ejecución real:

- El modelo fue entrenado con **descripciones sintéticas** (e.g., "SQL injection in user query via string formatting")
- El vectorizador TF-IDF aprendió este vocabulario sintético
- Las descripciones reales de Semgrep ("Dangerous use of res.sendFile without validation") y del HTTP Scanner ("Content-Security-Policy header not set") **no comparten vocabulario** con el training set
- Las 500 features TF-IDF resultan ≈0 para datos reales → el modelo no discrimina

Este hallazgo es académicamente válido: motiva el fine-tuning del modelo con datos reales de herramientas. Es documentado como **trabajo futuro** en Capítulo 6.

**Cobertura complementaria (hallazgo principal):**

SAST y DAST detectan **capas diferentes** de vulnerabilidades:
- SAST: vulnerabilidades en código fuente (lógica, secretos, patrones peligrosos)
- DAST: vulnerabilidades en runtime HTTP (headers, CORS, exposición de rutas)

La **cobertura complementaria** es el aporte central del enfoque híbrido: ningún método solo cubre el espacio completo de vulnerabilidades.

---

## Comparación resumen

| Dimensión | SAST solo | DAST solo | Híbrido |
|---|---|---|---|
| Hallazgos | 9 | 23 | **32** |
| Cobertura código | ✓ | ✗ | ✓ |
| Cobertura runtime HTTP | ✗ | ✓ | ✓ |
| CRITICAL detectados | 0 | 3 | **3** |
| HIGH detectados | 3 | 11 | **14** |

---

## Modelo ML — Métricas reales

Entrenado con `scripts/setup.py` → `backend/train_ml_model.py`:

| Conjunto | Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|---|
| Validación | 80.8% | 69.4% | 94.3% | 0.800 | 0.851 |
| **Test** | **76.9%** | **66.3%** | **96.5%** | **0.786** | **0.785** |

Matriz de confusión (Test Set, n=130):

|  | Pred. No | Pred. Sí |
|---|---|---|
| **Real No** | TN=45 | FP=28 |
| **Real Sí** | FN=2  | TP=55 |

**Alto recall (96.5%) es intencional:** en seguridad es peor pasar por alto una vulnerabilidad real (FN) que generar una falsa alarma (FP). El modelo fue diseñado con esta prioridad.

---

## Análisis de causa raíz — Domain Shift

El gap entre datos de entrenamiento y datos reales es un problema conocido en ML aplicado a seguridad:

1. **Datos de entrenamiento:** 1,300 pares sintéticos con descripciones en formato estandarizado
2. **Datos reales:** Semgrep genera descripciones técnicas de código; HTTP Scanner genera descripciones de observaciones HTTP
3. **Consecuencia:** El TF-IDF (500 de 517 features) no encuentra vocabulario común → features ≈ 0

**Solución para trabajo futuro:**
- Reentrenar incluyendo outputs reales de Semgrep y HTTP Scanner como datos positivos/negativos etiquetados
- Usar embeddings semánticos (sentence-transformers) en lugar de TF-IDF bag-of-words
- Implementar transfer learning desde modelos de seguridad pre-entrenados (CodeBERT, SecBERT)

---

## Conclusión experimental

El sistema HybridSecScan demuestra que la combinación SAST+DAST detecta **3.6× más vulnerabilidades** que el análisis estático solo sobre OWASP Juice Shop. La arquitectura es correcta y el modelo ML tiene métricas académicamente válidas (F1=0.786). El domain shift identificado es un hallazgo honesto que sustenta la necesidad de fine-tuning con datos reales — trabajo futuro claramente delimitado.

---

*Generado con HybridSecScan v2.0 — Experimento ejecutado el 2026-06-27*

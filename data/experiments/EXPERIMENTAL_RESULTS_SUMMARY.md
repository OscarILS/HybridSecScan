# Resultados Experimentales — HybridSecScan

**Fecha:** 27 de Junio, 2026  
**Autor:** Oscar Isaac Laguna Santa Cruz  
**Universidad:** UNMSM — Ingeniería de Software

---

> **Nota:** este resumen corresponde a una ejecución del 27/06/2026 (archivos `*_juiceshop_20260627_0107*.json`).
> Es distinta de la evaluación a escala (`scale_evaluation_*.json`), que usa otra ejecución de Juice Shop
> (17 hallazgos SAST y 20 DAST) y sí compara contra el ground truth. Las cifras de ambas no deben mezclarse.

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
| Hallazgos combinados (SAST + DAST) | **32 hallazgos** (sin verificar contra ground truth) |
| Correlaciones ML (threshold 0.70) | 0 |
| Modelo ML utilizado | Random Forest, F1=0.900, Recall=94.7% (sobre el test sintético) |

Los hallazgos no son vulnerabilidades verificadas: cuántos son verdaderos positivos solo se sabe comparando
contra el ground truth, que es lo que hace la evaluación a escala (en su ejecución de Juice Shop, 3 de 37
hallazgos combinados fueron verdaderos positivos).

**Interpretación de 0 correlaciones ML:**

La causa principal **no** es el domain shift, sino la **falta de solapamiento**: SAST y DAST no detectaron
ninguna vulnerabilidad en común. De los 9 × 23 = 207 pares posibles, **0 comparten tipo de vulnerabilidad**, y
las rutas de archivo de SAST (`.ts`) no coinciden con los endpoints HTTP de DAST. La confianza de correlación
pondera endpoint (40%) y tipo (35%); si ninguno de los dos coincide, ningún par llega al umbral de 0.70.

El par de mayor confianza (0.434) lo ilustra: similitud de endpoint 0.375 (→0.15), tipo 0.571 por ser tipos
*relacionados*, no iguales (→0.20), semántica 0.16 (→0.016), Random Forest 0.18 (→0.018) y severidad 1.0
(→0.05). El *domain shift* del TF-IDF solo afecta a los términos semántico y ML, que juntos pesan el 20% del
score; aunque fueran perfectos, el par no alcanzaría 0.70.

Esto se re-confirmó con el modelo corregido (F1 0.900 en sintético): mejorar el modelo **no** cambia el
resultado (siguen 0 correlaciones), porque el cuello de botella no es la calidad del modelo sino que ambas
técnicas detectan vulnerabilidades distintas. Es la otra cara de la **cobertura complementaria**: SAST y DAST
se complementan precisamente porque ven cosas distintas, y por eso rara vez hay un mismo hallazgo que ambas
confirmen. El domain shift sí limitaría la correlación cuando sí hay solapamiento, y se documenta como riesgo y
trabajo futuro (fine-tuning con salidas reales).

**Cobertura complementaria (hallazgo principal):**

SAST y DAST detectan **capas diferentes** de vulnerabilidades:
- SAST: vulnerabilidades en código fuente (lógica, secretos, patrones peligrosos)
- DAST: vulnerabilidades en runtime HTTP (headers, CORS, exposición de rutas)

En esta ejecución, SAST y DAST reportan hallazgos de capas distintas, por lo que ninguno de los dos cubre por sí solo todos los tipos observados. La evaluación a escala contra ground truth matiza este resultado: la unión SAST+DAST aumenta el recall solo en Juice Shop y reduce la precisión media.

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
| Validación | 91.5% | 86.2% | 94.3% | 0.901 | 0.954 |
| **Test** | **90.8%** | **85.7%** | **94.7%** | **0.900** | **0.955** |

Matriz de confusión (Test Set, n=130):

|  | Pred. No | Pred. Sí |
|---|---|---|
| **Real No** | TN=64 | FP=9 |
| **Real Sí** | FN=3  | TP=54 |

La feature más importante del modelo es `module_match` (¿el archivo SAST y el endpoint
DAST son del mismo componente?): es la que separa los positivos limpios de los negativos
difíciles. Umbral de decisión por defecto (0.5) y `class_weight='balanced'`. **Estas
métricas son sobre el test sintético.** En los experimentos reales el correlador confirma 0 pares, pero
principalmente por falta de solapamiento entre SAST y DAST (ver arriba), no por la calidad del modelo.

---

## Análisis de causa raíz

**Causa principal de las 0 correlaciones — falta de solapamiento.** El correlador solo puede confirmar un
hallazgo si SAST y DAST detectan la *misma* vulnerabilidad. En Juice Shop no hay ningún par con el mismo tipo
(0 de 207) y las rutas de archivo no se mapean a endpoints HTTP, así que las dos señales de mayor peso
(endpoint 40%, tipo 35%) nunca coinciden. Es inherente al enfoque: SAST y DAST aportan cobertura complementaria
*porque* ven capas distintas, y por eso el solapamiento confirmable es escaso.

**Factor secundario — domain shift del TF-IDF.** El modelo se entrenó con descripciones sintéticas; las reales
de Semgrep y del escáner HTTP no comparten vocabulario, así que las 500 features TF-IDF resultan ≈0 para datos
reales. Esto degrada los términos semántico y ML (20% del score), pero no es lo que provoca las 0
correlaciones: incluso con esos términos perfectos, sin coincidencia de endpoint ni de tipo el par no alcanza
el umbral.

**Solución para trabajo futuro:**
- Reentrenar incluyendo outputs reales de Semgrep y HTTP Scanner como datos positivos/negativos etiquetados
- Usar embeddings semánticos (sentence-transformers) en lugar de TF-IDF bag-of-words
- Implementar transfer learning desde modelos de seguridad pre-entrenados (CodeBERT, SecBERT)

---

## Conclusión experimental

En OWASP Juice Shop, SAST y DAST producen hallazgos de capas distintas (código fuente frente a comportamiento HTTP), por lo que su combinación amplía la cobertura: 32 hallazgos frente a 9 de SAST solo. Son hallazgos sin verificar; la exactitud de cada método contra el ground truth se reporta en la evaluación a escala. El motor de correlación no encontró correlaciones en esta aplicación porque SAST y DAST detectaron vulnerabilidades distintas (ningún par comparte tipo y las rutas no coinciden con los endpoints); el domain shift del TF-IDF es un factor secundario. Reentrenar con datos reales y correlacionar a nivel de componente (no solo de endpoint) quedan como trabajo futuro.

---

*Generado con HybridSecScan v2.0 — Experimento ejecutado el 2026-06-27*

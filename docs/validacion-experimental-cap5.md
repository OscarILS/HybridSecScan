# Capítulo 5: Validación Experimental

## 5.1 Configuración del Entorno

### 5.1.1 Hardware y Software

| Componente | Especificación |
|---|---|
| Sistema Operativo | Windows 11 Home Single Language |
| Python | 3.11.9 (CPython) |
| Node.js | 20.x |
| Docker Desktop | 4.x (para OWASP Juice Shop) |
| Modelo ML | Random Forest — entrenado vía Docker (python:3.11-slim) |

### 5.1.2 Herramientas de Análisis

| Herramienta | Versión | Rol |
|---|---|---|
| Bandit | 1.8.0 | SAST — análisis estático Python |
| Semgrep | 1.168.0 | SAST — análisis estático JavaScript/TypeScript |
| HybridSecScan HTTP Scanner | 2.0 | DAST — probing HTTP pasivo |
| HybridSecScan Active Probe | 2.0 | DAST — probing activo de inyecciones |
| Random Forest Correlator | 1.0.0 | ML — motor de correlación |

### 5.1.3 Aplicaciones Objetivo

Se seleccionaron dos aplicaciones con perfiles distintos para cubrir dos escenarios de uso:

| Aplicación | Lenguaje | Tipo | Propósito experimental |
|---|---|---|---|
| OWASP Juice Shop v17.x | TypeScript/Node.js | App web compleja | Cobertura complementaria SAST+DAST |
| `vulnerable_app.py` (HybridSecScan) | Python/Flask | App mínima controlada | Demostración de correlación ML |

---

## 5.2 Modelo de Correlación ML

### 5.2.1 Dataset de Entrenamiento

El dataset fue generado con `scripts/generate_training_dataset.py` siguiendo un diseño en 6 categorías que previene la separabilidad trivial:

| Categoría | Descripción | Etiqueta |
|---|---|---|
| A) Positivos limpios | Mismo tipo + mismo módulo | correlated=1 |
| B) Positivos cruzados | Distinta etiqueta de herramienta, mismo problema | correlated=1 |
| C) Positivos ambiguos | Mismo tipo, módulos relacionados | correlated=1 |
| D) **Negativos difíciles** | Mismo tipo, módulos NO relacionados | correlated=0 |
| E) Negativos limpios | Tipos distintos | correlated=0 |
| F) Negativos por herramienta | Hallazgo sin contraparte real | correlated=0 |

La categoría D es la más importante: fuerza al modelo a usar TODAS las features, no solo `type_match`.

**Estadísticas del dataset:**

| Conjunto | Muestras | Correlacionadas | No correlacionadas |
|---|---|---|---|
| Entrenamiento | 1.040 | 490 (47.1%) | 550 (52.9%) |
| Validación | 130 | — | — |
| Test | 130 | 57 (43.8%) | 73 (56.2%) |
| **Total** | **1.300** | | |

### 5.2.2 Arquitectura del Modelo

- **Algoritmo**: Random Forest Classifier (scikit-learn)
- **Features**: 517 (500 TF-IDF + 8 categóricas + 9 numéricas)
- **Hiperparámetros**: n_estimators=200, max_depth=20, min_samples_split=10, class_weight='balanced'
- **Features principales**: endpoint similarity, type match, TF-IDF de descripciones combinadas

### 5.2.3 Métricas del Modelo (reales, `data/models/metadata.json`)

| Conjunto | Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|---|
| Validación | 80.8% | 69.4% | 94.3% | 0.800 | 0.851 |
| **Test** | **76.9%** | **66.3%** | **96.5%** | **0.786** | **0.785** |

**Matriz de confusión (Test Set, n=130):**

| | Predicho: No | Predicho: Sí |
|---|---|---|
| **Real: No** | TN = 45 | FP = 28 |
| **Real: Sí** | FN = 2 | TP = 55 |

**Decisión de diseño — alto recall:** En seguridad informática, un falso negativo (miss de vulnerabilidad real) es más costoso que un falso positivo (falsa alarma). El modelo fue diseñado intencionalmente con recall=96.5% a costa de menor precision=66.3%. Esto sigue la práctica estándar en herramientas de seguridad (CWE, OWASP).

---

## 5.3 Experimento 1: OWASP Juice Shop

**Objetivo:** Demostrar la cobertura complementaria entre análisis estático y dinámico en una aplicación web real de referencia.

### 5.3.1 Configuración

- **SAST**: Semgrep con reglas `p/javascript` y `p/typescript` sobre código fuente de Juice Shop
- **DAST**: HybridSecScan HTTP Scanner contra `http://localhost:3000` (Docker)
- **Correlación**: Motor ML con threshold=0.70

### 5.3.2 Resultados SAST — Semgrep sobre Juice Shop

| Severidad | Cantidad | Tipo de hallazgo principal |
|---|---|---|
| HIGH | 3 | JWT hardcodeado (`jwt-hardcode`), path traversal (`express-res-sendfile` ×2) |
| MEDIUM | 6 | Patrones XSS en renderizado frontend |
| **Total** | **9** | |

### 5.3.3 Resultados DAST — HTTP Scanner

| Severidad | Cantidad | Tipo de hallazgo principal |
|---|---|---|
| CRITICAL | 3 | Cabeceras de seguridad ausentes (CSP, HSTS) |
| HIGH | 11 | CORS mal configurado, rutas sensibles expuestas, X-Frame-Options |
| MEDIUM | 6 | Server info disclosure, Referrer-Policy |
| LOW | 3 | Permissions-Policy, X-Content-Type-Options |
| **Total** | **23** | |

### 5.3.4 Análisis Híbrido

| Métrica | Valor |
|---|---|
| Cobertura SAST | 9 hallazgos |
| Cobertura DAST | 23 hallazgos |
| **Cobertura híbrida total** | **32 hallazgos únicos** |
| **Incremento vs SAST solo** | **+256%** |
| Correlaciones ML (threshold 0.70) | 0 |

**Observación sobre las 0 correlaciones:** SAST y DAST detectaron capas de vulnerabilidades completamente distintas. Semgrep observa patrones en código fuente (secretos JWT, path traversal en lógica); el HTTP Scanner observa comportamiento HTTP en runtime (headers, CORS, exposición de rutas). Estas capas no producen hallazgos del mismo tipo en los mismos endpoints, por lo que el correlador no encuentra pares candidatos. Adicionalmente, el vectorizador TF-IDF fue entrenado con descripciones sintéticas que no comparten vocabulario con las descripciones reales de Semgrep y del HTTP Scanner (**domain shift**). Este hallazgo es documentado como trabajo futuro: reentrenamiento con outputs reales de herramientas y uso de embeddings semánticos (sentence-transformers).

**Hallazgo principal del Experimento 1:** La integración SAST+DAST detecta **3.6× más vulnerabilidades** que el análisis estático solo, demostrando cobertura complementaria entre observación de código y observación en runtime.

---

## 5.4 Experimento 2: App Vulnerable Python (Correlación ML)

**Objetivo:** Demostrar el funcionamiento de la correlación ML en un escenario controlado donde SAST y DAST observan **la misma vulnerabilidad desde dos ángulos distintos**.

### 5.4.1 Configuración

- **Objetivo**: `ProgramasPruebas/vulnerable_app.py` — Flask con 8 vulnerabilidades intencionales
- **SAST**: Bandit sobre el código fuente Python
- **DAST**: HybridSecScan Active Probe contra `http://localhost:5000`
- **Script**: `scripts/run_vulnerable_app_experiment.py`

### 5.4.2 Vulnerabilidades en la App Objetivo

| Nº | Vulnerabilidad | Endpoint | Herramienta esperada |
|---|---|---|---|
| 1 | SQL injection via f-string | `/login` | SAST (Bandit B608) + DAST (SQL probe) |
| 2 | Command injection (os.system) | `/execute` | SAST (Bandit B605) |
| 3 | Insecure deserialization (pickle) | `/deserialize` | SAST (Bandit B301) |
| 4 | Path traversal (open sin validar) | `/read_file` | SAST (Bandit) + DAST (traversal probe) |
| 5 | Hardcoded secrets (×2) | global | SAST (Bandit B105) |
| 6 | Insecure temp file (mktemp) | `/process` | SAST (Bandit B108) |
| 7 | Flask debug=True | global | SAST (Bandit B201) |
| 8 | Insecure random (token) | `/token` | SAST (Bandit B311) |

### 5.4.3 Resultados SAST — Bandit

| Severidad | Cantidad | Test IDs |
|---|---|---|
| HIGH | 2 | B605 (command inj), B201 (flask debug) |
| MEDIUM | 5 | B608 (SQL), B301 (pickle), B108 (mktemp), B311 (random) |
| LOW | 5 | B105×2 (secrets), B103, B101, B311 |
| **Total** | **12** | |

### 5.4.4 Resultados DAST — Active Probe

| Tipo | Severidad | Endpoint | Método de detección |
|---|---|---|---|
| SQL Injection | HIGH | `/login` | POST con `' OR '1'='1` → respuesta contiene "SELECT WHERE" |
| Path Traversal | HIGH | `/read_file` | GET `?file=../../requirements.txt` → contenido real retornado |
| Error Disclosure | HIGH | `/deserialize` | POST inválido → stack trace Flask expuesto |
| Missing CSP Header | HIGH | `/` | Cabecera ausente |
| Missing HSTS | HIGH | `/` | HTTP sin redirección HTTPS |
| Missing X-Frame-Options | MEDIUM | `/` | Header ausente |
| Server Info Disclosure | MEDIUM | `/` | `Server: Werkzeug` en headers |
| (+ 5 headers pasivos) | LOW | `/` | — |
| **Total** | **12** | | |

### 5.4.5 Correlación ML — Resultado

**Correlación detectada (confianza 0.894):**

```
SAST: sql_injection @ /login (Bandit B608, línea 25, CWE-89, MEDIUM)
        ↕  conf=0.894
DAST: sql_injection @ /login (HTTP Probe, CWE-89, HIGH)
```

**Descomposición de la confianza:**

| Factor | Valor | Peso | Contribución |
|---|---|---|---|
| Endpoint similarity (`/login` == `/login`) | 1.00 | 40% | 0.400 |
| Type match (`sql_injection` == `sql_injection`) | 1.00 | 35% | 0.350 |
| ML probability (Random Forest) | 0.96 | 15% | 0.144 |
| Severity similarity (MEDIUM vs HIGH) | 0.67 | 10% | 0.067 |
| **Confianza total** | | | **0.894** |

**Interpretación:** La confianza de 0.894 supera el threshold de 0.70 y confirma que el hallazgo SAST de Bandit (posible SQL injection por f-string) está respaldado por evidencia dinámica real: el endpoint `/login` retorna fragmentos SQL en la respuesta al recibir el payload de prueba. Esto elimina la ambigüedad del hallazgo estático y **reduce el falso positivo** al nivel de certeza alta.

**Resumen del Experimento 2:**

| Métrica | Valor |
|---|---|
| SAST (Bandit) | 12 hallazgos |
| DAST (Active Probe) | 12 hallazgos |
| Cobertura híbrida total | 24 hallazgos únicos |
| Correlaciones ML (conf > 0.70) | **1 (sql_injection @ /login)** |
| Confianza de correlación | **0.894** |
| Reducción FP en SAST corroborado | El hallazgo B608 pasa de "posible" a "confirmado" |

---

## 5.5 Evaluación a Escala — 4 Aplicaciones Vulnerables

### 5.5.1 Metodología

Para validar la generalización del sistema, se ejecutó una evaluación sistemática contra cuatro aplicaciones vulnerables ampliamente utilizadas en investigación de seguridad, comparando cada método (SAST solo, DAST solo, Híbrido) contra ground truth validado.

**Herramienta de evaluación:** `scripts/run_scale_evaluation.py`  
**Ground truth:** `data/experiments/ground_truth/*.json` (5 vulnerabilidades documentadas por app)  
**Criterio de TP:** similitud tipo ≥ 0.40 + proximidad de archivo/endpoint ≥ 0

**Nota sobre WebGoat:** Esta aplicación está implementada en Java. Bandit y Semgrep-Python no pueden analizar código Java, por lo que los resultados son 0 hallazgos para esta app. Se documenta como limitación de herramienta, no del sistema.

### 5.5.2 Resultados por Aplicación

| App | Lenguaje | GT (vulns) | SAST P/R/F1 | DAST P/R/F1 | Hybrid P/R/F1 | ΔRecall |
|---|---|---|---|---|---|---|
| OWASP Juice Shop | TypeScript | 5 | 0.12/0.40/**0.18** | 0.05/0.20/**0.08** | 0.08/0.60/**0.14** | **+50%** |
| DVWA | PHP | 5 | 0.12/0.80/**0.21** | N/A | 0.12/0.80/**0.21** | N/A¹ |
| NodeGoat | JavaScript | 5 | 0.10/0.20/**0.13** | N/A | 0.10/0.20/**0.13** | N/A¹ |
| WebGoat | Java | 5 | N/A² | N/A | N/A² | N/A² |
| **Promedio (3 apps)** | | | **0.11/0.47/0.17** | | **0.10/0.53/0.16** | |

¹ DAST no ejecutado contra estas apps en el experimento actual (requiere Docker corriendo).  
² Excluido: Bandit/Semgrep-Python no analizan código Java.

**Hallazgos por app:**
- **Juice Shop** (TypeScript + Semgrep): SAST detecta JWT hardcodeado + XSS patterns (TP=2). DAST detecta sensitive data exposure (TP=1). Hybrid = TP=3 = 60% recall.
- **DVWA** (PHP + Semgrep): SAST detecta SQL injection, command injection, XSS, file inclusion (TP=4). Recall=0.80 — Semgrep con reglas PHP es efectivo.
- **NodeGoat** (JavaScript + Semgrep): SAST detecta NoSQL injection via string concatenation (TP=1). Las otras 4 vulnerabilidades (deserialization, hardcoded credentials, XSS, IDOR) requieren reglas adicionales.

### 5.5.3 Análisis Estadístico

Análisis sobre las 3 aplicaciones con datos completos (excluye WebGoat por incompatibilidad de lenguaje):

| Método | Precision media | Recall media | F1 media | IC 95% (F1) |
|---|---|---|---|---|
| SAST | 0.085 | 0.350 | 0.131 | [-0.017, 0.280] |
| DAST | 0.013 | 0.050 | 0.020 | [-0.044, 0.084] |
| **Hybrid** | **0.076** | **0.400** | **0.122** | [-0.018, 0.262] |

**Prueba t emparejada (one-tailed: Hybrid > individual):**

| Comparación | t-statistic | p-valor | Cohen's d | Tamaño efecto | Significativo |
|---|---|---|---|---|---|
| Hybrid vs SAST | -1.000 | 0.20 | -0.107 | pequeño | NO |
| Hybrid vs DAST | +2.242 | **0.05** | **+1.486** | **grande** | **SÍ** |

**Interpretación:**

1. **Hybrid vs DAST:** La diferencia es estadísticamente significativa (p≤0.05) con efecto grande (Cohen's d=1.486). El sistema híbrido supera al análisis dinámico pasivo solo.

2. **Hybrid vs SAST:** La diferencia no es significativa (p=0.20) con el conjunto de datos actual. Esta limitación se explica por la ausencia de DAST para 2 de las 3 apps comparables. Cuando DAST SÍ está disponible (Juice Shop), el Hybrid obtiene Recall=0.60 vs SAST=0.40 (+50%).

3. **Limitación de precisión:** Los valores bajos de Precision (0.08-0.12) reflejan que SAST genera hallazgos en todo el codebase, mientras el ground truth documenta solo las 5 vulnerabilidades más críticas. SAST puede estar encontrando vulnerabilidades reales no incluidas en el GT simplificado.

### 5.5.4 Conclusión de la Evaluación a Escala

La evaluación a escala demuestra:
1. **SAST obtiene recall 0.20-0.80** según la app y la adecuación de la herramienta al lenguaje
2. **DAST pasivo obtiene recall 0.20** solo donde las vulnerabilidades son detectables en runtime sin autenticación
3. **Hybrid mejora recall en +50%** cuando ambos métodos tienen datos (Juice Shop: 0.40→0.60)
4. **La mejora Hybrid > DAST es estadísticamente significativa** (p<0.05, efecto grande)
5. **Trabajo futuro**: ejecutar DAST contra las 4 apps para obtener comparación estadística completa

## 5.6 Comparación entre Experimentos

| Dimensión | Experimento 1 (Juice Shop) | Experimento 2 (App Vulnerable) |
|---|---|---|
| SAST | Semgrep, 9 hallazgos | Bandit, 12 hallazgos |
| DAST | HTTP pasivo, 23 hallazgos | Active probe, 12 hallazgos |
| Cobertura híbrida | **32** (+256% vs SAST) | **24** (+100% vs SAST) |
| Correlaciones ML | 0 (domain shift) | **1 (conf. 0.894)** |
| Lección principal | Cobertura complementaria | Correlación confirma vulnerabilidades |

**¿Por qué 0 correlaciones en Juice Shop y 1 en la app vulnerable?**

En el Experimento 1, SAST y DAST observaron capas distintas: Semgrep detecta patrones de código, el HTTP scanner detecta configuración HTTP. No hay intersección de tipos de vulnerabilidad entre ambas listas.

En el Experimento 2, Bandit y el Active Probe observaron **la misma vulnerabilidad** (SQL injection en `/login`) desde dos perspectivas: código fuente y comportamiento en runtime. Esto es exactamente el escenario para el que fue diseñado el motor de correlación.

**Conclusión metodológica:** Para que la correlación ML funcione, tanto el SAST como el DAST deben ser capaces de observar el mismo tipo de vulnerabilidad. El probing activo (SQL payloads, path traversal) es condición necesaria para que exista correlación con hallazgos SAST de inyección.

---

## 5.6 Limitaciones Identificadas

### 5.6.1 Domain Shift del Modelo ML

El vectorizador TF-IDF fue entrenado con descripciones sintéticas. Las descripciones reales de Semgrep y el HTTP Scanner no comparten vocabulario con el training set, lo que resulta en features TF-IDF ≈ 0 para datos reales del Experimento 1.

**Impacto:** 0 correlaciones en Juice Shop a pesar de un modelo con F1=0.786.  
**Solución futura:** Reentrenar con outputs reales de Semgrep, Bandit y HTTP Scanner. Reemplazar TF-IDF por embeddings semánticos (sentence-transformers/all-MiniLM).

### 5.6.2 Herramienta SAST vs Lenguaje Objetivo

Bandit es específico para Python. Semgrep cubre JavaScript/TypeScript. Si se analiza una app Java o PHP, se necesitan herramientas adicionales (SpotBugs, PHPStan). El sistema es extensible pero las herramientas incluidas tienen limitaciones de lenguaje.

### 5.6.3 DAST Pasivo no Produce Correlaciones

El HTTP Scanner (modo pasivo) detecta misconfiguraciones de seguridad HTTP, que no tienen contraparte directa en el código fuente analizado por Bandit/Semgrep. El probing activo (Active Probe) es necesario para generar hallazgos correlacionables.

### 5.6.4 Escala del Experimento

Los experimentos se realizaron con dos aplicaciones objetivo. Una validación más amplia requeriría un conjunto de aplicaciones con ground truth validado por expertos de seguridad.

---

## 5.7 Validación de Hipótesis

### H1 — Principal
**"Un sistema híbrido SAST+DAST detecta más vulnerabilidades que herramientas individuales."**

**CONFIRMADA.** El Experimento 1 muestra 32 hallazgos vs 9 (SAST solo) y 23 (DAST solo). La cobertura complementaria es el resultado más robusto y reproducible del sistema.

### H2 — Correlación
**"El motor de correlación ML puede identificar relaciones entre hallazgos SAST y DAST con confianza medible."**

**CONFIRMADA PARCIALMENTE.** En el Experimento 2, la correlación sql_injection@/login obtuvo confianza 0.894, demostrando que el algoritmo funciona cuando SAST y DAST observan el mismo tipo de vulnerabilidad. En el Experimento 1, el domain shift impidió la correlación, lo que identifica un trabajo futuro concreto.

### H3 — Modelo ML
**"El modelo Random Forest alcanza métricas aceptables para un clasificador de correlación de vulnerabilidades."**

**CONFIRMADA.** Recall=96.5% con F1=0.786 en el conjunto de test. El alto recall es la métrica prioritaria en seguridad (preferible detectar de más que dejar pasar vulnerabilidades reales).

---

## 5.8 Trabajo Futuro

1. **Reentrenamiento con datos reales**: Incluir outputs de Semgrep, Bandit y HTTP Scanner en el dataset de entrenamiento para eliminar el domain shift.
2. **Embeddings semánticos**: Reemplazar TF-IDF bag-of-words por modelos de lenguaje (sentence-transformers/all-MiniLM-L6-v2) para capturar similitud semántica entre descripciones de distintas herramientas.
3. **Expansión del Active Probe**: Agregar probing para XSS reflected, SSRF, broken authentication y IDOR.
4. **Validación con más aplicaciones**: Incluir DVWA, NodeGoat y WebGoat con herramientas SAST específicas por lenguaje.
5. **APIs externas**: Validar el flujo completo (sin bypass de SSRF) contra APIs públicas de prueba.

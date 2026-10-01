# HybridSecScan - Sistema de Auditoría Híbrida para APIs REST

## Introducción

En el desarrollo de este trabajo de investigación para mi tesis de grado, he identificado una problemática importante en el ámbito de la ciberseguridad: la falta de herramientas integradas que combinen efectivamente el análisis estático (SAST) y dinámico (DAST) de código, especialmente para APIs REST. Como parte de mi proyecto de titulación en Ingeniería de Software, propongo HybridSecScan, un sistema híbrido que correlaciona hallazgos estáticos y dinámicos, apoyándose en un clasificador de aprendizaje automático, con el objetivo de reducir los falsos positivos.

## Fundamentación del Proyecto

El sistema parte de la premisa de que combinar análisis estático y dinámico puede compensar las limitaciones de cada enfoque por separado. El trabajo toma como marco de referencia el OWASP API Security Top 10 (edición 2023); la sección "Cobertura del OWASP API Security Top 10" detalla qué categorías comprueba el sistema y cuáles no.

## Arquitectura del Sistema

La arquitectura propuesta implementa un diseño modular que facilita la escalabilidad y mantenibilidad del sistema:

- **Backend**: Implementado en FastAPI (Python) para garantizar un rendimiento óptimo en el procesamiento de análisis
- **Frontend**: Desarrollado en React con TypeScript para proporcionar una interfaz de usuario moderna y mantenible
- **Base de Datos**: SQLite para persistencia de resultados y metadatos de análisis
- **Motor de Correlación**: puntuación de confianza ponderada que combina similitud de endpoint, tipo de vulnerabilidad, similitud semántica, severidad y la probabilidad de un clasificador Random Forest (uno de los cinco factores, con un 10 % del peso)

## Metodología de Implementación

### Inicio rápido (backend y frontend)

```bash
git clone https://github.com/OscarILS/HybridSecScan.git
cd HybridSecScan
chmod +x run_hybridscan.sh && ./run_hybridscan.sh
```

### Configuración del Entorno de Desarrollo (Manual)

#### Prerrequisitos del Sistema

- Python 3.11 (versión con la que se probó el proyecto)
- Node.js 18+ con npm
- Git
- Opcional: Semgrep, OWASP ZAP (daemon en el puerto 8080) y Docker para levantar las aplicaciones vulnerables de prueba

#### Configuración del Backend

1. **Instalación de dependencias Python**:
```bash
pip install -r requirements.txt
```

2. **Configuración de herramientas de análisis**:
```bash
# Instalación de Semgrep para análisis estático avanzado
pip install semgrep

# OWASP ZAP para análisis dinámico (descarga opcional)
# Disponible en: https://www.zaproxy.org/download/
```

3. **Inicialización del servidor**:
```bash
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

#### Configuración del Frontend

1. **Instalación de dependencias Node.js**:
```bash
cd frontend
npm install
```

2. **Ejecución del entorno de desarrollo**:
```bash
npm run dev
```

## Utilización del Sistema

### Interfaz de Usuario Web

El sistema proporciona una interfaz web intuitiva accesible a través de `http://localhost:5173` que permite:

1. Carga de archivos de código fuente para análisis SAST
2. Configuración de parámetros específicos de análisis
3. Ejecución de análisis automatizados
4. Visualización de resultados y correlaciones

### Endpoints de la API REST

La API desarrollada expone los siguientes endpoints principales:

- `GET /` y `GET /health` - Información y estado del sistema
- `POST /upload/` - Carga de archivos para análisis
- `POST /scan/sast` - Análisis estático (Bandit o Semgrep)
- `POST /scan/dast` - Análisis dinámico (comprobaciones pasivas; ZAP si está disponible)
- `POST /scan/hybrid` - Correlación de un escaneo SAST y uno DAST
- `GET /scan-results` - Historial de análisis
- `GET /download/pdf/{scan_id}` y `GET /download/json/{scan_id}` - Reportes
- `POST /auth/register`, `POST /auth/login`, `GET /auth/me` - Autenticación JWT
- `GET /api/model-metrics` y `GET /api/scale-evaluation` - Métricas del modelo y de la evaluación

### Scripts de Análisis Independiente

```bash
# Análisis estático con Bandit
python scripts/run_bandit.py /ruta/al/codigo

# Análisis estático con Semgrep
python scripts/run_semgrep.py /ruta/al/codigo

# Análisis dinámico con OWASP ZAP
python scripts/run_zap.py https://api.ejemplo.com
```

## Características de Seguridad Implementadas

En el desarrollo del sistema, se han incorporado múltiples capas de seguridad:

- Validación estricta de tipos de archivo permitidos
- Limitación de tamaño de archivos (máximo 50 MB)
- Generación de nombres de archivo seguros mediante UUID
- Validación robusta de URLs para análisis DAST
- Manejo seguro de procesos subprocess
- Implementación de timeouts para prevenir análisis prolongados

## Cobertura del OWASP API Security Top 10

El escáner DAST propio (`backend/dast_scanner.py`) implementa comprobaciones orientadas a las siguientes
categorías de la edición 2023. La tabla indica **qué se comprueba**, no una tasa de detección: la cobertura
por categoría **no se ha validado experimentalmente** (la evaluación usa 5 vulnerabilidades por aplicación y
no está desglosada por categoría).

| Categoría (2023) | Comprobaciones DAST implementadas | Modo |
|---|---|---|
| API1: Broken Object Level Authorization | Acceso sin autenticación a objetos, enumeración de IDs (IDOR), acceso cruzado entre usuarios | Activo |
| API2: Broken Authentication | JWT con `alg: none`, secreto JWT débil, credenciales por defecto, tokens predecibles | Activo |
| API3: Broken Object Property Level Authorization | Exposición excesiva de datos: recorre los endpoints GET de la especificación OpenAPI y marca respuestas con campos sensibles | Guiado por OpenAPI |
| API4: Unrestricted Resource Consumption | Ausencia de rate limiting, límite declarado pero no aplicado | Pasivo |
| API5: Broken Function Level Authorization | Métodos HTTP peligrosos habilitados | Pasivo |
| API8: Security Misconfiguration | Cabeceras de seguridad, CORS, divulgación de errores, información del servidor, transporte sin TLS (pasivo); modo debug (activo) | Pasivo y activo |
| API9: Improper Inventory Management | Endpoints sensibles expuestos (documentación, métricas, administración) | Pasivo |

- **Pasivo:** lo ejecuta el endpoint `POST /scan/dast` de la aplicación (`run_dast_scan`).
- **Activo:** solo lo ejecutan los scripts de experimentos (`run_active_probe_scan`), pensados para entornos
  controlados; envía cargas de ataque, así que no se expone en la aplicación.
- **Guiado por OpenAPI:** `run_active_probe_scan(target, openapi_spec=...)` lee la especificación OpenAPI de la
  API, recorre sus endpoints reales y añade comprobaciones de observación (`backend/openapi_probe.py`).

No hay comprobaciones específicas para API6, API7 ni API10. La detección de API6 (flujos de negocio) y API7
(SSRF) requiere lógica específica del negocio o sondas activas delicadas, más propias de una herramienta madura
como OWASP ZAP; API10 (consumo de APIs de terceros) es un riesgo de código/dependencias, no observable por HTTP.
Las sondas activas de inyección SQL y *path traversal* detectan vulnerabilidades que la edición 2023 no trata
como categoría propia. El SAST (Bandit y Semgrep) aplica las reglas de cada herramienta, que no están
organizadas por categorías del OWASP API Top 10.

## Estructura del Proyecto

La organización del código fuente sigue una arquitectura modular que facilita la mantenibilidad y extensibilidad del sistema:

```
HybridSecScan/
├── backend/                    # API FastAPI
│   ├── main.py                 # Fábrica de la app, middleware y endpoints de métricas
│   ├── routers/                # Endpoints: sast, dast, hybrid, auth_router, reports
│   ├── correlation_engine.py   # Motor de correlación (confianza ponderada + Random Forest)
│   ├── dast_scanner.py         # Escáner HTTP (y ZAP si está disponible)
│   ├── ssrf_validator.py       # Bloqueo de destinos DAST internos (SSRF)
│   ├── auth.py                 # JWT y hashing de contraseñas
│   ├── pdf_generator.py        # Reportes PDF/JSON
│   ├── train_ml_model.py       # Entrenamiento del Random Forest
│   └── ...                     # utils, dependencies, cache, gestor de modelos
├── database/
│   └── models.py               # Modelos SQLAlchemy (ScanResult, User)
├── frontend/src/
│   ├── App.tsx                 # Escáner (SAST, DAST, híbrido)
│   └── ResearchDashboard.tsx   # Panel de investigación (datos reales)
├── data/
│   ├── processed/              # Dataset sintético (train/validation/test)
│   ├── models/                 # Modelo entrenado y metadata.json
│   └── experiments/            # Ground truth, resultados y evaluación a escala
├── scripts/
│   ├── generate_training_dataset.py  # Genera los 1,300 pares sintéticos
│   ├── run_scale_evaluation.py       # Evaluación en 4 apps vs ground truth
│   ├── run_*_experiment.py           # Experimentos de correlación
│   └── run_bandit.py / run_semgrep.py / run_zap.py
├── ProgramasPruebas/           # Apps intencionalmente vulnerables para pruebas
├── tests/                      # Pruebas (pytest)
├── requirements.txt       # Dependencias de Python
└── README.md             # Este documento
```

## Contribuciones del Proyecto

### Problemas Identificados y Solucionados

A lo largo del desarrollo de este proyecto de grado, se han abordado múltiples desafíos técnicos:

- **Integración CORS**: Configuración adecuada para comunicación frontend-backend
- **Gestión de Procesos**: Manejo robusto de errores en llamadas subprocess
- **Seguridad en Carga de Archivos**: Implementación de validaciones exhaustivas
- **Optimización de Rendimiento**: Implementación de timeouts para prevenir procesos bloqueados
- **Arquitectura de Datos**: Diseño optimizado del modelo de base de datos
- **Experiencia de Usuario**: Desarrollo de una interfaz intuitiva y responsive

### Algoritmo de Correlación ML

Mi contribución principal es un motor de correlación que empareja hallazgos SAST y DAST:

1. **Puntuación de confianza ponderada**: combina similitud de endpoint, tipo de vulnerabilidad, similitud semántica de las descripciones, probabilidad del Random Forest y severidad
2. **Clasificador Random Forest**: entrenado con pares sintéticos etiquetados (correlacionado / no correlacionado)
3. **Confirmación cruzada**: marca los hallazgos estáticos que la evidencia dinámica confirma

El objetivo de diseño es reducir falsos positivos priorizando los hallazgos confirmados por ambas técnicas; los experimentos actuales no lo demuestran (ver Resultados).

## Validación del Sistema

### Metodología de Evaluación

La validación se realizó en dos niveles:

- **Modelo ML**: dataset sintético de 1,300 pares SAST–DAST (6 categorías, split 80/10/10), 517 features
- **Sistema completo**: 4 aplicaciones intencionalmente vulnerables (OWASP Juice Shop, DVWA, NodeGoat, OWASP WebGoat) contrastadas contra ground truth
- **Métricas**: Precision, Recall, F1-Score, ROC-AUC; prueba t pareada y d de Cohen para comparar métodos

### Resultados Obtenidos

**Modelo Random Forest** (fuente: `data/models/metadata.json`):

| Conjunto | Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|---|
| Validación | 80.8% | 69.4% | 94.3% | 0.800 | 0.851 |
| Test | 76.9% | 66.3% | 96.5% | 0.786 | 0.785 |

El modelo resulta con recall alto y precisión menor. Es un resultado observado, no un ajuste: se usa el umbral de decisión por defecto (0.5) con `class_weight='balanced'`.

**Evaluación a escala en 4 aplicaciones** (fuente: `data/experiments/scale_evaluation_20260929_203402.json`).
En esta evaluación, "Híbrido" es la **unión** de los hallazgos SAST y DAST comparada contra el ground truth; **no aplica el motor de correlación**, así que mide la cobertura combinada de ambas técnicas, no el correlador:

| Método | Precision media | Recall medio | F1 medio |
|---|---|---|---|
| SAST | 0.171 | 0.500 | 0.219 |
| DAST | 0.013 | 0.050 | 0.020 |
| Híbrido | 0.158 | 0.550 | 0.203 |

- El enfoque híbrido supera a DAST solo en F1 (t pareada, gl = 3, t = 2.37, p = 0.049 unilateral; p = 0.098 bilateral).
- Frente a SAST solo, el híbrido no mejora el F1 (−0.016; t = −1.65, p = 0.20 bilateral, p = 0.90 unilateral). El recall medio sube +0.05 de forma descriptiva (p = 0.20 unilateral, no significativo); todo ese aumento viene de Juice Shop (0.40 → 0.60).
- La precisión media del híbrido (0.158) es menor que la de SAST (0.171): los hallazgos DAST añaden sobre todo falsos positivos. Con n = 4 aplicaciones, la potencia estadística es baja.

**Experimentos de correlación** (sí aplican el motor de correlación):

- App vulnerable (Flask, SAST con Bandit): 1 correlación confirmada, SQL injection en `/login`, confianza 0.884 (`data/experiments/results/hybrid_vulnerable_20260930_095950.json`).
  Contra su ground truth de 9 vulnerabilidades (`data/experiments/correlation_evaluation_vulnerable_app_20260930_230706.json`, caso de estudio):

  | Método | Precisión | Recall |
  |---|---|---|
  | SAST (Bandit) | 0.750 | 0.889 (8 de 9) |
  | DAST (escáner activo) | 0.250 | 0.333 (3 de 9) |
  | Unión SAST+DAST | 0.500 | 1.000 (9 de 9) |
  | Correlación (pares confirmados) | 1.000 (1 de 1) | 0.111 (1 de 9) |

  La correlación confirmada es correcta, pero solo confirma 1 de las 2 vulnerabilidades que ambas técnicas detectaron. La otra, el modo debug (falla global de la aplicación), queda en 0.523 porque el correlador compara endpoints y esa falla no pertenece a ninguno. El desglose de ambas confianzas (valor, peso y aporte de cada factor) está en `data/experiments/figures/tabla_evaluacion_correlacion.md`.

  Pesos de la confianza (`CONFIDENCE_WEIGHTS` en `backend/correlation_engine.py`, decisión de diseño): endpoint 0.40, tipo 0.35, similitud semántica 0.10, Random Forest 0.10, severidad 0.05.
- **VAmPI** (API REST vulnerable, Flask/OpenAPI; SAST con Bandit, DAST activo): ground truth de 9 vulnerabilidades tomadas de su documentación oficial, 8 de ellas de categorías propias de APIs (`data/experiments/correlation_evaluation_vampi_20260930_230706.json`):

  | Método | Precisión | Recall |
  |---|---|---|
  | SAST (Bandit) | 0.286 | 0.222 (2 de 9) |
  | DAST (escáner activo) | 0.100 | 0.111 (1 de 9) |
  | Unión SAST+DAST | 0.176 | 0.333 (3 de 9) |
  | Correlación (pares confirmados) | — (0 pares) | 0.000 |

  Detectadas: inyección SQL y clave JWT débil (SAST) y falta de rate limiting (DAST). No se detectó ninguna vulnerabilidad de API1 (BOLA) ni de API3 (mass assignment, exposición excesiva de datos): los probes activos están pensados para formularios y rutas fijas, no para endpoints JSON con parámetros en la ruta. Ninguna vulnerabilidad fue detectada por ambas técnicas, así que el correlador no tuvo nada que confirmar. Semgrep no pudo ejecutarse en este equipo (bloqueado por una política de control de aplicaciones de Windows).
- OWASP Juice Shop (SAST con Semgrep): 0 correlaciones. Es una ejecución distinta de la evaluación a escala (9 hallazgos SAST y 23 DAST; ver `data/experiments/EXPERIMENTAL_RESULTS_SUMMARY.md`). El modelo no correlaciona por *domain shift*: el vocabulario TF-IDF aprendido de descripciones sintéticas no coincide con el de Semgrep y el escáner HTTP. Reentrenar con salidas reales de las herramientas queda como trabajo futuro.

## Limitaciones y Trabajo Futuro

### Limitaciones

1. **Domain shift del modelo**: el Random Forest se entrenó con 1,300 pares sintéticos; su vocabulario TF-IDF no coincide con el de Semgrep y el escáner HTTP, y no produjo correlaciones en OWASP Juice Shop.
2. **Muestra pequeña**: la evaluación a escala usa 4 aplicaciones con 5 vulnerabilidades cada una, por lo que las pruebas estadísticas tienen poca potencia.
3. **La evaluación a escala no mide el correlador**: compara la unión de hallazgos SAST+DAST; el motor de correlación solo se evaluó en un caso de estudio (una aplicación).
4. **Fallas globales**: el correlador compara endpoints, por lo que no confirma vulnerabilidades que afectan a toda la aplicación (p. ej. el modo debug).
5. **Pesos por diseño**: los pesos de la fórmula de confianza y el umbral de 0.70 no se optimizaron empíricamente.
6. **Cobertura OWASP parcial**: no hay comprobaciones para API3, API6, API7 ni API10. Sobre una API REST real (VAmPI), el sistema detectó 3 de 9 vulnerabilidades y ninguna de API1 ni API3: los probes activos no exploran endpoints JSON con parámetros en la ruta.

### Trabajo futuro

- Reentrenar el clasificador con salidas reales de las herramientas SAST/DAST.
- Ampliar la evaluación del correlador a más aplicaciones con ground truth.
- Tratar las vulnerabilidades globales sin depender de la similitud de endpoint.
- Calibrar los pesos y el umbral de la fórmula de confianza con datos etiquetados.
- Hacer el DAST consciente de la especificación OpenAPI: recorrer los endpoints declarados y probar BOLA, mass assignment y exposición de datos sobre endpoints JSON con parámetros.
- Añadir comprobaciones para las categorías OWASP no cubiertas y validarlas por categoría.

## Consideraciones del Proyecto

- **Uso Responsable**: diseñado para seguridad defensiva. Los probes activos solo se ejecutan desde los scripts de experimentos, contra aplicaciones de prueba en entornos controlados.
- **Protección SSRF**: el endpoint DAST rechaza destinos en redes privadas, loopback y link-local.
- **Código Abierto**: MIT License.

## Información Académica

**Autor**: Oscar Laguna Santa Cruz
**Institución**: Universidad Nacional Mayor de San Marcos - Facultad de Ingeniería de Sistemas e Informática
**Carrera**: Ingeniería de Software
**Proyecto**: Tesis de Grado / Proyecto de Titulación
**Asesor(a)**: [por completar]
**Año**: [por completar]

## Documentación

- **[CLAUDE.md](CLAUDE.md)** - Arquitectura técnica, comandos y convenciones del proyecto
- **[data/experiments/README.md](data/experiments/README.md)** - Ground truth, evaluación a escala, evaluación del correlador y figuras
- **[data/experiments/EXPERIMENTAL_RESULTS_SUMMARY.md](data/experiments/EXPERIMENTAL_RESULTS_SUMMARY.md)** - Experimento en OWASP Juice Shop
- **[ProgramasPruebas/GUIA_PRUEBAS.md](ProgramasPruebas/GUIA_PRUEBAS.md)** - Aplicaciones vulnerables y guía de pruebas

## Licencia

MIT License - Ver archivo LICENSE para más detalles.

## Contribución

1. Fork el proyecto
2. Crear branch para feature (`git checkout -b feature/AmazingFeature`)
3. Commit cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push al branch (`git push origin feature/AmazingFeature`)
5. Abrir Pull Request

## Soporte

Para reportar bugs o solicitar features, por favor crea un issue en GitHub.


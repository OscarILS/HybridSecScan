# HybridSecScan - Sistema de Auditoría Híbrida para APIs REST

## Introducción

En el desarrollo de este trabajo de investigación para mi tesis de grado, he identificado una problemática importante en el ámbito de la ciberseguridad: la falta de herramientas integradas que combinen efectivamente el análisis estático (SAST) y dinámico (DAST) de código, especialmente para APIs REST. Como parte de mi proyecto de titulación en Ingeniería de Software, propongo HybridSecScan, un sistema híbrido que incorpora técnicas de aprendizaje automático para correlacionar vulnerabilidades y reducir los falsos positivos.

## Fundamentación del Proyecto

El sistema desarrollado se basa en la premisa de que la integración inteligente de múltiples metodologías de análisis de seguridad puede superar las limitaciones individuales de cada enfoque. Mi trabajo de grado se centra específicamente en las vulnerabilidades catalogadas en el OWASP API Security Top 10, proporcionando una cobertura integral de los riesgos más críticos en el desarrollo de APIs modernas.

## Arquitectura del Sistema

La arquitectura propuesta implementa un diseño modular que facilita la escalabilidad y mantenibilidad del sistema:

- **Backend**: Implementado en FastAPI (Python) para garantizar un rendimiento óptimo en el procesamiento de análisis
- **Frontend**: Desarrollado en React con TypeScript para proporcionar una interfaz de usuario moderna y mantenible
- **Base de Datos**: SQLite para persistencia de resultados y metadatos de análisis
- **Motor de Correlación**: Algoritmo basado en Random Forest para la correlación inteligente de vulnerabilidades

## Metodología de Implementación

### 🐳 Despliegue con Docker (Recomendado para Producción)

**La forma más rápida y segura de desplegar HybridSecScan es usando Docker:**

```bash
# Linux/macOS
git clone https://github.com/OscarILS/HybridSecScan.git
cd HybridSecScan
chmod +x deploy.sh
./deploy.sh

# Windows PowerShell
git clone https://github.com/OscarILS/HybridSecScan.git
cd HybridSecScan
.\deploy.ps1
```

**Acceso**: `http://localhost`

📖 **Documentación completa de Docker**: Ver [DOCKER.md](DOCKER.md) y [DEPLOYMENT.md](DEPLOYMENT.md)

---

### Configuración del Entorno de Desarrollo (Manual)

#### Prerrequisitos del Sistema

Para la implementación completa del sistema, es necesario contar con:
- Python 3.8 o superior (recomendado 3.11+)
- Node.js 18+ con npm
- Git para control de versiones
- **O alternativamente**: Docker + Docker Compose

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

- `GET /` - Información general del sistema
- `POST /upload/` - Carga de archivos para análisis
- `POST /scan/sast` - Ejecución de análisis estático
- `POST /scan/dast` - Ejecución de análisis dinámico
- `GET /scan-results` - Recuperación del historial de análisis
- `GET /health` - Verificación del estado del sistema

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
- Limitación configurable de tamaño de archivos (máximo 10MB)
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
| API4: Unrestricted Resource Consumption | Ausencia de rate limiting, límite declarado pero no aplicado | Pasivo |
| API5: Broken Function Level Authorization | Métodos HTTP peligrosos habilitados | Pasivo |
| API8: Security Misconfiguration | Cabeceras de seguridad, CORS, divulgación de errores, información del servidor, transporte sin TLS (pasivo); modo debug (activo) | Pasivo y activo |
| API9: Improper Inventory Management | Endpoints sensibles expuestos (documentación, métricas, administración) | Pasivo |

- **Pasivo:** lo ejecuta el endpoint `POST /scan/dast` de la aplicación (`run_dast_scan`).
- **Activo:** solo lo ejecutan los scripts de experimentos (`run_active_probe_scan`), pensados para entornos
  controlados; envía cargas de ataque, así que no se expone en la aplicación.

No hay comprobaciones específicas para API3, API6, API7 ni API10. Las sondas activas de inyección SQL y *path
traversal* detectan vulnerabilidades que la edición 2023 no trata como categoría propia. El SAST (Bandit y
Semgrep) aplica las reglas de cada herramienta, que no están organizadas por categorías del OWASP API Top 10.

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
  Contra su ground truth de 9 vulnerabilidades (`data/experiments/correlation_evaluation_20260930_131217.json`, caso de estudio):

  | Método | Precisión | Recall |
  |---|---|---|
  | SAST (Bandit) | 0.750 | 0.889 (8 de 9) |
  | DAST (escáner activo) | 0.250 | 0.333 (3 de 9) |
  | Unión SAST+DAST | 0.500 | 1.000 (9 de 9) |
  | Correlación (pares confirmados) | 1.000 (1 de 1) | 0.111 (1 de 9) |

  La correlación confirmada es correcta, pero solo confirma 1 de las 2 vulnerabilidades que ambas técnicas detectaron. La otra, el modo debug (falla global de la aplicación), queda en 0.523 porque el correlador compara endpoints y esa falla no pertenece a ninguno.
- OWASP Juice Shop (SAST con Semgrep): 0 correlaciones. Es una ejecución distinta de la evaluación a escala (9 hallazgos SAST y 23 DAST; ver `data/experiments/EXPERIMENTAL_RESULTS_SUMMARY.md`). El modelo no correlaciona por *domain shift*: el vocabulario TF-IDF aprendido de descripciones sintéticas no coincide con el de Semgrep y el escáner HTTP. Reentrenar con salidas reales de las herramientas queda como trabajo futuro.

## Limitaciones y Trabajo Futuro

### Limitaciones Actuales

Como parte de la honestidad académica, reconozco las siguientes limitaciones:

1. **Escalabilidad**: El sistema actual está optimizado para análisis de proyectos pequeños y medianos
2. **Cobertura de Lenguajes**: Enfoque principal en Python, con soporte básico para otros lenguajes
3. **Análisis en Tiempo Real**: La correlación ML requiere procesamiento offline

### Direcciones Futuras

Mi trabajo continuará evolucionando en las siguientes áreas:

- **Integración con CI/CD**: Desarrollo de plugins para pipelines de integración continua
- **Análisis de Contenedores**: Extensión para análisis de vulnerabilidades en imágenes Docker
- **Mejoras en ML**: Exploración de algoritmos más avanzados para mejor correlación
- **Análisis de Dependencias**: Incorporación de Software Composition Analysis (SCA)
- **Interfaz Mejorada**: Dashboard más completo para visualización de resultados

## Consideraciones del Proyecto

El desarrollo de este trabajo de grado se ha realizado siguiendo principios éticos:

- **Uso Responsable**: El sistema está diseñado exclusivamente para propósitos de seguridad defensiva
- **Privacidad de Datos**: No se almacenan datos sensibles de los proyectos analizados
- **Código Abierto**: MIT License para fomentar el aprendizaje y la colaboración
- **Transparencia**: Todo el código fuente está disponible para revisión

## Información Académica

**Autor**: Oscar Laguna Santa Cruz
**Institución**: Universidad Nacional Mayor de San Marcos - Facultad de Ingeniería de Sistemas e Informática 
**Carrera**: Ingeniería de Software 
**Proyecto**: Tesis de Grado / Proyecto de Titulación  
**Director**: Dra. Luzmila
**Año**: 2025

Para consultas académicas o sobre el funcionamiento del sistema, puede contactar a través de los canales oficiales de la universidad.

## 📚 Documentación Completa

Toda la documentación del proyecto está organizada en la carpeta [`docs/`](docs/):

- **[Índice de Documentación](docs/README.md)** - Índice completo de toda la documentación disponible
- **[Documentación Académica](docs/academic-documentation.md)** - Documentación completa para tesis
- **[Propuesta del Sistema](docs/propuesta-sistema-cap4.md)** - Capítulo 4: Arquitectura y diseño
- **[Validación Experimental](docs/validacion-experimental-cap5.md)** - Capítulo 5: Resultados experimentales
- **[Diagramas UML](docs/uml/)** - Arquitectura completa del sistema
- **[Configuración SAST](docs/configuracion-herramientas-sast.md)** - Resultados de validación con herramientas

## Reconocimientos

Agradezco especialmente a mi directora de tesis, a los docentes de la carrera, y a la comunidad open source por sus contribuciones que han hecho posible este proyecto de grado.

---

*Este trabajo representa una contribución al campo de la ciberseguridad para APIs REST, desarrollado como proyecto de tesis para optar al título de Ingeniero de Sistemas.*

## Problemas Solucionados

-  Configuración CORS para comunicación frontend-backend
-  Manejo de errores en subprocess calls
-  Validación de seguridad en subida de archivos
-  Timeouts para evitar procesos colgados
-  Estructura de directorios corregida
-  Scripts con rutas absolutas
-  Modelo de base de datos mejorado
-  Interfaz de usuario más robusta

##  Mejoras Futuras

-  Autenticación y autorización de usuarios
-  Análisis de contenedores Docker
-  Integración con CI/CD pipelines
-  Reportes en PDF
-  Dashboard de métricas avanzado
-  Análisis de dependencias (SCA)
-  Integración con más herramientas SAST/DAST

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


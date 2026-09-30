# Graph Report - HybridSecScan  (2026-09-29)

## Corpus Check
- 1 files · ~182,251 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 996 nodes · 1475 edges · 73 communities (57 shown, 10 thin omitted)
- Extraction: 93% EXTRACTED · 6% INFERRED · 0% AMBIGUOUS · INFERRED: 95 edges (avg confidence: 0.88)
- Token cost: 57,843 input · 0 output

## Community Hubs (Navigation)
- Benchmark Evaluation System
- Experimental Validator
- DAST Scanner Engines
- README: System & Tooling
- Project Guide & Pipeline Docs
- Frontend npm Package
- Scale Evaluation Stats
- PDF Report Generator
- React Dashboard UI
- Cache Manager
- ML Model Manager
- TS App Config
- Training Visualizations Code
- TS Node Config
- Experimental Analyzer
- Auth Router & JWT
- Correlator Core & Tests
- SAST Router & Utils
- Experimental Plotter
- NVD Dataset Processing
- Correlation Similarity Scoring
- DAST Router & SSRF Guard
- Correlation Confidence Engine
- Security Validation Tests
- JWT Auth Core
- Vulnerability Types & Hybrid
- Upload Validation
- Juice Shop Experiment
- Vulnerable JS App
- Vulnerable App Experiment
- Training Dataset Generator
- RF Test-Set Metric Charts
- SCA pip-audit Report
- Auth Test Fixtures
- Vulnerable Flask App
- Requirements & Reports
- Registration Tests
- FastAPI Main App
- Reports Download Router
- Vulnerable Apps Launcher
- Hybrid Correlation Tests
- Semantic Similarity
- Model Diagnostics
- ML Training Pipeline
- Password Hashing Tests
- Login Tests
- DAST SSRF Tests
- Integration Test Setup
- SAST Endpoint Tests
- Feature Engineering
- Feature Analysis Charts
- Scan Config
- Protected Endpoint Tests
- Auth Security Tests
- API Endpoint Tests
- Performance Limit Tests
- Setup Script
- File Upload Tests
- Run Script
- Token Expiration Tests
- Health & Root Tests
- Train Script Entry
- TS Root Config
- Quick Reference Script
- SCA Runner
- Vite logo (vite.svg)
- React logo (react.svg)

## God Nodes (most connected - your core abstractions)
1. `VulnerabilityCorrelator` - 40 edges
2. `Vulnerability` - 26 edges
3. `ExperimentalValidator` - 22 edges
4. `compilerOptions` - 19 edges
5. `CorrelationMLTrainer` - 18 edges
6. `HTTPSecurityScanner` - 17 edges
7. `ScanFinding` - 17 edges
8. `compilerOptions` - 17 edges
9. `BenchmarkSuite` - 16 edges
10. `VulnerabilityType` - 15 edges

## Surprising Connections (you probably didn't know these)
- `CorrelationMLTrainer` --references--> `Top 20 Feature Importance Chart (Gini)`  [INFERRED]
  backend/train_ml_model.py → data/models/visualizations/02_feature_importance.png
- `Random Forest Correlation Engine` --implements--> `VulnerabilityCorrelator`  [INFERRED]
  README.md → backend/correlation_engine.py
- `CorrelationMLTrainer` --references--> `ROC Curve (AUC = 0.7854)`  [INFERRED]
  backend/train_ml_model.py → data/models/visualizations/04_roc_curve.png
- `CorrelationMLTrainer` --references--> `Feature Correlation Heatmap (Features 497-516, Pearson)`  [INFERRED]
  backend/train_ml_model.py → data/models/visualizations/correlation_heatmap.png
- `CorrelationMLTrainer` --references--> `Feature Distribution Boxplots by Correlation Class (Features 509-516)`  [INFERRED]
  backend/train_ml_model.py → data/models/visualizations/feature_distribution_boxplots.png

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Hybrid scan pipeline tools and correlator** — claude_bandit, claude_semgrep, claude_owasp_zap, data_experiments_experimental_results_summary_http_security_scanner, claude_random_forest_correlator [EXTRACTED 1.00]
- **Engineered Feature Analysis (497-516)** — data_models_visualizations_02_feature_importance, data_models_visualizations_correlation_heatmap, data_models_visualizations_feature_distribution_boxplots [INFERRED 0.85]
- **Random Forest Correlator Test-Set Evaluation** — data_models_visualizations_03_confusion_matrix, data_models_visualizations_04_roc_curve, data_models_visualizations_05_precision_recall_curve, data_models_visualizations_06_metrics_comparison [INFERRED 0.85]
- **Hybrid SAST+DAST Correlation Flow** — readme_sast, readme_dast, readme_random_forest_correlation_engine, readme_false_positive_reduction [EXTRACTED 1.00]
- **External Security Tooling Stack** — readme_bandit, readme_semgrep, readme_owasp_zap, scripts_run_bandit, scripts_run_semgrep, scripts_run_zap [EXTRACTED 1.00]
- **System Validation Methodology** — readme_synthetic_training_dataset, readme_scale_evaluation, readme_vulnerable_benchmark_apps, readme_statistical_tests, data_models_metadata [EXTRACTED 1.00]

## Communities (73 total, 10 thin omitted)

### Community 0 - "Benchmark Evaluation System"
Cohesion: 0.05
Nodes (30): BenchmarkSuite, EvaluationMetrics, MetricType, Enum, Sistema de Métricas y Evaluación de Efectividad Módulo para medir y comparar la…, Ejecuta evaluación comparativa entre herramientas individuales y sistema híbrido, Evalúa una herramienta individual, Evalúa el sistema híbrido completo (+22 more)

### Community 1 - "Experimental Validator"
Cohesion: 0.07
Nodes (30): ExperimentalValidator, main(), Path, Sistema de Validación Experimental - HybridSecScan…, Aplicación vulnerable de prueba, Valida experimentalmente la efectividad de HybridSecScan, Carga la lista de aplicaciones vulnerables de prueba, Descarga una aplicación de prueba si no existe (+22 more)

### Community 2 - "DAST Scanner Engines"
Cohesion: 0.07
Nodes (25): HTTPSecurityScanner, Any, Motor de análisis DAST real para HybridSecScan. Implementa dos estrategias: 1.…, Probing activo de vulnerabilidades de inyección. SOLO para entornos controlados…, Scanner DAST que realiza peticiones HTTP reales al objetivo. Cubre las…, Controlador de OWASP ZAP en modo daemon vía su API REST. Para iniciar ZAP como…, Escaneo DAST con probing activo de inyecciones. Combina los checks pasivos del…, Ejecuta un escaneo DAST real contra target_url. Prioridad: 1. OWASP ZAP daemon… (+17 more)

### Community 3 - "README: System & Tooling"
Cohesion: 0.06
Nodes (42): Copilot Instructions, OWASP API Security Top 10, data/models/metadata.json, Bandit, DAST (Dynamic Analysis), Docker Deployment, Domain Shift (TF-IDF vocabulary mismatch), False Positive Reduction (+34 more)

### Community 4 - "Project Guide & Pipeline Docs"
Cohesion: 0.07
Nodes (41): CI/CD Pipeline Workflow, CI Backend Tests (pytest + coverage), Code Quality Job (flake8, black, isort, bandit), Frontend Build Job (React + TS), CI Integration and Auth Tests, Trivy Vulnerability Scan Job, Security Analysis Pipeline Workflow, SAST Job Bandit + Semgrep (+33 more)

### Community 5 - "Frontend npm Package"
Cohesion: 0.05
Nodes (39): eslint, @eslint/js, eslint-plugin-react-hooks, eslint-plugin-react-refresh, dependencies, react, react-dom, recharts (+31 more)

### Community 6 - "Scale Evaluation Stats"
Cohesion: 0.11
Nodes (33): best_result_file(), classify_findings(), cohens_d(), compute_metrics(), confidence_interval_95(), load_app_results(), main(), match_finding_to_gt() (+25 more)

### Community 7 - "PDF Report Generator"
Cohesion: 0.14
Nodes (31): _build_owasp_table(), _cover_page(), _dast_flow_page(), _executive_summary(), _findings_pages(), generate_json_summary(), generate_pdf_report(), _health_bar_drawing() (+23 more)

### Community 8 - "React Dashboard UI"
Cohesion: 0.08
Nodes (27): Frontend index.html, #root mount to /src/main.tsx, Frontend README, React + TypeScript + Vite stack, App(), Finding, FindingCard(), findingLabel() (+19 more)

### Community 9 - "Cache Manager"
Cohesion: 0.09
Nodes (15): CacheManager, Any, Sistema de caché en memoria para resultados de escaneos. Reduce carga en base…, Limpia todas las entradas del caché. Returns: Número de entradas eliminadas, Elimina todas las entradas expiradas. Returns: Número de entradas eliminadas, Gestor de caché en memoria con TTL (Time To Live). Almacena resultados de…, Verifica si una clave existe y no ha expirado. Args: prefix: Prefijo de la…, Obtiene estadísticas del caché. Returns: Diccionario con estadísticas (hits,… (+7 more)

### Community 10 - "ML Model Manager"
Cohesion: 0.10
Nodes (16): MLModelManager, Any, Gestor de modelos de Machine Learning para persistencia y versionado. Permite…, Carga un modelo guardado. Args: version: Versión específica a cargar (None =…, Lista todas las versiones disponibles con su metadata. Returns: Diccionario con…, Gestor centralizado de modelos ML. Maneja persistencia, versionado y metadatos…, Elimina una versión específica del modelo. Args: version: Número de versión a…, Obtiene el número de versión actual. (+8 more)

### Community 11 - "TS App Config"
Cohesion: 0.08
Nodes (24): compilerOptions, allowImportingTsExtensions, erasableSyntaxOnly, jsx, lib, module, moduleDetection, moduleResolution (+16 more)

### Community 12 - "Training Visualizations Code"
Cohesion: 0.10
Nodes (11): Path, Gráfica de barras: Top N features más importantes, Heatmap de matriz de confusión, Curva ROC con área bajo la curva, Curva Precision-Recall, Gráfica comparativa de métricas, Mapa de calor de correlación entre features principales, Boxplots comparativos de distribución de features por clase (+3 more)

### Community 13 - "TS Node Config"
Cohesion: 0.10
Nodes (20): compilerOptions, allowImportingTsExtensions, erasableSyntaxOnly, lib, module, moduleDetection, moduleResolution, noEmit (+12 more)

### Community 14 - "Experimental Analyzer"
Cohesion: 0.14
Nodes (12): ExperimentalAnalyzer, main(), DataFrame, Análisis Estadístico de Resultados Experimentales…, Calcula estadísticas descriptivas, Realiza pruebas de hipótesis estadísticas, Analiza la reducción de falsos positivos, Genera tabla en formato LaTeX para tesis (+4 more)

### Community 15 - "Auth Router & JWT"
Cohesion: 0.15
Nodes (19): create_access_token(), get_password_hash(), Genera un hash seguro de la contraseña. Args: password: Contraseña en texto…, Crea un token JWT con los datos proporcionados. Args: data: Datos a codificar…, get_current_user_info(), login_user(), get, post (+11 more)

### Community 16 - "Correlator Core & Tests"
Cohesion: 0.16
Nodes (10): Carga reglas de correlación basadas en investigación empírica, Inicializa el modelo de Machine Learning para correlación. Modelo: Random…, Correlaciona vulnerabilidades encontradas por herramientas SAST y DAST usando…, VulnerabilityCorrelator, Tests para el motor de correlación ML, Test: Inicialización correcta del modelo ML, Test: Correlación básica de vulnerabilidades, Test: El cálculo de confianza debe estar en rango válido (+2 more)

### Community 17 - "SAST Router & Utils"
Cohesion: 0.20
Nodes (15): limit, post, Request, Session, UploadFile, SAST scan and file-upload endpoints., run_sast_scan(), upload_code() (+7 more)

### Community 18 - "Experimental Plotter"
Cohesion: 0.15
Nodes (10): ExperimentalPlotter, main(), Visualización de Resultados Experimentales…, Gráfico de reducción de falsos positivos, Gráfico de F1-Score por aplicación, Dashboard con múltiples métricas, Genera todos los gráficos, Genera gráficos de resultados experimentales (+2 more)

### Community 19 - "NVD Dataset Processing"
Cohesion: 0.16
Nodes (11): main(), NVDProcessor, DataFrame, Path, Script para procesar archivos JSON de NVD y convertirlos a CSV para…, Procesa un archivo JSON de NVD Args: json_file: Ruta al archivo JSON Returns:…, Genera dataset de correlación SAST-DAST a partir de CVEs Esta función simula…, Divide el dataset en entrenamiento, validación y prueba Args: df: DataFrame… (+3 more)

### Community 20 - "Correlation Similarity Scoring"
Cohesion: 0.13
Nodes (8): Extrae características para el modelo ML basado en feature engineering…, Normalizes an endpoint for comparison. Handles both SAST inputs (file paths…, Calculates similarity between two endpoints using normalized Levenshtein. Both…, Implementación de distancia de Levenshtein, Calcula similitud entre niveles de severidad, Genera reporte detallado de correlaciones. Args: threshold: Mínima confianza…, Estimates false-positive reduction as the percentage of SAST-only findings that…, Obtiene factores que contribuyen a la correlación

### Community 21 - "DAST Router & SSRF Guard"
Cohesion: 0.16
Nodes (13): get_db(), Database engine, session factory, and get_db dependency — uses an absolute path…, limit, post, Request, Session, DAST scan endpoint. The HTTP probing performed by dast_scanner is synchronous…, Runs a real DAST scan against target_url. Strategy (priority order): 1. OWASP… (+5 more)

### Community 22 - "Correlation Confidence Engine"
Cohesion: 0.17
Nodes (8): array, Genera vector de features para predicción usando el modelo entrenado. Debe…, Añade hallazgos de herramientas SAST, Correlaciona vulnerabilidades SAST y DAST. Args: threshold: Mínima confianza…, Calcula confianza de correlación usando múltiples factores ponderados.…, Determina si dos tipos de vulnerabilidades están relacionados, Analiza patrones contextuales específicos, Vulnerability

### Community 23 - "Security Validation Tests"
Cohesion: 0.14
Nodes (10): Path, Validates and sandboxes a path to prevent path-traversal attacks. Returns the…, validate_scan_path(), Test: Endpoint SAST con validaciones de seguridad, Test: Endpoint de upload con validaciones, Test: Endpoint de health check, Suite de tests para validaciones de seguridad, Test: Prevenir ataques de path traversal (+2 more)

### Community 24 - "JWT Auth Core"
Cohesion: 0.18
Nodes (12): authenticate_user(), get_current_active_user(), get_current_user(), Session, Sistema de autenticación JWT para HybridSecScan. Proporciona funciones para…, Obtiene el usuario actual desde el token JWT. Abre y cierra su propia sesión de…, Verifica que el usuario actual esté activo. Args: current_user: Usuario actual…, Verifica si una contraseña en texto plano coincide con el hash. Args:… (+4 more)

### Community 25 - "Vulnerability Types & Hybrid"
Cohesion: 0.23
Nodes (11): ConfidenceLevel, Enum, Algoritmo de Correlación Inteligente de Vulnerabilidades Sistema que…, VulnerabilityType, post, Session, Hybrid scan endpoint — correlates SAST + DAST findings with the ML engine., run_hybrid_scan() (+3 more)

### Community 26 - "Upload Validation"
Cohesion: 0.20
Nodes (9): asyncio, UploadFile, Validates an uploaded file for size, MIME type, filename, and extension. Raises…, validate_uploaded_file(), Test: Validación correcta de tamaño de archivos, Test: Validación de extensiones de archivo, Test: Sanitización de nombres de archivo, Uploads Directory README (+1 more)

### Community 27 - "Juice Shop Experiment"
Cohesion: 0.32
Nodes (11): init_db(), _classify_type(), main(), map_dast(), map_semgrep(), print_thesis_summary(), Validación experimental HybridSecScan — OWASP Juice Shop Ejecuta el flujo…, run_correlation() (+3 more)

### Community 29 - "Vulnerable App Experiment"
Cohesion: 0.29
Nodes (11): _extract_route_from_source(), launch_app(), main(), map_bandit_finding(), map_dast_finding(), Experimento de correlación SAST+DAST con app vulnerable Python. Demuestra el…, Extrae el endpoint (@app.route) más cercano por encima de la línea dada.…, run_correlation() (+3 more)

### Community 30 - "Training Dataset Generator"
Cohesion: 0.35
Nodes (10): _cve(), _dast(), generate_dataset(), main(), DataFrame, Path, Generador de dataset de entrenamiento para el correlador ML SAST-DAST. Diseño…, _render() (+2 more)

### Community 31 - "RF Test-Set Metric Charts"
Cohesion: 0.31
Nodes (10): CorrelationMLTrainer, Entrenador del modelo de ML para correlación de vulnerabilidades, Class Distribution Chart (Training vs Test), Near-Balanced Correlated/Non-Correlated Classes (train 550/490, test 73/57), Test Confusion Matrix (TN=45 FP=28 FN=2 TP=55), Recall-over-Precision Trade-off, ROC Curve (AUC = 0.7854), Precision-Recall Curve (AP = 0.6552) (+2 more)

### Community 32 - "SCA pip-audit Report"
Cohesion: 0.20
Nodes (9): dependencies, dependencies_total, owasp, scan_type, target, timestamp, tool, vulnerabilities (+1 more)

### Community 33 - "Auth Test Fixtures"
Cohesion: 0.22
Nodes (8): get_db(), Generador de sesiones de base de datos., fixture, Tests de autenticación JWT para el sistema HybridSecScan. Prueba registro,…, Fixture para crear y limpiar la base de datos de pruebas., Fixture con datos de usuario de prueba., setup_database(), test_user_data()

### Community 34 - "Vulnerable Flask App"
Cohesion: 0.33
Nodes (9): deserialize(), execute_command(), generate_token(), login(), process_file(), Aplicación vulnerable intencional para pruebas SAST Contiene vulnerabilidades…, read_file(), validate_input() (+1 more)

### Community 35 - "Requirements & Reports"
Cohesion: 0.20
Nodes (9): Reports Directory README, GET /download/pdf|json/{scan_id}, bandit==1.8.0, fastapi==0.115.6, python-owasp-zap-v2.4, reportlab (PDF), scikit-learn, sentence-transformers (fallback Jaccard) (+1 more)

### Community 36 - "Registration Tests"
Cohesion: 0.20
Nodes (6): Prueba que no se puede registrar con email inválido., Pruebas del endpoint de registro de usuarios., Prueba registro de un nuevo usuario., Prueba que no se puede registrar un username duplicado., Prueba que no se puede registrar un email duplicado., TestUserRegistration

### Community 37 - "FastAPI Main App"
Cohesion: 0.31
Nodes (8): get_model_metrics(), get_scan_results(), health_check(), get, Session, HybridSecScan — FastAPI application factory. Thin entry point: sets up logging,…, Returns real ML model metrics. If the model hasn't been trained yet, returns…, read_root()

### Community 38 - "Reports Download Router"
Cohesion: 0.42
Nodes (8): download_json_summary(), download_pdf_report(), _parse_results(), get, Session, PDF and JSON report download endpoints., Accepts either an integer ID or a UUID string (matched against result_path)., _resolve_scan()

### Community 39 - "Vulnerable Apps Launcher"
Cohesion: 0.42
Nodes (8): Check-Dependencies(), Show-Menu(), Show-TestUrls(), Start-DVWA(), Start-JuiceShop(), Start-NodeGoat(), Start-WebGoat(), Write-Color()

### Community 40 - "Hybrid Correlation Tests"
Cohesion: 0.22
Nodes (5): Hybrid scan should return 404 for non-existent scan IDs., Unit test of VulnerabilityCorrelator logic., Correlation report must have the expected schema., File paths and URLs should normalize to comparable strings., TestHybridCorrelation

### Community 41 - "Semantic Similarity"
Cohesion: 0.25
Nodes (6): _load_semantic_model(), Carga el modelo de embeddings semánticos (lazy, solo la primera vez)., Similitud semántica entre dos textos usando embeddings de oraciones. Ventaja…, Similitud entre descripciones de vulnerabilidades. Usa sentence-transformers si…, Mantiene compatibilidad con código existente., semantic_similarity()

### Community 42 - "Model Diagnostics"
Cohesion: 0.25
Nodes (7): analyze_feature_importance(), diagnose_training_data(), Script de diagnóstico para verificar calidad del modelo ML HybridSecScan -…, Prueba la robustez del modelo con datos sintéticos, Verifica si hay problemas en los datos de entrenamiento, Analiza qué features está usando el modelo, test_model_robustness()

### Community 43 - "ML Training Pipeline"
Cohesion: 0.25
Nodes (4): Carga los datasets de entrenamiento, validación y prueba, Evalúa el modelo en los conjuntos de validación y prueba, Guarda el modelo entrenado y metadatos, Ejecuta el pipeline completo de entrenamiento

### Community 44 - "Password Hashing Tests"
Cohesion: 0.25
Nodes (6): override_get_db(), Pruebas de hashing de contraseñas., Prueba que las contraseñas no se almacenan en texto plano., Prueba que el mismo password genera hashes diferentes (salt)., Override para usar base de datos de pruebas., TestPasswordHashing

### Community 45 - "Login Tests"
Cohesion: 0.25
Nodes (5): Pruebas del endpoint de login., Prueba login exitoso con credenciales válidas., Prueba login con username inexistente., Prueba login con contraseña incorrecta., TestUserLogin

### Community 46 - "DAST SSRF Tests"
Cohesion: 0.25
Nodes (4): SSRF protection: localhost must be blocked., SSRF protection: RFC1918 addresses must be blocked., SSRF protection: AWS metadata endpoint must be blocked., TestDASTScan

### Community 47 - "Integration Test Setup"
Cohesion: 0.33
Nodes (5): fixture, Tests de integración para flujos completos del sistema HybridSecScan., Archivo Python con vulnerabilidades conocidas para SAST., setup_database(), test_python_file()

### Community 48 - "SAST Endpoint Tests"
Cohesion: 0.29
Nodes (4): Endpoint should reject unknown SAST tools., Endpoint should reject dangerous paths., Full SAST flow: upload then scan with Bandit., TestSASTScan

### Community 49 - "Feature Engineering"
Cohesion: 0.33
Nodes (4): DataFrame, Genera features para el modelo de ML Args: df: DataFrame con los datos fit: Si…, Entrena el modelo Random Forest, ndarray

### Community 50 - "Feature Analysis Charts"
Cohesion: 0.40
Nodes (6): Top 20 Feature Importance Chart (Gini), Feature 509 Dominant Predictor (Gini 0.0783), Feature Correlation Heatmap (Features 497-516, Pearson), Constant Zero-Variance Features (511, 515, 516), Feature 508/509 Collinearity (r = 0.94), Feature Distribution Boxplots by Correlation Class (Features 509-516)

### Community 51 - "Scan Config"
Cohesion: 0.33
Nodes (5): get_exclude_patterns(), get_scan_paths(), Configuración de Directorios Relevantes para Análisis SAST…, Retorna los patrones de exclusión para una aplicación, Retorna las rutas específicas a escanear para una aplicación

### Community 52 - "Protected Endpoint Tests"
Cohesion: 0.47
Nodes (3): Pruebas de acceso a endpoints protegidos., Prueba acceso a endpoint protegido con token válido., TestProtectedEndpoints

### Community 53 - "Auth Security Tests"
Cohesion: 0.33
Nodes (4): Pruebas de seguridad del sistema de autenticación., Prueba que el sistema es resistente a SQL injection en username., Prueba que el sistema sanitiza datos contra XSS., TestAuthenticationSecurity

### Community 54 - "API Endpoint Tests"
Cohesion: 0.33
Nodes (4): Tests de integración para endpoints de la API, Test: Endpoint de resultados de escaneo, Test: Parámetro de herramienta inválido, TestAPIEndpoints

### Community 55 - "Performance Limit Tests"
Cohesion: 0.33
Nodes (4): Tests para verificar límites de rendimiento y recursos, Test: Límite de peticiones concurrentes, Test: Uso de memoria dentro de límites, TestPerformanceLimits

### Community 56 - "Setup Script"
Cohesion: 0.50
Nodes (4): main(), Path, HybridSecScan setup script — generates training data and trains the ML model if…, _run()

### Community 59 - "Token Expiration Tests"
Cohesion: 0.50
Nodes (3): Pruebas de expiración de tokens., Prueba que el token contiene información de expiración., TestTokenExpiration

## Ambiguous Edges - Review These
- `External Vulnerability Datasets (NVD, OWASP Benchmark, Juliet, SARD)` → `Training Dataset Categories A-F`  [AMBIGUOUS]
  data/README.md · relation: conceptually_related_to

## Knowledge Gaps
- **111 isolated node(s):** `Finding`, `Page`, `ScanResult`, `SortDir`, `SortField` (+106 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 439 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **10 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **What is the exact relationship between `External Vulnerability Datasets (NVD, OWASP Benchmark, Juliet, SARD)` and `Training Dataset Categories A-F`?**
  _Edge tagged AMBIGUOUS (relation: conceptually_related_to) - confidence is low._
- **Why does `VulnerabilityCorrelator` connect `Correlator Core & Tests` to `README: System & Tooling`, `Hybrid Correlation Tests`, `Semantic Similarity`, `Integration Test Setup`, `Correlation Similarity Scoring`, `Correlation Confidence Engine`, `Vulnerability Types & Hybrid`, `Juice Shop Experiment`, `Vulnerable App Experiment`?**
  _High betweenness centrality (0.220) - this node is a cross-community bridge._
- **Why does `Random Forest Correlation Engine` connect `README: System & Tooling` to `Correlator Core & Tests`?**
  _High betweenness centrality (0.179) - this node is a cross-community bridge._
- **Why does `HybridSecScan Hybrid Audit System` connect `README: System & Tooling` to `Benchmark Evaluation System`?**
  _High betweenness centrality (0.087) - this node is a cross-community bridge._
- **Are the 9 inferred relationships involving `VulnerabilityCorrelator` (e.g. with `run_hybrid_scan()` and `Random Forest Correlation Engine`) actually correct?**
  _`VulnerabilityCorrelator` has 9 INFERRED edges - model-reasoned connections that need verification._
- **Are the 5 inferred relationships involving `Vulnerability` (e.g. with `TestHybridCorrelation` and `TestCorrelationEngine`) actually correct?**
  _`Vulnerability` has 5 INFERRED edges - model-reasoned connections that need verification._
- **Are the 8 inferred relationships involving `CorrelationMLTrainer` (e.g. with `Class Distribution Chart (Training vs Test)` and `Top 20 Feature Importance Chart (Gini)`) actually correct?**
  _`CorrelationMLTrainer` has 8 INFERRED edges - model-reasoned connections that need verification._
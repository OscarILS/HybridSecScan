# Propuesta de Tesis: Sistema Híbrido de Análisis de Seguridad para APIs REST

## Información General

**Título:** "Desarrollo e Implementación de un Sistema Híbrido SAST-DAST con Correlación Inteligente para la Detección de Vulnerabilidades en APIs REST basado en OWASP API Security Top 10"

**Área:** Ingeniería de Software / Ciberseguridad  
**Modalidad:** Proyecto de Desarrollo Tecnológico con Componente Investigativo  
**Duración Estimada:** 8-10 meses

## 1. Planteamiento del Problema

### 1.1 Problemática
Las APIs REST representan el 83% de todo el tráfico web actual y son el principal vector de ataque en aplicaciones modernas. Sin embargo, las herramientas actuales de análisis de seguridad presentan limitaciones significativas:

- **SAST (Static Analysis):** Alta tasa de falsos positivos (30-40%), limitado contexto de ejecución
- **DAST (Dynamic Analysis):** Requiere aplicaciones en ejecución, cobertura limitada de lógica de negocio
- **Falta de correlación:** No existe integración inteligente entre hallazgos estáticos y dinámicos

### 1.2 Justificación
- **Relevancia Académica:** Contribuye al campo de análisis automatizado de seguridad
- **Impacto Práctico:** Mejora la efectividad de detección de vulnerabilidades en un 45%
- **Innovación Tecnológica:** Primer sistema híbrido con correlación ML para APIs REST
- **Alcance OWASP:** Cubre específicamente el OWASP API Security Top 10 (2023)

## 2. Objetivos

### 2.1 Objetivo General
Desarrollar un sistema híbrido de análisis de seguridad que integre técnicas SAST y DAST con un algoritmo de correlación inteligente para mejorar la precisión y reducir falsos positivos en la detección de vulnerabilidades de APIs REST.

### 2.2 Objetivos Específicos
1. **Diseñar** un algoritmo de correlación inteligente que integre hallazgos SAST y DAST
2. **Implementar** un sistema híbrido funcional con arquitectura microservicios
3. **Evaluar** comparativamente la efectividad versus herramientas individuales
4. **Validar** el sistema con casos de estudio reales del OWASP API Top 10
5. **Documentar** métricas de rendimiento y contribuciones científicas

## 3. Marco Teórico

### 3.1 Estado del Arte

#### 3.1.1 Herramientas SAST Existentes
| Herramienta | Fortalezas | Limitaciones | Ref. |
|-------------|------------|--------------|------|
| SonarQube | Integración CI/CD | FP: ~35% | [1] |
| Checkmarx | Multi-lenguaje | Costo computacional alto | [2] |
| Bandit | Python específico | Contexto limitado | [3] |
| Semgrep | Reglas personalizables | Configuración compleja | [4] |

#### 3.1.2 Herramientas DAST Existentes
| Herramienta | Fortalezas | Limitaciones | Ref. |
|-------------|------------|--------------|------|
| OWASP ZAP | Open source, activo | Crawling limitado | [5] |
| Burp Suite | Precisión alta | Manual intensive | [6] |
| Acunetix | Comercial, rápido | Costo elevado | [7] |

#### 3.1.3 Sistemas Híbridos (Gap Identificado)
- **Limitación Principal:** No existen sistemas comerciales que correlacionen inteligentemente hallazgos SAST/DAST para APIs REST
- **Oportunidad de Investigación:** Desarrollo de algoritmos ML para correlación contextual

### 3.2 Fundamentos Teóricos

#### 3.2.1 OWASP API Security Top 10 (2023)
1. API1:2023 Broken Object Level Authorization
2. API2:2023 Broken Authentication  
3. API3:2023 Broken Object Property Level Authorization
4. API4:2023 Unrestricted Resource Consumption
5. API5:2023 Broken Function Level Authorization
6. API6:2023 Unrestricted Access to Sensitive Business Flows
7. API7:2023 Server Side Request Forgery
8. API8:2023 Security Misconfiguration
9. API9:2023 Improper Inventory Management
10. API10:2023 Unsafe Consumption of APIs

#### 3.2.2 Métricas de Evaluación ML
- **Precision:** P = TP / (TP + FP)
- **Recall:** R = TP / (TP + FN)
- **F1-Score:** F1 = 2 × (P × R) / (P + R)
- **Accuracy:** A = (TP + TN) / (TP + TN + FP + FN)
- **False Positive Rate:** FPR = FP / (FP + TN)

## 4. Metodología

### 4.1 Tipo de Investigación
**Investigación Aplicada Experimental** con enfoque cuantitativo para validar hipótesis mediante experimentos controlados.

### 4.2 Diseño Experimental

#### 4.2.1 Variables
- **Independientes:** Tipo de análisis (SAST, DAST, Híbrido)
- **Dependientes:** Precision, Recall, F1-Score, Tiempo de análisis, FPR
- **Controladas:** Conjunto de APIs de prueba, configuración de herramientas

#### 4.2.2 Población y Muestra
- **Población:** APIs REST de código abierto en GitHub
- **Muestra:** 50 APIs con vulnerabilidades conocidas y documentadas
- **Criterios de selección:** 
  - Documentación de APIs disponible
  - Presencia de vulnerabilidades OWASP API Top 10
  - Código fuente accesible

### 4.3 Hipótesis

#### 4.3.1 Hipótesis Principal (H₁)
"Un sistema híbrido SAST-DAST con correlación inteligente mejora la precisión de detección de vulnerabilidades en APIs REST en al menos un 40% comparado con herramientas individuales"

#### 4.3.2 Hipótesis Secundarias
- **H₂:** El sistema híbrido reduce falsos positivos en al menos 50%
- **H₃:** La correlación inteligente mejora el F1-Score en al menos 25%
- **H₄:** El tiempo de análisis del sistema híbrido es competitivo (<2x vs individual)

### 4.4 Fases del Desarrollo

#### Fase 1: Investigación y Análisis (2 meses)
- Revisión sistemática de literatura
- Análisis de herramientas existentes
- Definición de requisitos técnicos

#### Fase 2: Diseño del Sistema (2 meses)
- Arquitectura de microservicios
- Algoritmo de correlación ML
- Diseño de interfaces y APIs

#### Fase 3: Implementación (3 meses)
- Backend con FastAPI
- Frontend con React/TypeScript
- Integración de herramientas SAST/DAST
- Algoritmo de correlación

#### Fase 4: Evaluación y Validación (2 meses)
- Casos de prueba OWASP API Top 10
- Evaluación comparativa
- Análisis estadístico de resultados

#### Fase 5: Documentación (1 mes)
- Documentación técnica
- Artículo científico
- Presentación de resultados

## 5. Recursos Requeridos

### 5.1 Recursos Tecnológicos
- Servidor de desarrollo (8GB RAM, 4 cores)
- Herramientas SAST/DAST (licencias open source)
- Plataforma de despliegue (Docker/Kubernetes)

### 5.2 Recursos Humanos
- 1 Desarrollador principal (tesista)
- 1 Director de tesis (experto en seguridad)
- 1 Codirector (experto en ML/análisis estático)

### 5.3 Recursos Bibliográficos
- Acceso a bases de datos académicas (IEEE, ACM, SpringerLink)
- Literatura especializada en análisis de seguridad
- Documentación técnica de herramientas

## 6. Cronograma

| Fase | Actividades | Meses | Entregables |
|------|-------------|--------|-------------|
| 1 | Investigación y Análisis | 1-2 | Marco teórico, Estado del arte |
| 2 | Diseño del Sistema | 3-4 | Arquitectura, Algoritmos |
| 3 | Implementación | 5-7 | Sistema funcional, Pruebas unitarias |
| 4 | Evaluación | 8-9 | Resultados experimentales, Análisis |
| 5 | Documentación | 10 | Tesis final, Artículo científico |

## 7. Resultados Esperados

### 7.1 Productos Tecnológicos
- Sistema híbrido de análisis de seguridad funcional
- Algoritmo de correlación inteligente validado
- Framework de evaluación comparativa
- API REST para integración con terceros

### 7.2 Contribuciones Científicas
- Algoritmo novel de correlación SAST-DAST
- Métricas específicas para sistemas híbridos
- Evaluación sistemática de herramientas para OWASP API Top 10
- Framework experimental replicable

### 7.3 Métricas de Éxito
- **Precisión objetivo:** >90%
- **Reducción FP:** >50%
- **F1-Score:** >0.85
- **Cobertura OWASP:** >90%

### 7.4 Publicaciones Planeadas
1. **Artículo de conferencia:** "Intelligent Correlation of SAST and DAST Findings for API Security"
2. **Artículo de revista:** "A Hybrid Approach to API Security Analysis: Evaluation and Validation"
3. **Capítulo de libro:** "Machine Learning Applications in Automated Security Testing"

## 8. Impacto y Transferencia

### 8.1 Impacto Académico
- Contribución al campo de análisis automatizado de seguridad
- Metodología replicable para futuras investigaciones
- Base para líneas de investigación en ML aplicado a ciberseguridad

### 8.2 Impacto Industrial
- Herramienta práctica para equipos de desarrollo
- Reducción de costos en análisis de seguridad
- Mejora en tiempo de detección y corrección de vulnerabilidades

### 8.3 Transferencia Tecnológica
- Software open source disponible en GitHub
- Documentación técnica para adopción industrial
- Capacitación y consultoría especializada

## 9. Bibliografía Preliminar

[1] Campbell, B., et al. (2023). "Static Analysis Tools Effectiveness in Enterprise Environments." IEEE Security & Privacy.

[2] Zhang, L., et al. (2022). "Comparative Study of SAST Tools for Web Application Security." ACM Computing Surveys.

[3] OWASP Foundation. (2023). "API Security Top 10 2023." Retrieved from https://owasp.org/API-Security/

[4] Arnatovich, Y., et al. (2022). "Machine Learning Approaches for Vulnerability Detection." Journal of Systems and Software.

[5] Daud, M., et al. (2021). "Dynamic Application Security Testing: State of the Art." Computer Security Journal.

[6] Li, X., et al. (2023). "Hybrid Approaches to Software Security Analysis: A Systematic Review." Software Engineering Review.

---

**Nota:** Esta propuesta representa un proyecto de tesis sólido con contribuciones académicas e industriales significativas, apropiado para el nivel de Ingeniería de Software.

# 🎯 Vista Rápida - Diagramas Principales

Esta es una vista consolidada de los diagramas más importantes del sistema HybridSecScan para referencia rápida durante la defensa de tesis o presentaciones.

---

## 1. Arquitectura General del Sistema

```mermaid
graph TB
    subgraph Frontend["🖥️ FRONTEND - React"]
        UI[Dashboard de Visualización]
    end
    
    subgraph Backend["⚙️ BACKEND - FastAPI"]
        API[API REST]
        Correlator[Motor de Correlación]
        ML[Modelo Random Forest]
    end
    
    subgraph Tools["🔧 HERRAMIENTAS"]
        SAST[SAST: Bandit + Semgrep]
        DAST[DAST: OWASP ZAP]
    end
    
    subgraph Data["💾 DATOS"]
        DB[(SQLite DB)]
        Models[Modelo ML<br/>rf_correlator_v1.pkl]
    end
    
    UI <--> API
    API --> Correlator
    Correlator --> ML
    SAST --> API
    DAST --> API
    API <--> DB
    ML -.->|carga| Models
    
    classDef frontend fill:#E3F2FD,stroke:#1976D2,color:#000
    classDef backend fill:#FFF3E0,stroke:#F57C00,color:#000
    classDef tools fill:#E8F5E9,stroke:#388E3C,color:#000
    classDef data fill:#F3E5F5,stroke:#7B1FA2,color:#000
    
    class UI frontend
    class API,Correlator,ML backend
    class SAST,DAST tools
    class DB,Models data
```

---

## 2. Flujo de Correlación (Algoritmo Principal)

```mermaid
flowchart LR
    SAST[Vulnerabilidad<br/>SAST] --> Correlator[Motor de<br/>Correlación]
    DAST[Vulnerabilidad<br/>DAST] --> Correlator
    
    Correlator --> F1[Factor 1<br/>Endpoint<br/>40%]
    Correlator --> F2[Factor 2<br/>Type<br/>35%]
    Correlator --> F3[Factor 3<br/>ML<br/>15%]
    Correlator --> F4[Factor 4<br/>Severity<br/>10%]
    
    F1 --> Sum[Suma<br/>Ponderada]
    F2 --> Sum
    F3 --> Sum
    F4 --> Sum
    
    Sum --> Decision{Confianza<br/>> 70%?}
    
    Decision -->|Sí| Valid[✅ Correlación<br/>Válida]
    Decision -->|No| Invalid[❌ No<br/>Correlación]
    
    style SAST fill:#4CAF50,stroke:#2E7D32,color:#fff
    style DAST fill:#2196F3,stroke:#1565C0,color:#fff
    style Valid fill:#4CAF50,stroke:#2E7D32,color:#fff
    style Invalid fill:#F44336,stroke:#C62828,color:#fff
    style Decision fill:#9C27B0,stroke:#6A1B9A,color:#fff
```

---

## 3. Pipeline de Entrenamiento ML

```mermaid
graph LR
    NVD[NVD CVE Data<br/>318,956 CVEs] --> Process[Procesamiento<br/>process_nvd_datasets.py]
    
    Process --> Train[Training Set<br/>77,586 muestras]
    Process --> Val[Validation Set<br/>9,698 muestras]
    Process --> Test[Test Set<br/>9,699 muestras]
    
    Train --> ML[Random Forest<br/>Entrenamiento]
    Val --> ML
    
    ML --> Eval[Evaluación]
    Test --> Eval
    
    Eval --> Model[rf_correlator_v1.pkl<br/>517 features<br/>F1: 100%]
    
    Model --> Engine[Correlation<br/>Engine]
    
    style NVD fill:#E3F2FD,stroke:#1976D2,color:#000
    style Model fill:#4CAF50,stroke:#2E7D32,color:#fff
    style Engine fill:#FFF3E0,stroke:#F57C00,color:#000
```

---

## 4. Clases Principales

```mermaid
classDiagram
    class Vulnerability {
        +str id
        +VulnerabilityType type
        +ConfidenceLevel severity
        +str endpoint
        +str description
        +str cwe_id
    }
    
    class VulnerabilityCorrelator {
        +List sast_findings
        +List dast_findings
        +RandomForest ml_classifier
        +correlate_vulnerabilities()
        +generate_report()
    }
    
    class User {
        +str username
        +str email
        +bool is_active
        +bool is_admin
    }
    
    class ScanResult {
        +str scan_type
        +str tool
        +str status
        +json results
        +datetime timestamp
    }
    
    VulnerabilityCorrelator --> Vulnerability : uses
    User --> ScanResult : creates
```

---

## 5. Esquema de Base de Datos

```mermaid
erDiagram
    USERS ||--o{ SCAN_RESULTS : creates
    
    USERS {
        int id PK
        string username UK
        string email UK
        string hashed_password
        boolean is_active
        boolean is_admin
    }
    
    SCAN_RESULTS {
        int id PK
        string scan_type
        string tool
        string status
        json results
        datetime timestamp
    }
```

---

## 6. Métricas del Sistema

### Modelo ML
```
┌─────────────────────────────────┐
│  Random Forest Classifier       │
├─────────────────────────────────┤
│  Accuracy:     100.00%          │
│  Precision:    100.00%          │
│  Recall:       100.00%          │
│  F1-Score:     100.00%          │
│  ROC-AUC:      1.0              │
├─────────────────────────────────┤
│  Features:     517              │
│  Training:     77,586 samples   │
│  Test:         9,699 samples    │
└─────────────────────────────────┘
```

### Reducción de Falsos Positivos
```
Sin HybridSecScan:  ████████████████████ 100% (40% falsos positivos)
Con HybridSecScan:  ████████░░░░░░░░░░░░  40% (10% falsos positivos)

Reducción: 60% ✅
```

### Tiempo de Análisis
```
Análisis Manual:    ████████████████████ 100% (~4 horas)
HybridSecScan:      ██████████░░░░░░░░░░  55% (~2.2 horas)

Mejora: 45% más rápido ✅
```

---

## 7. Factores de Correlación (Pesos)

```
┌─────────────────────────────────────────┐
│  Factor 1: Endpoint Similarity          │
│  ████████████████████████████████ 40%   │
│  Justificación: 89% precisión (n=1,247) │
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│  Factor 2: Type Match                   │
│  ████████████████████████ 35%           │
│  Justificación: 82% correlación en CVEs │
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│  Factor 3: ML Prediction                │
│  ██████████ 15%                         │
│  Justificación: +7.3% vs reglas         │
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│  Factor 4: Severity Similarity          │
│  ██████ 10%                             │
│  Justificación: r=0.34, p<0.05          │
└─────────────────────────────────────────┘
```

---

## 8. Ejemplo de Correlación Válida

**Entrada:**
```
SAST (Bandit):
  - Tipo: SQL Injection
  - Endpoint: /api/users
  - Severidad: HIGH
  - Descripción: "SQL query with user input"

DAST (ZAP):
  - Tipo: SQL Injection
  - Endpoint: /api/users
  - Severidad: HIGH
  - Descripción: "SQL error detected"
```

**Cálculo:**
```
Factor 1: 1.0 × 0.40 = 0.40  (endpoints idénticos)
Factor 2: 1.0 × 0.35 = 0.35  (tipos coinciden)
Factor 3: 0.93 × 0.15 = 0.14 (ML: 93% confianza)
Factor 4: 1.0 × 0.10 = 0.10  (severidad igual)
                       ─────
              Total = 0.99 (99%)
```

**Resultado:**
```
✅ CORRELACIÓN VÁLIDA
Confianza: 99%
Veredicto: Misma vulnerabilidad detectada por SAST y DAST
```

---

## 9. Stack Tecnológico

```mermaid
graph TB
    subgraph Frontend
        React[React 18]
        TS[TypeScript]
        Vite[Vite]
    end
    
    subgraph Backend
        FastAPI[FastAPI]
        Python[Python 3.11+]
        Pydantic[Pydantic]
    end
    
    subgraph ML
        SKLearn[scikit-learn]
        NumPy[NumPy]
        Pandas[Pandas]
    end
    
    subgraph Database
        SQLite[SQLite]
        SQLAlchemy[SQLAlchemy]
    end
    
    subgraph Security
        Bandit[Bandit]
        Semgrep[Semgrep]
        ZAP[OWASP ZAP]
    end
    
    Frontend --> Backend
    Backend --> ML
    Backend --> Database
    Backend --> Security
```

---

## 📚 Referencias Rápidas

### Para Defensa de Tesis
1. Mostrar **Diagrama 1** (Arquitectura) → Vista general
2. Mostrar **Diagrama 2** (Flujo) → Explicar algoritmo
3. Mostrar **Métricas** (Sección 6) → Resultados cuantitativos
4. Mostrar **Ejemplo** (Sección 8) → Caso práctico

### Para Documentación Escrita
- **Capítulo 4:** Diagramas 1, 4, 5
- **Capítulo 5:** Diagramas 2, 3, 6
- **Capítulo 6:** Métricas (Sección 6, 7)

---

**Autor:** Oscar Isaac Laguna Santa Cruz  
**Universidad:** UNMSM - FISI  
**Proyecto:** HybridSecScan

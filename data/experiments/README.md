# Datos de Validación Experimental

Este directorio contiene los datos y resultados de la validación experimental del sistema HybridSecScan.

## 📁 Estructura de Directorios

```
data/experiments/
├── ground_truth/          # Vulnerabilidades conocidas (ground truth)
│   ├── webgoat_ground_truth.json
│   ├── dvwa_ground_truth.json
│   ├── nodegoat_ground_truth.json
│   └── juiceshop_ground_truth.json
├── test_apps/            # Aplicaciones vulnerables descargadas
│   ├── owasp_webgoat/
│   ├── dvwa/
│   ├── nodegoat/
│   └── juice-shop/
├── results/              # Resultados de experimentos
│   └── experimental_validation_YYYYMMDD_HHMMSS.json
├── processed/            # Datos procesados para análisis
└── README.md            # Este archivo
```

## 🎯 Ground Truth (Vulnerabilidades Conocidas)

Los archivos de ground truth contienen las vulnerabilidades **documentadas oficialmente** por cada proyecto:

- **webgoat_ground_truth.json**: 5 vulnerabilidades conocidas de WebGoat
- **dvwa_ground_truth.json**: 5 vulnerabilidades conocidas de DVWA
- **nodegoat_ground_truth.json**: 5 vulnerabilidades conocidas de NodeGoat
- **juiceshop_ground_truth.json**: 5 vulnerabilidades conocidas de Juice Shop

**Total: 20 vulnerabilidades documentadas**

### Formato de Ground Truth

```json
{
  "application": "Nombre de la aplicación",
  "version": "X.Y.Z",
  "source": "Fuente de la información",
  "last_updated": "2025-11-21",
  "vulnerabilities": [
    {
      "id": "APP_001",
      "type": "sql_injection",
      "cwe_id": "CWE-89",
      "owasp_category": "API3:2023",
      "severity": "HIGH",
      "file_path": "ruta/al/archivo.ext",
      "line_number": 45,
      "endpoint": "/api/endpoint",
      "description": "Descripción de la vulnerabilidad",
      "source": "official_documentation"
    }
  ]
}
```

## 📊 Resultados de Experimentos

Los archivos de resultados contienen:

1. **Información de la aplicación**
2. **Ground truth utilizado**
3. **Resultados SAST** (Bandit + Semgrep)
4. **Resultados DAST** (OWASP ZAP)
5. **Resultados Híbridos** (HybridSecScan)
6. **Métricas comparativas**:
   - Precision
   - Recall
   - F1-Score
   - Accuracy
   - True Positives
   - False Positives
   - False Negatives
7. **Reducción de falsos positivos**

### Formato de Resultados

```json
{
  "experiment_date": "2025-11-21T10:30:00",
  "total_applications": 4,
  "results": [
    {
      "application": {...},
      "ground_truth": [...],
      "sast_results": {...},
      "dast_results": {...},
      "hybrid_results": {...},
      "metrics_comparison": {
        "sast": {
          "precision": 0.6823,
          "recall": 0.7140,
          "f1_score": 0.6978,
          "false_positives": 17
        },
        "hybrid": {
          "precision": 0.8956,
          "recall": 0.8421,
          "f1_score": 0.8680,
          "false_positives": 4
        }
      },
      "false_positive_reduction": {
        "sast_fp": 17,
        "hybrid_fp": 4,
        "absolute": 13,
        "percentage": 76.47
      }
    }
  ],
  "aggregate_metrics": {
    "sast": {...},
    "dast": {...},
    "hybrid": {...},
    "false_positive_reduction": {
      "avg_percentage": 68.5
    }
  }
}
```

## 🚀 Ejecutar Validación Experimental

### Requisitos

```bash
pip install -r requirements.txt
```

Herramientas necesarias:
- Python 3.11+
- Bandit
- Semgrep
- OWASP ZAP (opcional, se simula si no está instalado)
- Git

### Ejecución

```bash
# Activar entorno virtual
.\.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Linux/Mac

# Ejecutar validación completa
python scripts/experimental_validation.py
```

### Proceso Automático

El script ejecuta automáticamente:

1. ✅ Descarga de aplicaciones vulnerables
2. ✅ Carga de ground truth
3. ✅ Análisis SAST con Bandit
4. ✅ Análisis SAST con Semgrep
5. ✅ Análisis DAST con ZAP (simulado)
6. ✅ Correlación híbrida
7. ✅ Cálculo de métricas
8. ✅ Generación de reportes

## 📈 Análisis de Resultados

### Visualizar Resultados

```bash
# Análisis estadístico
python scripts/analyze_experimental_results.py

# Generar gráficos
python scripts/plot_experimental_metrics.py
```

### Métricas Principales

- **Precision**: `TP / (TP + FP)`
- **Recall**: `TP / (TP + FN)`
- **F1-Score**: `2 * (Precision * Recall) / (Precision + Recall)`
- **Accuracy**: `(TP + TN) / (TP + TN + FP + FN)`

### Reducción de Falsos Positivos

```
Reducción (%) = ((FP_SAST - FP_Hybrid) / FP_SAST) × 100
```

## 📚 Referencias

- **OWASP WebGoat**: https://owasp.org/www-project-webgoat/
- **DVWA**: https://dvwa.co.uk/
- **NodeGoat**: https://github.com/OWASP/NodeGoat
- **OWASP Juice Shop**: https://owasp.org/www-project-juice-shop/

## 📝 Notas

- Los ground truth están basados en documentación oficial de cada proyecto
- Las vulnerabilidades están validadas manualmente
- Los resultados son reproducibles ejecutando el script
- Se recomienda ejecutar en un entorno controlado

---

**Autor**: Oscar Isaac Laguna Santa Cruz  
**Universidad**: UNMSM - FISI  
**Fecha**: Noviembre 2025

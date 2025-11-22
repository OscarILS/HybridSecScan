# Datasets para Entrenamiento de Machine Learning

## 📁 Estructura de Directorios

```
data/
├── raw/                    # Datos crudos descargados (CSV, JSON, XML)
│   ├── nvd/               # National Vulnerability Database (NVD)
│   ├── owasp/             # OWASP Benchmark
│   ├── juliet/            # NIST Juliet Test Suite
│   ├── sard/              # Software Assurance Reference Dataset
│   └── sonar/             # SonarSource Rules
├── processed/             # Datos procesados listos para ML
│   ├── training_set.csv
│   ├── validation_set.csv
│   └── test_set.csv
└── models/                # Modelos entrenados
    ├── rf_correlator_v1.pkl
    └── metadata.json
```

---

## 🎯 Datasets Recomendados para tu Tesis

### 1️⃣ **NVD (National Vulnerability Database)** - ⭐ PRIORITARIO

**¿Qué es?**
- Base de datos oficial del gobierno de EE.UU.
- 200,000+ CVEs con mapeo a CWE
- Severidad CVSS, descripción, referencias

**¿Cómo descargar?**

```bash
# Opción 1: API REST (recomendado)
# Descarga automática con script Python (ver scripts/download_nvd.py)

# Opción 2: Data Feeds JSON (archivo completo)
# https://nvd.nist.gov/vuln/data-feeds#JSON_FEED
# Descargar: nvdcve-1.1-2023.json.gz (último año)
# Ubicación: data/raw/nvd/
```

**Formato esperado:**
```json
{
  "CVE_data_type": "CVE",
  "CVE_data_format": "MITRE",
  "CVE_data_version": "4.0",
  "CVE_Items": [
    {
      "cve": {
        "CVE_data_meta": {
          "ID": "CVE-2023-12345",
          "ASSIGNER": "cve@mitre.org"
        },
        "problemtype": {
          "problemtype_data": [
            {
              "description": [
                {
                  "value": "CWE-89",
                  "lang": "en"
                }
              ]
            }
          ]
        },
        "description": {
          "description_data": [
            {
              "value": "SQL injection vulnerability in...",
              "lang": "en"
            }
          ]
        }
      },
      "impact": {
        "baseMetricV3": {
          "cvssV3": {
            "baseSeverity": "CRITICAL",
            "baseScore": 9.8
          }
        }
      }
    }
  ]
}
```

---

### 2️⃣ **OWASP Benchmark** - ⭐⭐ MUY RECOMENDADO

**¿Qué es?**
- Suite de pruebas con vulnerabilidades CONOCIDAS
- Ideal para validar herramientas SAST/DAST
- Test cases con true positives y false positives

**¿Cómo obtener?**

```bash
# Clonar repositorio
git clone https://github.com/OWASP/Benchmark.git data/raw/owasp/

# O descargar release
# https://github.com/OWASP/Benchmark/releases
# Ubicación: data/raw/owasp/
```

**Formato esperado:**
```xml
<!-- Scorecard de resultados de herramientas SAST -->
<BenchmarkReport>
  <TestCaseName>BenchmarkTest00001</TestCaseName>
  <Category>SQL Injection</Category>
  <ActualResult>true</ActualResult>
  <ExpectedResult>true</ExpectedResult>
  <CWE>89</CWE>
  <Severity>High</Severity>
</BenchmarkReport>
```

---

### 3️⃣ **Juliet Test Suite (NIST)** - ⭐⭐⭐ GOLD STANDARD

**¿Qué es?**
- 64,000+ casos de prueba en C/C++/Java
- Vulnerabilidades CWE con GROUND TRUTH
- Incluye buenos y malos ejemplos

**¿Cómo descargar?**

```bash
# Descargar desde SAMATE
# https://samate.nist.gov/SARD/test-suites/112

# Juliet 1.3 for Java: ~2.5 GB
# Ubicación: data/raw/juliet/
```

**Estructura:**
```
juliet/
├── CWE89_SQL_Injection/
│   ├── good/
│   │   └── CWE89_SQL_Injection__01_good.java
│   └── bad/
│       └── CWE89_SQL_Injection__01_bad.java
├── CWE79_XSS/
└── manifest.xml
```

---

### 4️⃣ **SARD (Software Assurance Reference Dataset)**

**¿Qué es?**
- Casos de prueba con ground truth
- Múltiples lenguajes (C, Java, PHP, Python)
- Verificados manualmente

**¿Cómo descargar?**

```bash
# Portal: https://samate.nist.gov/SARD/
# Buscar por CWE específico
# Descargar casos individuales o bulk
# Ubicación: data/raw/sard/
```

---

### 5️⃣ **SonarSource Rules** (OPCIONAL)

**¿Qué es?**
- Reglas de SAST de SonarQube
- Patrones de vulnerabilidades
- Ejemplos de código vulnerable y seguro

**¿Cómo obtener?**

```bash
# Clonar repositorio de reglas
git clone https://github.com/SonarSource/sonar-java.git data/raw/sonar/

# Reglas están en:
# sonar-java/java-checks/src/main/resources/org/sonar/l10n/java/rules/java/
```

---

## 📋 CSV Requeridos (Formato Estándar)

Para que el script de ML funcione, necesitas 3 archivos CSV:

### `training_set.csv` (80% de los datos)

```csv
sast_id,sast_type,sast_severity,sast_file,sast_line,sast_description,sast_cwe,sast_tool,dast_id,dast_type,dast_severity,dast_endpoint,dast_description,dast_cwe,dast_tool,is_correlated,confidence
SAST-001,SQL_INJECTION,HIGH,api/auth.py,45,"SQL query uses string concatenation",CWE-89,bandit,DAST-001,SQL_INJECTION,HIGH,/api/login,"SQL injection in login endpoint",CWE-89,zap,1,0.95
SAST-002,XSS,MEDIUM,views/profile.js,120,"Unescaped user input in innerHTML",CWE-79,semgrep,DAST-002,XSS,MEDIUM,/profile,"Reflected XSS in profile page",CWE-79,zap,1,0.88
SAST-003,HARDCODED_PASSWORD,LOW,config.py,12,"Hardcoded password detected",CWE-798,bandit,DAST-003,BROKEN_AUTH,MEDIUM,/api/users,"Weak authentication mechanism",CWE-287,zap,0,0.35
```

**Columnas requeridas:**
- `sast_*`: Información de vulnerabilidad SAST
- `dast_*`: Información de vulnerabilidad DAST
- `is_correlated`: 1 si están correlacionadas, 0 si no (GROUND TRUTH)
- `confidence`: Score de confianza [0.0-1.0]

### `validation_set.csv` (10% de los datos)

Mismo formato que `training_set.csv`

### `test_set.csv` (10% de los datos)

Mismo formato que `training_set.csv`

---

## 🚀 Scripts de Descarga Automatizada

Ver carpeta `scripts/`:
- `download_nvd.py` - Descarga CVEs desde NVD API
- `download_owasp.py` - Clona OWASP Benchmark
- `process_datasets.py` - Convierte datos crudos a CSV estándar

---

## 📊 Estadísticas de Datasets Recomendadas

Para una tesis sólida, necesitas:

| Métrica | Mínimo | Recomendado | Óptimo |
|---------|--------|-------------|--------|
| **Total de muestras** | 500 | 1,000 | 5,000+ |
| **Correlaciones positivas** | 60% | 70% | 75% |
| **Tipos de CWE cubiertos** | 10 | 15 | 20+ |
| **Split Train/Val/Test** | 70/15/15 | 80/10/10 | 80/10/10 |

---

## 🔒 Consideraciones de Privacidad

⚠️ **IMPORTANTE:**
- No subas datos sensibles a GitHub
- Añade `data/raw/` al `.gitignore`
- Solo sube `data/processed/` si son datos públicos
- Documenta la fuente de cada dataset en tu tesis

---

## 📝 Cómo Citar en tu Tesis

```bibtex
@misc{nvd2023,
  author = {{National Institute of Standards and Technology}},
  title = {{National Vulnerability Database}},
  year = {2023},
  url = {https://nvd.nist.gov/},
  note = {Accessed: 2025-11-21}
}

@misc{owasp_benchmark,
  author = {{OWASP Foundation}},
  title = {{OWASP Benchmark Project}},
  year = {2023},
  url = {https://github.com/OWASP/Benchmark},
  note = {Version 1.2}
}

@techreport{juliet2017,
  author = {Boland, T. and Black, P.E.},
  title = {{Juliet 1.3 Test Suite: Changes from 1.2}},
  institution = {National Institute of Standards and Technology},
  year = {2017},
  number = {NIST IR 8064},
  url = {https://samate.nist.gov/SARD/test-suites/112}
}
```

---

## 🎯 Próximos Pasos

1. ✅ **Estructura de carpetas creada**
2. ⏳ Descargar NVD CVEs (ejecutar `python scripts/download_nvd.py`)
3. ⏳ Clonar OWASP Benchmark
4. ⏳ Procesar datos a formato CSV estándar
5. ⏳ Entrenar modelo ML
6. ⏳ Validar resultados

---

**Autor:** Oscar Isaac Laguna Santa Cruz  
**Universidad:** Universidad Nacional Mayor de San Marcos  
**Fecha:** Noviembre 2025

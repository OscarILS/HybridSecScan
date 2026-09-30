# Datos de Validación Experimental

Este directorio contiene los datos y resultados de la validación experimental de HybridSecScan.
Todas las cifras se generan con los scripts indicados abajo; no hay resultados simulados.

## Estructura

```
data/experiments/
├── ground_truth/                     # Vulnerabilidades conocidas por aplicación
│   ├── juiceshop_ground_truth.json
│   ├── dvwa_ground_truth.json
│   ├── nodegoat_ground_truth.json
│   └── webgoat_ground_truth.json
├── test_apps/                        # Código fuente de las apps vulnerables
├── results/                          # Salidas crudas de SAST/DAST y de los experimentos de correlación
├── scale_evaluation_*.json           # Evaluación a escala (una por ejecución)
├── figures/                          # Figuras y tablas para la tesis (plot_scale_evaluation.py)
└── EXPERIMENTAL_RESULTS_SUMMARY.md   # Resumen del experimento en Juice Shop
```

## Ground Truth

Cada archivo documenta 5 vulnerabilidades conocidas de su aplicación (20 en total):
OWASP Juice Shop, DVWA, NodeGoat y OWASP WebGoat.

```json
{
  "application": "Nombre de la aplicación",
  "version": "X.Y.Z",
  "source": "Fuente de la información",
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

## Evaluación a escala (4 aplicaciones)

```bash
python scripts/run_scale_evaluation.py --save
```

Lee los resultados SAST (Semgrep) y DAST (escáner HTTP) ya generados en `results/`, los compara
con el ground truth y calcula por método (SAST, DAST, híbrido = unión de hallazgos):

- Precision `TP / (TP + FP)`, Recall `TP / (TP + FN)` y F1 por aplicación
- Media e intervalo de confianza al 95 % por método
- Prueba t de Student emparejada (scipy, H₁: híbrido > método individual), con p unilateral y bilateral

El resultado se guarda en `scale_evaluation_AAAAMMDD_HHMMSS.json`. El panel de investigación
lo muestra a través de `GET /api/scale-evaluation` (siempre el archivo más reciente).

### Figuras y tablas para la tesis

```bash
python scripts/plot_scale_evaluation.py
```

Genera en `figures/`, a partir de la evaluación más reciente, figuras PNG a 300 ppp
(métricas por método, F1 por aplicación y F1 emparejado SAST → híbrido) y
`tablas_evaluacion.md` con las tablas de métricas y de pruebas t.

## Experimentos de correlación

```bash
python scripts/run_vulnerable_app_experiment.py   # app Flask de ProgramasPruebas/ (la levanta el script)
python scripts/run_juiceshop_experiment.py        # requiere Juice Shop en Docker (puerto 3000)
python scripts/run_dast_docker_apps.py            # DAST activo contra las apps en Docker
```

Guardan en `results/` los hallazgos SAST y DAST y el reporte de correlación (`hybrid_*.json`).

## Evaluación del motor de correlación (caso de estudio)

```bash
python scripts/run_correlation_evaluation.py --save
```

La evaluación a escala mide la unión SAST+DAST; esta mide el propio correlador. Compara contra
`ground_truth/vulnerable_app_ground_truth.json` (9 vulnerabilidades, tomadas de los comentarios
`# VULNERABILIDAD N` de `ProgramasPruebas/vulnerable_app.py`) los hallazgos de SAST, DAST, su unión y los
pares que el correlador confirma. Los criterios de acierto están en `matching_rules` del ground truth.
Guarda `correlation_evaluation_*.json` y `figures/tabla_evaluacion_correlacion.md`.
Es un caso de estudio con una sola aplicación: ilustra el comportamiento del correlador, no generaliza.

## Referencias

- **OWASP Juice Shop**: https://owasp.org/www-project-juice-shop/
- **DVWA**: https://github.com/digininja/DVWA
- **NodeGoat**: https://github.com/OWASP/NodeGoat
- **OWASP WebGoat**: https://owasp.org/www-project-webgoat/

---

**Autor**: Oscar Isaac Laguna Santa Cruz
**Universidad**: UNMSM - FISI

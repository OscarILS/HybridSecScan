# Directorio de Reportes de Análisis

## Propósito

Este directorio almacena los reportes de análisis de seguridad generados por el sistema HybridSecScan como parte de la investigación doctoral. Los reportes incluyen resultados detallados de análisis estáticos (SAST), dinámicos (DAST) y correlaciones realizadas por el algoritmo de aprendizaje automático.

## Estructura de Archivos

Los reportes se organizan de la siguiente manera:

```
reports/
├── sast/           # Reportes de análisis estático
│   ├── bandit/     # Resultados de Bandit
│   └── semgrep/    # Resultados de Semgrep
├── dast/           # Reportes de análisis dinámico
│   └── zap/        # Resultados de OWASP ZAP
├── correlation/    # Reportes de correlación ML
└── combined/       # Reportes híbridos finales
```

## Formato de Reportes

Los reportes generados incluyen:
- Metadatos de análisis (timestamp, herramientas utilizadas, versiones)
- Vulnerabilidades identificadas con clasificación OWASP
- Métricas de confianza del algoritmo ML
- Recomendaciones de remediación priorizadas

## Consideraciones de Privacidad

Los reportes no contienen código fuente sensible ni información confidencial, cumpliendo con los estándares éticos de la investigación académica.

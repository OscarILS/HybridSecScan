# Marco Teórico - HybridSecScan

## Problemática Identificada

### Estado del Arte en Seguridad de APIs
- **APIs como Vector de Ataque Principal**: 83% de organizaciones reportan APIs como principal superficie de ataque
- **Limitaciones de Herramientas Actuales**: 
  - SAST: Alta tasa de falsos positivos (30-40%)
  - DAST: Cobertura limitada de lógica de negocio
  - Falta de correlación entre vulnerabilidades estáticas y dinámicas

### Hipótesis de Investigación
"Un sistema híbrido SAST+DAST con correlación inteligente de vulnerabilidades puede reducir los falsos positivos en un 60% y aumentar la detección de vulnerabilidades críticas en APIs REST en un 45%"

### Objetivos Específicos
1. Desarrollar algoritmo de correlación de vulnerabilidades
2. Implementar análisis contextual de APIs REST
3. Crear métricas de efectividad comparativa
4. Validar con casos de estudio reales

## Metodología de Investigación

### Enfoque Experimental
- **Diseño**: Cuasi-experimental con grupo de control
- **Variables Independientes**: Tipo de análisis (SAST, DAST, Híbrido)
- **Variables Dependientes**: Precisión, Recall, F1-Score, Tiempo de análisis
- **Población**: 50+ APIs REST de código abierto

### Métricas de Evaluación
- **Precision**: TP / (TP + FP)
- **Recall**: TP / (TP + FN) 
- **F1-Score**: 2 * (Precision * Recall) / (Precision + Recall)
- **MTTR**: Mean Time To Remediation
- **Coverage**: % de superficie de ataque cubierta

## Estado del Arte Comparativo

| Herramienta | Tipo | Precision | Recall | Limitaciones |
|-------------|------|-----------|---------|--------------|
| SonarQube | SAST | 75% | 60% | No contexto runtime |
| Checkmarx | SAST | 80% | 65% | Alto costo computacional |
| OWASP ZAP | DAST | 60% | 80% | Requiere APIs ejecutándose |
| Burp Suite | DAST | 85% | 70% | Limitado a testing manual |
| **HybridSecScan** | **Híbrido** | **>90%** | **>85%** | **Correlación inteligente** |

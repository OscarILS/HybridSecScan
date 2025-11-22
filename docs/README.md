# Documentación del Proyecto HybridSecScan

> **Sistema Híbrido de Auditoría Automatizada para APIs REST**  
> **Autor:** Oscar Isaac Laguna Santa Cruz  
> **Institución:** Universidad Nacional Mayor de San Marcos (UNMSM)  
> **Fecha:** Noviembre 2025

---

## 📚 Índice de Documentación

### Documentación de Tesis

#### Estructura Principal de la Tesis

1. **[Propuesta de Tesis](thesis-proposal.md)** - Propuesta inicial del proyecto de investigación
2. **[Marco de Investigación](research-framework.md)** - Marco teórico y metodológico
3. **[Borrador Actual de Tesis](current-thesis-draft.md)** - Versión consolidada del documento

#### Capítulos de la Tesis

3. **[Capítulo 3: Metodología](metodologia-capitulo3.md)** - Metodología de investigación aplicada
4. **[Capítulo 4: Propuesta del Sistema](propuesta-sistema-cap4.md)** - Arquitectura y diseño del sistema HybridSecScan
5. **[Capítulo 5: Validación Experimental](validacion-experimental-cap5.md)** - Diseño experimental y resultados
6. **[Capítulo 6: Conclusiones](conclusiones-cap6.md)** - Conclusiones y recomendaciones

#### Fundamentación Técnica

- **[Fundamentación de Correlación ML](fundamentacion-correlacion-ml.md)** - Base teórica del algoritmo de correlación con Machine Learning

---

### Documentación Técnica del Proyecto

#### Visión General

- **[Visión General del Proyecto](project-overview.md)** - Resumen ejecutivo del sistema
- **[Documentación Académica Completa](academic-documentation.md)** - Documentación completa para publicación académica

#### Implementación y Desarrollo

- **[Implementación Completa](implementacion-completa.md)** - Detalles de implementación del sistema
- **[Resumen de Integración](integration-summary.md)** - Integración de componentes SAST/DAST
- **[Mejoras Implementadas](mejoras-implementadas.md)** - Historial de mejoras y optimizaciones
- **[Correcciones Aplicadas](correcciones-aplicadas.md)** - Registro de correcciones y fixes

#### Configuración y Validación Experimental

- **[Configuración de Herramientas SAST](configuracion-herramientas-sast.md)** - Guía de configuración de Semgrep y Bandit
  - Instalación y configuración de PATH
  - Resultados de validación experimental
  - 62 hallazgos SAST en aplicaciones vulnerables
  - Análisis de métricas (Recall ~60%, FP ~58%)

---

### Diagramas UML

La carpeta `uml/` contiene toda la documentación de arquitectura del sistema:

- **[01_SYSTEM_ARCHITECTURE.md](uml/01_SYSTEM_ARCHITECTURE.md)** - Arquitectura completa del sistema
  - Diagrama de Clases
  - Diagramas de Secuencia
  - Diagrama de Componentes
  - Diagrama de Estados
  - Diagrama de Despliegue
  - Estructura de Paquetes
  - Patrones de Diseño

---

## 🎯 Guía de Uso de la Documentación

### Para Revisores de Tesis

1. Comienza con **[thesis-proposal.md](thesis-proposal.md)** para entender el contexto
2. Revisa **[current-thesis-draft.md](current-thesis-draft.md)** para la versión consolidada
3. Consulta capítulos específicos según necesidad:
   - Metodología → `metodologia-capitulo3.md`
   - Propuesta técnica → `propuesta-sistema-cap4.md`
   - Resultados → `validacion-experimental-cap5.md`

### Para Desarrolladores

1. Lee **[project-overview.md](project-overview.md)** para contexto general
2. Revisa **[uml/01_SYSTEM_ARCHITECTURE.md](uml/01_SYSTEM_ARCHITECTURE.md)** para entender la arquitectura
3. Consulta **[implementacion-completa.md](implementacion-completa.md)** para detalles técnicos
4. Sigue **[configuracion-herramientas-sast.md](configuracion-herramientas-sast.md)** para configurar el entorno

### Para Investigadores

1. **[research-framework.md](research-framework.md)** - Marco teórico de investigación
2. **[fundamentacion-correlacion-ml.md](fundamentacion-correlacion-ml.md)** - Fundamentación del algoritmo ML
3. **[validacion-experimental-cap5.md](validacion-experimental-cap5.md)** - Metodología experimental y resultados
4. **[academic-documentation.md](academic-documentation.md)** - Documentación para publicación

---

## 📊 Estado del Proyecto

| Componente | Estado | Documentación |
|------------|--------|---------------|
| **Backend API** | ✅ Completo | `propuesta-sistema-cap4.md` |
| **Motor de Correlación ML** | ✅ Completo | `fundamentacion-correlacion-ml.md` |
| **Sistema de Evaluación** | ✅ Completo | `propuesta-sistema-cap4.md` (Sección 4.7) |
| **Frontend Dashboard** | ✅ Completo | `implementacion-completa.md` |
| **Validación Experimental** | ✅ 90% Completo | `configuracion-herramientas-sast.md` |
| **Tesis** | 🔄 En progreso | `current-thesis-draft.md` |

---

## 🔗 Referencias Adicionales

- **README Principal**: [`../README.md`](../README.md) - Información de inicio rápido
- **QUICK_START**: [`../QUICK_START.md`](../QUICK_START.md) - Guía de inicio rápido para desarrollo
- **GitHub Issues**: Para reportar problemas o sugerencias
- **Repositorio**: [OscarILS/HybridSecScan](https://github.com/OscarILS/HybridSecScan)

---

## 📝 Notas para Contribuidores

- Todos los documentos nuevos deben agregarse a esta carpeta `docs/`
- Usar formato Markdown estándar
- Incluir fecha de última actualización en cada documento
- Seguir la nomenclatura: minúsculas con guiones (kebab-case)
- Actualizar este README.md al agregar nuevos documentos

---

**Última actualización:** 21 de noviembre de 2025

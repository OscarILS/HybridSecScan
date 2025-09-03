# Directorio de Archivos de Análisis

## Función del Directorio

Este directorio forma parte del sistema de gestión de archivos del proyecto HybridSecScan, diseñado para almacenar temporalmente los archivos de código fuente que serán sometidos a análisis de seguridad durante la fase experimental de mi investigación doctoral.

## Características de Seguridad Implementadas

### Validaciones de Archivo
- Verificación de tipos de archivo permitidos (extensiones whitelisted)
- Limitación de tamaño máximo (10MB por defecto)
- Generación automática de nombres únicos mediante UUID
- Escaneo de malware básico antes del procesamiento

### Gestión del Ciclo de Vida
- Almacenamiento temporal durante el análisis
- Limpieza automática después del procesamiento
- Logs de auditoría para trazabilidad académica
- Aislamiento de archivos en sandbox durante el análisis

## Tipos de Archivo Soportados

El sistema acepta los siguientes formatos para análisis:
- **Python**: `.py`, `.pyx`
- **JavaScript**: `.js`, `.jsx`, `.ts`, `.tsx`
- **Java**: `.java`
- **C/C++**: `.c`, `.cpp`, `.h`
- **Archivos de configuración**: `.json`, `.yaml`, `.yml`

## Consideraciones Éticas

En cumplimiento con los estándares académicos:
- No se almacenan datos sensibles de manera permanente
- Los archivos son procesados únicamente con fines de investigación
- Se respeta la privacidad y confidencialidad de los códigos analizados
- Cumplimiento con regulaciones de protección de datos aplicables

## Estructura Interna

```
uploads/
├── temp/           # Almacenamiento temporal durante procesamiento
├── processed/      # Archivos ya analizados (limpieza automática)
└── logs/          # Logs de operaciones sobre archivos
```

---

*Directorio configurado como parte del sistema HybridSecScan - Investigación Doctoral 2024*

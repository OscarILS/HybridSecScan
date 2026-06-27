# uploads/

Directorio de almacenamiento temporal para archivos de código fuente subidos vía `POST /upload/`.

## Restricciones de seguridad

| Restricción | Valor |
|---|---|
| Tamaño máximo | 50 MB |
| Extensiones permitidas | `.py .js .ts .tsx .java .cpp .c .go .php .rb .cs` |
| Nombrado | UUID + timestamp (nunca el nombre original) |
| Limpieza | Manual — los archivos persisten hasta que se eliminen |

Los archivos son copiados a un sandbox temporal en `TEMP/hybridscan_secure/` antes de ser analizados por Bandit o Semgrep, previniendo ataques de path traversal.

Este directorio está en `.gitignore` (excepto este README).

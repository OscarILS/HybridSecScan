# 🔐 ProgramasPruebas - Testing Suite for HybridSecScan

Carpeta con códigos vulnerables y herramientas para probar el sistema HybridSecScan (SAST + DAST).

## 📁 Contenido

| Archivo | Tipo | Propósito |
|---------|------|----------|
| `vulnerable_app.py` | Python/Flask | App vulnerable para SAST (9 vulnerabilidades) |
| `vulnerable_js.js` | JavaScript | Código JS vulnerable para SAST (12 vulnerabilidades) |
| `vulnerable_sql.sql` | SQL | Script SQL con malas prácticas (10 vulnerabilidades) |
| `test_urls.txt` | Text | URLs para pruebas DAST |
| `GUIA_PRUEBAS.md` | Markdown | Guía completa paso a paso |
| `launch_vulnerable_apps.bat` | Batch Script | Lanzador para Windows (CMD) |
| `launch_vulnerable_apps.ps1` | PowerShell | Lanzador avanzado (PowerShell) |

## 🚀 Inicio Rápido

### Opción 1: SAST (Análisis Estático)

```powershell
# 1. Dashboard abierto en http://localhost:5173
# 2. Pestaña: SAST
# 3. Subir: vulnerable_app.py
# 4. Herramienta: Bandit
# 5. Click: "Ejecutar Auditoría"
# 6. Resultado: 16 vulnerabilidades encontradas + Progress Bar
```

### Opción 2: DAST (Análisis Dinámico)

```powershell
# 1. Dashboard abierto en http://localhost:5173
# 2. Pestaña: DAST
# 3. URL: https://juice-shop.herokuapp.com/ (o local)
# 4. Click: "Ejecutar Auditoría"
# 5. Resultado: Vulnerabilidades dinámicas + Progress Bar
```

## 🛠️ Scripts de Instalación

### Windows PowerShell (Recomendado)
```powershell
.\launch_vulnerable_apps.ps1
# Menú interactivo para instalar/ejecutar apps vulnerables
```

### Windows CMD
```cmd
launch_vulnerable_apps.bat
# Script básico para Windows
```

## 📋 URLs de Prueba DAST

### Locales (requieren instalación)
- `http://localhost:3000/` - OWASP Juice Shop
- `http://localhost:4000/` - NodeGoat
- `http://localhost/DVWA/` - DVWA
- `http://localhost:8080/WebGoat/` - WebGoat

### Remotas (sin instalación)
- `https://juice-shop.herokuapp.com/` - Juice Shop
- `https://webgoat.herokuapp.com/WebGoat/` - WebGoat
- `http://testphp.vulnweb.com/` - PHP Vulnerable

## 📊 Vulnerabilidades Incluidas

### vulnerable_app.py (9)
1. ✗ Hardcoded secrets
2. ✗ SQL Injection
3. ✗ Command Injection
4. ✗ Insecure deserialization
5. ✗ Path Traversal
6. ✗ Insecure temp files
7. ✗ Assert for validation
8. ✗ Insecure random
9. ✗ Debug mode enabled

### vulnerable_js.js (12)
1. ✗ eval() en user input
2. ✗ XSS (innerHTML)
3. ✗ Hardcoded credentials
4. ✗ Math.random() for tokens
5. ✗ JSON.parse without validation
6. ✗ SSRF (fetch sin validación)
7. ✗ Function constructor
8. ✗ External scripts sin CSP
9. ✗ localStorage for tokens
10. ✗ Plain password transmission
11. ✗ ReDoS regex
12. ✗ Datos sensibles en comentarios

### vulnerable_sql.sql (10)
1. ✗ Privilegios excesivos
2. ✗ Contraseñas débiles
3. ✗ Comentarios con secretos
4. ✗ SQL Injection vulnerable
5. ✗ Datos sin encriptación
6. ✗ Sin índices críticos
7. ✗ Permisos abiertos
8. ✗ Transacciones ausentes
9. ✗ Triggers inseguros
10. ✗ Sesiones sin encriptar

## 📈 Progress Bars en Frontend

Ambos tipos de análisis (SAST y DAST) muestran:

```
┌─────────────────────────────┐
│ 📊 Análisis SAST             │
│ Analizando con BANDIT...     │
├─────────────────────────────┤
│ ████████████░░░░░░░░░░░ 45% │
└─────────────────────────────┘
```

Características:
- ✓ Animación suave (0.3s transition)
- ✓ Simulación realista de progreso
- ✓ Color verde cuando completa (100%)
- ✓ Indicador de estado
- ✓ Porcentaje en tiempo real

## ⚙️ Requisitos

| Herramienta | Versión | Uso |
|-------------|---------|-----|
| Python | 3.7+ | SAST analysis |
| Node.js | 14+ | JavaScript apps |
| npm | 6+ | Package management |
| Docker | Latest | Container apps |
| Git | Latest | Repository cloning |

## 🔗 Enlaces Útiles

- [HybridSecScan Docs](../README.md)
- [GUÍA DE PRUEBAS COMPLETA](./GUIA_PRUEBAS.md)
- [Bandit Documentation](https://bandit.readthedocs.io/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP DVWA](https://github.com/digininja/DVWA)

## ❓ FAQ

**P: ¿Puedo modificar las vulnerabilidades?**  
R: Sí, son archivos de prueba. Modifícalos para tus necesidades.

**P: ¿Es seguro ejecutar esto?**  
R: Sí, usa máquinas locales/virtuales. Las apps tienen vulnerabilidades intencionales.

**P: ¿Cómo cargo otras apps?**  
R: Copia el patrón de vulnerable_app.py o usa URLs de test_urls.txt.

**P: ¿Los progress bars funcionan sin cambios?**  
R: Sí, están integrados en App.tsx. Se activan automáticamente en SAST/DAST.

---

**Última actualización:** Noviembre 27, 2025  
**Estado:** ✅ Pronto para producción  
**Mantenedor:** HybridSecScan Team

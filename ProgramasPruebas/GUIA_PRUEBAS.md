# Guía de Pruebas - HybridSecScan

## 📁 Estructura de `/ProgramasPruebas/`

### Archivos Disponibles:

#### 1. **vulnerable_app.py** - Aplicación Flask Vulnerable
```python
# Contiene 9 vulnerabilidades SAST:
- Hardcoded secrets/passwords
- SQL Injection
- Command Injection
- Insecure deserialization
- Path Traversal
- Insecure temporary files
- Use of assert for validation
- Insecure random for tokens
- Debug mode enabled in production
```

**Cómo ejecutar:**
```bash
cd ProgramasPruebas
python vulnerable_app.py
# Accesible en http://localhost:5000
```

---

#### 2. **vulnerable_js.js** - Código JavaScript Vulnerable
```javascript
// Contiene 12 vulnerabilidades SAST:
- eval() en input de usuario
- innerHTML sin sanitización (XSS)
- Credenciales hardcodeadas
- Math.random() para seguridad
- JSON.parse sin validación
- fetch sin validación de URL (SSRF)
- Function constructor
- Scriptss externos sin CSP
- localStorage para tokens
- Contraseña sin encriptación
- Expresión regular ReDoS
- Comentarios con información sensible
```

**Cómo usar en el frontend:**
```bash
# Copiar a tu proyecto Node.js para análisis
cp vulnerable_js.js ../frontend/src/
# Ejecutar Bandit o Semgrep desde el dashboard
```

---

#### 3. **vulnerable_sql.sql** - Código SQL Vulnerable
```sql
// Contiene 10 vulnerabilidades:
- Usuarios con privilegios excesivos
- Contraseñas débiles
- Información sensible en comentarios
- Vulnerable a SQL injection
- Datos sensibles sin encriptación
- Falta de índices críticos
- Permisos demasiado abiertos
- Transacciones ausentes
- Triggers inseguros
- Sesiones sin encriptación
```

---

#### 4. **test_urls.txt** - URLs para DAST Testing

## 🧪 Flujo de Pruebas

### **PARTE 1: PRUEBAS SAST (Static Analysis)**

#### Paso 1: Subir archivos vulnerables
1. Abre el dashboard: `http://localhost:5173`
2. Selecciona pestaña **SAST**
3. Sube uno de estos archivos:
   - `ProgramasPruebas/vulnerable_app.py`
   - `ProgramasPruebas/vulnerable_js.js`

#### Paso 2: Ejecutar análisis
```
Herramienta: Bandit (para Python)
O
Herramienta: Semgrep (análisis más detallado)
```

#### Paso 3: Revisar resultados
- La barra de progreso mostrará:
  ```
  ├─ "Iniciando..."
  ├─ "Analizando con BANDIT..." (progreso 0-90%)
  ├─ "✅ Análisis completado" (100%)
  └─ Se muestran las vulnerabilidades encontradas
  ```

---

### **PARTE 2: PRUEBAS DAST (Dynamic Analysis)**

#### Opción A: URLs Online (sin instalación local)

1. Abre dashboard: `http://localhost:5173`
2. Selecciona pestaña **DAST**
3. Ingresa una de estas URLs:

```
# OWASP Juice Shop (e-commerce vulnerable)
https://juice-shop.herokuapp.com/

# WebGoat Online
https://webgoat.herokuapp.com/WebGoat/

# DVWA Vulnerable
http://testphp.vulnweb.com/
```

#### Opción B: URLs Locales (requiere instalar aplicaciones)

**DVWA (Damn Vulnerable Web App):**
```bash
# 1. Instalar DVWA
git clone https://github.com/digininja/DVWA.git
cd DVWA

# 2. Crear Docker container
docker build -t dvwa .
docker run -p 80:80 dvwa

# 3. En HybridSecScan DAST ingresa:
http://localhost/DVWA/
```

**OWASP Juice Shop (Local):**
```bash
# 1. Instalar
npm install -g @owasp/juice-shop@latest
juice-shop

# 2. Acceso local
http://localhost:3000/

# 3. En HybridSecScan DAST ingresa:
http://localhost:3000/
```

**NodeGoat:**
```bash
# 1. Instalar
git clone https://github.com/OWASP/NodeGoat.git
cd NodeGoat
npm install
npm start

# 2. Acceso
http://localhost:4000/

# 3. En HybridSecScan DAST ingresa:
http://localhost:4000/
```

---

## 📊 Progreso Esperado

### Para SAST (vulnerable_app.py):
```
Progreso:    |████████████████████████████████| 100%
Status:      ✅ Análisis completado
Resultado:   Bandit encontró 16 vulnerabilidades
- 5 MEDIUM severity
- 11 LOW severity
```

### Para DAST (OWASP Juice Shop):
```
Progreso:    |████████████████████████████████| 100%
Status:      ✅ Análisis completado
Resultado:   OWASP ZAP encontró vulnerabilidades
- XSS vulnerabilities
- SQL Injection points
- Insecure authentication
- CORS misconfigurations
```

---

## 🔍 Verificar Progreso en Terminal

### Backend Logs:
```powershell
# Ver en terminal donde corre FastAPI (puerto 8000)
INFO:     127.0.0.1:56737 - "POST /scan/sast HTTP/1.1" 200 OK
INFO:     Scan completed successfully
```

### Frontend Logs:
```powershell
# Ver en terminal donde corre Vite (puerto 5173)
✓ updated 1 files in 245ms
[React] Progress: 45%
[React] Scan submitted successfully
```

---

## 📈 Parámetros para Análisis

### SAST:
- **Timeout:** 30 segundos
- **Profundidad:** Completa (todos los archivos)
- **Severidad:** Mostrar todas (LOW, MEDIUM, HIGH, CRITICAL)

### DAST:
- **Timeout:** 60 segundos (sitios remotos pueden ser lentos)
- **Profundidad:** Normal (por defecto)
- **Autenticación:** None (para sitios públicos)

---

## 🛠️ Solución de Problemas

### Problema: Progress bar no aparece
**Solución:**
```
1. Verifica que isLoading esté true
2. Revisa console en DevTools (F12)
3. Asegúrate que la conexión al backend sea correcta
```

### Problema: URL de DAST no responde
**Solución:**
```
1. Verifica que la URL sea correcta y esté online
2. Intenta con https:// si http:// no funciona
3. Para URLs locales, asegúrate que el servicio está corriendo
4. Algunos firewalls pueden bloquear - usa VPN si es necesario
```

### Problema: Bandit no encuentra vulnerabilidades
**Solución:**
```
1. Asegúrate que el archivo sea Python (.py)
2. Verifica que Bandit esté instalado: pip install bandit
3. Revisa el archivo vulnerable_app.py tiene código vulnerable
```

---

## 📝 Historial de Auditorías

Después de ejecutar análisis, aparecerán en la tabla "Historial de Auditorías":

```
| Tipo | Herramienta | Objetivo          | Estado    | Fecha              |
|------|-------------|-------------------|-----------|-------------------|
| SAST | bandit      | vulnerable_app.py | finished  | 2025-11-27 10:30  |
| DAST | zap         | juice-shop...com  | finished  | 2025-11-27 10:45  |
```

---

## ✅ Checklist de Pruebas

- [ ] SAST con vulnerable_app.py - Bandit
- [ ] SAST con vulnerable_js.js - Semgrep
- [ ] DAST con URL local (DVWA o Juice Shop)
- [ ] DAST con URL remota (Juice Shop Heroku)
- [ ] Progress bar visible en SAST
- [ ] Progress bar visible en DAST
- [ ] Resultados aparecen en consola
- [ ] Historial se actualiza automáticamente
- [ ] Sin errores en DevTools (F12)
- [ ] Sin errores en terminal del backend

---

## 📚 Recursos Adicionales

- **Bandit Documentation:** https://bandit.readthedocs.io/
- **OWASP DVWA:** https://github.com/digininja/DVWA
- **OWASP Juice Shop:** https://github.com/bkimminich/juice-shop
- **OWASP ZAP:** https://www.zaproxy.org/
- **HybridSecScan Docs:** Ver `/docs/` del proyecto

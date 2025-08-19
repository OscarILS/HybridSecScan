# HybridSecScan

Sistema de auditoría automatizada híbrida (SAST + DAST) para APIs REST, enfocado en la detección de vulnerabilidades del OWASP API Security Top 10.

## 🔧 Arquitectura

- **Backend**: FastAPI (Python) - API REST para gestión de análisis
- **Frontend**: React + TypeScript + Vite - Interfaz web moderna
- **Base de Datos**: SQLite - Almacenamiento de resultados
- **Herramientas SAST**: Bandit, Semgrep
- **Herramientas DAST**: OWASP ZAP

## 🚀 Instalación y Configuración

### Prerrequisitos

- Python 3.8+
- Node.js 18+
- Git

### Configuración del Backend

1. Instalar dependencias de Python:
```bash
pip install -r requirements.txt
```

2. Instalar herramientas de seguridad:
```bash
# Instalar Semgrep
pip install semgrep

# Instalar OWASP ZAP (opcional para DAST)
# Descargar desde: https://www.zaproxy.org/download/
```

3. Ejecutar el servidor:
```bash
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Configuración del Frontend

1. Instalar dependencias de Node.js:
```bash
cd frontend
npm install
```

2. Ejecutar el servidor de desarrollo:
```bash
npm run dev
```

## 📝 Uso

### Interfaz Web

1. Acceder a `http://localhost:5173`
2. Subir archivo de código fuente para análisis SAST
3. Configurar parámetros de análisis
4. Ejecutar análisis y revisar resultados

### API Endpoints

- `GET /` - Información de la API
- `POST /upload/` - Subir archivo de código
- `POST /scan/sast` - Ejecutar análisis SAST
- `POST /scan/dast` - Ejecutar análisis DAST  
- `GET /scan-results` - Obtener historial de análisis
- `GET /health` - Health check

### Scripts Independientes

```bash
# Análisis SAST con Bandit
python scripts/run_bandit.py /ruta/al/codigo

# Análisis SAST con Semgrep
python scripts/run_semgrep.py /ruta/al/codigo

# Análisis DAST con OWASP ZAP
python scripts/run_zap.py https://api.ejemplo.com
```

## 🛡️ Características de Seguridad

- Validación de tipos de archivo permitidos
- Limitación de tamaño de archivos (10MB máximo)
- Nombres de archivo seguros con UUID
- Validación de URLs para DAST
- Manejo seguro de procesos subprocess
- Timeouts para evitar análisis colgados

## 📊 OWASP API Security Top 10 Coverage

| Vulnerabilidad | SAST | DAST | Herramienta |
|----------------|------|------|-------------|
| API1: Broken Object Level Authorization | ✅ | ✅ | Semgrep, ZAP |
| API2: Broken Authentication | ✅ | ✅ | Bandit, Semgrep, ZAP |
| API3: Broken Object Property Level Authorization | ✅ | ✅ | Semgrep, ZAP |
| API4: Unrestricted Resource Consumption | ✅ | ✅ | Semgrep, ZAP |
| API5: Broken Function Level Authorization | ✅ | ✅ | Semgrep, ZAP |
| API6: Unrestricted Access to Sensitive Business Flows | ⚠️ | ✅ | ZAP |
| API7: Server Side Request Forgery | ✅ | ✅ | Bandit, Semgrep, ZAP |
| API8: Security Misconfiguration | ✅ | ✅ | Bandit, Semgrep, ZAP |
| API9: Improper Inventory Management | ⚠️ | ✅ | ZAP |
| API10: Unsafe Consumption of APIs | ✅ | ✅ | Semgrep, ZAP |

**Leyenda:** ✅ Detección completa | ⚠️ Detección parcial | ❌ No detectado

## 🗂️ Estructura del Proyecto

```
HybridSecScan/
├── backend/                 # API FastAPI
│   ├── __init__.py
│   └── main.py             # Servidor principal
├── database/               # Modelos y BD
│   ├── __init__.py
│   ├── models.py           # Modelos SQLAlchemy
│   └── hybridsecscan.db    # Base de datos SQLite
├── frontend/               # Aplicación React
│   ├── src/
│   │   ├── App.tsx        # Componente principal
│   │   ├── App.css        # Estilos
│   │   └── main.tsx       # Punto de entrada
│   ├── package.json
│   └── index.html
├── reports/                # Reportes generados
├── scripts/               # Scripts independientes
│   ├── run_bandit.py      # Ejecutor Bandit
│   ├── run_semgrep.py     # Ejecutor Semgrep
│   └── run_zap.py         # Ejecutor OWASP ZAP
├── uploads/               # Archivos subidos
├── requirements.txt       # Dependencias Python
└── README.md             # Este archivo
```

## 🐛 Problemas Solucionados

- ✅ Configuración CORS para comunicación frontend-backend
- ✅ Manejo de errores en subprocess calls
- ✅ Validación de seguridad en subida de archivos
- ✅ Timeouts para evitar procesos colgados
- ✅ Estructura de directorios corregida
- ✅ Scripts con rutas absolutas
- ✅ Modelo de base de datos mejorado
- ✅ Interfaz de usuario más robusta

## 🔮 Mejoras Futuras

- [ ] Autenticación y autorización de usuarios
- [ ] Análisis de contenedores Docker
- [ ] Integración con CI/CD pipelines
- [ ] Reportes en PDF
- [ ] Dashboard de métricas avanzado
- [ ] Análisis de dependencias (SCA)
- [ ] Integración con más herramientas SAST/DAST

## 📄 Licencia

MIT License - Ver archivo LICENSE para más detalles.

## 🤝 Contribución

1. Fork el proyecto
2. Crear branch para feature (`git checkout -b feature/AmazingFeature`)
3. Commit cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push al branch (`git push origin feature/AmazingFeature`)
5. Abrir Pull Request

## 📞 Soporte

Para reportar bugs o solicitar features, por favor crea un issue en GitHub.


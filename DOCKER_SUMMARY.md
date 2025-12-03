# 📦 HybridSecScan - Resumen de Containerización

## ✅ Archivos Creados para Docker

### 🐳 Configuración Docker

| Archivo | Propósito | Estado |
|---------|-----------|--------|
| `Dockerfile.backend` | Imagen del backend FastAPI + SAST tools | ✅ Creado |
| `Dockerfile.frontend` | Imagen del frontend React + Nginx | ✅ Creado |
| `docker-compose.yml` | Orquestación de servicios | ✅ Creado |
| `nginx.conf` | Configuración de Nginx con reverse proxy | ✅ Creado |
| `.dockerignore` | Exclusión de archivos del build | ✅ Creado |

### 📜 Scripts de Despliegue

| Archivo | Plataforma | Propósito | Estado |
|---------|------------|-----------|--------|
| `deploy.sh` | Linux/macOS | Script automatizado de despliegue | ✅ Creado |
| `deploy.ps1` | Windows | Script PowerShell de despliegue | ✅ Creado |

### 📖 Documentación

| Archivo | Contenido | Estado |
|---------|-----------|--------|
| `DOCKER.md` | Guía rápida de Docker | ✅ Creado |
| `DEPLOYMENT.md` | Guía completa de despliegue empresarial | ✅ Creado |
| `.env.example` | Template de variables de entorno | ⚠️ Ya existía |
| `README.md` | Actualizado con sección Docker | ✅ Actualizado |

### 🔄 CI/CD

| Archivo | Propósito | Estado |
|---------|-----------|--------|
| `.github/workflows/docker-build.yml` | Pipeline de GitHub Actions | ✅ Creado |

### 🔧 Modificaciones en Código

| Archivo | Cambio | Estado |
|---------|--------|--------|
| `frontend/src/App.tsx` | API_BASE_URL → ruta relativa `/api` | ✅ Modificado |
| `.gitignore` | Agregar exclusiones de Docker | ✅ Modificado |

---

## 🏗️ Arquitectura Implementada

```
┌─────────────────────────────────────────────────────┐
│              Internet / Red Empresarial             │
└────────────────────┬────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────┐
│               Puerto 80 (HTTP) / 443 (HTTPS)        │
│                   pfSense Firewall                   │
└────────────────────┬────────────────────────────────┘
                     │ Port Forward
                     ▼
┌─────────────────────────────────────────────────────┐
│              Proxmox Virtual Machine                │
│               (Ubuntu/Debian Server)                │
│                                                     │
│  ┌───────────────────────────────────────────────┐ │
│  │      hybridscan-frontend Container            │ │
│  │  ┌─────────────────────────────────────────┐  │ │
│  │  │   Nginx (Reverse Proxy)                 │  │ │
│  │  │   - Sirve frontend React (build)        │  │ │
│  │  │   - Proxy /api → backend:8000           │  │ │
│  │  │   - SSL termination                     │  │ │
│  │  └─────────────────────────────────────────┘  │ │
│  └────────────────┬──────────────────────────────┘ │
│                   │ Internal Network                │
│                   ▼                                 │
│  ┌───────────────────────────────────────────────┐ │
│  │      hybridscan-backend Container             │ │
│  │  ┌─────────────────────────────────────────┐  │ │
│  │  │   FastAPI + Uvicorn                     │  │ │
│  │  │   - Bandit (SAST Python)                │  │ │
│  │  │   - Semgrep (SAST Multi-language)       │  │ │
│  │  │   - Correlation Engine (ML)             │  │ │
│  │  │   - PDF Generator                       │  │ │
│  │  └─────────────┬───────────────────────────┘  │ │
│  └────────────────┼──────────────────────────────┘ │
│                   │                                 │
│                   ▼                                 │
│  ┌───────────────────────────────────────────────┐ │
│  │         Docker Volumes (Persistentes)         │ │
│  │  - hybridscan-database (SQLite)               │ │
│  │  - hybridscan-reports (PDFs/JSON)             │ │
│  │  - hybridscan-uploads (Código temporal)       │ │
│  └───────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────┘
```

---

## 🚀 Flujo de Despliegue

### **Opción 1: Despliegue Rápido (Linux/macOS)**

```bash
# 1. Clonar repositorio
git clone https://github.com/OscarILS/HybridSecScan.git
cd HybridSecScan

# 2. Ejecutar script
chmod +x deploy.sh
./deploy.sh

# 3. Acceder
open http://localhost
```

### **Opción 2: Despliegue Rápido (Windows)**

```powershell
# 1. Clonar repositorio
git clone https://github.com/OscarILS/HybridSecScan.git
cd HybridSecScan

# 2. Ejecutar script
.\deploy.ps1

# 3. Acceder
start http://localhost
```

### **Opción 3: Despliegue Manual**

```bash
# 1. Crear directorios
mkdir -p database reports uploads

# 2. Build de imágenes
docker-compose build --no-cache

# 3. Iniciar servicios
docker-compose up -d

# 4. Verificar estado
docker-compose ps
docker-compose logs -f
```

---

## 🌐 URLs de Acceso

| Servicio | URL | Descripción |
|----------|-----|-------------|
| **Frontend** | `http://localhost` | Dashboard principal |
| **API Docs** | `http://localhost/api/docs` | Swagger UI |
| **API Redoc** | `http://localhost/api/redoc` | Redoc UI |
| **Health Check** | `http://localhost/api/health` | Estado del backend |
| **OpenAPI JSON** | `http://localhost/api/openapi.json` | Especificación OpenAPI |

---

## 📊 Características de la Solución Docker

### ✅ Seguridad

- ✅ Contenedores ejecutan como usuario no-root (UID 1000)
- ✅ Imágenes base oficiales (python:3.11-slim, node:18-alpine, nginx:1.25-alpine)
- ✅ Multi-stage build para frontend (reduce tamaño de imagen)
- ✅ Health checks automáticos cada 30 segundos
- ✅ Cabeceras de seguridad en Nginx (X-Frame-Options, CSP, etc.)
- ✅ Timeouts configurados para scans largos (5 minutos)

### ⚡ Performance

- ✅ Nginx con compresión gzip
- ✅ Cache de assets estáticos (1 año)
- ✅ Uvicorn con 2 workers (configurable)
- ✅ Límites de recursos (CPU: 2 cores, RAM: 2GB backend)
- ✅ Volúmenes para persistencia sin overhead

### 🔧 Operaciones

- ✅ Auto-restart de contenedores
- ✅ Logs estructurados en JSON
- ✅ Health checks con 3 reintentos
- ✅ Backups fáciles (volúmenes en directorio local)
- ✅ Rollback simple con `docker-compose down && docker-compose up -d`

### 📈 Escalabilidad

- ✅ Fácil escalar workers: modificar `--workers` en docker-compose.yml
- ✅ Fácil agregar load balancer (Nginx upstream)
- ✅ Separación de servicios permite escalado horizontal
- ✅ Volúmenes compartibles entre instancias

---

## 🔄 Comandos Esenciales

### Gestión de Servicios

```bash
# Iniciar
docker-compose up -d

# Detener
docker-compose down

# Reiniciar
docker-compose restart

# Ver logs
docker-compose logs -f

# Ver estado
docker-compose ps

# Rebuild
docker-compose up -d --build
```

### Debugging

```bash
# Entrar al backend
docker-compose exec backend /bin/bash

# Entrar al frontend
docker-compose exec frontend /bin/sh

# Ver logs de errores
docker-compose logs backend | grep ERROR

# Ver recursos
docker stats
```

### Mantenimiento

```bash
# Backup de BD
cp database/hybridsecscan.db database/backup_$(date +%Y%m%d).db

# Limpiar espacio
docker system prune -a --volumes -f

# Ver imágenes
docker images | grep hybridscan

# Ver volúmenes
docker volume ls | grep hybridscan
```

---

## 🏢 Configuración Empresarial

### pfSense Configuration

```
Firewall → NAT → Port Forward
┌──────────────────────────────────┐
│ Interface:      WAN              │
│ Protocol:       TCP              │
│ Dest. Port:     80, 443          │
│ Redirect IP:    192.168.1.100    │ ← IP de VM Proxmox
│ Redirect Port:  80, 443          │
└──────────────────────────────────┘

Firewall → Rules → WAN
┌──────────────────────────────────┐
│ Action:         Pass             │
│ Protocol:       TCP              │
│ Destination:    192.168.1.100    │
│ Dest. Port:     80, 443          │
└──────────────────────────────────┘
```

### DNS Configuration

```
Services → DNS Resolver → Host Overrides
┌──────────────────────────────────┐
│ Host:           hybridscan       │
│ Domain:         empresa.local    │
│ IP:             192.168.1.100    │
└──────────────────────────────────┘
```

### HTTPS Setup

```bash
# Obtener certificado Let's Encrypt
sudo certbot certonly --standalone -d hybridscan.empresa.com

# Agregar a docker-compose.yml
volumes:
  - /etc/letsencrypt:/etc/letsencrypt:ro

# Actualizar nginx.conf con SSL
```

---

## 🎯 Checklist Pre-Producción

- [ ] Docker y Docker Compose instalados
- [ ] Firewall configurado (puertos 80, 443)
- [ ] DNS configurado (interno o público)
- [ ] Variables de entorno en `.env`
- [ ] SECRET_KEY generado aleatoriamente
- [ ] CORS_ORIGINS configurado con dominios reales
- [ ] HTTPS con certificado SSL
- [ ] Backups automáticos configurados
- [ ] Monitoreo activo (logs, health checks)
- [ ] Límites de rate-limiting (opcional)
- [ ] Documentación entregada al equipo
- [ ] Tests de integración ejecutados
- [ ] Plan de rollback definido

---

## 📞 Soporte y Recursos

### Documentación

- **Guía Rápida**: [DOCKER.md](DOCKER.md)
- **Despliegue Completo**: [DEPLOYMENT.md](DEPLOYMENT.md)
- **README Principal**: [README.md](README.md)
- **Documentación API**: http://localhost/api/docs

### Scripts

- **Despliegue Linux/macOS**: `./deploy.sh`
- **Despliegue Windows**: `.\deploy.ps1`

### CI/CD

- **GitHub Actions**: `.github/workflows/docker-build.yml`
- Builds automáticos en push a `main` o `develop`

### Troubleshooting

Ver sección "Troubleshooting" en:
- [DOCKER.md](DOCKER.md#-troubleshooting)
- [DEPLOYMENT.md](DEPLOYMENT.md#-troubleshooting)

---

## 📝 Notas Finales

### Ventajas de la Containerización

1. **Portabilidad**: Mismo comportamiento en dev, staging y producción
2. **Aislamiento**: Dependencias encapsuladas, no conflictos
3. **Escalabilidad**: Fácil replicar instancias
4. **Mantenibilidad**: Actualizaciones sin afectar el host
5. **Seguridad**: Capas de aislamiento adicionales
6. **DevOps**: CI/CD automatizado con GitHub Actions

### Próximos Pasos Recomendados

1. **Monitoreo**: Implementar Prometheus + Grafana
2. **Logging**: Centralizar logs con ELK Stack
3. **Backup**: Automatizar backups con cron jobs
4. **Scaling**: Implementar Kubernetes para alta disponibilidad
5. **Security**: Escaneo de imágenes con Trivy/Snyk
6. **Performance**: Implementar Redis para caché

---

**Versión**: 1.0.0  
**Fecha**: Diciembre 2025  
**Autor**: Oscar ILS  
**Estado**: ✅ Listo para Producción

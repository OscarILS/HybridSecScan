# 🐳 HybridSecScan - Despliegue con Docker

Sistema de auditoría de seguridad híbrido (SAST + DAST) con correlación mediante ML, containerizado y listo para producción.

---

## 🚀 Quick Start

### Linux/macOS

```bash
# 1. Clonar repositorio
git clone https://github.com/OscarILS/HybridSecScan.git
cd HybridSecScan

# 2. Ejecutar script de despliegue
chmod +x deploy.sh
./deploy.sh

# 3. Acceder a la aplicación
open http://localhost
```

### Windows (PowerShell)

```powershell
# 1. Clonar repositorio
git clone https://github.com/OscarILS/HybridSecScan.git
cd HybridSecScan

# 2. Ejecutar script de despliegue
.\deploy.ps1

# 3. Acceder a la aplicación
start http://localhost
```

### Manual con Docker Compose

```bash
# Build y Start
docker-compose up -d --build

# Verificar estado
docker-compose ps

# Ver logs
docker-compose logs -f
```

---

## 📦 Arquitectura de Contenedores

```
┌────────────────────────────────────────────┐
│         hybridscan-frontend                │
│  Nginx + React (Build Estático)           │
│  Puerto: 80, 443                           │
│  Imagen: node:18-alpine → nginx:1.25       │
└──────────────┬─────────────────────────────┘
               │ Reverse Proxy (/api → backend)
               ↓
┌────────────────────────────────────────────┐
│         hybridscan-backend                 │
│  FastAPI + ML + Bandit + Semgrep           │
│  Puerto: 8000 (interno)                    │
│  Imagen: python:3.11-slim                  │
└──────────────┬─────────────────────────────┘
               │
               ↓
┌────────────────────────────────────────────┐
│         Docker Volumes                     │
│  - hybridscan-database (SQLite)            │
│  - hybridscan-reports  (PDFs/JSON)         │
│  - hybridscan-uploads  (Código temporal)   │
└────────────────────────────────────────────┘
```

---

## 🔧 Archivos de Configuración

### Estructura del Proyecto

```
HybridSecScan/
├── Dockerfile.backend           # Backend FastAPI
├── Dockerfile.frontend          # Frontend React + Nginx
├── docker-compose.yml           # Orquestación de servicios
├── nginx.conf                   # Configuración de Nginx
├── .dockerignore                # Archivos excluidos del build
├── deploy.sh                    # Script de despliegue (Linux/macOS)
├── deploy.ps1                   # Script de despliegue (Windows)
├── .env.example                 # Variables de entorno
└── DEPLOYMENT.md                # Guía completa de despliegue
```

### Variables de Entorno

Crear archivo `.env` en la raíz:

```bash
# Backend
ENVIRONMENT=production
DATABASE_URL=sqlite:///./database/hybridsecscan.db
MAX_UPLOAD_SIZE=100MB
CORS_ORIGINS=http://localhost,https://tudominio.com

# Security
SECRET_KEY=genera_un_secret_key_aleatorio

# Performance
MAX_WORKERS=2
REQUEST_TIMEOUT=300
```

---

## 🛠️ Comandos Útiles

### Gestión de Contenedores

```bash
# Iniciar servicios
docker-compose up -d

# Detener servicios
docker-compose down

# Reiniciar servicios
docker-compose restart

# Ver estado
docker-compose ps

# Ver logs en tiempo real
docker-compose logs -f

# Ver logs de un servicio específico
docker-compose logs -f backend
docker-compose logs -f frontend

# Rebuild sin caché
docker-compose build --no-cache

# Rebuild y reiniciar
docker-compose up -d --build
```

### Gestión de Datos

```bash
# Backup de base de datos
docker-compose exec backend cp /app/database/hybridsecscan.db /app/database/backup_$(date +%Y%m%d).db

# Restaurar backup
docker cp backup.db hybridscan-backend:/app/database/hybridsecscan.db
docker-compose restart backend

# Limpiar reportes antiguos
docker-compose exec backend find /app/reports -mtime +30 -delete
```

### Debugging

```bash
# Entrar al contenedor backend
docker-compose exec backend /bin/bash

# Entrar al contenedor frontend
docker-compose exec frontend /bin/sh

# Ver variables de entorno
docker-compose exec backend env

# Inspeccionar contenedor
docker inspect hybridscan-backend

# Ver uso de recursos
docker stats hybridscan-backend hybridscan-frontend
```

### Limpieza

```bash
# Limpiar contenedores detenidos
docker container prune -f

# Limpiar imágenes no usadas
docker image prune -a -f

# Limpiar volúmenes no usados
docker volume prune -f

# Limpieza completa
docker system prune -a --volumes -f
```

---

## 🌐 Despliegue en Servidor Empresarial

### Requisitos del Servidor

- **OS**: Ubuntu 22.04 / Debian 12 / CentOS 8+
- **CPU**: 2 cores mínimo
- **RAM**: 4GB mínimo
- **Disco**: 50GB SSD
- **Docker**: 24.0+
- **Docker Compose**: 2.20+

### Pasos de Despliegue

#### 1. Preparar el Servidor

```bash
# Actualizar sistema
sudo apt update && sudo apt upgrade -y

# Instalar Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Instalar Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Agregar usuario al grupo docker
sudo usermod -aG docker $USER
newgrp docker
```

#### 2. Clonar y Configurar

```bash
# Clonar repositorio
cd /opt
sudo git clone https://github.com/OscarILS/HybridSecScan.git
cd HybridSecScan

# Configurar permisos
sudo chown -R $USER:$USER .

# Crear archivo .env
cp .env.example .env
nano .env  # Editar valores
```

#### 3. Configurar Firewall

```bash
# Ubuntu/Debian (UFW)
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# CentOS/RHEL (Firewalld)
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

#### 4. Desplegar

```bash
# Ejecutar script de despliegue
chmod +x deploy.sh
./deploy.sh

# O manualmente
docker-compose up -d --build
```

#### 5. Configurar HTTPS (Opcional)

```bash
# Instalar Certbot
sudo apt install certbot -y

# Obtener certificado
sudo certbot certonly --standalone -d hybridscan.tudominio.com

# Actualizar docker-compose.yml para montar certificados
# Ver DEPLOYMENT.md para más detalles
```

---

## 🔒 Seguridad

### Recomendaciones

1. **Cambiar SECRET_KEY** en `.env`
2. **Configurar CORS** correctamente
3. **Usar HTTPS** en producción
4. **Limitar acceso** con firewall
5. **Backups automáticos** de la base de datos
6. **Actualizar imágenes** regularmente

### Hardening

```bash
# Ejecutar como usuario no-root (ya implementado en Dockerfiles)
# Limitar recursos
docker-compose up -d --scale backend=1

# Escanear vulnerabilidades en imágenes
docker scan hybridscan-backend
docker scan hybridscan-frontend
```

---

## 📊 Monitoreo

### Health Checks

```bash
# Health check backend
curl http://localhost/api/health

# Health check frontend
curl http://localhost/

# Docker health status
docker inspect --format='{{.State.Health.Status}}' hybridscan-backend
docker inspect --format='{{.State.Health.Status}}' hybridscan-frontend
```

### Logs Persistentes

```bash
# Configurar log rotation
docker-compose logs --tail=1000 > logs_$(date +%Y%m%d).txt

# Ver logs de errores
docker-compose logs --tail=100 | grep ERROR
```

### Portainer (Opcional)

Interfaz gráfica para gestión de Docker:

```bash
docker volume create portainer_data

docker run -d \
  -p 9000:9000 \
  --name portainer \
  --restart=always \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v portainer_data:/data \
  portainer/portainer-ce:latest
```

Acceder a: `http://servidor:9000`

---

## 🔄 Actualización

```bash
# 1. Pull últimos cambios
git pull origin main

# 2. Detener servicios
docker-compose down

# 3. Backup de datos
cp -r database database_backup_$(date +%Y%m%d)

# 4. Rebuild
docker-compose build --no-cache

# 5. Iniciar
docker-compose up -d

# 6. Verificar
docker-compose ps
docker-compose logs -f
```

---

## 🐛 Troubleshooting

### Problema: Puerto 80 ocupado

```bash
# Ver qué está usando el puerto
sudo netstat -tulpn | grep :80

# Detener servicio conflictivo
sudo systemctl stop apache2
sudo systemctl disable apache2
```

### Problema: Contenedor no inicia

```bash
# Ver logs completos
docker-compose logs backend

# Verificar configuración
docker-compose config

# Recrear contenedor
docker-compose up -d --force-recreate backend
```

### Problema: Error de permisos en volumes

```bash
# Dar permisos correctos
sudo chown -R 1000:1000 database reports uploads
sudo chmod -R 755 database reports uploads
```

### Problema: Base de datos corrupta

```bash
# Restaurar desde backup
docker-compose down
cp database_backup_FECHA/hybridsecscan.db database/
docker-compose up -d
```

---

## 📈 Performance

### Optimizaciones

```yaml
# docker-compose.yml
services:
  backend:
    deploy:
      resources:
        limits:
          cpus: '4.0'
          memory: 4G
        reservations:
          cpus: '1.0'
          memory: 1G
    command: ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
```

### Métricas

```bash
# Ver uso de recursos
docker stats

# Logs de performance
docker-compose logs backend | grep "INFO"
```

---

## 📝 URLs Importantes

- **Frontend**: http://localhost
- **API Docs**: http://localhost/api/docs
- **API Redoc**: http://localhost/api/redoc
- **Health Check**: http://localhost/api/health
- **OpenAPI JSON**: http://localhost/api/openapi.json

---

## 🤝 Soporte

- **Documentación Completa**: Ver `DEPLOYMENT.md`
- **Issues**: https://github.com/OscarILS/HybridSecScan/issues
- **Email**: oscar@empresa.com

---

## 📄 Licencia

Ver archivo `LICENSE`

---

**Versión**: 1.0.0  
**Última actualización**: Diciembre 2025  
**Autor**: Oscar ILS

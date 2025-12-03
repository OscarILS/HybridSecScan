# 🚀 Guía de Despliegue - HybridSecScan

## 📋 Requisitos Previos

### En el Servidor (Linux/Proxmox VM)

```bash
# Sistema Operativo
Ubuntu Server 22.04 LTS / Debian 12 / CentOS 8+

# Recursos Mínimos
CPU: 2 cores
RAM: 4GB
Disco: 50GB SSD
```

### Software Necesario

```bash
# Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Verificar instalación
docker --version
docker-compose --version
```

---

## 🏗️ Arquitectura Docker

```
┌─────────────────────────────────────┐
│         Docker Host (VM)            │
│                                     │
│  ┌─────────────────────────────┐   │
│  │  hybridscan-frontend        │   │
│  │  (Nginx + React Build)      │   │
│  │  Puerto: 80, 443            │   │
│  └─────────────┬───────────────┘   │
│                │ proxy_pass         │
│                ↓                    │
│  ┌─────────────────────────────┐   │
│  │  hybridscan-backend         │   │
│  │  (FastAPI + ML + SAST)      │   │
│  │  Puerto: 8000 (interno)     │   │
│  └─────────────┬───────────────┘   │
│                │                    │
│                ↓                    │
│  ┌─────────────────────────────┐   │
│  │  Volumes Persistentes       │   │
│  │  - database/                │   │
│  │  - reports/                 │   │
│  │  - uploads/                 │   │
│  └─────────────────────────────┘   │
└─────────────────────────────────────┘
```

---

## 📦 Despliegue Rápido

### Opción 1: Script Automatizado (Recomendado)

```bash
# 1. Clonar repositorio
git clone https://github.com/OscarILS/HybridSecScan.git
cd HybridSecScan

# 2. Dar permisos al script
chmod +x deploy.sh

# 3. Ejecutar despliegue
./deploy.sh
```

### Opción 2: Manual con Docker Compose

```bash
# 1. Clonar repositorio
git clone https://github.com/OscarILS/HybridSecScan.git
cd HybridSecScan

# 2. Crear directorios
mkdir -p database reports uploads

# 3. Build de imágenes
docker-compose build

# 4. Iniciar servicios
docker-compose up -d

# 5. Verificar estado
docker-compose ps
docker-compose logs -f
```

---

## 🔧 Configuración Avanzada

### Variables de Entorno

Crear archivo `.env` en la raíz del proyecto:

```bash
# Backend Configuration
ENVIRONMENT=production
DATABASE_URL=sqlite:///./database/hybridsecscan.db
MAX_UPLOAD_SIZE=100MB

# CORS Origins (agregar tu dominio)
CORS_ORIGINS=http://localhost,https://hybridscan.empresa.com

# Security
SECRET_KEY=tu_secret_key_aleatorio_aqui

# Limites de recursos
MAX_WORKERS=2
REQUEST_TIMEOUT=300
```

### Modificar `docker-compose.yml`:

```yaml
services:
  backend:
    env_file:
      - .env
    environment:
      - SECRET_KEY=${SECRET_KEY}
```

---

## 🌐 Configuración de Red Empresarial

### En pfSense

#### 1. Port Forwarding

```
Firewall → NAT → Port Forward
┌──────────────────────────────────┐
│ Interface:      WAN              │
│ Protocol:       TCP              │
│ Dest. Port:     80, 443          │
│ Redirect IP:    192.168.1.100    │ ← IP de tu VM
│ Redirect Port:  80, 443          │
│ Description:    HybridSecScan    │
└──────────────────────────────────┘
```

#### 2. Firewall Rule

```
Firewall → Rules → WAN
┌──────────────────────────────────┐
│ Action:         Pass             │
│ Protocol:       TCP              │
│ Source:         Any              │
│ Destination:    Single host      │
│                 192.168.1.100    │
│ Dest. Port:     80, 443          │
└──────────────────────────────────┘
```

### DNS Interno (pfSense)

```
Services → DNS Resolver → Host Overrides
┌──────────────────────────────────┐
│ Host:           hybridscan       │
│ Domain:         empresa.local    │
│ IP Address:     192.168.1.100    │
│ Description:    Security Scanner │
└──────────────────────────────────┘
```

---

## 🔒 HTTPS con Let's Encrypt

### Opción 1: Certbot en el Host

```bash
# Instalar Certbot
sudo apt install certbot

# Detener contenedores temporalmente
docker-compose down

# Obtener certificado
sudo certbot certonly --standalone -d hybridscan.empresa.com

# Certificados estarán en:
# /etc/letsencrypt/live/hybridscan.empresa.com/fullchain.pem
# /etc/letsencrypt/live/hybridscan.empresa.com/privkey.pem
```

### Modificar `docker-compose.yml`:

```yaml
services:
  frontend:
    volumes:
      - /etc/letsencrypt:/etc/letsencrypt:ro
```

### Actualizar `nginx.conf`:

```nginx
server {
    listen 443 ssl http2;
    server_name hybridscan.empresa.com;

    ssl_certificate /etc/letsencrypt/live/hybridscan.empresa.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/hybridscan.empresa.com/privkey.pem;
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # ... resto de la configuración
}

# Redirect HTTP → HTTPS
server {
    listen 80;
    server_name hybridscan.empresa.com;
    return 301 https://$server_name$request_uri;
}
```

---

## 📊 Monitoreo y Logs

### Ver Logs en Tiempo Real

```bash
# Todos los servicios
docker-compose logs -f

# Solo backend
docker-compose logs -f backend

# Solo frontend
docker-compose logs -f frontend

# Últimas 100 líneas
docker-compose logs --tail=100
```

### Health Checks

```bash
# Estado de contenedores
docker-compose ps

# Health status
docker inspect hybridscan-backend | grep -A 5 Health
docker inspect hybridscan-frontend | grep -A 5 Health

# Test manual
curl http://localhost/api/health
```

### Monitoreo con Portainer (Opcional)

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

Acceder a: `http://servidor-ip:9000`

---

## 🔄 Mantenimiento

### Actualizar la Aplicación

```bash
# 1. Pull últimos cambios
git pull origin main

# 2. Rebuild
docker-compose build --no-cache

# 3. Reiniciar servicios
docker-compose down
docker-compose up -d

# 4. Verificar
docker-compose ps
```

### Backup de Base de Datos

```bash
# Backup manual
cp database/hybridsecscan.db database/hybridsecscan_backup_$(date +%Y%m%d).db

# Backup automático (cron)
crontab -e
# Agregar línea:
0 2 * * * cd /opt/HybridSecScan && cp database/hybridsecscan.db database/backup_$(date +\%Y\%m\%d).db
```

### Limpieza de Espacio

```bash
# Limpiar contenedores detenidos
docker container prune -f

# Limpiar imágenes no usadas
docker image prune -a -f

# Limpiar volúmenes no usados
docker volume prune -f

# Limpieza completa del sistema
docker system prune -a --volumes -f
```

---

## 🐛 Troubleshooting

### Contenedor no inicia

```bash
# Ver logs de error
docker-compose logs backend

# Inspeccionar contenedor
docker inspect hybridscan-backend

# Entrar al contenedor
docker exec -it hybridscan-backend /bin/bash
```

### Error de permisos en volumes

```bash
# Dar permisos a directorios
sudo chown -R 1000:1000 database reports uploads
sudo chmod -R 755 database reports uploads
```

### Puerto 80 ocupado

```bash
# Ver qué está usando el puerto
sudo netstat -tulpn | grep :80

# Detener servicio conflictivo (ej: Apache)
sudo systemctl stop apache2
sudo systemctl disable apache2
```

### Base de datos corrupta

```bash
# Restaurar desde backup
docker-compose down
cp database/hybridsecscan_backup_FECHA.db database/hybridsecscan.db
docker-compose up -d
```

---

## 📈 Escalabilidad

### Aumentar Workers del Backend

```yaml
# docker-compose.yml
services:
  backend:
    command: ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
    deploy:
      resources:
        limits:
          cpus: '4.0'
          memory: 4G
```

### Load Balancer con Nginx

Para múltiples instancias del backend:

```yaml
services:
  backend-1:
    # ... config backend
  backend-2:
    # ... config backend
  
  nginx-lb:
    image: nginx:alpine
    volumes:
      - ./nginx-lb.conf:/etc/nginx/nginx.conf
    depends_on:
      - backend-1
      - backend-2
```

---

## 🎯 Checklist de Producción

- [ ] Firewall configurado (puertos 80, 443)
- [ ] HTTPS con certificado válido
- [ ] DNS apuntando al servidor
- [ ] Backups automáticos configurados
- [ ] Monitoring activo (logs, health checks)
- [ ] Variables de entorno en `.env`
- [ ] Recursos adecuados (CPU/RAM)
- [ ] Límites de rate-limiting (Nginx)
- [ ] Autenticación implementada (si es necesario)
- [ ] Documentación entregada al equipo

---

## 📞 Soporte

- **Repositorio**: https://github.com/OscarILS/HybridSecScan
- **Issues**: https://github.com/OscarILS/HybridSecScan/issues
- **Documentación**: `/docs`

---

**Versión**: 1.0.0  
**Última actualización**: Diciembre 2025  
**Autor**: Oscar ILS

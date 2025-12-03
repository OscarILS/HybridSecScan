#!/bin/bash
###############################################################################
# HybridSecScan - Comandos Rápidos de Docker
# Copia estos comandos para uso diario
###############################################################################

# ==========================================
# COMANDOS DE DESPLIEGUE
# ==========================================

# Despliegue inicial
docker-compose up -d --build

# Despliegue rápido (sin rebuild)
docker-compose up -d

# Detener servicios
docker-compose down

# Detener y eliminar volúmenes
docker-compose down -v

# ==========================================
# MONITOREO
# ==========================================

# Ver logs en tiempo real (todos los servicios)
docker-compose logs -f

# Logs solo del backend
docker-compose logs -f backend

# Logs solo del frontend
docker-compose logs -f frontend

# Últimas 100 líneas de logs
docker-compose logs --tail=100

# Ver estado de contenedores
docker-compose ps

# Ver recursos (CPU, RAM)
docker stats hybridscan-backend hybridscan-frontend

# Health check manual
curl http://localhost/api/health

# ==========================================
# DEBUGGING
# ==========================================

# Entrar al contenedor backend
docker-compose exec backend /bin/bash

# Entrar al contenedor frontend
docker-compose exec frontend /bin/sh

# Ver variables de entorno del backend
docker-compose exec backend env

# Inspeccionar contenedor
docker inspect hybridscan-backend

# Ver logs de errores
docker-compose logs backend | grep -i error
docker-compose logs backend | grep -i exception

# ==========================================
# REINICIO Y ACTUALIZACIÓN
# ==========================================

# Reiniciar todos los servicios
docker-compose restart

# Reiniciar solo backend
docker-compose restart backend

# Rebuild y reiniciar
docker-compose up -d --build --force-recreate

# Pull últimos cambios y rebuild
git pull origin main
docker-compose down
docker-compose build --no-cache
docker-compose up -d

# ==========================================
# BACKUP Y RESTAURACIÓN
# ==========================================

# Backup de base de datos
cp database/hybridsecscan.db database/backup_$(date +%Y%m%d_%H%M%S).db

# Backup completo (BD + Reports)
tar -czf backup_$(date +%Y%m%d_%H%M%S).tar.gz database/ reports/

# Restaurar desde backup
docker-compose down
cp database/backup_FECHA.db database/hybridsecscan.db
docker-compose up -d

# ==========================================
# LIMPIEZA
# ==========================================

# Limpiar contenedores detenidos
docker container prune -f

# Limpiar imágenes no usadas
docker image prune -a -f

# Limpiar volúmenes no usados
docker volume prune -f

# Limpieza completa del sistema
docker system prune -a --volumes -f

# Limpiar solo imágenes de HybridSecScan
docker rmi $(docker images | grep hybridscan | awk '{print $3}')

# ==========================================
# TESTING
# ==========================================

# Test del backend (dentro del contenedor)
docker-compose exec backend python -m pytest tests/

# Test de conectividad
curl -f http://localhost/ || echo "Frontend FAILED"
curl -f http://localhost/api/health || echo "Backend FAILED"
curl -f http://localhost/api/docs || echo "API Docs FAILED"

# ==========================================
# INFORMACIÓN DEL SISTEMA
# ==========================================

# Ver imágenes de HybridSecScan
docker images | grep hybridscan

# Ver volúmenes de HybridSecScan
docker volume ls | grep hybridscan

# Ver redes de Docker
docker network ls | grep hybridscan

# Tamaño de imágenes
docker images hybridscan-backend --format "{{.Repository}}:{{.Tag}} - {{.Size}}"
docker images hybridscan-frontend --format "{{.Repository}}:{{.Tag}} - {{.Size}}"

# Información detallada del contenedor
docker inspect hybridscan-backend | jq '.[0].Config.Env'
docker inspect hybridscan-backend | jq '.[0].State.Health'

# ==========================================
# OPERACIONES AVANZADAS
# ==========================================

# Escalar backend a 4 workers
# Editar docker-compose.yml: --workers 4
docker-compose up -d --build backend

# Ver logs filtrados por fecha
docker-compose logs --since 2h backend

# Seguir logs de un proceso específico dentro del contenedor
docker-compose exec backend tail -f /var/log/uvicorn.log

# Copiar archivo desde contenedor al host
docker cp hybridscan-backend:/app/database/hybridsecscan.db ./local_backup.db

# Copiar archivo desde host al contenedor
docker cp local_file.txt hybridscan-backend:/app/

# Ejecutar comando único en contenedor
docker-compose exec backend python -c "print('Hello from container')"

# Ver procesos dentro del contenedor
docker-compose exec backend ps aux

# ==========================================
# SEGURIDAD
# ==========================================

# Escanear vulnerabilidades en imagen
docker scan hybridscan-backend
docker scan hybridscan-frontend

# Ver puertos expuestos
docker-compose ps --format json | jq '.[] | {name: .Name, ports: .Ports}'

# Verificar usuario que ejecuta el proceso
docker-compose exec backend whoami

# ==========================================
# PERFORMANCE
# ==========================================

# Ver uso de disco por contenedor
docker system df -v

# Ver estadísticas de red
docker stats --no-stream --format "table {{.Name}}\t{{.NetIO}}"

# Benchmark de inicio
time docker-compose up -d

# Ver tiempo de respuesta de la API
time curl -w "@curl-format.txt" -o /dev/null -s http://localhost/api/health

# ==========================================
# AUTOMATIZACIÓN CON CRON
# ==========================================

# Agregar a crontab para backup automático diario a las 2 AM
# crontab -e
# 0 2 * * * cd /opt/HybridSecScan && cp database/hybridsecscan.db database/backup_$(date +\%Y\%m\%d).db

# Agregar a crontab para limpiar reportes antiguos (>30 días)
# 0 3 * * * cd /opt/HybridSecScan && find reports/ -mtime +30 -delete

# Agregar a crontab para reiniciar contenedores semanalmente
# 0 4 * * 0 cd /opt/HybridSecScan && docker-compose restart

# ==========================================
# TROUBLESHOOTING
# ==========================================

# Si el puerto 80 está ocupado
sudo netstat -tulpn | grep :80
# O cambiar puerto en docker-compose.yml a 8080:80

# Si hay problemas de permisos
sudo chown -R 1000:1000 database/ reports/ uploads/
sudo chmod -R 755 database/ reports/ uploads/

# Si el contenedor no inicia
docker-compose logs backend --tail=50
docker-compose up backend  # Sin -d para ver output directo

# Recrear contenedor desde cero
docker-compose rm -fsv backend
docker-compose up -d backend

# ==========================================
# ALIAS ÚTILES (agregar a ~/.bashrc o ~/.zshrc)
# ==========================================

# alias hscan-start='docker-compose up -d'
# alias hscan-stop='docker-compose down'
# alias hscan-logs='docker-compose logs -f'
# alias hscan-restart='docker-compose restart'
# alias hscan-ps='docker-compose ps'
# alias hscan-backend='docker-compose exec backend /bin/bash'
# alias hscan-frontend='docker-compose exec frontend /bin/sh'

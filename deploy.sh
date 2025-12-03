#!/bin/bash

###############################################################################
# Script de Despliegue de HybridSecScan en Servidor Empresarial
# Autor: Oscar ILS
# Fecha: Diciembre 2025
# Descripción: Automatiza el despliegue completo con Docker Compose
###############################################################################

set -e  # Exit on error

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Función para logging
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Banner
echo -e "${BLUE}"
cat << "EOF"
╦ ╦┬ ┬┌┐ ┬─┐┬┌┬┐╔═╗┌─┐┌─┐╔═╗┌─┐┌─┐┌┐┌
╠═╣└┬┘├┴┐├┬┘│ ││╚═╗├┤ │  ╚═╗│  ├─┤│││
╩ ╩ ┴ └─┘┴└─┴─┴┘╚═╝└─┘└─┘╚═╝└─┘┴ ┴┘└┘
    Deployment Script v1.0
EOF
echo -e "${NC}"

# Verificar que Docker está instalado
log_info "Verificando Docker..."
if ! command -v docker &> /dev/null; then
    log_error "Docker no está instalado. Por favor instala Docker primero."
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    log_error "Docker Compose no está instalado. Por favor instala Docker Compose primero."
    exit 1
fi
log_success "Docker encontrado: $(docker --version)"

# Verificar que estamos en el directorio correcto
if [ ! -f "docker-compose.yml" ]; then
    log_error "No se encontró docker-compose.yml. Asegúrate de estar en el directorio raíz del proyecto."
    exit 1
fi

# Crear directorios necesarios
log_info "Creando directorios necesarios..."
mkdir -p database reports uploads
chmod 755 database reports uploads
log_success "Directorios creados"

# Detener contenedores existentes
log_info "Deteniendo contenedores existentes..."
docker-compose down 2>/dev/null || true

# Limpiar imágenes antiguas (opcional)
read -p "¿Deseas limpiar imágenes Docker antiguas? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    log_info "Limpiando imágenes antiguas..."
    docker system prune -f
    log_success "Limpieza completada"
fi

# Build de las imágenes
log_info "Construyendo imágenes Docker..."
docker-compose build --no-cache

log_success "Imágenes construidas exitosamente"

# Iniciar servicios
log_info "Iniciando servicios..."
docker-compose up -d

# Esperar a que los servicios estén listos
log_info "Esperando a que los servicios estén listos..."
sleep 10

# Verificar estado de los servicios
log_info "Verificando estado de los servicios..."
docker-compose ps

# Health checks
log_info "Ejecutando health checks..."
sleep 5

BACKEND_HEALTH=$(docker inspect --format='{{.State.Health.Status}}' hybridscan-backend 2>/dev/null || echo "unknown")
FRONTEND_HEALTH=$(docker inspect --format='{{.State.Health.Status}}' hybridscan-frontend 2>/dev/null || echo "unknown")

if [ "$BACKEND_HEALTH" = "healthy" ] || [ "$BACKEND_HEALTH" = "starting" ]; then
    log_success "Backend: $BACKEND_HEALTH"
else
    log_warning "Backend: $BACKEND_HEALTH (puede tardar hasta 40 segundos)"
fi

if [ "$FRONTEND_HEALTH" = "healthy" ] || [ "$FRONTEND_HEALTH" = "starting" ]; then
    log_success "Frontend: $FRONTEND_HEALTH"
else
    log_warning "Frontend: $FRONTEND_HEALTH"
fi

# Mostrar información de despliegue
echo ""
log_success "=================================="
log_success "  DESPLIEGUE COMPLETADO"
log_success "=================================="
echo ""
log_info "URLs de acceso:"
echo "  🌐 Frontend:  http://localhost"
echo "  🔧 API Docs:  http://localhost/api/docs"
echo "  ❤️  Health:   http://localhost/api/health"
echo ""
log_info "Comandos útiles:"
echo "  Ver logs:          docker-compose logs -f"
echo "  Reiniciar:         docker-compose restart"
echo "  Detener:           docker-compose down"
echo "  Estado:            docker-compose ps"
echo ""
log_info "Archivos persistentes:"
echo "  📊 Base de datos:  ./database/hybridsecscan.db"
echo "  📄 Reportes:       ./reports/"
echo "  📁 Uploads:        ./uploads/"
echo ""

# Mostrar logs en tiempo real (opcional)
read -p "¿Deseas ver los logs en tiempo real? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    docker-compose logs -f
fi

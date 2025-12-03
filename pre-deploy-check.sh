#!/bin/bash
###############################################################################
# Pre-Deployment Checker for HybridSecScan
# Verifica que todos los requisitos estén cumplidos antes del despliegue
###############################################################################

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════╗"
echo "║   HybridSecScan Pre-Deployment Check     ║"
echo "╚═══════════════════════════════════════════╝"
echo -e "${NC}"

ERRORS=0
WARNINGS=0

# Función para checks
check_pass() {
    echo -e "${GREEN}[✓]${NC} $1"
}

check_fail() {
    echo -e "${RED}[✗]${NC} $1"
    ((ERRORS++))
}

check_warn() {
    echo -e "${YELLOW}[!]${NC} $1"
    ((WARNINGS++))
}

check_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

echo ""
echo "═════════════════════════════════════════════"
echo "1. Verificando Sistema Operativo"
echo "═════════════════════════════════════════════"

OS=$(uname -s)
check_info "Sistema Operativo: $OS"

if [[ "$OS" == "Linux" ]]; then
    check_pass "Linux detectado"
    DISTRO=$(lsb_release -is 2>/dev/null || echo "Desconocido")
    check_info "Distribución: $DISTRO"
elif [[ "$OS" == "Darwin" ]]; then
    check_pass "macOS detectado"
else
    check_warn "Sistema operativo no reconocido: $OS"
fi

echo ""
echo "═════════════════════════════════════════════"
echo "2. Verificando Docker"
echo "═════════════════════════════════════════════"

if command -v docker &> /dev/null; then
    DOCKER_VERSION=$(docker --version | awk '{print $3}' | tr -d ',')
    check_pass "Docker instalado: $DOCKER_VERSION"
    
    # Verificar que Docker está corriendo
    if docker ps &> /dev/null; then
        check_pass "Docker daemon está corriendo"
    else
        check_fail "Docker daemon no está corriendo. Ejecuta: sudo systemctl start docker"
    fi
    
    # Verificar permisos de Docker
    if docker ps &> /dev/null 2>&1; then
        check_pass "Usuario tiene permisos para usar Docker"
    else
        check_warn "Usuario no está en el grupo docker. Ejecuta: sudo usermod -aG docker $USER"
    fi
else
    check_fail "Docker no está instalado. Instala desde: https://docs.docker.com/get-docker/"
fi

echo ""
echo "═════════════════════════════════════════════"
echo "3. Verificando Docker Compose"
echo "═════════════════════════════════════════════"

if command -v docker-compose &> /dev/null; then
    COMPOSE_VERSION=$(docker-compose --version | awk '{print $4}' | tr -d ',')
    check_pass "Docker Compose (standalone) instalado: $COMPOSE_VERSION"
elif docker compose version &> /dev/null 2>&1; then
    COMPOSE_VERSION=$(docker compose version --short)
    check_pass "Docker Compose (plugin) instalado: $COMPOSE_VERSION"
else
    check_fail "Docker Compose no está instalado"
fi

echo ""
echo "═════════════════════════════════════════════"
echo "4. Verificando Archivos del Proyecto"
echo "═════════════════════════════════════════════"

FILES=(
    "Dockerfile.backend"
    "Dockerfile.frontend"
    "docker-compose.yml"
    "nginx.conf"
    ".dockerignore"
    "backend/main.py"
    "frontend/package.json"
    "requirements.txt"
)

for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        check_pass "Archivo encontrado: $file"
    else
        check_fail "Archivo faltante: $file"
    fi
done

echo ""
echo "═════════════════════════════════════════════"
echo "5. Verificando Directorios Necesarios"
echo "═════════════════════════════════════════════"

DIRS=("database" "reports" "uploads")

for dir in "${DIRS[@]}"; do
    if [ -d "$dir" ]; then
        check_pass "Directorio existe: $dir"
        
        # Verificar permisos
        if [ -w "$dir" ]; then
            check_pass "Directorio tiene permisos de escritura: $dir"
        else
            check_warn "Directorio sin permisos de escritura: $dir"
        fi
    else
        check_warn "Directorio no existe (se creará): $dir"
    fi
done

echo ""
echo "═════════════════════════════════════════════"
echo "6. Verificando Puertos Disponibles"
echo "═════════════════════════════════════════════"

PORTS=(80 443 8000)

for port in "${PORTS[@]}"; do
    if command -v netstat &> /dev/null; then
        if netstat -tuln | grep -q ":$port "; then
            check_warn "Puerto $port está en uso"
        else
            check_pass "Puerto $port está disponible"
        fi
    elif command -v ss &> /dev/null; then
        if ss -tuln | grep -q ":$port "; then
            check_warn "Puerto $port está en uso"
        else
            check_pass "Puerto $port está disponible"
        fi
    else
        check_info "No se puede verificar puerto $port (netstat/ss no disponible)"
    fi
done

echo ""
echo "═════════════════════════════════════════════"
echo "7. Verificando Recursos del Sistema"
echo "═════════════════════════════════════════════"

# CPU
CPU_CORES=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo "unknown")
if [ "$CPU_CORES" != "unknown" ]; then
    check_info "CPUs disponibles: $CPU_CORES"
    if [ "$CPU_CORES" -ge 2 ]; then
        check_pass "CPU: Suficientes cores ($CPU_CORES >= 2)"
    else
        check_warn "CPU: Se recomiendan al menos 2 cores"
    fi
else
    check_info "No se pudo determinar número de CPUs"
fi

# RAM
if [ -f /proc/meminfo ]; then
    TOTAL_RAM=$(grep MemTotal /proc/meminfo | awk '{print int($2/1024/1024)}')
    check_info "RAM total: ${TOTAL_RAM}GB"
    if [ "$TOTAL_RAM" -ge 4 ]; then
        check_pass "RAM: Suficiente memoria (${TOTAL_RAM}GB >= 4GB)"
    else
        check_warn "RAM: Se recomiendan al menos 4GB (actual: ${TOTAL_RAM}GB)"
    fi
elif command -v sysctl &> /dev/null; then
    TOTAL_RAM=$(sysctl -n hw.memsize 2>/dev/null | awk '{print int($1/1024/1024/1024)}')
    if [ -n "$TOTAL_RAM" ]; then
        check_info "RAM total: ${TOTAL_RAM}GB"
        if [ "$TOTAL_RAM" -ge 4 ]; then
            check_pass "RAM: Suficiente memoria (${TOTAL_RAM}GB >= 4GB)"
        else
            check_warn "RAM: Se recomiendan al menos 4GB (actual: ${TOTAL_RAM}GB)"
        fi
    fi
fi

# Disco
DISK_FREE=$(df -BG . | awk 'NR==2 {print int($4)}')
check_info "Espacio libre en disco: ${DISK_FREE}GB"
if [ "$DISK_FREE" -ge 20 ]; then
    check_pass "Disco: Suficiente espacio (${DISK_FREE}GB >= 20GB)"
else
    check_warn "Disco: Se recomiendan al menos 20GB libres (actual: ${DISK_FREE}GB)"
fi

echo ""
echo "═════════════════════════════════════════════"
echo "8. Verificando Variables de Entorno"
echo "═════════════════════════════════════════════"

if [ -f ".env" ]; then
    check_pass "Archivo .env encontrado"
    
    # Verificar variables críticas
    if grep -q "SECRET_KEY" .env; then
        SECRET_KEY=$(grep "SECRET_KEY" .env | cut -d'=' -f2)
        if [ "$SECRET_KEY" = "CHANGE_THIS_TO_RANDOM_SECRET_KEY" ]; then
            check_warn "SECRET_KEY no ha sido cambiado"
        else
            check_pass "SECRET_KEY está configurado"
        fi
    else
        check_warn "SECRET_KEY no encontrado en .env"
    fi
    
    if grep -q "CORS_ORIGINS" .env; then
        check_pass "CORS_ORIGINS está configurado"
    else
        check_warn "CORS_ORIGINS no encontrado en .env"
    fi
else
    check_warn "Archivo .env no encontrado. Copia .env.example a .env"
fi

echo ""
echo "═════════════════════════════════════════════"
echo "9. Verificando Git (opcional)"
echo "═════════════════════════════════════════════"

if command -v git &> /dev/null; then
    check_pass "Git instalado: $(git --version | awk '{print $3}')"
    
    if [ -d .git ]; then
        check_pass "Repositorio Git inicializado"
        
        # Verificar cambios sin commitear
        if git diff-index --quiet HEAD -- 2>/dev/null; then
            check_pass "No hay cambios sin commitear"
        else
            check_info "Hay cambios sin commitear"
        fi
    else
        check_info "No es un repositorio Git"
    fi
else
    check_info "Git no está instalado (no es crítico)"
fi

echo ""
echo "═════════════════════════════════════════════"
echo "10. Verificando Firewall (opcional)"
echo "═════════════════════════════════════════════"

if command -v ufw &> /dev/null; then
    UFW_STATUS=$(sudo ufw status 2>/dev/null | head -1)
    check_info "UFW: $UFW_STATUS"
elif command -v firewall-cmd &> /dev/null; then
    check_info "Firewalld detectado"
else
    check_info "No se detectó firewall UFW/Firewalld"
fi

echo ""
echo "═════════════════════════════════════════════"
echo "RESUMEN"
echo "═════════════════════════════════════════════"

if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}✓ Sin errores críticos${NC}"
else
    echo -e "${RED}✗ Errores encontrados: $ERRORS${NC}"
fi

if [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}✓ Sin advertencias${NC}"
else
    echo -e "${YELLOW}! Advertencias: $WARNINGS${NC}"
fi

echo ""

if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ✓ LISTO PARA DESPLIEGUE                 ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════╝${NC}"
    echo ""
    echo "Ejecuta: ./deploy.sh"
    exit 0
else
    echo -e "${RED}╔═══════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  ✗ CORRIGE LOS ERRORES ANTES DE CONTINUAR║${NC}"
    echo -e "${RED}╚═══════════════════════════════════════════╝${NC}"
    exit 1
fi

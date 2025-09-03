#!/bin/bash

# HybridSecScan - Sistema de Auditoría Híbrida SAST+DAST+ML
# Script de inicialización y ejecución con validaciones de seguridad
# Versión: 2.0 - Implementación corregida según evaluación técnica

set -e  # Salir en caso de error

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # Sin color

echo -e "${BOLD}${BLUE}"
echo "════════════════════════════════════════════════════════════════"
echo "                    HybridSecScan v2.0                         "
echo "      Sistema de Auditoría Híbrida SAST+DAST+ML              "
echo "                                                               "
echo "  Análisis estático (SAST): Bandit, Semgrep               "
echo "  Análisis dinámico (DAST): OWASP ZAP                     " 
echo "  Correlación ML: Random Forest con validación            "
echo "  Enfoque: OWASP API Top 10 Security Risks               "
echo "                                                               "
echo "  Correcciones aplicadas según comité evaluador:               "
echo "  Inicialización ML corregida                              "
echo "  Prevención path traversal                                "
echo "  Validación segura de archivos                            "
echo "  Logging estructurado completo                            "
echo "  Tests automatizados                                      "
echo "════════════════════════════════════════════════════════════════"
echo -e "${NC}"

echo -e "${YELLOW}Verificando prerrequisitos del sistema...${NC}"

# Función para verificar comandos
check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}Error: $1 no está instalado${NC}"
        echo -e "${YELLOW}Instalar con: $2${NC}"
        return 1
    else
        echo -e "${GREEN}$1 encontrado${NC}"
        return 0
    fi
}

# Verificar Python 3.11+
if ! python3 --version | grep -E "Python 3\.(11|12|13)" > /dev/null; then
    echo -e "${RED}Se requiere Python 3.11 o superior${NC}"
    exit 1
fi
echo -e "${GREEN}Python $(python3 --version | cut -d' ' -f2) encontrado${NC}"

# Verificar pip
check_command "pip3" "curl https://bootstrap.pypa.io/get-pip.py | python3"

# Verificar Node.js (para frontend)
if ! command -v node &> /dev/null; then
    echo -e "${YELLOW}Node.js no encontrado - solo backend disponible${NC}"
    FRONTEND_AVAILABLE=false
else
    echo -e "${GREEN}Node.js $(node --version) encontrado${NC}"
    FRONTEND_AVAILABLE=true
fi

echo ""
echo -e "${YELLOW}Creando estructura de directorios del sistema...${NC}"

# Crear directorios necesarios
mkdir -p reports uploads logs models tests/temp backend/temp
echo -e "${GREEN}Directorios del sistema creados${NC}"

echo ""
echo -e "${YELLOW}Instalando dependencias de Python...${NC}"

# Instalar dependencias Python de forma segura
if pip3 install -r requirements.txt --user --upgrade; then
    echo -e "${GREEN}Dependencias de Python instaladas${NC}"
else
    echo -e "${RED}Error instalando dependencias de Python${NC}"
    echo -e "${YELLOW}Intentando instalación individual de paquetes críticos...${NC}"
    
    # Instalar paquetes críticos individualmente
    CRITICAL_PACKAGES=("fastapi" "uvicorn" "sqlalchemy" "scikit-learn" "pandas" "numpy")
    for package in "${CRITICAL_PACKAGES[@]}"; do
        pip3 install "$package" --user --upgrade || echo -e "${YELLOW}No se pudo instalar $package${NC}"
    done
fi

echo ""
echo -e "${YELLOW}Instalando herramientas de seguridad opcionales...${NC}"

# Verificar herramientas SAST
if ! command -v bandit &> /dev/null; then
    echo -e "${YELLOW}Instalando Bandit...${NC}"
    pip3 install bandit --user
fi

# Semgrep (opcional)
if ! command -v semgrep &> /dev/null; then
    echo -e "${YELLOW}Semgrep no encontrado. Para instalarlo:${NC}"
    echo -e "${BLUE}   python3 -m pip install semgrep${NC}"
    echo -e "${BLUE}   O visite: https://semgrep.dev/docs/getting-started/${NC}"
else
    echo -e "${GREEN}Semgrep encontrado${NC}"
fi

# OWASP ZAP (opcional para DAST)
if ! command -v zap-cli &> /dev/null; then
    echo -e "${YELLOW}OWASP ZAP CLI no encontrado. Para DAST completo instale ZAP:${NC}"
    echo -e "${BLUE}   https://www.zaproxy.org/download/${NC}"
else
    echo -e "${GREEN}OWASP ZAP CLI encontrado${NC}"
fi

echo ""
echo -e "${YELLOW}Inicializando base de datos SQLite...${NC}"

# Inicializar base de datos SQLite
python3 -c "
import sys, os
sys.path.insert(0, 'backend')
sys.path.insert(0, 'database')
try:
    from main import engine, Base
    Base.metadata.create_all(bind=engine)
    print('Base de datos inicializada correctamente')
except Exception as e:
    print(f'Error inicializando base de datos: {e}')
    exit(1)
"

echo ""
echo -e "${YELLOW}Ejecutando tests de seguridad...${NC}"

# Ejecutar tests si pytest está disponible
if command -v pytest &> /dev/null; then
    if [ -f "tests/test_security_validations.py" ]; then
        echo -e "${BLUE}Ejecutando suite de tests de seguridad...${NC}"
        python3 -m pytest tests/test_security_validations.py -v --tb=short || {
            echo -e "${YELLOW}Algunos tests fallaron - el sistema seguirá funcionando${NC}"
        }
    else
        echo -e "${YELLOW}Archivo de tests no encontrado${NC}"
    fi
else
    echo -e "${YELLOW}pytest no encontrado. Para ejecutar tests: pip3 install pytest${NC}"
fi

echo ""
echo -e "${YELLOW}Iniciando servicios del sistema...${NC}"

# Función para limpiar procesos al salir
cleanup() {
    echo -e "\n${YELLOW}Limpiando procesos...${NC}"
    
    # Matar procesos del backend
    if [[ -n "$BACKEND_PID" ]]; then
        kill $BACKEND_PID 2>/dev/null || true
        echo -e "${GREEN}Backend detenido${NC}"
    fi
    
    # Matar procesos del frontend
    if [[ -n "$FRONTEND_PID" ]] && [[ "$FRONTEND_AVAILABLE" == true ]]; then
        kill $FRONTEND_PID 2>/dev/null || true
        echo -e "${GREEN}Frontend detenido${NC}"
    fi
    
    # Limpiar archivos temporales
    find backend/temp tests/temp -type f -delete 2>/dev/null || true
    echo -e "${GREEN}Archivos temporales limpiados${NC}"
    
    echo -e "${BOLD}${GREEN}HybridSecScan detenido correctamente${NC}"
}

# Registrar función de limpieza
trap cleanup EXIT INT TERM

# Iniciar backend
echo -e "${BLUE}Iniciando servicio backend FastAPI en puerto 8000...${NC}"
cd backend
python3 -m uvicorn main:app --reload --host 0.0.0.0 --port 8000 --log-level info &
BACKEND_PID=$!
cd ..

# Esperar a que el backend esté listo
echo -e "${YELLOW}Esperando inicialización del backend...${NC}"
sleep 5

# Verificar que el backend funciona
if curl -s http://localhost:8000/health > /dev/null; then
    echo -e "${GREEN}Servicio backend iniciado correctamente${NC}"
    echo -e "${BLUE}API disponible en: http://localhost:8000${NC}"
    echo -e "${BLUE}Documentación API: http://localhost:8000/docs${NC}"
else
    echo -e "${RED}Error: Backend no responde${NC}"
    exit 1
fi

# Iniciar frontend si está disponible
if [[ "$FRONTEND_AVAILABLE" == true ]] && [[ -f "frontend/package.json" ]]; then
    echo -e "${BLUE}Iniciando interfaz de usuario React en puerto 5173...${NC}"
    cd frontend
    
    # Instalar dependencias si es necesario
    if [[ ! -d "node_modules" ]]; then
        echo -e "${YELLOW}Instalando dependencias de Node.js...${NC}"
        npm install || {
            echo -e "${YELLOW}Error instalando dependencias del frontend${NC}"
            cd ..
        }
    fi
    
    if [[ -d "node_modules" ]]; then
        npm run dev &
        FRONTEND_PID=$!
        cd ..
        
        sleep 3
        echo -e "${GREEN}Servicio frontend iniciado${NC}"
        echo -e "${BLUE}Dashboard disponible en: http://localhost:5173${NC}"
    fi
else
    echo -e "${YELLOW}Frontend no disponible - solo API REST${NC}"
fi

echo ""
echo -e "${BOLD}${GREEN}HybridSecScan iniciado correctamente${NC}"
echo ""
echo -e "${BOLD}${BLUE}SERVICIOS DISPONIBLES:${NC}"
echo -e "${GREEN}API REST Backend: http://localhost:8000${NC}"
echo -e "${GREEN}Documentación Swagger: http://localhost:8000/docs${NC}"
if [[ "$FRONTEND_AVAILABLE" == true ]] && [[ -n "$FRONTEND_PID" ]]; then
    echo -e "${GREEN}Dashboard React: http://localhost:5173${NC}"
fi
echo ""
echo -e "${BOLD}${BLUE}EJEMPLOS DE USO:${NC}"
echo ""
echo -e "${YELLOW}1. Escaneo SAST (Análisis Estático):${NC}"
echo -e "   curl -X POST 'http://localhost:8000/scan/sast' \\"
echo -e "        -F 'target_path=/path/to/your/code' \\"
echo -e "        -F 'tool=bandit'"
echo ""
echo -e "${YELLOW}2. Subir archivo para análisis:${NC}"
echo -e "   curl -X POST 'http://localhost:8000/upload/' \\"
echo -e "        -F 'file=@your_code.py'"
echo ""
echo -e "${YELLOW}3. Ver resultados de escaneos:${NC}"
echo -e "   curl http://localhost:8000/scan-results"
echo ""
echo -e "${YELLOW}4. Health check:${NC}"
echo -e "   curl http://localhost:8000/health"
echo ""
echo -e "${BOLD}${BLUE}CARACTERÍSTICAS DE SEGURIDAD IMPLEMENTADAS:${NC}"
echo -e "${GREEN}Prevención de ataques path traversal${NC}"
echo -e "${GREEN}Validación segura de tamaño y tipo de archivos${NC}"
echo -e "${GREEN}Sistema de logging estructurado para auditoría${NC}"
echo -e "${GREEN}Correlación ML con Random Forest entrenado${NC}"
echo -e "${GREEN}Suite de tests automatizados de seguridad${NC}"
echo -e "${GREEN}Manejo robusto de errores del sistema${NC}"
echo -e "${GREEN}Metadatos completos en base de datos${NC}"
echo ""
echo -e "${BOLD}${RED}PARA DETENER EL SISTEMA: Presione Ctrl+C${NC}"
echo ""

# Mantener el script corriendo hasta que el usuario lo detenga
wait

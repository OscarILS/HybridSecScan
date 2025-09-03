#!/bin/bash

# HybridSecScan - Script de instalación y configuración del sistema
# Configura el entorno completo para análisis de seguridad híbrido
# Uso: bash setup.sh

set -e

echo "Configurando HybridSecScan - Sistema de Auditoría Híbrida..."

# Verificar Python
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 no está instalado. Instale Python 3.11 o superior."
    exit 1
fi

# Verificar Node.js
if ! command -v node &> /dev/null; then
    echo "Error: Node.js no está instalado. Instale Node.js para el frontend."
    exit 1
fi

# Crear entorno virtual Python
echo "Creando entorno virtual aislado de Python..."
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias Python
echo "Instalando dependencias de Python en entorno aislado..."
pip install --upgrade pip
pip install -r requirements.txt

# Instalar herramientas SAST adicionales si no están ya instaladas
echo "Instalando herramientas de análisis estático de seguridad..."
pip install semgrep || echo "Advertencia: Semgrep ya instalado o error en instalación"

# Configurar frontend
echo "Configurando interfaz de usuario frontend..."
cd frontend
npm install
cd ..

# Crear base de datos
echo "Inicializando esquema de base de datos..."
cd backend
python -c "from main import engine, Base; Base.metadata.create_all(bind=engine); print('Base de datos creada correctamente')"
cd ..

# Verificar instalación
echo "Verificando instalación del sistema..."
echo "Python: $(python3 --version)"
echo "Node.js: $(node --version)"
echo "Bandit: $(python -m bandit --version 2>/dev/null || echo 'No instalado')"
echo "Semgrep: $(semgrep --version 2>/dev/null || echo 'No instalado')"

echo ""
echo "Instalación completada exitosamente."
echo ""
echo "Para iniciar la aplicación:"
echo "1. Backend:  cd backend && uvicorn main:app --reload"
echo "2. Frontend: cd frontend && npm run dev"
echo ""
echo "Luego acceda a: http://localhost:5173"

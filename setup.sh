#!/bin/bash

# Script de instalación y configuración de HybridSecScan
# Uso: bash setup.sh

set -e

echo "🔧 Configurando HybridSecScan..."

# Verificar Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 no está instalado. Por favor, instálalo primero."
    exit 1
fi

# Verificar Node.js
if ! command -v node &> /dev/null; then
    echo "❌ Node.js no está instalado. Por favor, instálalo primero."
    exit 1
fi

# Crear entorno virtual Python
echo "📦 Creando entorno virtual Python..."
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias Python
echo "📦 Instalando dependencias Python..."
pip install --upgrade pip
pip install -r requirements.txt

# Instalar herramientas SAST adicionales si no están ya instaladas
echo "🔍 Instalando herramientas SAST..."
pip install semgrep || echo "⚠️  Semgrep ya instalado o error en instalación"

# Configurar frontend
echo "🌐 Configurando frontend..."
cd frontend
npm install
cd ..

# Crear base de datos
echo "💾 Inicializando base de datos..."
cd backend
python -c "from main import engine, Base; Base.metadata.create_all(bind=engine); print('Base de datos creada')"
cd ..

# Verificar instalación
echo "✅ Verificando instalación..."
echo "Python: $(python3 --version)"
echo "Node.js: $(node --version)"
echo "Bandit: $(python -m bandit --version 2>/dev/null || echo 'No instalado')"
echo "Semgrep: $(semgrep --version 2>/dev/null || echo 'No instalado')"

echo ""
echo "🎉 ¡Instalación completada!"
echo ""
echo "Para iniciar la aplicación:"
echo "1. Backend:  cd backend && uvicorn main:app --reload"
echo "2. Frontend: cd frontend && npm run dev"
echo ""
echo "Luego visita: http://localhost:5173"

#!/bin/bash

# Script de prueba y verificación del sistema HybridSecScan
echo "Ejecutando pruebas de funcionalidad del sistema..."

# Activar entorno virtual
source venv/bin/activate

# Probar backend
echo "Verificando servicio backend..."
cd backend
python -c "
import main
print('Backend: Sistema operativo')
from main import engine, Base
try:
    Base.metadata.create_all(bind=engine)
    print('Base de datos: Sistema operativo')
except Exception as e:
    print(f'Base de datos: Error - {e}')
"
cd ..

# Probar herramientas SAST
echo "Verificando herramientas de análisis estático..."
python -m bandit --version > /dev/null 2>&1 && echo "Bandit: Disponible" || echo "Bandit: No disponible"
semgrep --version > /dev/null 2>&1 && echo "Semgrep: Disponible" || echo "Semgrep: No disponible"

# Probar frontend
echo "Verificando interfaz de usuario frontend..."
cd frontend
if [ -d "node_modules" ]; then
    npm run build > /dev/null 2>&1 && echo "Frontend: Sistema operativo" || echo "Frontend: Error en construcción"
else
    echo "Frontend: Dependencias no instaladas (ejecutar 'npm install' en directorio frontend/)"
fi
cd ..

echo ""
echo "Pruebas completadas."
echo "Para iniciar el sistema:"
echo "  Backend:  cd backend && uvicorn main:app --reload"
echo "  Frontend: cd frontend && npm run dev"

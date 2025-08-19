#!/bin/bash

# Script de prueba rápida para HybridSecScan
echo "🧪 Probando HybridSecScan..."

# Activar entorno virtual
source venv/bin/activate

# Probar backend
echo "📡 Probando backend..."
cd backend
python -c "
import main
print('✅ Backend: OK')
from main import engine, Base
try:
    Base.metadata.create_all(bind=engine)
    print('✅ Base de datos: OK')
except Exception as e:
    print(f'❌ Base de datos: {e}')
"
cd ..

# Probar herramientas SAST
echo "🔍 Probando herramientas SAST..."
python -m bandit --version > /dev/null 2>&1 && echo "✅ Bandit: OK" || echo "❌ Bandit: No disponible"
semgrep --version > /dev/null 2>&1 && echo "✅ Semgrep: OK" || echo "❌ Semgrep: No disponible"

# Probar frontend
echo "🌐 Probando frontend..."
cd frontend
if [ -d "node_modules" ]; then
    npm run build > /dev/null 2>&1 && echo "✅ Frontend: OK" || echo "❌ Frontend: Error en build"
else
    echo "⚠️  Frontend: Dependencias no instaladas (ejecuta 'npm install' en frontend/)"
fi
cd ..

echo ""
echo "🎉 Pruebas completadas!"
echo "Para iniciar:"
echo "  Backend:  cd backend && uvicorn main:app --reload"
echo "  Frontend: cd frontend && npm run dev"

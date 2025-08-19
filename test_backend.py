#!/usr/bin/env python3
"""
Script para probar que el backend funciona correctamente
"""

import os
import sys

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_backend():
    print("🧪 Probando backend...")
    
    try:
        # Test database models
        sys.path.append('database')
        from models import Base, ScanResult
        print("✅ Modelos de base de datos cargados")
        
        # Test FastAPI imports
        from fastapi import FastAPI
        from sqlalchemy import create_engine
        print("✅ Dependencias FastAPI disponibles")
        
        # Test backend main
        os.chdir('backend')
        sys.path.insert(0, '.')
        import main
        print("✅ Backend main cargado correctamente")
        
        print("\n🎉 ¡Todas las pruebas pasaron!")
        return True
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

if __name__ == "__main__":
    test_backend()

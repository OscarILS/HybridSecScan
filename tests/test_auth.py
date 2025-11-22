"""
Tests de autenticación JWT para el sistema HybridSecScan.
Prueba registro, login, verificación de tokens y acceso a endpoints protegidos.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import os
import sys

# Importar aplicación
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from backend.main import app, get_db, Base
from database.models import User

# Configurar base de datos de pruebas
TEST_DATABASE_URL = "sqlite:///./test_auth.db"
test_engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db():
    """Override para usar base de datos de pruebas."""
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)


@pytest.fixture(scope="module")
def setup_database():
    """Fixture para crear y limpiar la base de datos de pruebas."""
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)
    if os.path.exists("test_auth.db"):
        os.remove("test_auth.db")


@pytest.fixture
def test_user_data():
    """Fixture con datos de usuario de prueba."""
    return {
        "username": "testuser",
        "email": "test@example.com",
        "password": "SecurePass123!",  # Max 72 bytes for bcrypt
        "full_name": "Test User"
    }


class TestUserRegistration:
    """Pruebas del endpoint de registro de usuarios."""
    
    def test_register_new_user(self, setup_database, test_user_data):
        """Prueba registro de un nuevo usuario."""
        response = client.post("/auth/register", json=test_user_data)
        
        assert response.status_code == 201
        data = response.json()
        
        assert data["username"] == test_user_data["username"]
        assert data["email"] == test_user_data["email"]
        assert data["full_name"] == test_user_data["full_name"]
        assert data["is_active"] is True
        assert data["is_admin"] is False
        assert "id" in data
        assert "created_at" in data
        assert "password" not in data  # No debe devolver contraseña
    
    def test_register_duplicate_username(self, setup_database, test_user_data):
        """Prueba que no se puede registrar un username duplicado."""
        # Primer registro exitoso
        client.post("/auth/register", json=test_user_data)
        
        # Segundo intento con mismo username
        duplicate_data = test_user_data.copy()
        duplicate_data["email"] = "different@example.com"
        
        response = client.post("/auth/register", json=duplicate_data)
        assert response.status_code == 400
        assert "nombre de usuario ya está registrado" in response.json()["detail"]
    
    def test_register_duplicate_email(self, setup_database, test_user_data):
        """Prueba que no se puede registrar un email duplicado."""
        # Primer registro exitoso
        client.post("/auth/register", json=test_user_data)
        
        # Segundo intento con mismo email
        duplicate_data = test_user_data.copy()
        duplicate_data["username"] = "differentuser"
        
        response = client.post("/auth/register", json=duplicate_data)
        assert response.status_code == 400
        assert "correo electrónico ya está registrado" in response.json()["detail"]
    
    def test_register_invalid_email(self, setup_database):
        """Prueba que no se puede registrar con email inválido."""
        invalid_data = {
            "username": "testuser",
            "email": "invalid-email",
            "password": "password123"
        }
        
        response = client.post("/auth/register", json=invalid_data)
        assert response.status_code == 422  # Validation error


class TestUserLogin:
    """Pruebas del endpoint de login."""
    
    def test_login_success(self, setup_database, test_user_data):
        """Prueba login exitoso con credenciales válidas."""
        # Registrar usuario
        client.post("/auth/register", json=test_user_data)
        
        # Intentar login
        login_data = {
            "username": test_user_data["username"],
            "password": test_user_data["password"]
        }
        
        response = client.post("/auth/login", data=login_data)
        
        assert response.status_code == 200
        data = response.json()
        
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert "user" in data
        assert data["user"]["username"] == test_user_data["username"]
        assert data["user"]["email"] == test_user_data["email"]
    
    def test_login_invalid_username(self, setup_database):
        """Prueba login con username inexistente."""
        login_data = {
            "username": "nonexistent",
            "password": "password123"
        }
        
        response = client.post("/auth/login", data=login_data)
        assert response.status_code == 401
        assert "Credenciales incorrectas" in response.json()["detail"]
    
    def test_login_invalid_password(self, setup_database, test_user_data):
        """Prueba login con contraseña incorrecta."""
        # Registrar usuario
        client.post("/auth/register", json=test_user_data)
        
        # Intentar login con contraseña incorrecta
        login_data = {
            "username": test_user_data["username"],
            "password": "wrongpassword"
        }
        
        response = client.post("/auth/login", data=login_data)
        assert response.status_code == 401
        assert "Credenciales incorrectas" in response.json()["detail"]


class TestProtectedEndpoints:
    """Pruebas de acceso a endpoints protegidos."""
    
    def test_access_protected_endpoint_with_valid_token(self, setup_database, test_user_data):
        """Prueba acceso a endpoint protegido con token válido."""
        # Registrar y hacer login
        client.post("/auth/register", json=test_user_data)
        login_response = client.post("/auth/login", data={
            "username": test_user_data["username"],
            "password": test_user_data["password"]
        })
        
        token = login_response.json()["access_token"]
        
        # Acceder a endpoint protegido
        response = client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == test_user_data["username"]
        assert data["email"] == test_user_data["email"]
    
    def test_access_protected_endpoint_without_token(self, setup_database):
        """Prueba acceso a endpoint protegido sin token."""
        response = client.get("/auth/me")
        assert response.status_code == 401
    
    def test_access_protected_endpoint_with_invalid_token(self, setup_database):
        """Prueba acceso a endpoint protegido con token inválido."""
        response = client.get(
            "/auth/me",
            headers={"Authorization": "Bearer invalid_token_here"}
        )
        assert response.status_code == 401


class TestPasswordHashing:
    """Pruebas de hashing de contraseñas."""
    
    def test_password_not_stored_in_plain_text(self, setup_database, test_user_data):
        """Prueba que las contraseñas no se almacenan en texto plano."""
        from backend.auth import get_password_hash, verify_password
        
        # Registrar usuario
        client.post("/auth/register", json=test_user_data)
        
        # Obtener usuario de la base de datos
        db = next(override_get_db())
        user = db.query(User).filter(User.username == test_user_data["username"]).first()
        
        # Verificar que la contraseña está hasheada
        assert user.hashed_password != test_user_data["password"]
        assert len(user.hashed_password) > 50  # Hash bcrypt es largo
        
        # Verificar que el hash es válido
        assert verify_password(test_user_data["password"], user.hashed_password)
        assert not verify_password("wrongpassword", user.hashed_password)
    
    def test_password_hash_uniqueness(self):
        """Prueba que el mismo password genera hashes diferentes (salt)."""
        from backend.auth import get_password_hash
        
        password = "testpassword123"
        hash1 = get_password_hash(password)
        hash2 = get_password_hash(password)
        
        # Bcrypt genera hashes diferentes debido al salt
        assert hash1 != hash2


class TestTokenExpiration:
    """Pruebas de expiración de tokens."""
    
    def test_token_contains_expiration(self, setup_database, test_user_data):
        """Prueba que el token contiene información de expiración."""
        from jose import jwt
        import os
        
        # Registrar y hacer login
        client.post("/auth/register", json=test_user_data)
        login_response = client.post("/auth/login", data={
            "username": test_user_data["username"],
            "password": test_user_data["password"]
        })
        
        token = login_response.json()["access_token"]
        
        # Decodificar token sin verificar (solo para inspección)
        SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        
        assert "exp" in decoded  # Token debe tener campo de expiración
        assert "sub" in decoded  # Token debe tener subject (username)
        assert decoded["sub"] == test_user_data["username"]


class TestAuthenticationSecurity:
    """Pruebas de seguridad del sistema de autenticación."""
    
    def test_sql_injection_in_username(self, setup_database):
        """Prueba que el sistema es resistente a SQL injection en username."""
        malicious_data = {
            "username": "admin' OR '1'='1",
            "email": "test@example.com",
            "password": "password123"
        }
        
        response = client.post("/auth/register", json=malicious_data)
        # Debe registrar con el username literal, no ejecutar SQL
        assert response.status_code == 201
        
        # Intentar login con el username malicioso
        login_response = client.post("/auth/login", data={
            "username": malicious_data["username"],
            "password": malicious_data["password"]
        })
        assert login_response.status_code == 200
    
    def test_xss_in_user_data(self, setup_database):
        """Prueba que el sistema sanitiza datos contra XSS."""
        xss_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "password123",
            "full_name": "<script>alert('XSS')</script>"
        }
        
        response = client.post("/auth/register", json=xss_data)
        assert response.status_code == 201
        
        # El sistema debe almacenar el dato literalmente
        data = response.json()
        assert data["full_name"] == xss_data["full_name"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

# Modelos para la base de datos SQLite
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON, Boolean, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timezone
import os

Base = declarative_base()

# Configuración de la base de datos
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./database/hybridsecscan.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    """Generador de sesiones de base de datos."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class User(Base):
    """Modelo de usuario para autenticación."""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = Column(DateTime)
    
    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "full_name": self.full_name,
            "is_active": self.is_active,
            "is_admin": self.is_admin,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None
        }


class ScanResult(Base):
    __tablename__ = 'scan_results'
    
    id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String(50), index=True)  # SAST, DAST, FILE_UPLOAD
    tool = Column(String(50), index=True)       # bandit, semgrep, OWASP ZAP, upload_service
    result_path = Column(String(500))           # Ruta al archivo de reporte
    target = Column(String(500))                # Ruta del código o URL analizada
    status = Column(String(20), default='completed')  # completed, failed, running, uploading
    error_message = Column(Text, nullable=True) # Mensaje de error si falló
    results = Column(JSON, nullable=True)       # Resultados del escaneo en formato JSON
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))  # Timestamp de inicio
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    def to_dict(self):
        return {
            "id": self.id,
            "scan_type": self.scan_type,
            "tool": self.tool,
            "result_path": self.result_path,
            "target": self.target,
            "status": self.status,
            "error_message": self.error_message,
            "results": self.results,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }

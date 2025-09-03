# Modelos para la base de datos SQLite
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON
from sqlalchemy.ext.declarative import declarative_base
from datetime import datetime

Base = declarative_base()

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
    timestamp = Column(DateTime, default=datetime.utcnow)  # Timestamp de inicio
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
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

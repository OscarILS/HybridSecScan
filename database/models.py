# Modelos para la base de datos SQLite
from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
import datetime

Base = declarative_base()

class ScanResult(Base):
    __tablename__ = 'scan_results'
    id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String, index=True)  # SAST o DAST
    tool = Column(String, index=True)
    result_path = Column(String)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

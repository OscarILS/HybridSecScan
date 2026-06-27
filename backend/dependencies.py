"""
Database engine, session factory, and get_db dependency — uses an absolute path
so the DB resolves correctly regardless of the working directory at startup.
"""

import importlib.util
import sys
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

BASE_DIR: Path = Path(__file__).resolve().parent.parent
DATABASE_URL = f"sqlite:///{BASE_DIR / 'database' / 'hybridsecscan.db'}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Ensure the database package is importable
_db_path = str(BASE_DIR / "database")
if _db_path not in sys.path:
    sys.path.insert(0, _db_path)

try:
    from models import Base, ScanResult  # type: ignore[import]
except ImportError:
    _spec = importlib.util.spec_from_file_location("models", BASE_DIR / "database" / "models.py")
    _mod = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
    _spec.loader.exec_module(_mod)  # type: ignore[union-attr]
    Base = _mod.Base
    ScanResult = _mod.ScanResult


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    Base.metadata.create_all(bind=engine)

"""Authentication endpoints: register, login, me."""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, ConfigDict, EmailStr
from sqlalchemy.orm import Session

try:
    from backend.auth import (
        ACCESS_TOKEN_EXPIRE_MINUTES,
        authenticate_user,
        create_access_token,
        get_current_active_user,
        get_password_hash,
    )
    from backend.dependencies import get_db
    from models import User  # database dir is on sys.path after dependencies import
except ImportError:
    from auth import (  # type: ignore[no-redef]
        ACCESS_TOKEN_EXPIRE_MINUTES,
        authenticate_user,
        create_access_token,
        get_current_active_user,
        get_password_hash,
    )
    from dependencies import get_db  # type: ignore[no-redef]

    from models import User  # type: ignore[no-redef]

router = APIRouter(prefix="/auth")
logger = logging.getLogger(__name__)


class UserRegister(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    username: str
    email: EmailStr
    password: str
    full_name: Optional[str] = None


class UserLogin(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    access_token: str
    token_type: str
    user: dict


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    email: str
    full_name: Optional[str] = None
    is_active: bool
    is_admin: bool
    created_at: str


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register_user(user_data: UserRegister, db: Session = Depends(get_db)):
    try:
        existing = (
            db.query(User).filter((User.username == user_data.username) | (User.email == user_data.email)).first()
        )
        if existing:
            field = "nombre de usuario" if existing.username == user_data.username else "correo electrónico"
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"El {field} ya está registrado")

        new_user = User(
            username=user_data.username,
            email=user_data.email,
            hashed_password=get_password_hash(user_data.password),
            full_name=user_data.full_name,
            is_active=True,
            is_admin=False,
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        logger.info(f"Usuario registrado: {new_user.username} (ID: {new_user.id})")

        # Return plain dict — avoids Pydantic v2 serialization issues con SQLAlchemy models
        return {
            "id": new_user.id,
            "username": new_user.username,
            "email": new_user.email,
            "full_name": new_user.full_name,
            "is_active": bool(new_user.is_active),
            "is_admin": bool(new_user.is_admin),
            "created_at": new_user.created_at.isoformat() if new_user.created_at else "",
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Error en registro: {type(exc).__name__}: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error interno: {type(exc).__name__}: {str(exc)[:200]}")


@router.post("/login", response_model=UserLogin)
async def login_user(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales incorrectas",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user.last_login = datetime.now(timezone.utc)
    db.commit()

    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    logger.info(f"Usuario autenticado: {user.username} (ID: {user.id})")

    return UserLogin(
        access_token=access_token,
        token_type="bearer",
        user={
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "is_admin": user.is_admin,
        },
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user=Depends(get_current_active_user)):
    """Devuelve el usuario autenticado. Requiere un Bearer token válido."""
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "full_name": current_user.full_name,
        "is_active": bool(current_user.is_active),
        "is_admin": bool(current_user.is_admin),
        "created_at": current_user.created_at.isoformat() if current_user.created_at else "",
    }

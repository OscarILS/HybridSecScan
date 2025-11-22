# API REST Endpoints - HybridSecScan
## FastAPI Backend Documentation

> **Autor:** Oscar Isaac Laguna Santa Cruz  
> **Co-Autor**: Kenneth Evander Ortega Morán 
> **Universidad:** UNMSM - FISI  
> **Fecha:** Noviembre 2025  
> **Versión:** 1.0

---

## 📋 Índice

1. [Arquitectura de la API](#arquitectura-de-la-api)
2. [Mapa de Endpoints](#mapa-de-endpoints)
3. [Autenticación y Autorización](#autenticación-y-autorización)
4. [Endpoints de Escaneo](#endpoints-de-escaneo)
5. [Endpoints de Correlación](#endpoints-de-correlación)
6. [Modelos de Datos](#modelos-de-datos)
7. [Manejo de Errores](#manejo-de-errores)

---

## 1. Arquitectura de la API

```mermaid
graph TB
    subgraph Client["🌐 CLIENTE"]
        Browser[Navegador Web<br/>React App]
        CLI[CLI Tools<br/>curl, Postman]
    end
    
    subgraph Gateway["🚪 GATEWAY"]
        CORS[CORS Middleware<br/>Origen: localhost:5173]
        Auth[JWT Authentication<br/>Bearer Token]
    end
    
    subgraph API["⚙️ FASTAPI SERVER"]
        Router1["/auth"<br/>Autenticación]
        Router2["/scan"<br/>Escaneos]
        Router3["/correlate"<br/>Correlación]
        Router4["/results"<br/>Resultados]
        Router5["/upload"<br/>Archivos]
    end
    
    subgraph Services["🔧 SERVICIOS"]
        AuthService[Auth Service<br/>JWT + Bcrypt]
        ScanService[Scan Service<br/>Bandit, Semgrep, ZAP]
        CorrelationService[Correlation Service<br/>ML Engine]
    end
    
    subgraph Database["💾 BASE DE DATOS"]
        DB[(SQLite DB)]
    end
    
    Browser --> CORS
    CLI --> CORS
    CORS --> Auth
    
    Auth --> Router1
    Auth --> Router2
    Auth --> Router3
    Auth --> Router4
    Auth --> Router5
    
    Router1 --> AuthService
    Router2 --> ScanService
    Router3 --> CorrelationService
    Router4 --> DB
    Router5 --> DB
    
    AuthService --> DB
    ScanService --> DB
    CorrelationService --> DB
    
    classDef clientStyle fill:#E3F2FD,stroke:#1976D2,color:#000
    classDef gatewayStyle fill:#FFF3E0,stroke:#F57C00,color:#000
    classDef apiStyle fill:#E8F5E9,stroke:#388E3C,color:#000
    classDef serviceStyle fill:#F3E5F5,stroke:#7B1FA2,color:#000
    classDef dbStyle fill:#FFEBEE,stroke:#C62828,color:#000
    
    class Browser,CLI clientStyle
    class CORS,Auth gatewayStyle
    class Router1,Router2,Router3,Router4,Router5 apiStyle
    class AuthService,ScanService,CorrelationService serviceStyle
    class DB dbStyle
```

---

## 2. Mapa de Endpoints

### Vista General

```mermaid
mindmap
  root((HybridSecScan API<br/>Port 8000))
    /auth
      POST /register
      POST /login
      GET /me
      POST /logout
    /scan
      POST /bandit
      POST /semgrep
      POST /zap
      GET /status/:id
    /correlate
      POST /
      GET /report/:id
    /results
      GET /all
      GET /:id
      DELETE /:id
    /upload
      POST /file
      GET /files
```

### Tabla Completa de Endpoints

| Método | Endpoint | Autenticación | Descripción |
|--------|----------|---------------|-------------|
| `POST` | `/auth/register` | ❌ No | Registrar nuevo usuario |
| `POST` | `/auth/login` | ❌ No | Iniciar sesión (obtener JWT) |
| `GET` | `/auth/me` | ✅ Sí | Obtener usuario actual |
| `POST` | `/auth/logout` | ✅ Sí | Cerrar sesión |
| `POST` | `/scan/bandit` | ✅ Sí | Ejecutar análisis SAST con Bandit |
| `POST` | `/scan/semgrep` | ✅ Sí | Ejecutar análisis SAST con Semgrep |
| `POST` | `/scan/zap` | ✅ Sí | Ejecutar análisis DAST con ZAP |
| `GET` | `/scan/status/{scan_id}` | ✅ Sí | Consultar estado de escaneo |
| `POST` | `/correlate` | ✅ Sí | Correlacionar vulnerabilidades |
| `GET` | `/correlate/report/{report_id}` | ✅ Sí | Obtener reporte de correlación |
| `GET` | `/results/all` | ✅ Sí | Listar todos los resultados |
| `GET` | `/results/{result_id}` | ✅ Sí | Obtener resultado específico |
| `DELETE` | `/results/{result_id}` | ✅ Sí | Eliminar resultado |
| `POST` | `/upload/file` | ✅ Sí | Subir archivo para análisis |
| `GET` | `/upload/files` | ✅ Sí | Listar archivos subidos |

---

## 3. Autenticación y Autorización

### POST /auth/register

**Descripción:** Registra un nuevo usuario en el sistema.

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant Bcrypt
    participant DB
    
    Client->>API: POST /auth/register<br/>{username, email, password}
    
    API->>API: Validar datos (Pydantic)
    
    alt Datos inválidos
        API-->>Client: 422 Unprocessable Entity
    end
    
    API->>DB: Verificar si usuario existe
    
    alt Usuario ya existe
        API-->>Client: 400 Bad Request<br/>"Usuario ya registrado"
    end
    
    API->>Bcrypt: hash_password(password)
    Bcrypt-->>API: hashed_password
    
    API->>DB: INSERT INTO users
    DB-->>API: user_id
    
    API-->>Client: 201 Created<br/>{user_id, username, email}
    
    Note over Client: Usuario creado exitosamente
```

**Request:**
```json
POST /auth/register
Content-Type: application/json

{
  "username": "oscar.laguna",
  "email": "oscar.laguna@unmsm.edu.pe",
  "password": "SecurePass123!",
  "full_name": "Oscar Isaac Laguna Santa Cruz"
}
```

**Response (201 Created):**
```json
{
  "id": 1,
  "username": "oscar.laguna",
  "email": "oscar.laguna@unmsm.edu.pe",
  "full_name": "Oscar Isaac Laguna Santa Cruz",
  "is_active": true,
  "is_admin": false,
  "created_at": "2025-11-21T10:30:00Z"
}
```

---

### POST /auth/login

**Descripción:** Autentica usuario y retorna JWT token.

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant Bcrypt
    participant JWT
    participant DB
    
    Client->>API: POST /auth/login<br/>{username, password}
    
    API->>DB: SELECT * FROM users<br/>WHERE username = ?
    
    alt Usuario no existe
        API-->>Client: 401 Unauthorized<br/>"Credenciales inválidas"
    end
    
    DB-->>API: user_data
    
    API->>Bcrypt: verify_password(password, hashed_password)
    
    alt Contraseña incorrecta
        Bcrypt-->>API: False
        API-->>Client: 401 Unauthorized<br/>"Credenciales inválidas"
    end
    
    Bcrypt-->>API: True
    
    API->>JWT: create_access_token(user_id)
    JWT-->>API: jwt_token
    
    API->>DB: UPDATE users<br/>SET last_login = NOW()
    
    API-->>Client: 200 OK<br/>{access_token, token_type}
    
    Note over Client: Guardar token en localStorage
```

**Request:**
```json
POST /auth/login
Content-Type: application/json

{
  "username": "oscar.laguna",
  "password": "SecurePass123!"
}
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

---

### GET /auth/me

**Descripción:** Obtiene información del usuario autenticado.

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant JWT
    participant DB
    
    Client->>API: GET /auth/me<br/>Authorization: Bearer <token>
    
    API->>JWT: decode_token(token)
    
    alt Token inválido o expirado
        JWT-->>API: TokenError
        API-->>Client: 401 Unauthorized
    end
    
    JWT-->>API: user_id
    
    API->>DB: SELECT * FROM users<br/>WHERE id = user_id
    DB-->>API: user_data
    
    API-->>Client: 200 OK<br/>{user_info}
```

**Request:**
```http
GET /auth/me
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Response (200 OK):**
```json
{
  "id": 1,
  "username": "oscar.laguna",
  "email": "oscar.laguna@unmsm.edu.pe",
  "full_name": "Oscar Isaac Laguna Santa Cruz",
  "is_active": true,
  "is_admin": false,
  "created_at": "2025-11-21T10:30:00Z",
  "last_login": "2025-11-21T15:45:00Z"
}
```

---

## 4. Endpoints de Escaneo

### POST /scan/bandit

**Descripción:** Ejecuta análisis SAST con Bandit en código Python.

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant Bandit
    participant DB
    
    Client->>API: POST /scan/bandit<br/>{target_path}
    
    API->>API: Validar autenticación (JWT)
    
    API->>DB: INSERT scan_result<br/>status='running'
    DB-->>API: scan_id
    
    API-->>Client: 202 Accepted<br/>{scan_id, status: 'running'}
    
    Note over Client: Cliente puede consultar<br/>estado con scan_id
    
    par Ejecución en background
        API->>Bandit: bandit -r {target_path} -f json
        
        alt Escaneo exitoso
            Bandit-->>API: results.json
            API->>DB: UPDATE scan_result<br/>status='completed', results=data
        else Error en escaneo
            Bandit-->>API: error
            API->>DB: UPDATE scan_result<br/>status='failed', error=message
        end
    end
```

**Request:**
```json
POST /scan/bandit
Authorization: Bearer <token>
Content-Type: application/json

{
  "target_path": "/app/backend",
  "options": {
    "severity": "HIGH",
    "confidence": "MEDIUM",
    "exclude": ["tests/", "venv/"]
  }
}
```

**Response (202 Accepted):**
```json
{
  "scan_id": "scan_001",
  "status": "running",
  "scan_type": "SAST",
  "tool": "bandit",
  "started_at": "2025-11-21T16:00:00Z",
  "message": "Escaneo iniciado. Consulte /scan/status/scan_001"
}
```

---

### POST /scan/zap

**Descripción:** Ejecuta análisis DAST con OWASP ZAP en URL objetivo.

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant ZAP
    participant DB
    
    Client->>API: POST /scan/zap<br/>{target_url}
    
    API->>API: Validar autenticación (JWT)
    API->>API: Validar URL formato
    
    API->>DB: INSERT scan_result<br/>status='running'
    DB-->>API: scan_id
    
    API-->>Client: 202 Accepted<br/>{scan_id}
    
    par Ejecución en background
        API->>ZAP: zap-cli quick-scan<br/>--spider --ajax-spider<br/>{target_url}
        
        Note over ZAP: Spider: 5-10 min<br/>Active Scan: 15-30 min
        
        alt Escaneo exitoso
            ZAP-->>API: vulnerabilities.json
            API->>API: Parsear resultados
            API->>DB: UPDATE scan_result<br/>status='completed'
        else Error
            ZAP-->>API: error
            API->>DB: UPDATE scan_result<br/>status='failed'
        end
    end
```

**Request:**
```json
POST /scan/zap
Authorization: Bearer <token>
Content-Type: application/json

{
  "target_url": "http://localhost:8000",
  "scan_policy": "full",
  "options": {
    "spider": true,
    "ajax_spider": true,
    "active_scan": true,
    "max_duration": 1800
  }
}
```

**Response (202 Accepted):**
```json
{
  "scan_id": "scan_002",
  "status": "running",
  "scan_type": "DAST",
  "tool": "zap",
  "target": "http://localhost:8000",
  "estimated_duration": "15-30 minutes",
  "started_at": "2025-11-21T16:05:00Z"
}
```

---

### GET /scan/status/{scan_id}

**Descripción:** Consulta el estado de un escaneo en progreso.

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant DB
    
    Client->>API: GET /scan/status/scan_001
    
    API->>DB: SELECT * FROM scan_results<br/>WHERE id = 'scan_001'
    
    alt Scan no encontrado
        API-->>Client: 404 Not Found
    end
    
    DB-->>API: scan_data
    
    API->>API: Calcular progreso
    
    alt Status = running
        API-->>Client: 200 OK<br/>{status: 'running', progress: 45%}
    else Status = completed
        API-->>Client: 200 OK<br/>{status: 'completed', results: {...}}
    else Status = failed
        API-->>Client: 200 OK<br/>{status: 'failed', error: "..."}
    end
```

**Request:**
```http
GET /scan/status/scan_001
Authorization: Bearer <token>
```

**Response (200 OK - Running):**
```json
{
  "scan_id": "scan_001",
  "status": "running",
  "progress": 45,
  "scan_type": "SAST",
  "tool": "bandit",
  "started_at": "2025-11-21T16:00:00Z",
  "elapsed_time": "00:02:30",
  "estimated_remaining": "00:03:00"
}
```

**Response (200 OK - Completed):**
```json
{
  "scan_id": "scan_001",
  "status": "completed",
  "scan_type": "SAST",
  "tool": "bandit",
  "started_at": "2025-11-21T16:00:00Z",
  "completed_at": "2025-11-21T16:05:30Z",
  "duration": "00:05:30",
  "vulnerabilities_found": 8,
  "results": {
    "high": 2,
    "medium": 4,
    "low": 2
  }
}
```

---

## 5. Endpoints de Correlación

### POST /correlate

**Descripción:** Correlaciona vulnerabilidades SAST y DAST usando ML.

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant Correlator
    participant ML
    participant DB
    
    Client->>API: POST /correlate<br/>{sast_scan_id, dast_scan_id}
    
    API->>DB: SELECT * FROM scan_results<br/>WHERE id IN (sast_scan_id, dast_scan_id)
    DB-->>API: scan_data
    
    API->>API: Parsear vulnerabilidades
    
    API->>Correlator: add_sast_findings(vulns)
    API->>Correlator: add_dast_findings(vulns)
    
    Correlator->>Correlator: correlate_vulnerabilities()
    
    loop Para cada par SAST-DAST
        Correlator->>Correlator: _calculate_correlation_confidence()
        
        alt ML disponible
            Correlator->>ML: predict_proba(features)
            ML-->>Correlator: confidence
        else Fallback
            Correlator->>Correlator: Correlación determinística
        end
        
        alt Confidence > 70%
            Correlator->>Correlator: Agregar correlación
        end
    end
    
    Correlator-->>API: correlations[]
    
    API->>DB: INSERT correlation_report
    DB-->>API: report_id
    
    API-->>Client: 200 OK<br/>{report_id, correlations}
```

**Request:**
```json
POST /correlate
Authorization: Bearer <token>
Content-Type: application/json

{
  "sast_scan_id": "scan_001",
  "dast_scan_id": "scan_002",
  "options": {
    "min_confidence": 0.70,
    "use_ml": true,
    "include_low_confidence": false
  }
}
```

**Response (200 OK):**
```json
{
  "report_id": "corr_001",
  "summary": {
    "total_sast_findings": 8,
    "total_dast_findings": 12,
    "correlations_found": 5,
    "high_confidence": 3,
    "medium_confidence": 2,
    "false_positive_reduction": "62.5%"
  },
  "correlations": [
    {
      "id": "corr_001_01",
      "confidence": 0.9324,
      "sast_vulnerability": {
        "id": "SAST_001",
        "type": "sql_injection",
        "file": "/api/users.py",
        "line": 45,
        "tool": "bandit"
      },
      "dast_vulnerability": {
        "id": "DAST_001",
        "type": "sql_injection",
        "endpoint": "/api/users",
        "tool": "zap"
      },
      "factors": {
        "endpoint_similarity": 1.0,
        "type_match": true,
        "ml_confidence": 0.9324,
        "severity_similarity": 1.0
      }
    }
  ],
  "created_at": "2025-11-21T16:10:00Z"
}
```

---

## 6. Modelos de Datos (Pydantic)

### UserCreate (Request)

```python
from pydantic import BaseModel, EmailStr, Field

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=100)
    full_name: str | None = None
    
    class Config:
        schema_extra = {
            "example": {
                "username": "oscar.laguna",
                "email": "oscar.laguna@unmsm.edu.pe",
                "password": "SecurePass123!",
                "full_name": "Oscar Laguna"
            }
        }
```

### ScanRequest (Request)

```python
class ScanRequest(BaseModel):
    target_path: str = Field(..., description="Ruta o URL objetivo")
    scan_type: str = Field(..., regex="^(SAST|DAST)$")
    tool: str = Field(..., regex="^(bandit|semgrep|zap)$")
    options: dict | None = None
    
    class Config:
        schema_extra = {
            "example": {
                "target_path": "/app/backend",
                "scan_type": "SAST",
                "tool": "bandit",
                "options": {
                    "severity": "HIGH",
                    "exclude": ["tests/"]
                }
            }
        }
```

### CorrelationRequest (Request)

```python
class CorrelationRequest(BaseModel):
    sast_scan_id: str
    dast_scan_id: str
    min_confidence: float = Field(default=0.70, ge=0.0, le=1.0)
    use_ml: bool = Field(default=True)
    
    class Config:
        schema_extra = {
            "example": {
                "sast_scan_id": "scan_001",
                "dast_scan_id": "scan_002",
                "min_confidence": 0.70,
                "use_ml": True
            }
        }
```

---

## 7. Manejo de Errores

### Códigos de Estado HTTP

| Código | Significado | Uso |
|--------|-------------|-----|
| `200` | OK | Operación exitosa |
| `201` | Created | Recurso creado exitosamente |
| `202` | Accepted | Solicitud aceptada, procesando en background |
| `400` | Bad Request | Datos inválidos en la solicitud |
| `401` | Unauthorized | Token JWT inválido o faltante |
| `403` | Forbidden | Usuario no tiene permisos |
| `404` | Not Found | Recurso no encontrado |
| `422` | Unprocessable Entity | Validación de Pydantic falló |
| `500` | Internal Server Error | Error interno del servidor |

### Formato de Error

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "El campo 'email' debe ser un email válido",
    "details": {
      "field": "email",
      "value": "invalid-email",
      "constraint": "email_format"
    },
    "timestamp": "2025-11-21T16:15:00Z"
  }
}
```

---

## 8. Configuración de CORS

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="HybridSecScan API", version="1.0.0")

# Configuración CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # React dev server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

---

## 9. Documentación Interactiva

FastAPI genera automáticamente documentación interactiva:

- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`
- **OpenAPI JSON**: `http://localhost:8000/openapi.json`

---

## 📚 Referencias

### FastAPI
- **Documentación Oficial**: https://fastapi.tiangolo.com/
- **Pydantic**: https://pydantic-docs.helpmanual.io/

### Seguridad
- **JWT**: https://jwt.io/
- **OAuth2**: https://oauth.net/2/

---

## 📧 Contacto

**Autor:** Oscar Isaac Laguna Santa Cruz  
**Email:** oscar.laguna@unmsm.edu.pe  
**Universidad:** UNMSM - FISI

---

**Última actualización:** Noviembre 21, 2025

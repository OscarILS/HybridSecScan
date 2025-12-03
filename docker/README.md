# Docker - HybridSecScan

Estructura simplificada para Docker:

```
docker/
├── backend/
│   └── Dockerfile          # Dockerfile del backend
├── frontend/
│   └── Dockerfile          # Dockerfile del frontend (pendiente)
├── docker-compose.yml      # Orquestación de servicios
└── .dockerignore          # Archivos a excluir
```

## Uso

### Backend solo (testing)

```bash
cd docker
docker-compose build backend
docker-compose up backend
```

### Verificar logs

```bash
docker-compose logs -f backend
```

### Detener

```bash
docker-compose down
```

## Notas

- El Dockerfile usa `uvicorn backend.main:app` para evitar problemas de imports
- PYTHONPATH está configurado en `/app`
- Los volúmenes permiten persistencia de datos
- Health check configurado para monitoreo

#!/usr/bin/env pwsh
###############################################################################
# Script de Despliegue de HybridSecScan en Windows con Docker Desktop
# Autor: Oscar ILS
# Fecha: Diciembre 2025
# Descripción: Automatiza el despliegue completo con Docker Compose en Windows
###############################################################################

$ErrorActionPreference = "Stop"

# Colores para output
function Write-Info { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Blue }
function Write-Success { param($msg) Write-Host "[SUCCESS] $msg" -ForegroundColor Green }
function Write-Warning { param($msg) Write-Host "[WARNING] $msg" -ForegroundColor Yellow }
function Write-Error-Custom { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }

# Banner
Write-Host @"

╦ ╦┬ ┬┌┐ ┬─┐┬┌┬┐╔═╗┌─┐┌─┐╔═╗┌─┐┌─┐┌┐┌
╠═╣└┬┘├┴┐├┬┘│ ││╚═╗├┤ │  ╚═╗│  ├─┤│││
╩ ╩ ┴ └─┘┴└─┴─┴┘╚═╝└─┘└─┘╚═╝└─┘┴ ┴┘└┘
    Deployment Script v1.0 (Windows)

"@ -ForegroundColor Cyan

# Verificar Docker
Write-Info "Verificando Docker Desktop..."
try {
    $dockerVersion = docker --version
    Write-Success "Docker encontrado: $dockerVersion"
} catch {
    Write-Error-Custom "Docker no está instalado o no está en el PATH."
    Write-Info "Por favor instala Docker Desktop desde: https://www.docker.com/products/docker-desktop"
    exit 1
}

# Verificar Docker Compose
try {
    $composeVersion = docker compose version
    Write-Success "Docker Compose encontrado: $composeVersion"
} catch {
    Write-Error-Custom "Docker Compose no está disponible."
    exit 1
}

# Verificar archivo docker-compose.yml
if (-not (Test-Path "docker-compose.yml")) {
    Write-Error-Custom "No se encontró docker-compose.yml en el directorio actual."
    Write-Info "Asegúrate de estar en el directorio raíz del proyecto."
    exit 1
}

# Crear directorios necesarios
Write-Info "Creando directorios necesarios..."
@("database", "reports", "uploads") | ForEach-Object {
    if (-not (Test-Path $_)) {
        New-Item -ItemType Directory -Path $_ -Force | Out-Null
    }
}
Write-Success "Directorios creados"

# Detener contenedores existentes
Write-Info "Deteniendo contenedores existentes..."
docker compose down 2>$null

# Limpiar imágenes antiguas (opcional)
$cleanOld = Read-Host "¿Deseas limpiar imágenes Docker antiguas? (y/N)"
if ($cleanOld -eq "y" -or $cleanOld -eq "Y") {
    Write-Info "Limpiando imágenes antiguas..."
    docker system prune -f
    Write-Success "Limpieza completada"
}

# Build de las imágenes
Write-Info "Construyendo imágenes Docker..."
Write-Warning "Esto puede tardar varios minutos la primera vez..."
docker compose build --no-cache

if ($LASTEXITCODE -ne 0) {
    Write-Error-Custom "Error al construir las imágenes Docker"
    exit 1
}
Write-Success "Imágenes construidas exitosamente"

# Iniciar servicios
Write-Info "Iniciando servicios..."
docker compose up -d

if ($LASTEXITCODE -ne 0) {
    Write-Error-Custom "Error al iniciar los servicios"
    exit 1
}

# Esperar a que los servicios estén listos
Write-Info "Esperando a que los servicios estén listos..."
Start-Sleep -Seconds 10

# Verificar estado de los servicios
Write-Info "Verificando estado de los servicios..."
docker compose ps

# Health checks
Write-Info "Ejecutando health checks..."
Start-Sleep -Seconds 5

$backendHealth = (docker inspect --format='{{.State.Health.Status}}' hybridscan-backend 2>$null)
$frontendHealth = (docker inspect --format='{{.State.Health.Status}}' hybridscan-frontend 2>$null)

if ($backendHealth -eq "healthy" -or $backendHealth -eq "starting") {
    Write-Success "Backend: $backendHealth"
} else {
    Write-Warning "Backend: $backendHealth (puede tardar hasta 40 segundos)"
}

if ($frontendHealth -eq "healthy" -or $frontendHealth -eq "starting") {
    Write-Success "Frontend: $frontendHealth"
} else {
    Write-Warning "Frontend: $frontendHealth"
}

# Mostrar información de despliegue
Write-Host ""
Write-Success "=================================="
Write-Success "  DESPLIEGUE COMPLETADO"
Write-Success "=================================="
Write-Host ""
Write-Info "URLs de acceso:"
Write-Host "  🌐 Frontend:  http://localhost" -ForegroundColor White
Write-Host "  🔧 API Docs:  http://localhost/api/docs" -ForegroundColor White
Write-Host "  ❤️  Health:   http://localhost/api/health" -ForegroundColor White
Write-Host ""
Write-Info "Comandos útiles:"
Write-Host "  Ver logs:          docker compose logs -f"
Write-Host "  Reiniciar:         docker compose restart"
Write-Host "  Detener:           docker compose down"
Write-Host "  Estado:            docker compose ps"
Write-Host ""
Write-Info "Archivos persistentes:"
Write-Host "  📊 Base de datos:  .\database\hybridsecscan.db"
Write-Host "  📄 Reportes:       .\reports\"
Write-Host "  📁 Uploads:        .\uploads\"
Write-Host ""

# Abrir navegador automáticamente
$openBrowser = Read-Host "¿Deseas abrir el navegador automáticamente? (Y/n)"
if ($openBrowser -ne "n" -and $openBrowser -ne "N") {
    Start-Sleep -Seconds 2
    Start-Process "http://localhost"
}

# Mostrar logs en tiempo real (opcional)
$showLogs = Read-Host "¿Deseas ver los logs en tiempo real? (y/N)"
if ($showLogs -eq "y" -or $showLogs -eq "Y") {
    docker compose logs -f
}

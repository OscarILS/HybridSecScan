# Script de Configuracion de Herramientas SAST
# Autor: Oscar Isaac Laguna Santa Cruz
# Fecha: 21 Noviembre 2025

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  CONFIGURACION HERRAMIENTAS SAST" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Agregar Semgrep al PATH permanentemente
$scriptsPath = "$env:LOCALAPPDATA\Packages\PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0\LocalCache\local-packages\Python313\Scripts"

Write-Host "[1/5] Configurando PATH para Semgrep..." -ForegroundColor Yellow
if ($env:Path -notlike "*$scriptsPath*") {
    $env:Path += ";$scriptsPath"
    Write-Host "[OK] PATH actualizado para sesion actual" -ForegroundColor Green
    
    # Agregar permanentemente al User PATH
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$scriptsPath*") {
        [Environment]::SetEnvironmentVariable("Path", "$userPath;$scriptsPath", "User")
        Write-Host "[OK] PATH actualizado permanentemente" -ForegroundColor Green
    }
} else {
    Write-Host "[OK] Semgrep ya esta en PATH" -ForegroundColor Green
}

# Verificar Semgrep
Write-Host ""
Write-Host "[2/5] Verificando Semgrep..." -ForegroundColor Yellow
try {
    $semgrepVersion = semgrep --version 2>&1
    Write-Host "[OK] Semgrep instalado: $semgrepVersion" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Error verificando Semgrep" -ForegroundColor Red
    exit 1
}

# Verificar Bandit
Write-Host ""
Write-Host "[3/5] Verificando Bandit..." -ForegroundColor Yellow
try {
    $banditVersion = python -m bandit --version 2>&1
    Write-Host "[OK] Bandit instalado: $banditVersion" -ForegroundColor Green
} catch {
    Write-Host "[WARN] Bandit no instalado, instalando..." -ForegroundColor Yellow
    pip install bandit
}

# Instalar herramientas adicionales
Write-Host ""
Write-Host "[4/5] Instalando herramientas SAST adicionales..." -ForegroundColor Yellow

# Para Node.js/JavaScript
Write-Host "  -> ESLint Security Plugin (Node.js/JS)..." -ForegroundColor Cyan
if (Get-Command npm -ErrorAction SilentlyContinue) {
    npm install -g eslint eslint-plugin-security 2>&1 | Out-Null
    Write-Host "  [OK] ESLint Security instalado" -ForegroundColor Green
} else {
    Write-Host "  [WARN] npm no disponible, instala Node.js para analisis JS" -ForegroundColor Yellow
}

# Descargar reglas de Semgrep
Write-Host ""
Write-Host "[5/5] Descargando reglas de seguridad de Semgrep..." -ForegroundColor Yellow
try {
    # Descargar reglas OWASP Top 10
    semgrep --config=auto --dryrun 2>&1 | Out-Null
    Write-Host "[OK] Reglas de Semgrep actualizadas" -ForegroundColor Green
} catch {
    Write-Host "[WARN] No se pudieron descargar reglas (se usaran las default)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  [OK] CONFIGURACION COMPLETA" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Herramientas instaladas:" -ForegroundColor White
Write-Host "  - Bandit (Python)" -ForegroundColor Gray
Write-Host "  - Semgrep (Multi-lenguaje)" -ForegroundColor Gray
Write-Host "  - ESLint Security (JavaScript/TypeScript)" -ForegroundColor Gray
Write-Host ""
Write-Host "Ejecuta: python scripts/experimental_validation.py" -ForegroundColor Yellow
Write-Host ""

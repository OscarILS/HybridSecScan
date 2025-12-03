# Script PowerShell para lanzar aplicaciones vulnerables - HybridSecScan
# Uso: ./launch_vulnerable_apps.ps1

# Colores para output
function Write-Color($Message, $Color = "White") {
    Write-Host $Message -ForegroundColor $Color
}

function Show-Menu {
    Write-Color "`n╔════════════════════════════════════════════════════╗" "Cyan"
    Write-Color "║     HybridSecScan - Vulnerable Apps Launcher       ║" "Cyan"
    Write-Color "╚════════════════════════════════════════════════════╝" "Cyan"
    Write-Color "`nSelecciona una aplicación vulnerable:`n" "Yellow"
    Write-Color "  1. OWASP Juice Shop (Node.js)" "Green"
    Write-Color "  2. NodeGoat (Node.js + MongoDB)" "Green"
    Write-Color "  3. DVWA (PHP + MySQL con Docker)" "Green"
    Write-Color "  4. WebGoat (Java con Docker)" "Green"
    Write-Color "  5. Ver URLs de prueba" "Green"
    Write-Color "  6. Verificar dependencias" "Green"
    Write-Color "  7. Salir" "Green"
    Write-Color ""
}

function Check-Dependencies {
    Write-Color "`n[*] Verificando dependencias..." "Yellow"
    Write-Color ""
    
    # Verificar Node.js
    try {
        $node_version = node --version
        Write-Color "  ✓ Node.js $node_version" "Green"
    } catch {
        Write-Color "  ✗ Node.js NO instalado. Descarga de https://nodejs.org/" "Red"
    }
    
    # Verificar npm
    try {
        $npm_version = npm --version
        Write-Color "  ✓ npm v$npm_version" "Green"
    } catch {
        Write-Color "  ✗ npm NO instalado" "Red"
    }
    
    # Verificar Python
    try {
        $python_version = python --version 2>&1
        Write-Color "  ✓ $python_version" "Green"
    } catch {
        Write-Color "  ✗ Python NO instalado. Descarga de https://python.org/" "Red"
    }
    
    # Verificar Docker
    try {
        $docker_version = docker --version
        Write-Color "  ✓ $docker_version" "Green"
    } catch {
        Write-Color "  ✗ Docker NO instalado. Descarga Docker Desktop" "Red"
    }
    
    # Verificar Git
    try {
        $git_version = git --version
        Write-Color "  ✓ $git_version" "Green"
    } catch {
        Write-Color "  ✗ Git NO instalado. Descarga de https://git-scm.com/" "Red"
    }
    
    Write-Color ""
}

function Show-TestUrls {
    Write-Color "`n╔════════════════════════════════════════════════════╗" "Cyan"
    Write-Color "║         URLs para DAST Testing en HybridSecScan     ║" "Cyan"
    Write-Color "╚════════════════════════════════════════════════════╝" "Cyan"
    Write-Color "`n📍 URLs LOCALES (después de ejecutar apps):`n" "Yellow"
    Write-Color "   OWASP Juice Shop:  http://localhost:3000/" "White"
    Write-Color "   NodeGoat:          http://localhost:4000/" "White"
    Write-Color "   DVWA:              http://localhost/DVWA/ (o :8080)" "White"
    Write-Color "   WebGoat:           http://localhost:8080/WebGoat/" "White"
    Write-Color "`n🌐 URLs REMOTAS (no requieren instalación):`n" "Yellow"
    Write-Color "   Juice Shop:        https://juice-shop.herokuapp.com/" "White"
    Write-Color "   WebGoat:           https://webgoat.herokuapp.com/WebGoat/" "White"
    Write-Color "   Vulnerable PHP:    http://testphp.vulnweb.com/" "White"
    Write-Color ""
}

function Start-JuiceShop {
    Write-Color "`n[*] Iniciando OWASP Juice Shop..." "Yellow"
    
    # Verificar si está instalado
    $installed = npm list -g @owasp/juice-shop 2>&1 | Select-String "juice-shop" | Measure-Object | Select-Object -ExpandProperty Count
    
    if ($installed -eq 0) {
        Write-Color "  [!] Juice Shop no encontrado. Instalando globalmente..." "Red"
        npm install -g "@owasp/juice-shop@latest"
    }
    
    Write-Color "  [+] Acceso en http://localhost:3000" "Green"
    Write-Color "  [+] Presiona CTRL+C para detener`n" "Gray"
    
    juice-shop
}

function Start-NodeGoat {
    Write-Color "`n[*] Iniciando NodeGoat..." "Yellow"
    
    if (-Not (Test-Path "NodeGoat")) {
        Write-Color "  [!] Clonando repositorio NodeGoat..." "Yellow"
        git clone https://github.com/OWASP/NodeGoat.git
        cd NodeGoat
    } else {
        cd NodeGoat
    }
    
    Write-Color "  [+] Instalando dependencias..." "Yellow"
    npm install
    
    Write-Color "  [+] Acceso en http://localhost:4000" "Green"
    Write-Color "  [+] Presiona CTRL+C para detener`n" "Gray"
    
    npm start
}

function Start-DVWA {
    Write-Color "`n[*] Iniciando DVWA con Docker..." "Yellow"
    
    # Verificar Docker
    try {
        docker --version | Out-Null
    } catch {
        Write-Color "  [!] ERROR: Docker no instalado" "Red"
        Write-Color "  [!] Descarga Docker Desktop de https://www.docker.com/" "Red"
        Read-Host "  Presiona Enter para continuar"
        return
    }
    
    Write-Color "  [+] Descargando imagen DVWA..." "Yellow"
    docker pull vulnerables/web-dvwa
    
    Write-Color "  [+] Iniciando contenedor..." "Yellow"
    Write-Color "  [+] Acceso en http://localhost/DVWA (usuario: admin, pass: password)" "Green"
    Write-Color "  [+] Presiona CTRL+C para detener`n" "Gray"
    
    docker run --rm -p 80:80 vulnerables/web-dvwa
}

function Start-WebGoat {
    Write-Color "`n[*] Iniciando OWASP WebGoat con Docker..." "Yellow"
    
    # Verificar Docker
    try {
        docker --version | Out-Null
    } catch {
        Write-Color "  [!] ERROR: Docker no instalado" "Red"
        Write-Color "  [!] Descarga Docker Desktop de https://www.docker.com/" "Red"
        Read-Host "  Presiona Enter para continuar"
        return
    }
    
    Write-Color "  [+] Descargando imagen WebGoat..." "Yellow"
    docker pull webgoat/goatandwolf
    
    Write-Color "  [+] Iniciando contenedor..." "Yellow"
    Write-Color "  [+] Acceso en http://localhost:8080/WebGoat/" "Green"
    Write-Color "  [+] Presiona CTRL+C para detener`n" "Gray"
    
    docker run --rm -p 8080:8080 webgoat/goatandwolf
}

# Main Loop
$continue = $true
while ($continue) {
    Show-Menu
    $choice = Read-Host "Ingresa tu opción (1-7)"
    
    switch ($choice) {
        "1" { Start-JuiceShop }
        "2" { Start-NodeGoat }
        "3" { Start-DVWA }
        "4" { Start-WebGoat }
        "5" { Show-TestUrls }
        "6" { Check-Dependencies }
        "7" { 
            Write-Color "`n[+] ¡Hasta luego!" "Green"
            $continue = $false 
        }
        default {
            Write-Color "`n[!] Opción inválida. Intenta de nuevo." "Red"
        }
    }
}

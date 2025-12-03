@echo off
REM Script para instalar y ejecutar aplicaciones vulnerables para DAST testing
REM Requiere: Docker Desktop, Git, Python, Node.js

echo.
echo ================================
echo HybridSecScan - Vulnerable Apps Launcher
echo ================================
echo.

setlocal enabledelayedexpansion

REM Menu de seleccion
echo Elige una aplicacion vulnerable:
echo.
echo 1. OWASP Juice Shop (Node.js)
echo 2. NodeGoat (Node.js + MongoDB)
echo 3. DVWA (PHP + MySQL)
echo 4. WebGoat (Java)
echo 5. Salir
echo.

set /p choice="Ingresa tu opcion (1-5): "

if "%choice%"=="1" goto juice_shop
if "%choice%"=="2" goto nodegoat
if "%choice%"=="3" goto dvwa
if "%choice%"=="4" goto webgoat
if "%choice%"=="5" goto end
goto invalid

:juice_shop
echo.
echo [*] Iniciando OWASP Juice Shop...
echo.
npm list -g @owasp/juice-shop >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Juice Shop no instalado. Instalando...
    npm install -g @owasp/juice-shop@latest
) else (
    echo [+] Juice Shop ya instalado
)
echo.
echo [+] Iniciando servidor en http://localhost:3000
echo.
juice-shop
goto end

:nodegoat
echo.
echo [*] Iniciando NodeGoat...
echo.
if not exist "NodeGoat" (
    echo [!] Clonando repositorio NodeGoat...
    git clone https://github.com/OWASP/NodeGoat.git
)
cd NodeGoat
echo [+] Instalando dependencias...
npm install
echo [+] Iniciando servidor en http://localhost:4000
npm start
goto end

:dvwa
echo.
echo [*] Iniciando DVWA con Docker...
echo.
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] ERROR: Docker no instalado. Descarga Docker Desktop de https://www.docker.com/
    pause
    goto end
)
echo [+] Descargando imagen DVWA...
docker pull vulnerables/web-dvwa
echo [+] Iniciando contenedor en http://localhost/DVWA
docker run --rm -p 80:80 vulnerables/web-dvwa
goto end

:webgoat
echo.
echo [*] Iniciando OWASP WebGoat...
echo.
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] ERROR: Docker no instalado. Descarga Docker Desktop de https://www.docker.com/
    pause
    goto end
)
echo [+] Descargando imagen WebGoat...
docker pull webgoat/goatandwolf
echo [+] Iniciando contenedor en http://localhost:8080/WebGoat
docker run --rm -p 8080:8080 webgoat/goatandwolf
goto end

:invalid
echo.
echo [!] Opcion invalida. Intenta de nuevo.
echo.
goto juice_shop

:end
echo.
pause

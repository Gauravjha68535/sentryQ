@echo off
echo 🚀 Starting SentryQ Windows Build Process...

:: 1. Build the Frontend
echo 📦 Building React Frontend...
cd web
if not exist "node_modules" (
    echo 📥 Installing frontend dependencies...
    call npm install
    if errorlevel 1 (
        echo ❌ npm install failed. Aborting.
        cd ..
        exit /b 1
    )
)
call npm run build
if errorlevel 1 (
    echo ❌ Frontend build failed. Aborting.
    cd ..
    exit /b 1
)
cd ..

:: 2. Synchronize assets to internal\ui\dist
echo 🔄 Synchronizing assets to internal\ui\dist...

:: Clean destination to avoid stale assets
echo 🗑️ Cleaning old assets...
if exist "internal\ui\dist" rmdir /s /q "internal\ui\dist"
mkdir "internal\ui\dist"

if exist "web\dist" (
    echo 📂 Copying build assets...
    xcopy /e /i /y "web\dist\*" "internal\ui\dist\"
    
    if exist "internal\ui\dist\index.html" (
        echo ✅ Assets synchronized successfully
    ) else (
        echo ❌ Error: No assets were copied to internal\ui\dist
        exit /b 1
    )
) else (
    echo ⚠️ Warning: web\dist is missing. Creating placeholder.
    type nul > internal\ui\dist\.gitkeep
)

:: 3. Build the Go Application
echo Building Go application (sentryq.exe)...

:: go-tree-sitter requires CGO which requires a C compiler (MinGW-w64 / MSYS2).
:: Check that gcc is available before attempting the build.
where gcc >nul 2>&1
if errorlevel 1 (
    echo ERROR: gcc not found in PATH.
    echo SentryQ requires a C compiler for CGO ^(go-tree-sitter^).
    echo Install MinGW-w64 via MSYS2 ^(https://www.msys2.org/^) and add its bin
    echo directory to PATH, then re-run this script.
    exit /b 1
)

set CGO_ENABLED=1
go build -o sentryq.exe .\cmd\scanner
if errorlevel 1 (
    echo Go build failed. Aborting.
    exit /b 1
)

:: 4. Package binary + rules\ into dist\
:: The scanner resolves rules at runtime relative to the executable location
:: (getDefaultRulesDir). rules\ must be in the same directory as the binary.
echo 📦 Packaging binary and rules\ into dist\...
if not exist "dist" mkdir "dist"
copy /y sentryq.exe dist\sentryq.exe >nul
if exist "rules" (
    xcopy /e /i /y "rules" "dist\rules\" >nul
    echo ✅ dist\ ready: sentryq.exe + rules\ directory
) else (
    echo ⚠️ Warning: rules\ directory not found - scanner will fall back to CWD at runtime
)

echo.
echo ✅ Build Complete!
echo    Run from project root:  sentryq.exe
echo    Or deploy the dist\ folder and run: dist\sentryq.exe

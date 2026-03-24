#!/bin/bash

# Exit on error
set -e

echo "🚀 Starting SentryQ Build Process..."

# 1. Build the Frontend
echo "📦 Building React Frontend..."
cd web
if [ ! -d "node_modules" ]; then
    echo "📥 Installing frontend dependencies..."
    npm install
fi
npm run build
cd ..

# 2. Synchronize assets to internal/ui/dist
echo "🔄 Synchronizing assets to internal/ui/dist..."
mkdir -p internal/ui/dist

# Clean destination to avoid stale assets
rm -rf internal/ui/dist/*

if [ -d "web/dist" ] && [ "$(ls -A web/dist)" ]; then
    echo "📂 Copying build assets..."
    cp -r web/dist/* internal/ui/dist/
    
    # Validate that assets were copied
    if [ -d "internal/ui/dist" ] && [ "$(ls -A internal/ui/dist)" ]; then
        echo "✅ Assets synchronized successfully"
    else
        echo "❌ Error: No assets were copied to internal/ui/dist"
        exit 1
    fi
else
    echo "⚠️ Warning: web/dist is empty or missing. Creating placeholder."
    touch internal/ui/dist/.gitkeep
fi

# 3. Build the Go Application
echo "🐹 Building Go application..."
go build -o sentryq ./cmd/scanner

echo "✅ Build Complete! You can now run the scanner with: ./sentryq"

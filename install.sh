#!/bin/bash
set -e

# Получаем абсолютный путь к директории скрипта
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$SCRIPT_DIR"
SERVICE_NAME="astracat-dns"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
BINARY_PATH="$PROJECT_DIR/$SERVICE_NAME"

echo "🚀 Starting installation of Astracat DNS Resolver..."

# Проверка наличия Go
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please install Go first."
    exit 1
fi

echo "📁 Project directory: $PROJECT_DIR"
cd "$PROJECT_DIR"

echo "🔨 Building the project with optimizations..."
go build -ldflags="-s -w" -o "$SERVICE_NAME" .

if [ ! -f "$BINARY_PATH" ]; then
    echo "❌ Build failed: binary not found at $BINARY_PATH"
    exit 1
fi

echo "✅ Build successful: $BINARY_PATH"

echo "📝 Creating systemd service file: $SERVICE_FILE..."

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Astracat DNS Resolver Service
After=network.target

[Service]
ExecStart=$BINARY_PATH
WorkingDirectory=$PROJECT_DIR
Restart=always
User=root
StandardOutput=null
StandardError=null
LogLevelMax=0

[Install]
WantedBy=multi-user.target
EOF

echo "🔄 Reloading systemd daemon..."
systemctl daemon-reload

echo "🔌 Enabling and starting the $SERVICE_NAME service..."
systemctl enable "$SERVICE_NAME" --now

echo "🎉 Installation complete! The $SERVICE_NAME service is now running."
echo "✅ Systemd logs are disabled for this service."

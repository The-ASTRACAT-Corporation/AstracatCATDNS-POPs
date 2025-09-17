#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

PROJECT_DIR="/root/Astracat-DNS-Resolver"
SERVICE_NAME="astracat-dns"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
BINARY_PATH="${PROJECT_DIR}/${SERVICE_NAME}"

echo "🚀 Starting installation of Astracat DNS Resolver..."

# Проверка наличия Go
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please install Go first."
    exit 1
fi

echo "📁 Project directory: ${PROJECT_DIR}"
cd "$PROJECT_DIR"

echo "🔨 Building the project..."
go build -o "${SERVICE_NAME}" .

# Проверяем, что бинарник создался
if [ ! -f "${BINARY_PATH}" ]; then
    echo "❌ Build failed: binary not found at ${BINARY_PATH}"
    exit 1
fi

echo "✅ Build successful: ${BINARY_PATH}"

echo "📝 Creating systemd service file: ${SERVICE_FILE}..."

# Генерируем unit-файл БЕЗ кавычек и шаблонов — только чистые абсолютные пути
cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=Astracat DNS Resolver Service
After=network.target

[Service]
ExecStart=${BINARY_PATH}
WorkingDirectory=${PROJECT_DIR}
Restart=always
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

echo "🔄 Reloading systemd daemon..."
systemctl daemon-reload

echo "🔌 Enabling and starting the ${SERVICE_NAME} service..."
systemctl enable "${SERVICE_NAME}" --now

# Проверяем статус
echo "🔍 Checking service status..."
sleep 2
systemctl status "${SERVICE_NAME}" --no-pager

echo "🎉 Installation complete! The ${SERVICE_NAME} service is now running."
echo "📄 View logs with: journalctl -u ${SERVICE_NAME} -f"

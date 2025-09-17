#!/bin/bash

set -e

PROJECT_DIR="/root/Astracat-DNS-Resolver"
SERVICE_NAME="astracat-dns"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
BINARY_PATH="${PROJECT_DIR}/${SERVICE_NAME}"

cd "$PROJECT_DIR"

# Сборка
go build -o "${SERVICE_NAME}" .

if [ ! -f "${BINARY_PATH}" ]; then
    echo "❌ Build failed."
    exit 1
fi

# Генерация systemd unit-файла БЕЗ логов (без StandardOutput/Error)
cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=Astracat DNS Resolver Service
After=network.target

[Service]
ExecStart=${BINARY_PATH}
WorkingDirectory=${PROJECT_DIR}
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "${SERVICE_NAME}" --now

echo "✅ ${SERVICE_NAME} installed and started."

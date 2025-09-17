#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

PROJECT_DIR="/Users/astracat/Astracat-DNS-Resolver-1"
SERVICE_NAME="astracat-dns"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

echo "Building the project..."
cd "$PROJECT_DIR"
go build -o "${SERVICE_NAME}" .

echo "Creating systemd service file..."
cat <<EOF > "${SERVICE_FILE}"
[Unit]
Description=Astracat DNS Resolver Service
After=network.target

[Service]
ExecStart="$PROJECT_DIR/${SERVICE_NAME}"
WorkingDirectory="$PROJECT_DIR"
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

echo "Enabling and starting the ${SERVICE_NAME} service..."
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
systemctl start "${SERVICE_NAME}"

echo "Installation complete. The ${SERVICE_NAME} service is now running."
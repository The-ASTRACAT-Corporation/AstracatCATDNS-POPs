#!/bin/bash

set -e

echo "Building astracat-dns server..."
go build -o dnsserver cmd/dnsserver/dnsserver.go

echo "Installing astracat-dns to /usr/local/bin..."
sudo mv dnsserver /usr/local/bin/astracat-dns

echo "Creating systemd service file..."
sudo tee /etc/systemd/system/astracat-dns.service > /dev/null <<EOF
[Unit]
Description=Astracat DNS Server
After=network.target

[Service]
ExecStart=/usr/local/bin/astracat-dns
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

echo "Enabling and starting astracat-dns service..."
sudo systemctl daemon-reload
sudo systemctl enable astracat-dns
sudo systemctl start astracat-dns

echo "Astracat DNS server installed and started successfully!"
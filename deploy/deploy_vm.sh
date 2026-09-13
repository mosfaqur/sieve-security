#!/usr/bin/env bash
set -euo pipefail

TARGET_HOST="${1:-192.168.1.30}"
TARGET_USER="${2:-root}"
INSTALL_DIR="/opt/sieve"

echo "========================================================"
echo "Sieve Security — Remote VM Deployment"
echo "Target: ${TARGET_USER}@${TARGET_HOST}"
echo "========================================================"

echo "[1/5] Building static Linux amd64 binary..."
cp -f web/index.html pkg/server/index.html
mkdir -p dist
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o dist/sieve ./cmd/sieve
echo "✓ Binary built successfully: $(ls -lh dist/sieve | awk '{print $5}')"

echo "[2/5] Creating deployment bundle..."
BUNDLE_DIR=$(mktemp -d)
mkdir -p "${BUNDLE_DIR}/opt/sieve"
cp dist/sieve "${BUNDLE_DIR}/opt/sieve/"
cp -r content "${BUNDLE_DIR}/opt/sieve/"
mkdir -p "${BUNDLE_DIR}/opt/sieve/data"

echo "[3/5] Syncing bundle to ${TARGET_HOST}..."
ssh "${TARGET_USER}@${TARGET_HOST}" "mkdir -p ${INSTALL_DIR}/data ${INSTALL_DIR}/content"
scp dist/sieve "${TARGET_USER}@${TARGET_HOST}:${INSTALL_DIR}/sieve.new"
scp -r content/plugins "${TARGET_USER}@${TARGET_HOST}:${INSTALL_DIR}/content/"
scp deploy/sieve.service "${TARGET_USER}@${TARGET_HOST}:/etc/systemd/system/sieve.service"

echo "[4/5] Configuring firewall and systemd on ${TARGET_HOST}..."
ssh "${TARGET_USER}@${TARGET_HOST}" bash << 'EOF'
  mv -f /opt/sieve/sieve.new /opt/sieve/sieve
  chmod +x /opt/sieve/sieve
  
  # Ensure firewall allows Sieve Web UI port 8080
  if command -v ufw >/dev/null 2>&1; then
    ufw allow 8080/tcp comment "Sieve Security Web UI" || true
  fi

  # Reload and restart systemd service
  systemctl daemon-reload
  systemctl enable sieve
  systemctl restart sieve
EOF

echo "[5/5] Verifying deployment health on http://${TARGET_HOST}:8080..."
sleep 2
HEALTH_OUTPUT=$(ssh "${TARGET_USER}@${TARGET_HOST}" "curl -s http://127.0.0.1:8080/api/v1/health || true")
echo "✓ Health Response from ${TARGET_HOST}: ${HEALTH_OUTPUT}"

echo "========================================================"
echo "Deployment Complete!"
echo "Web UI URL: http://${TARGET_HOST}:8080"
echo "========================================================"

#!/usr/bin/env bash
# setup_server.sh
# Run on Ubuntu 24 - Expects the compiled Go binary "serve-n-collect"
# present in the current directory. Installs minimal packages, creates service user,
# installs binary to /opt/outfaze, configures systemd, sets capabilities, and opens firewall.
#
# Usage:
#   sudo bash setup_server.sh
set -euo pipefail


BINARY_NAME="serve-n-collect"
INSTALL_DIR="/opt/outfaze"
SERVICE_USER="outfaze"
LOG_DIR="/var/log/outfaze"
SYSTEMD_UNIT="/etc/systemd/system/serve-n-collect.service"
ENV_FILE="/etc/default/serve-n-collect"

DEFAULT_ARGS="--http-port=8080 --tcp-port=4444 --udp-port=5000 --dns-port=8053 --log-dir=${LOG_DIR}"

if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root. Use sudo."
  exit 1
fi

if [[ ! -f "./${BINARY_NAME}" ]]; then
  echo "Binary ./${BINARY_NAME} not found. Build or copy the Go binary into this directory first."
  exit 2
fi

echo "Updating apt and installing prerequisites..."
apt-get update -y
apt-get install -y ufw libcap2-bin

echo "Creating service account (if missing)..."
if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
  echo "User ${SERVICE_USER} created."
else
  echo "User ${SERVICE_USER} already exists."
fi

echo "Creating directories..."
mkdir -p "${INSTALL_DIR}"
mkdir -p "${LOG_DIR}"
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${INSTALL_DIR}" "${LOG_DIR}"
chmod 750 "${INSTALL_DIR}" "${LOG_DIR}"

echo "Installing binary to ${INSTALL_DIR}..."
install -m 0750 "./${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
chown "${SERVICE_USER}:${SERVICE_USER}" "${INSTALL_DIR}/${BINARY_NAME}"

echo "Setting CAP_NET_BIND_SERVICE on ${INSTALL_DIR}/${BINARY_NAME}..."
if command -v setcap >/dev/null 2>&1; then
  if setcap 'cap_net_bind_service=+ep' "${INSTALL_DIR}/${BINARY_NAME}" >/dev/null 2>&1; then
    echo "setcap applied."
  else
    echo "setcap failed or binary not compatible; proceed but privileged ports may require root or systemd capabilities."
  fi
else
  echo "setcap not available; installed libcap2-bin should have provided it but it's missing. Continuing."
fi

echo "Creating environment file ${ENV_FILE} (can be edited to change runtime args)..."
cat > "${ENV_FILE}" <<EOF
# Environment file for serve-n-collect
# Edit ARGS to change runtime options or ports
ARGS="${DEFAULT_ARGS}"
EOF
chmod 640 "${ENV_FILE}"

echo "Writing systemd unit ${SYSTEMD_UNIT}..."
cat > "${SYSTEMD_UNIT}" <<'UNIT_EOF'
[Unit]
Description=Outfaze serve-n-collect
After=network.target

[Service]
Type=simple
User=outfaze
Group=outfaze
WorkingDirectory=/opt/outfaze
EnvironmentFile=-/etc/default/serve-n-collect
ExecStart=/opt/outfaze/serve-n-collect $ARGS
Restart=on-failure
RestartSec=5s
# Allow binding privileged ports if needed (also keep setcap on the binary)
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
UNIT_EOF

chmod 644 "${SYSTEMD_UNIT}"

echo "Reloading systemd daemon and enabling service..."
systemctl daemon-reload
systemctl enable --now serve-n-collect.service

echo "Configuring UFW firewall rules..."
ufw allow OpenSSH   
ufw allow 5000/udp   
ufw allow 8053/udp    
ufw allow 1:65535/tcp 

if ufw status verbose | grep -q "Status: inactive"; then
  echo "Enabling UFW (SSH allowed)..."
  ufw --force enable
else
  echo "UFW already active."
fi

echo "Waiting for service to start and reporting status..."
sleep 1
systemctl restart serve-n-collect.service || true
systemctl status --no-pager -l serve-n-collect.service

echo
echo "Installation complete."
echo "Logs are written to ${LOG_DIR} and to the systemd journal (journalctl -u serve-n-collect)."
echo "To edit runtime args (ports, log dir) edit ${ENV_FILE} and run: systemctl restart serve-n-collect"
echo "To remove capability (if needed): sudo setcap -r ${INSTALL_DIR}/${BINARY_NAME}"

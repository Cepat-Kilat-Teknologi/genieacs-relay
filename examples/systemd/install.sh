#!/bin/bash
# install.sh - Script to install GenieACS Relay on Linux
#
# Usage: sudo ./install.sh

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=== GenieACS Relay Installer ===${NC}"

# Check root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Error: Please run as root (sudo)${NC}"
  exit 1
fi

# Variables
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/genieacs-relay"
DATA_DIR="/var/lib/genieacs-relay"
SERVICE_USER="genieacs"
BINARY_NAME="genieacs-relay"

# Detect architecture
ARCH=$(uname -m)
case $ARCH in
  x86_64) ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  armv7l) ARCH="arm" ;;
  *) echo -e "${RED}Unsupported architecture: $ARCH${NC}"; exit 1 ;;
esac

echo -e "${YELLOW}Architecture: $ARCH${NC}"

# Create user
if ! id "$SERVICE_USER" &>/dev/null; then
  echo -e "${YELLOW}Creating user: $SERVICE_USER${NC}"
  useradd --system --no-create-home --shell /usr/sbin/nologin $SERVICE_USER
fi

# Create directories
echo -e "${YELLOW}Creating directories...${NC}"
mkdir -p $CONFIG_DIR
mkdir -p $DATA_DIR
chown $SERVICE_USER:$SERVICE_USER $DATA_DIR

# Copy binary (assumes binary is in current directory or specify path)
if [ -f "./$BINARY_NAME" ]; then
  echo -e "${YELLOW}Installing binary...${NC}"
  cp ./$BINARY_NAME $INSTALL_DIR/$BINARY_NAME
  chmod +x $INSTALL_DIR/$BINARY_NAME
elif [ -f "./main" ]; then
  echo -e "${YELLOW}Installing binary from ./main...${NC}"
  cp ./main $INSTALL_DIR/$BINARY_NAME
  chmod +x $INSTALL_DIR/$BINARY_NAME
else
  echo -e "${RED}Binary not found. Please build first:${NC}"
  echo "  go build -o genieacs-relay ."
  echo "Then run this script again."
  exit 1
fi

# Copy environment file
if [ ! -f "$CONFIG_DIR/env" ]; then
  echo -e "${YELLOW}Creating environment file...${NC}"
  cp ./env.example $CONFIG_DIR/env
  chmod 600 $CONFIG_DIR/env
  chown root:$SERVICE_USER $CONFIG_DIR/env
  echo -e "${YELLOW}Please edit $CONFIG_DIR/env with your configuration${NC}"
else
  echo -e "${YELLOW}Environment file already exists, skipping...${NC}"
fi

# Copy systemd service
echo -e "${YELLOW}Installing systemd service...${NC}"
cp ./genieacs-relay.service /etc/systemd/system/genieacs-relay.service

# Reload systemd
echo -e "${YELLOW}Reloading systemd...${NC}"
systemctl daemon-reload

# Enable and start service
echo -e "${YELLOW}Enabling service...${NC}"
systemctl enable genieacs-relay

echo ""
echo -e "${GREEN}=== Installation Complete ===${NC}"
echo ""
echo "Next steps:"
echo "  1. Edit configuration: sudo nano $CONFIG_DIR/env"
echo "  2. Start service: sudo systemctl start genieacs-relay"
echo "  3. Check status: sudo systemctl status genieacs-relay"
echo "  4. View logs: sudo journalctl -u genieacs-relay -f"
echo ""

#!/bin/bash

# Check if the script is run as root (via sudo)
if [[ "$EUID" -ne 0 ]]; then
  echo "❌ This script must be run with sudo. Try again with:"
  echo "   sudo $0"
  exit 1
fi

CONTAINER_NAME="android-container"

# Check if the container is running
if docker ps -q -f name="^/${CONTAINER_NAME}$" | grep -q .; then
  echo "🛑 Stopping container '$CONTAINER_NAME'..."
  docker stop "$CONTAINER_NAME"
  echo "🧹 Removing container '$CONTAINER_NAME'..."
  docker rm "$CONTAINER_NAME"
  echo "✅ Container '$CONTAINER_NAME' has been stopped and removed."
else
  echo "ℹ️ Container '$CONTAINER_NAME' is not running."
fi
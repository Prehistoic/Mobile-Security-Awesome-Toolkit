#!/bin/bash

# Check if the script is run as root (via sudo)
if [[ "$EUID" -ne 0 ]]; then
  echo "❌ This script must be run with sudo. Try again with:"
  echo "   sudo $0"
  exit 1
fi

# Default values
DEFAULT_DEVICE="Samsung Galaxy S10"
DEFAULT_VERSION="11.0"

# List of devices
DEVICES=(
  "Samsung Galaxy S10"
  "Samsung Galaxy S9"
  "Samsung Galaxy S8"
  "Samsung Galaxy S7 Edge"
  "Samsung Galaxy S7"
  "Samsung Galaxy S6"
  "Nexus 4"
  "Nexus 5"
  "Nexus One"
  "Nexus S"
  "Nexus 7"
  "Pixel C"
)

# List of Android versions
VERSIONS=("9.0" "10.0" "11.0" "12.0" "13.0" "14.0")

# Function to show the menu for device selection
select_device() {
  echo "Select a device:"
  select DEVICE in "${DEVICES[@]}"; do
    if [[ -n "$DEVICE" ]]; then
      break
    else
      echo "Invalid selection. Try again."
    fi
  done
}

# Function to show the menu for version selection
select_version() {
  echo "Select Android version:"
  select VERSION in "${VERSIONS[@]}"; do
    if [[ -n "$VERSION" ]]; then
      break
    else
      echo "Invalid selection. Try again."
    fi
  done
}

# Ask user to select device or use default
read -p "Use default device ($DEFAULT_DEVICE)? [Y/n]: " USE_DEFAULT_DEVICE
if [[ "$USE_DEFAULT_DEVICE" =~ ^[Nn]$ ]]; then
  select_device
else
  DEVICE="$DEFAULT_DEVICE"
fi

# Ask user to select Android version or use default
read -p "Use default Android version ($DEFAULT_VERSION)? [Y/n]: " USE_DEFAULT_VERSION
if [[ "$USE_DEFAULT_VERSION" =~ ^[Nn]$ ]]; then
  select_version
else
  VERSION="$DEFAULT_VERSION"
fi

# Run the Docker command
echo "Running Docker container with:"
echo "  Device: $DEVICE"
echo "  Android Version: $VERSION"

docker run -d -p 6080:6080 \
  -p 5554:5554 -p 5555:5555 \
  -e EMULATOR_DEVICE="$DEVICE" \
  -e WEB_VNC=true \
  --device /dev/kvm \
  --name android-container \
  budtmo/docker-android:emulator_"$VERSION"
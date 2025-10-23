# burpDrop
- [Description](#description)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Other commands](#other-commands)

## Description

**burpDrop** is a professional-grade automation tool that simplifies installing Burp Suite CA certificates into rooted Android devices or emulators.

Built for security professionals, pen testers, and mobile developers, it automates certificate conversion, deployment, permission setting, and rebooting — all with robust logging and cross-platform support.

**Official page** : https://github.com/Gashaw512/android-traffic-interception-guide/tree/main/scripts

## Requirements
- Python 3.6+
- ADB
- OpenSSL available in `PATH`
- Rooted Android device or emulator
- Burp Suite CA certificate exported as `.der` format

## Installation

```sh
pip install burpdrop
```

## Usage

1. Export your Burp certificate

In [Burp Suite](../../common/tools/burp-suite.md):
`Proxy -> Options -> Import / Export CA Certificate`
- Choose DER format
- Save it as `burp.der`

2. Connect your Android device
- Enable **USB debugging**
- Ensure `adb` is accessible from terminal (e.g., added to `PATH`)

3. Install the certificate

```sh
burpdrop install

# You'll be prompted to select the certificate file path
# The device will automatically reboot once the installation is successful
```

## Other commands

```sh
# Interactive install (prompt-based)
burpdrop install

# Direct path install
burpdrop install -c "/path/to/burp.der"

# View recent logs
burpdrop logs

# Interactive configuration wizard
burpdrop config

# Diagnostic tests (adb, root, cert, etc.)
burpdrop diagnose

# Help
burpdrop help
```
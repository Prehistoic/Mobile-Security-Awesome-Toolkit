# Frida
- [Description](#description)
- [Frida Tools](#frida-tools)
- [Frida Server](#frida-server)
- [Frida Gadget](#frida-gadget)
- [Common Frida CLI Commands](#common-frida-cli-commands)
- [Frida Scripts](#frida-scripts)
- [Frida CodeShare](#frida-codeshare)
- [Other Script Sources](#other-script-sources)

## Description

**Frida** is a dynamic instrumentation toolkit that lets you inject JavaScript snippets into native apps on Windows, macOS, GNU/Linux, iOS, Android... It's widely used in reverse engineering, mobile application security testing, and debugging.

## Frida Tools

Frida tools are a command-line interface (CLI) and Python modules used to interact with a target application or device from the host computer.

### Installation

```sh
pip install frida-tools
```

Then test with `frida --version`

## Frida Server

Frida Server is the agent that runs on the target device (for example a rooted Android phone). It listens for connections from the Frida Tools running on your host computer and injects the instrumentation scripts into the target process.

### Installation

1. **Identify Device Architecture** (`arm`, `arm64`, `x86`, `x86_64`)

```sh
adb shell getprop ro.product.cpu.abi
# or
adb shell getprop ro.product.cpu.abilist
```

2. **Download Frida Server** : Go to the official [Frida releases page](https://github.com/frida/frida/releases) and download the latest `frida-server-*-android-<arch>.xz` file that matches the device architecture

3. **Extract the Binary**

```sh
unxz frida-server-*.xz
```

4. **Push and Execute on Device**

```sh
# Rename for convenience (optional)
mv frida-server-* frida-server

# Push to device
adb push frida-server /data/local/tmp/

# Give execute permissions
adb shell "chmod 755 /data/local/tmp/frida-server"

# Run the server (as root if necessary, especially on newer Android versions)
# For rooted devices:
adb shell "su -c /data/local/tmp/frida-server &"
# Or for a simple rooted/emulator setup:
adb shell "/data/local/tmp/frida-server &"
```

5. **Test the Connection**

```sh
frida-ps -U
```

You should see a list of processes if the server is running correctly

## Frida Gadget

The Frida Gadget is a shared library (e.g., `.so` on Android) designed to be embedded directly into the application you want to instrument.

### When to use Frida Gadget
- **Non-rooted/Non-jailbroken devices**: When you cannot run the full `frida-server` daemon due to device restrictions (e.g., a non-rooted device).
- **Early Instrumentation**: When you need your script to run very early in the application's startup process, before any anti-debugging/anti-frida checks might be activated.

### Installation

Using Frida Gadget requires modifying the target application's binary. You have 2 options to inject the gadget depending on whether or not the target application already contains any native library.

See [Patching APK with Frida Gadget](../guides/patching-apk-with-frida-gadget.md)

## Common Frida CLI Commands

### frida-ps

- `frida-ps -U` : Lists running processes on the USB-connected device
- `frida-ps -Ua` : List all installed applications on the USB-connected device

### frida-trace

- `frida-trace -U -i [keyword]` : Traces all functions containing "keyword" in their name across all loaded modules on the USB device
- `frida-trace -U -i [keyword] -N com.package.name` : Traces all functions containing "keyword" in specified application

### frida

- `frida -U -f com.package.name` : Launches the application with the given package name on the USB dervice and attaches to it, but keeps it paused
- `frida -U -f com.package.name --no-pause` : Same but without pausing
- `frida -U com.package.name` : Attaches to an already running app process (using package name or PID)
- `frida -U -l script.js com.package.name` : Attaches to the running process and loads the Javascript file `script.js`

## Frida Scripts

See [Creating Frida Script](../guides/creating-custom-frida-script.md) to discover syntax and examples for Frida scripts targeting Android applications.

## Frida CodeShare

Developers around the world can share their best Frida scripts through [Frida CodeShare](https://codeshare.frida.re/).

### SSL Pinning Bypass Scripts
- [Universal Android SSL Pinning Bypass with Frida](https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/)
- [frida-multiple-unpinning](https://codeshare.frida.re/@akabe1/frida-multiple-unpinning/)

### Anti-Root Bypass Scripts
- [fridantiroot](https://codeshare.frida.re/@dzonerzy/fridantiroot/)

## Other Script Sources
- [HTTP Toolkit Frida Interception and Unpinning](https://github.com/httptoolkit/frida-interception-and-unpinning)
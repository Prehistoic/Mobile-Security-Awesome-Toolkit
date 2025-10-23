# Objection
- [Description](#description)
- [Installation](#installation)
- [Attaching to an Application](#attaching-to-an-application)
  - [Method 1: Runtime Attachment (Requires Frida Server)](#method-1-runtime-attachment-requires-frida-server)
  - [Method 2: Gadget Patching (No Root/Jailbreak Required)](#method-2-gadget-patching-no-rootjailbreak-required)
- [Common Exploration Commands](#common-exploration-commands)
  - [General Commands](#general-commands)
  - [Security Bypass Commands](#security-bypass-commands)
  - [Hooking and Class Analysis](#hooking-and-class-analysis)
  - [Data Exploration Commands](#data-exploration-commands)

## Description

**Objection**, powered by Frida, is a powerful, high-level runtime mobile exploration toolkit. It simplifies common security assessment tasks for both Android and iOS applications, often eliminating the need to write custom Frida scripts.

## Installation

```sh
pip install objection
```

Then test with `objection version`

## Attaching to an Application

You can attach **Objection** to an application using two main methods:

### Method 1: Runtime Attachment (Requires Frida Server)

This method works on rooted Android devices or jailbroken iOS devices where the Frida server is running.

- List processes with `frida-ps -Ua` and note the package name
- Attach and explore

```sh
objection -g com.example.app explore
```

`-g` flag can be either the package name or the PID.

### Method 2: Gadget Patching (No Root/Jailbreak Required)

```sh
objection patchapk --source path/to/target.apk

adb install target.objection.apk

objection -g com.example.app explore
```

**Note:** If automatic patching doesn't work, refer to [Patching APK with Frida Gadget](../guides/patching-apk-with-frida-gadget.md)

## Common Exploration Commands

### General Commands
- `env` : Dumps info about the application's environment
- `ls` : Lists files in current directory
- `pwd` : Prints current working directory
- `file cat <filename>` : Prints content of a specified file
- `file download <remote> <local>` : Download a file from device to host machine
- `import /path/to/script.js` : Import and execute a [custom Frida Javascript script](../guides/creating-custom-frida-script.md)
- `jobs list` : Lists active background jobs

### Security Bypass Commands

#### Android
- `android sslpinning disable` : Hook and disable common SSL Pinning methods
- `android root disable` : Hook and disable common root detection checks

#### iOS
- `ios sslpinning disable` : Hook and disable common SSL Pinning methods
- `ios jailbreak disable` : Hook and disable common jailbreak detection checks

### Hooking and Class Analysis

#### Android
- `android hooking list classes` : List all Java classes loded in the app memory
- `android hooking search classes <keyword>` : Search for Java classes whose names contain the keyword
- `android hooking watch class <Class.Name>` : Hook all methods in a specified class and prints arguments and return values
- `android hooking watch method <Class.Method>` : Hook a single method and print its arguments and return values

#### iOS
- `ios hooking list classes` : List all Java classes loded in the app memory
- `ios hooking search classes <keyword>` : Search for Java classes whose names contain the keyword
- `ios hooking watch class <Class.Name>` : Hook all methods in a specified class and prints arguments and return values
- `ios hooking watch method <Class.Method>` : Hook a single method and print its arguments and return values

### Data Exploration Commands

#### Android
- `android sqlite query <DB path> "SELECT * ..."` : Run a SQLite query on a database file inside the app sandbox

#### iOS
- `ios keychain dump` : Dump all data stored in the application's Keychain
- `ios plist cat Info.plist` : Print the content of a plist file
- `ios nsuserdefaults get` : Dump data stored in NSUserDefaults
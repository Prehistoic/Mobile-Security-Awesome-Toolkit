# Apktool
- [Description](#description)
- [Installation](#installation)
  - [Windows](#windows)
  - [Linux](#linux)
  - [MacOS](#macos)
- [Usage](#usage)
  - [Decompiling an APK](#decompiling-an-apk)
  - [Recompiling an APK](#recompiling-an-apk)

## Description

Apktool is an essential tool for reverse engineering Android applications. It allows to decompile an APK, modify its content and recompile it.

Apktool decompiles the .dex files into .smali files.

## Installation

**Requirements**
- JDK 11+

### Windows

- Download the [Windows wrapper script](https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/windows/apktool.bat). (Right click, Save Link As `apktool.bat`)
- Download the [latest version](https://bitbucket.org/iBotPeaches/apktool/downloads) of Apktool.
- Rename downloaded jar to `apktool.jar`.
- Move both `apktool.jar` and `apktool.bat` to your Windows directory. (Usually `C:/Windows`)
- If you do not have access to `C:/Windows`, you can place the two files anywhere and add that directory to your Environment Variables System PATH variable.
- Try running `apktool` via the command prompt.

### Linux

- Download the [Linux wrapper script](https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool). (Right click, Save Link As `apktool`)
- Download the [latest version](https://bitbucket.org/iBotPeaches/apktool/downloads) of Apktool.
- Rename the downloaded jar to `apktool.jar`.
- Move both `apktool.jar` and `apktool` to `/usr/local/bin`. (root needed)
- Make sure both files are executable. (`chmod +x`)
- Try running `apktool` via CLI.

### MacOS

- Download the [Mac wrapper script](https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/osx/apktool). (Right click, Save Link As `apktool`)
- Download the [latest version](https://bitbucket.org/iBotPeaches/apktool/downloads) of Apktool.
- Rename the downloaded jar to `apktool.jar`.
- Move both `apktool.jar` and `apktool` to `/usr/local/bin`. (root needed)
- Make sure both files are executable. (`chmod +x`)
- Try running `apktool` via CLI.

#### Brew

- Install Homebrew as described [in this page](https://brew.sh/).
- Execute the command `brew install apktool` in the terminal.
- Try running `apktool` via CLI.

## Usage

### Decompiling an APK

```
apktool d /path/to/your-app.apk
```

**Tips and Tricks**
- **Decoding Specific Parts** : if you only need to view resources or smali code, several options exist to skip decoding some parts of the APK (which might help when rebuilding and also makes things faster)

    - `no--assets` prevents decoding unknown asset files
    - `-r, --no-res` prevents decoding resources and keeps `resources.arsc` intact
    - `-s, --no-src` prevents disassembling dex files

### Recompiling an APK

```
apktool b path/to/your-app-folder
```
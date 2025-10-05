# JADX
- [Description](#description)
- [Installation](#installation)
- [Usage](#usage)
  - [GUI](#gui)
  - [CLI](#cli)
- [Plugins](#plugins)
  - [JADXecute](#jadxecute)

## Description

**JADX** is a free and open-source command-line tool for decompiling Android DEX and APK files to Java source code. Its main goal is to help with reverse engineering Android applications for various purposes, such as analyzing malware, understanding how an app works, or recovering lost source code.

JADX is known for its ability to produce readable Java code from the compiled Android bytecode, making the reverse engineering process much easier. It also comes with a graphical user interface (GUI) that allows users to browse and search the decompiled code, and it supports other Android-specific file formats like `.jar`, `.apk`, and `.aar`.

## Installation

- Download [latest release](https://github.com/skylot/jadx/releases/) from Github repo
- Unzip and run `jadx` (CLI) or `jadx-gui` (GUI) from the `bin` directory

## Usage

### GUI

Run `jadx-gui` from the `bin` directory

### CLI

- Basic Decompilation
```
jadx -d app_source my_application.apk
```

- Decompiling only source code (skipping resources)
```
jadx -d source_only --no-res my_application.apk
```

- Decompiling only resources (skipping source code)
```
jadx -d resources_only --no-src my_application.apk
```

- Enabling Deobfuscation
```
jadx -d output --deobf my_obfuscated_app.apk
```

## Plugins

### JADXecute

`JADXecute` is a plugin for JADX that enhances its functionality by adding Dynamic Code Execution abilities.

With JADXecute, you can dynamically run Java code to modify or print components of the jadx-gui output.

**Installing JADXecute**

JADX with the embedded JADXecute plugin can be download from the [official JADXecute repo releases page](https://github.com/LaurieWired/JADXecute/releases).
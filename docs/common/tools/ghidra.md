# Ghidra
- [Description](#description)
- [Installation](#installation)
- [Usage](#usage)
- [Tips \& Tricks](#tips--tricks)
  - [Search for Strings](#search-for-strings)
  - [JNI Types in Ghidra](#jni-types-in-ghidra)

## Description

`Ghidra` is a software reverse engineering (SRE) framework created and maintained by the [National Security Agency Research Directorate](https://www.nsa.gov/). This framework includes a suite of full-featured, high-end software analysis tools that enable users to analyze compiled code on a variety of platforms including Windows, macOS, and Linux. 

Capabilities include disassembly, assembly, decompilation, graphing, and scripting, along with hundreds of other features. Ghidra supports a wide variety of processor instruction sets and executable formats and can be run in both user-interactive and automated modes. Users may also develop their own Ghidra extension components and/or scripts using Java or Python.

## Installation

- Prerequisites : JDK 21+
- Download [latest release](https://github.com/NationalSecurityAgency/ghidra/releases) from official Github
- Unzip and run `ghidraRun`

## Usage

- Launch Ghidra with `ghidraRun`
- Create a **New Project** (`File > New Project`)
- **Import the Binary**: `File > Import File` and select target file
  - For Android, you can select the APK file directly. Ghidra supports both `.dex` and `.so` files
  - For iOS, extract the main Mach-O executable from the IPA bundle
- **Analyze the Binary**: double-click the imported file to open the **Code Browser**, click **Yes** to run the initial auto-analysis

## Tips & Tricks

### Search for Strings
- Window > Defined Strings
- Filter for wanted string. Can use `Text Filter Options` button to use regexes

### JNI Types in Ghidra

By default Ghidra will not know JNI types so all JNI functions are referenced with their offset to the JNIEnv pointer.

Several methods exist to make Ghidra recognize JNI types :

#### Importing [jni_all.gdt](https://github.com/Ayrx/JNIAnalyzer/blob/master/JNIAnalyzer/data/jni_all.gdt)

- `Open File Archive` in Data Type Manager
- Change the first parameter of native methods to JNIEnv*

#### Using the [JNIAnalyzer](https://github.com/Ayrx/JNIAnalyzer/tree/master) extension

- Build and install the extension
  - Clone the JNIAnalyzer git repository
  - Build the extension with `gradle -PGHIDRA_INSTALL_DIR=<YOUR GHIDRA INSTALLATION DIRECTORY>` (caution about gradle version, must match what Ghidra is expecting so most likely the latest if Ghidra is up to date)
  - In Ghidra, `File -> Install Extensions` and choose the .zip file in `JNIAnalyzer/dist`
  - Restart Ghidra

The extension exposes several scripts that can be accessed from Ghidra's Script Manager window.
- **JNIAnalyzer.java** : extract the function signature of all native methods in an APK file and applies the signature to all matching functions
- **TraceRegisterNatives.java** : parses the output of the Frida script [trace_registernatives](https://github.com/Ayrx/trace_registernatives) and applies results to the Ghidra project
- **RegisterNatives.java** (experimental) : looks for calls to `RegisterNatives` within a function and sets the `JNINativeMethod` structure type in the appropriate locations within the binary


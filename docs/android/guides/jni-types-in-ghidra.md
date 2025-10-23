# JNI Types in Ghidra

By default Ghidra will not know JNI types so all JNI functions are referenced with their offset to the JNIEnv pointer.

Several methods exist to make Ghidra recognize JNI types :

## Importing [jni_all.gdt](https://github.com/Ayrx/JNIAnalyzer/blob/master/JNIAnalyzer/data/jni_all.gdt)

- `Open File Archive` in Data Type Manager
- Change the first parameter of native methods to JNIEnv*

## Using the [JNIAnalyzer](https://github.com/Ayrx/JNIAnalyzer/tree/master) extension

- Build and install the extension
  - Clone the JNIAnalyzer git repository
  - Build the extension with `gradle -PGHIDRA_INSTALL_DIR=<YOUR GHIDRA INSTALLATION DIRECTORY>` (caution about gradle version, must match what Ghidra is expecting so most likely the latest if Ghidra is up to date)
  - In Ghidra, `File -> Install Extensions` and choose the .zip file in `JNIAnalyzer/dist`
  - Restart Ghidra

The extension exposes several scripts that can be accessed from Ghidra's Script Manager window.
- **JNIAnalyzer.java** : extract the function signature of all native methods in an APK file and applies the signature to all matching functions
- **TraceRegisterNatives.java** : parses the output of the Frida script [trace_registernatives](https://github.com/Ayrx/trace_registernatives) and applies results to the Ghidra project
- **RegisterNatives.java** (experimental) : looks for calls to `RegisterNatives` within a function and sets the `JNINativeMethod` structure type in the appropriate locations within the binary
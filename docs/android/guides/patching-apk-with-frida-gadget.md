# Patching an APK with Frida Gadget
- [Method 1: Target APK contains a native library](#method-1-target-apk-contains-a-native-library)
- [Method 2 : Target APK does not contain any native library](#method-2--target-apk-does-not-contain-any-native-library)

Using Frida Gadget requires modifying the target application's binary. You have 2 options to inject the gadget depending on whether or not the target application already contains any native library.

**Note**: Tools like [Objection](./objection.md) can automate the process of patching an APK with the Frida Gadget.

## Method 1: Target APK contains a native library

1. **Download the appropriate FridaGadget shared library** `libfrida-gadget.so` from the [Frida releases](https://github.com/frida/frida/releases) matching the app's and your device's architecture

```sh
wget https://github.com/frida/frida/releases/download/x.x.x/frida-gadget-x.x.x.-android-<arch>.so.xz
unxz -d frida-gadget-x.x.x-android-<arch>.so.xz
```

2. **Decompile the target APK**

```sh
apktool d -rs target.apk
```

3. **Copy frida-gadget to the unpacked APK directory**

```sh
cp libfrida-gadget.so target/lib/<arch>/libfrida-gadget.so
```

4. **Inject frida-gadget as a dependency of the native library**

- Create Python script

```python
#!/usr/bin/env python3

import lief

libnative = lief.parse("target/lib/<arch>/libfromapk.so")
libnative.add_library("libfrida-gadget.so") # Injection!
libnative.write("target/lib/<arch>/libfromapk.so")
```

- Run the script `python3 inject-gadget.py` and check if the injection succeeded :

```sh
readelf -d target/lib/<arch>/libfromapk.so
```

5. **Recompile, align, and re-sign the modified APK**

```sh
apktool b target
java -jar uber-apk-signer.jar -a ./target/dist/target.apk
```

## Method 2 : Target APK does not contain any native library

1. **Download the appropriate FridaGadget shared library** `libfrida-gadget.so` from the [Frida releases](https://github.com/frida/frida/releases) matching the app's and your device's architecture

```sh
wget https://github.com/frida/frida/releases/download/x.x.x/frida-gadget-x.x.x.-android-<arch>.so.xz
unxz -d frida-gadget-x.x.x-android-<arch>.so.xz
```

2. **Decompile the target APK**

```sh
apktool d -r target.apk
```

3. **Place the FridaGadget library into the appropriate directory** in the decompiled app

```sh
cp libfrida-gadget.so target/lib/<arch>/libfrida-gadget.so
```

4. **Inject System.loadLibrary into smali code**

- Find the `smali` file of the main activity
- Insert the following code inside its constructor

```
# direct methods
.method constructor <init>(Lcom/some/packet/activity/MainActivity;)V
    .locals 0
    ....
    
    const-string v0, "frida-gadget"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    return-void
.end method
```

5. **Recompile, align, and re-sign the modified APK**

```sh
apktool b target
java -jar uber-apk-signer.jar -a ./target/dist/target.apk
```
# Creating a custom Frida script
- [Core API Modules](#core-api-modules)
  - [Module and Process](#module-and-process)
  - [Interceptor (Hooking Engine)](#interceptor-hooking-engine)
- [Advanced API Usage](#advanced-api-usage)
  - [`Java` module (Android-Specific Hooking)](#java-module-android-specific-hooking)
  - [`Stalker` (Code Tracing Engine)](#stalker-code-tracing-engine)
  - [`Memory` (Manipulation and Searching)](#memory-manipulation-and-searching)
- [More Examples](#more-examples)
  - [1. Tracing and modifying arguments of `open()` (File I/O)](#1-tracing-and-modifying-arguments-of-open-file-io)
  - [2. Replacing a Native Function (Cryptography Stubbing)](#2-replacing-a-native-function-cryptography-stubbing)
  - [3. Hooking and Dumping Data from a Network Call](#3-hooking-and-dumping-data-from-a-network-call)
  - [4. Instantiating and Calling a Private Method](#4-instantiating-and-calling-a-private-method)
  - [5. Searching Memory for a Hardcoded Secret](#5-searching-memory-for-a-hardcoded-secret)
  - [6. Tracing Instructions and Register States](#6-tracing-instructions-and-register-states)

Frida allows creating custom scripts using its [JavaScript API](https://frida.re/docs/javascript-api/).

## Core API Modules

### Module and Process

These modules are fundamental for accessing the process's memory layout and loaded libraries.

|Module|Purpose|Key Methods|
|---|---|---|
|`Process`|Provides information about current process|`Process.enumerateModules()`, `Process.enumerateThreads()`, `Process.pointerSize`, `Process.getModuleByName(name)`|
|`Module`|Represents a loaded library (e.g. `libc.so`)|`Module.findExportByName(name, symbol)`, `Module.enumerateExports()`, `Module.base`|
|`NativePointer`|Represents an address in the target process's memory|`ptr(address_string)` (converts string to pointer), `pointer.readCString()`, `pointer.readUtf8String()`, `pointer.add(offset)`|

**Basic Example : Finding a Native Function Address**

```js
var targetModule = Process.getModuleByName("libssl.so");
var targetFunction = Module.findExportByName(targetModule.name, "SSL_read");

if (targetFunction) {
    console.log("[*] Found SSL_read at: " + targetFunction);
} else {
    console.log("[-] SSL_read not found.");
}
```

### Interceptor (Hooking Engine)

This is the primary module for **attaching hooks** to functions in the target process. It is used for monitoring, argument manipulation, and return value modification.

|Method|Usage|
|---|---|
|`Interceptor.attach(target, callbacks)`|Attaches a hook to a native function address (`target`)|
|`Interceptor.replace(target, replacement, [data])`|Completely replaces a function at `target` with your custom `replacement` function|

**Callback Properties for `Interceptor.attach`**
- `onEnter(args)`: Called just before the original function executes.
  - `args`: An array of `NativePointer`'s representing the function arguments
- `onLeave(retval)`: Called just after the original function returns
  - `retval`: A `NativePointer` or primitive value holding the function's return value. Can be changed with `retval.replace(new_value)`

**Example: Hooking a Native Crypto Function**

```js
var targetPtr = Module.findExportByName("libssl.so", "SSL_read");

Interceptor.attach(targetPtr, {
    onEnter: function (args) {
        // Log the function call and the buffer address
        console.log(`[+] SSL_read called!`);
        this.socket = args[0]; // Store the SSL object pointer for onLeave
        this.buffer = args[1]; // Store the buffer pointer
        this.length = args[2].toInt32(); // Read the requested length
    },

    onLeave: function (retval) {
        var bytesRead = retval.toInt32();
        if (bytesRead > 0) {
            // Read the actual data from memory after the function returned
            var data = this.buffer.readByteArray(bytesRead);
            console.log(`[+] Data (Plaintext, ${bytesRead} bytes):`);
            console.log(hexdump(data, {
                offset: 0,
                length: bytesRead,
                header: true,
                ansi: false
            }));
            
            // OPTIONAL: Modify the returned data (e.g., tamper with network traffic)
            // this.buffer.write("HACKED!!!", bytesRead); 
        }
    }
});
```

## Advanced API Usage

### `Java` module (Android-Specific Hooking)

For Android, the `Java` module is crucial for instrumenting Java/Kotlin code.

- `Java.perform(function() { ... })`: Must wrap all Java-related API calls
- `Java.use(class_name)`: Loads a Java class, allowing access to its static and instance methods
- `$new()`: Used to instantiate a new object of a hooked class
- `.implementation = function(...) { ... }`: The core mechanism to hook and replace a method's logic

**Example: Bypassing a simple Root Check**

```js
Java.perform(function () {
    try {
        var RootChecker = Java.use('com.app.security.RootChecker');

        // Hook a specific method and make it always return false
        RootChecker.isDeviceRooted.implementation = function () {
            console.log("[*] Root Check Bypassed !");
            return false; // Force return value to 'False'
        }

        // Handle method overloads if necessary
        // RootChecker.someMethod.overload('java.lang.String', 'int').implementation = function (str, num) { ... }
    } catch (e) {
        console.log("[-] Class not found or error " + e);
    }
})
```

### `Stalker` (Code Tracing Engine)

`Stalker` is Frida's low-level code tracing engine. It is an advanced technique used to capture every instruction, block or function call executed by a thread, primarily for analyzing native code, code coverage or defeating anti-debugging/obfuscation.

- `Stalker.follow(threadId, [options])`: Starts tracing a specific thread
- `Stalker.unfollow(threadId)`: Stops tracing a thread
- `options`: An object specifying what to trace (`call`, `ret`, `exec`, `block`)
- `transform(iterator)`: The most powerful part. It allows you to transform the code being executed **synchronously** before the target instructions run

### `Memory` (Manipulation and Searching)

The `Memory` module provides tools for reading, writing and allocating memory in target process.

- `Memory.alloc(size)`: Allocates new memory (return a `NativePointer`)
- `Memory.readByteArray(address, size)`: Reads memory into a buffer
- `Memory.protect(address, size, protection)`: Changes memory protection (e.g., to make a non-executable page executable)
- `Memory.scan(address, size, pattern, callbacks)`: Scans a memory region for a specific byte pattern (useful for finding magic bytes or strings)

**Example: Disabling Pinning in Flutter app**

```js
var m = Process.findModuleByName("libflutter.so"); 
var pattern = "2d e9 f0 4f a3 b0 82 46 50 20 10 70"
var res = Memory.scan(m.base, m.size, pattern, {
    onMatch: function(address, size){
        console.log('[+] ssl_verify_result found at: ' + address.toString());

        // Add 0x01 because it's a THUMB function
        // Otherwise, we would get 'Error: unable to intercept function at 0x9906f8ac; please file a bug'
        hook_ssl_verify_result(address.add(0x01));
        
    }, 
    onError: function(reason){
        console.log('[!] There was an error scanning memory');
    },
    onComplete: function()
    {
        console.log("All done")
    }
});
```

## More Examples

### 1. Tracing and modifying arguments of `open()` (File I/O)

This script hooks the standard open syscall, which is often used in file-based security checks (like root detection).

```js
Interceptor.attach(Module.getExportByName(null, 'open'), {
    onEnter: function (args) {
        // args[0] is the file path (const char *pathname)
        var filePath = args[0].readCString();
        console.log(`[+] open() called for: ${filePath}`);

        // **Modification Example:** Bypass a specific file check
        if (filePath.includes("frida_detection_file")) {
            console.warn("[*] Bypassing anti-Frida file check...");
            // Redirect the path to an irrelevant file
            var newPath = Memory.allocUtf8String("/dev/null");
            args[0] = newPath; 
        }

        this.fd = args[0]; // Store original path for onLeave
    },
    onLeave: function (retval) {
        // retval is the file descriptor (int) or -1 on error
        var fd_value = retval.toInt32();
        if (fd_value === -1) {
            // Check errno for details on the error
            console.error(`[-] open() failed for ${this.fd.readCString()}`);
        } else {
            console.log(`[+] open() returned FD: ${fd_value}`);
        }
    }
});
```

### 2. Replacing a Native Function (Cryptography Stubbing)

This is a more aggressive technique where you completely swap out a function with your own logic to disable entirely a security check.

```js
var targetFunctionPtr = Module.findExportByName("libcustomcrypto.so" "encryptData");

if (targetFunctionPtr) {
    Interceptor.replace(targetFunctionPtr, new NativeCallback((input_ptr, length) => {
        console.log("[!!!] encryptData() REPLACED! Returning NULL.");
        
        // This function will now always return NULL (0) or a mock pointer,
        // effectively disabling the encryption operation.
        return ptr(0);

    }, 'pointer', ['pointer', 'int']));
}
```

### 3. Hooking and Dumping Data from a Network Call

This script targets a common method in the Android HTTP stack to log the content sent by the application.

```js
Java.perform(function () {
    try {
        // Targeting a common class for network security (e.g., CertificatePinner)
        var Socket = Java.use("java.net.Socket");
        
        // Hook the connect method to log connection details
        Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function (address, timeout) {
            var hostName = address.toString();
            console.log(`[Net] Connecting to: ${hostName} with timeout ${timeout}`);
            
            // Call the original connect method
            this.connect(address, timeout);
        };

        // You would typically hook data processing classes (e.g., OkHttpClient) 
        // to dump request/response bodies, but this is a simple connection trace.

    } catch (e) {
        console.error("Java Hook Error: " + e.message);
    }
});
```

### 4. Instantiating and Calling a Private Method

```js
Java.perform(function () {
    var TargetClass = Java.use('com.app.logic.SecretManager');

    // 1. Instantiate the class (if it's not a static context)
    var secretManagerInstance = TargetClass.$new();
    console.log("[*] Created SecretManager instance.");

    // 2. Call a private method on the instance
    var secret = secretManagerInstance.getSecretKey(); // assuming this method is public or already hooked to be accessible

    // If the method is truly private, you must use reflection or hook the method directly.
    
    // Example using reflection (more complex but necessary for truly hidden members):
    // Note: Frida often makes private methods accessible after Java.use()
    var SecretManager_class = Java.use('com.app.logic.SecretManager').class;
    var hiddenMethod = SecretManager_class.getDeclaredMethod('decryptData', [Java.use('java.lang.String').class]);
    hiddenMethod.setAccessible(true); // Bypass Java's access checks
    
    var decrypted = hiddenMethod.invoke(secretManagerInstance, "encrypted_data_string");
    console.log("[*] Decrypted Data: " + decrypted);
});
```

### 5. Searching Memory for a Hardcoded Secret

```js
// Scan only the memory ranges belonging to the application's main module
var targetModule = Process.getCurrentModule(); 
var baseAddress = targetModule.base;
var size = targetModule.size;

// Search for the ASCII string "API_KEY_" in memory
// Note: Patterns are hex strings, here 0x41 is 'A', 0x50 is 'P', etc.
var pattern = '41 50 49 5f 4b 45 59 5f'; // "API_KEY_"

Memory.scan(baseAddress, size, pattern, {
    onMatch: function (address, size) {
        console.log(`[!!!] Secret Found at ${address} in ${targetModule.name}!`);
        // Dump the surrounding bytes for context
        console.log(hexdump(address, { length: 64 })); 
    },
    onError: function (reason) {
        console.error("Memory scan error: " + reason);
    },
    onComplete: function () {
        console.log("[*] Memory scan complete.");
    }
});
```

### 6. Tracing Instructions and Register States

This script attaches the Stalker to the current thread and logs every instruction execution in the specified module for deep analysis.

```js
// Scan only the memory ranges belonging to the application's main module
var targetModule = Process.getCurrentModule(); 
var baseAddress = targetModule.base;
var size = targetModule.size;

// Search for the ASCII string "API_KEY_" in memory
// Note: Patterns are hex strings, here 0x41 is 'A', 0x50 is 'P', etc.
var pattern = '41 50 49 5f 4b 45 59 5f'; // "API_KEY_"

Memory.scan(baseAddress, size, pattern, {
    onMatch: function (address, size) {
        console.log(`[!!!] Secret Found at ${address} in ${targetModule.name}!`);
        // Dump the surrounding bytes for context
        console.log(hexdump(address, { length: 64 })); 
    },
    onError: function (reason) {
        console.error("Memory scan error: " + reason);
    },
    onComplete: function () {
        console.log("[*] Memory scan complete.");
    }
});
```
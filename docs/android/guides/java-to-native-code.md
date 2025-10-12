# Java to Native Code Connection

In order to execute a function from the native library, there must be a Java-declared native method that the Java code can call. When this Java-declared native method is called, the “paired” native function from the native library (ELF/.so) is executed.

- [Declaring the function in Java](#declaring-the-function-in-java)
- [Option 1: Dynamic Linking](#option-1-dynamic-linking)
- [Option 2: Static Linking](#option-2-static-linking)

## Declaring the function in Java

A Java-declared native method appears in the Java code as below. It appears like any other Java method, except it includes the `native` keyword and has no code in its implementation, because its code is actually in the compiled, native library.

```
public native String myMethodInNativeLibrary(int var0);
```

## Option 1: Dynamic Linking

In order to link, or pair, the Java declared native method and the function in the native library dynamically, the developer names the method and the function according to the specs such that the JNI system can dynamically do the linking.

According to the spec, the developer would name the function as follow for the system to be able to dynamically link the native method and function. A native method name is concatenated from the following components:

1. the prefix `Java_`
2. a mangled fully-qualified class name
3. an underscore (“_”) separator
4. a mangled method name
5. for overloaded native methods, two underscores (“__”) followed by the mangled argument signature

### Dynamic Linking Example

1. **Java/Kotlin Declarations**

```java
// In com.example.yourapp.MainActivity.java
package com.example.yourapp;

public class MainActivity {
    static {
        System.loadLibrary("dynamic-lib"); // Loads the shared library
    }

    // The JVM will look for a C/C++ function named:
    // Java_com_example_yourapp_MainActivity_getMessage
    public native String getMessage();
    
    // The JVM will look for a C/C++ function named:
    // Java_com_example_yourapp_MainActivity_multiply
    public native int multiply(int x, int y);
    
    // ... rest of the class
}
```

2. **Native Function Implementations (in C/C++ file, e.g. `dynamic-lib.cpp`)**

```cpp
#include <jni.h>
#include <string>

// 1. Function for getMessage()
// Name: Java_com_example_yourapp_MainActivity_getMessage
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_yourapp_MainActivity_getMessage(
    JNIEnv* env, jobject /* this */) 
{
    std::string message = "Hello from Dynamic Linking!";
    return env->NewStringUTF(message.c_str());
}

// 2. Function for multiply(int x, int y)
// Name: Java_com_example_yourapp_MainActivity_multiply
extern "C" JNIEXPORT jint JNICALL
Java_com_example_yourapp_MainActivity_multiply(
    JNIEnv* env, jobject /* this */, jint x, jint y) 
{
    return x * y;
}
```

## Option 2: Static Linking

Using static linking for your Java Native Interface (JNI) methods in the Android NDK is achieved by using the `RegisterNatives` JNI function, typically inside the library's `JNI_OnLoad` function. This approach is often recommended as it avoids the need for JNI method names to follow the strict, long `Java_package_class_method` naming convention, and can improve library load time by explicitly defining the mapping.

A key benefit of using `RegisterNatives` is that it allows you to hide the JNI functions' symbols (except for `JNI_OnLoad`) from the shared library's public interface, which can lead to a smaller shared library and better security/stability.

```cpp
jint RegisterNatives(JNIEnv *env, jclass clazz, const JNINativeMethod *methods, jint nMethods);

typedef struct { 
    char *name; 
    char *signature; 
    void *fnPtr; 
} JNINativeMethod;
```

### Method Signature

The `JNINativeMethod` struct requires to use a method signature.

JNI Type Signatures can be found [in this documentation](https://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/types.html)

Method signatures follow this naming convention :
```
(<input1 signature><input2 signature>)<output signature>
```

**Examples**
```cpp
public native String doThingsInNativeLibrary(int var0);
=> (I)Ljava/lang/String;

public native long f (int n, String s, int[] arr);
=> (ILjava/lang/String;[I)J
```

### Static Linking Example

1. **Native Function Implementation (in C++ file, e.g. `native-lib.cpp`)**
```cpp
#include <jni.h>
#include <string>
#include <android/log.h>

// Tag for logging
#define LOG_TAG "NativeLib"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// The C++ function implementation for the native method.
// Note: It does NOT follow the Java_package_class_method naming convention.
extern "C" JNIEXPORT jstring JNICALL
nativeGetString(JNIEnv* env, jobject /* this */) {
    std::string hello = "Hello from RegisterNatives!";
    return env->NewStringUTF(hello.c_str());
}

// Another native method implementation
extern "C" JNIEXPORT jint JNICALL
nativeAddNumbers(JNIEnv* env, jobject /* this */, jint a, jint b) {
    return a + b;
}
```

2. **Method Registration in `JNI_OnLoad`**

```cpp
// Array of native methods to be registered
static const JNINativeMethod gMethods[] = {
    // { "Java Method Name", "Method Signature", (void*)Native Function Pointer }
    {"stringFromJNI", "()Ljava/lang/String;", (void*)nativeGetString},
    {"addNumbers", "(II)I", (void*)nativeAddNumbers}
};

// Class where the native methods are declared in Java/Kotlin
const char* const kClassName = "com/example/yourapp/MainActivity"; // Update with your actual Java class path

// JNI_OnLoad implementation
extern "C" JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM* vm, void* reserved) {
    JNIEnv* env = nullptr;

    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR; // JNI version not supported
    }

    // 1. Find the Java class
    jclass clazz = env->FindClass(kClassName);
    if (clazz == nullptr) {
        LOGI("JNI_OnLoad: Failed to find class %s", kClassName);
        return JNI_ERR;
    }

    // 2. Register all native methods
    int numMethods = sizeof(gMethods) / sizeof(gMethods[0]);
    if (env->RegisterNatives(clazz, gMethods, numMethods) < 0) {
        LOGI("JNI_OnLoad: Failed to register native methods for %s", kClassName);
        return JNI_ERR;
    }

    // 3. Delete local reference to the class
    env->DeleteLocalRef(clazz);
    
    // Return the JNI version
    return JNI_VERSION_1_6;
}
```

3. **Java/Kotlin Declarations**

```java
// In com.example.yourapp.MainActivity.java
public class MainActivity extends AppCompatActivity {
    static {
        System.loadLibrary("native-lib"); // Loads the shared library
    }

    // Matches {"stringFromJNI", "()Ljava/lang/String;", ...}
    public native String stringFromJNI();
    
    // Matches {"addNumbers", "(II)I", ...}
    public native int addNumbers(int a, int b);
    
    // ... rest of the class
}
```
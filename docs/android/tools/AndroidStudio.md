# Android Studio
- [Description](#description)
- [Installation](#installation)
- [Tips \& Tricks](#tips--tricks)
  - [Android SDK Default Paths](#android-sdk-default-paths)
  - [Android NDK Default Paths](#android-ndk-default-paths)

## Description

**Android Studio** is the official Integrated Development Environment (IDE) for Google's Android operating system, built on JetBrains' IntelliJ IDEA software.

It provides the fastest tools for building apps on every type of Android device. It includes:

- A flexible Gradle-based build system.
- A fast and feature-rich emulator (Android Emulator).
- A unified environment for developing for all Android devices.
- Code templates and GitHub integration.
- Testing tools and extensive debugging and performance profiling capabilities.
- A visual layout editor.

## Installation

The installation process for **Android Studio** is generally straightforward, but it's important to check the system requirements (which vary by OS: **Windows**, **macOS**, **Linux**, and **ChromeOS**) beforehand to ensure optimal performance.

1. **Download:** Navigate to the official Android Developers website and download the latest version of Android Studio for your operating system.

2. **Run Installer:**
   - **Windows/macOS:** Double-click the downloaded executable file. Follow the prompts in the setup wizard. It's usually safe to accept the default configuration settings.
   - **Linux:** Unpack the downloaded `.tar.gz` file and execute the `studio.sh` script located in the `bin/` directory.

3. **Setup Wizard:** Upon the first launch, **Android Studio** will open a Setup Wizard. This wizard helps you:
   - Choose a standard or custom installation.
   - Download and install essential components like the **Android SDK** (Software Development Kit), necessary platform tools, and an **Android Virtual Device** (AVD) for the emulator.

4. **Finish:** Once the wizard completes, Android Studio is ready to use for development.

## Tips & Tricks

### Android SDK Default Paths

|Operating System|Default Android SDK Path|
|--|--|
|**Windows**|`C:\Users\YourUsername\AppData\Local\Android\Sdk`|
|**macOS**|`/Users/YourUsername/Library/Android/sdk`|
|**Linux**|`~/Android/Sdk` or `/home/YourUsername/Android/Sdk`|

### Android NDK Default Paths

The NDK is typically installed as a component **inside** the main Android SDK directory.

|Component|Default Path (relative to **SDK root**)|Notes|
|--|--|--|
|**Current NDK**|`SDK_ROOT/ndk/version_number` (e.g., `ndk/25.1.8937393`)|For Android Studio versions 3.5 and later, NDKs are installed "side-by-side" in versioned folders within the `ndk` directory.|
|**Legacy NDK**|`SDK_ROOT/ndk-bundle`|Used by older versions of Android Studio (pre-3.5). This path is now deprecated.|
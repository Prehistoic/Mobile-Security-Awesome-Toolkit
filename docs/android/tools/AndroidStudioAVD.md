# Android Studio AVD (Android Virtual Device)
- [Description](#description)
- [AVD Setup without Android Studio](#avd-setup-without-android-studio)
- [Creating a New Device](#creating-a-new-device)
- [Using the Emulator](#using-the-emulator)
- [Using AVD CLI](#using-avd-cli)

## Description

The AVD Manager in Android Studio lets you set up virtual devices to run your apps or test security scenarios. An AVD definition includes:

- **Hardware Profile:** Screen size, resolution, RAM, CPU, camera, and other hardware features.
- **System Image:** The version of the Android OS (API level) and architecture (e.g., x86, ARM) to run on the virtual device.
- **Storage Location:** The location of the AVD's user data, SD card, and cache in your development machine.

The **Android Emulator** then uses this AVD configuration to provide a virtual environment that behaves like a real Android device.

## AVD Setup without Android Studio

It's possible to install everything needed for AVD without the trouble of downloading the very heavy Android Studio.

See [AVD Setup without Android Studio](https://github.com/maiz-an/AVD-Setup-without-Andriod-Studio)

Alternative source to download `cmdline-tools` : https://androidsdkmanager.azurewebsites.net/cmdline-tools.html

## Creating a New Device

You can create and manage AVDs using the Device Manager tool in Android Studio.

1. **Open Device Manager:** In Android Studio, go to `Tools → Device Manager` (or click the **Device Manager** icon in the toolbar).

2. **Start Creation:** Click the `Create device` button.

3. **Select Hardware:** Choose a Hardware Profile from the list (e.g., Pixel 8, Nexus 5, or a generic tablet). This defines the device's screen size and hardware capabilities.

4. **Select System Image (OS):** Choose a **System Image** for the AVD.

   - The table shows images by Android version, API level, and architecture (ABI).
   - Images with the **"Download"** link need to be downloaded first. Look for images with the Google APIs or Google Play logo for devices that require Google Play services.

5. **Configure AVD:** Click `Next`. Give your AVD a unique AVD Name and verify the settings (e.g., startup orientation, allocated RAM, internal storage size).

   - For performance, ensure the emulator uses hardware acceleration (HAXM or Hyper-V, depending on your OS).

6. **Finish:** Click `Finish` to create the AVD. The new device will now appear in your Device Manager list.

## Using the Emulator

Once an AVD is created, you can launch it using the **Android Emulator**.

1. **Launch the AVD:** Open the **Device Manager**. In the list of AVDs, click the `Launch` (play/triangle) button next to the device you want to start.

2. **Interaction:** The emulator window will open. You can interact with it just like a physical device:

   - **Install Apps:** Drag and drop an APK file onto the emulator screen, or use the ADB install command from your computer's terminal.
   - **Control Buttons:** Use the virtual control buttons on the emulator (e.g., Power, Volume, Home, Back).
   - **Sensors:** The emulator provides controls to simulate various sensors and hardware features like location (GPS), camera input, cellular network, and battery status.

## Using AVD CLI

You can also manage AVDs and the emulator using command-line tools. They are located in your Android SDK's `cmdline-tools/latest/bin/` or `emulator/` directories.

- **Creating an AVD**

```sh
avdmanager create avd --name MyTestDevice --abi google_apis/x86_64 --package "system-images;android-34;google_apis;x86_64"
```

**`--package` option**

```sh
"system-images;android-API_LEVEL;VARIANT;ABI"
```

|Segment|Meaning|Example Values|
|--|--|--|
|`system-images`|Always static, specifies the package type.|`system-images`|
|`android-API_LEVEL`|The Android API Level (OS version).|`android-34`, `android-Tiaramisu`|
|`VARIANT`|The "flavor" of the system image.|`google_apis`, `default`, `android-tv`, `google_apis_playstore`|
|`ABI`|The CPU architecture of the system image.|`x64_64`, `x86`, `armeabi-v7a`, `arm64-v8a`|

**`--abi` option**

```sh
"VARIANT/ABI"
```

|Segment|Meaning|Example Values|
|--|--|--|
|`VARIANT`|The "flavor" of the system image.|`google_apis`, `default`, `android-tv`, `google_apis_playstore`|
|`ABI`|The CPU architecture of the system image.|`x64_64`, `x86`, `armeabi-v7a`, `arm64-v8a`|

- **Listing all existing AVDs**

```sh
avdmanager list avd
```

- **List all ready-to-use AVDs**

```sh
emulator -list-avds
```

- **Start the Android Emulator for a specific AVD**

```sh
emulator -avd MyTestDevice
```

- **Force Kill an Emulator**

```sh
adb -s emulator-5554 emu kill
```
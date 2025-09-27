# ADB

- [Description](#description)
- [Installation](#installation)
  - [Enable USB Debugging](#enable-usb-debugging)
  - [Download SDK Platform-Tools](#download-sdk-platform-tools)
- [Commands](#commands)
  - [adb devices](#adb-devices)
  - [adb root](#adb-root)
  - [adb push/pull](#adb-pushpull)
  - [adb install/uninstall](#adb-installuninstall)
  - [adb shell](#adb-shell)
    - [adb shell pm](#adb-shell-pm)
    - [adb shell am](#adb-shell-am)
    - [adb shell content](#adb-shell-content)
    - [Other useful commands](#other-useful-commands)
  - [adb logcat](#adb-logcat)
  - [adb reboot](#adb-reboot)
  - [adb start/kill-server](#adb-startkill-server)
  - [adb tcpip](#adb-tcpip)
  - [adb connect](#adb-connect)
  - [adb forward](#adb-forward)
  - [adb backup/restore](#adb-backuprestore)
  - [adb sideload](#adb-sideload)
  - [adb remount](#adb-remount)
  - [adb wait-for-device](#adb-wait-for-device)


## Description

Android Debug Bridge (ADB) is a command-line tool that allows you to communicate with an Android device from a computer. It acts as a "bridge" between your development machine (the client) and an Android device or emulator (the daemon). ADB is a core component of the Android SDK (Software Development Kit) and is essential for developers, but it's also used by advanced users to gain more control over their devices.

Android Debug Bridge (ADB) is a command-line tool that allows you to communicate with an Android device from a computer. It acts as a "bridge" between your development machine (the client) and an Android device or emulator (the daemon). ADB is a core component of the Android SDK (Software Development Kit) and is essential for developers, but it's also used by advanced users to gain more control over their devices.

The ADB system is made up of three parts:

- **Client**: This runs on your computer and sends commands. You interact with it through a terminal or command prompt.
- **Daemon (adbd)**: This runs as a background process on the Android device and executes the commands sent from the client
- **Server**: This runs on your computer as a background process and manages the communication between the client and the daemon.

This client-server architecture allows you to perform a wide range of actions on your Android device from your computer, either through a USB connection or over Wi-Fi

## Installation

### Enable USB Debugging

- Go to **Settings** > **About phone**.
- Tap on **"Build number"** seven times to unlock **"Developer options"**.
- Go back to **Settings** and you'll find **"Developer options"** (usually under "System" or "Additional settings").
- Inside **"Developer options"**, enable **"USB debugging"**.

When you connect your device, you'll likely see a prompt on your phone asking you to "Allow USB debugging". Tap **"Allow"** and optionally check "Always allow from this computer".

### Download SDK Platform-Tools

- Go to the official Android Developers website: https://developer.android.com/studio/releases/platform-tools
- Download the appropriate ZIP file for your operating system
- Extract the contents of the ZIP file to an easily accessible location on your computer (e.g., C:\adb on Windows, ~/platform-tools or ~/.android-sdk-macosx/platform-tools on macOS/Linux).

## Commands

### adb devices

`adb devices` list all connected devices and their corresponding serial numbers.

Sample output :
```
List of devices attached
emulator-5554   device
8a928c2         device
```

It's possible to get more details with `adb devices -l`

```
List of devices attached
emulator-5554          device product:sdk_gphone_x86 model:sdk_gphone_x86 device:generic_x86_arm
8a928c2                device usb:1-5 product:walleye model:Pixel_2XL device:walleye transportid:1
```

If several devices are attached, it is necessary to specify which one to target. The syntax is

```
adb -s [serial_number] [command]
```

For convenience, ADB also offers a few other flags to target devices when a single type is connected:

- `-d`: Directs the command to the **only attached USB device**
- `-e`: Directs the command to the **only running emulator**

### adb root

By default ADB starts in non-root mode. If the phone is rooted it's possible to start it in **root mode** which will allow to run more privileged commands.

```
adb root
```

### adb push/pull

`adb push` and `adb pull` respectively allow to upload and download files.

```
adb push sample.txt /sdcard/
adb pull /sdcard/sample.txt .
```

### adb install/uninstall

`adb install` allows to install an APK file to the connected device.

```
adb install [path_to_apk]
```

It will fail if an app with the same package name is already installed (`INSTALL_FAILED_ALREADY_EXISTS`). To install a new version of an existing app the `-r` flag is needed (used to be `-k` in the past).

```
adb install -r [path_to_apk]
```

Note that applications installed with adb will by default go to internal storage. If (especially for storage volume reasons) you need to install an app in **shared storage**, you can use the `-s` flag.

```
adb install -s [path_to_apk]
```

(This is not really needed on newer Android versions, the app management there handles storage location automatically)

It is also possible to install several apps at the same time (useful for multidex apps)

```
adb install-multiple app1.apk app2.apk app3.apk
```

Finally to remove an existing app :

```
adb uninstall [package_name]
```

### adb shell

`adb shell` allows to open a shell on the connected device. This gives access to many binaries. Here below a list of useful shell commands

#### adb shell pm

`pm` for Package Manager holds some very useful commands to manage apps on the device.

- List installed packages
```
adb shell pm list packages
```
- Get storage path for an app
```
adb shell pm path [package_name]
```
- List user accounts
```
adb shell pm list users
```
- Hide packages (useful for disabling pre-installed apps)
```
adb shell pm hide [package_name]
```

#### adb shell am

`am` for Activity Manager holds some very useful commands to interact with exposed components.

`am start` can be used to launch activities

- Launch an Activity by Component Name
```
adb shell am start -n com.example.app/.MainActivity
```
- Launch an Activity with an Action and Data
```
adb shell am start -a android.intent.action.VIEW -d https://www.google.com
```
- Launch an Activity with Extras
```
adb shell am start -n com.example.app/.DisplayMessageActivity --es "message" "Hello from ADB"
```

`am broadcast` is used to send a broadcast intent

- Send a Broadcast by Action
```
adb shell am broadcast -a com.example.app.MY_CUSTOM_ACTION
```
- Send a Broadcast to a specific Receiver
```
adb shell am broadcast -n com.example.app/.MyReceiver -a com.example.app.MY_CUSTOM_ACTION
```
- Send a Broadcast with Extras
```
adb shell am broadcast -a com.example.app.MY_CUSTOM_ACTION --es "data_key" "some_value"
```

#### adb shell content

`content` is used to interact with Content Provider's data. It supports standard SQL-like operations: `query`, `insert`, `update` and `delete`. The `content://` URI is required.

- Query a Content Provider
```
adb shell content query --uri content://settings/secure --where "name='default_input_method'"
```
- Insert a row in a Content Provider
```
adb shell content insert --uri content://settings/secure --bind name:s:my_new_setting --bind value:s:test_value
```
- Update an existing record
```
adb shell content update --uri content://settings/secure -bind value:s:new_value --where "name='my_new_setting'"
```
- Delete a record
```
adb shell content delete --uri content://settings/secure --where "name='my_new_setting'"
```

#### Other useful commands

- Take a screenshot
```
adb shell screencap /sdcard/screenshot.png
```
- Record the screen
```
adb shell screenrecord /sdcard/recording.mp4
```
- Get detailed info about system services
```
adb shell dumpsys batteryinfo
```
- Get / set system properties
```
adb shell setprop ro.sf.lcd_density 240
adb shell getprop ro.product.cpu.abi
```
- Simulate user input
```
adb shell input tap 500 700
adb shell input text "Hello, Android!"
adb shell input swipe 100 500 300 500
adb shell input keyevent 24
```

### adb logcat

`adb logcat` allows to see the device's logs.

Use the `-c` flag to clear the cache :

```
adb logcat -c
```

Use the `-d` flag to save logs to a file :

```
adb logcat -d [path_to_file]
```

### adb reboot

`adb reboot` will restart the device.

### adb start/kill-server

`adb start-server` and `adb kill-server` allow to start or finish the current ADB server. Can be useful if it becomes unresponsive.

### adb tcpip

`adb tcpip` allows to switch from USB to TCP/IP mode for ADB connections (to connect wirelessly)

```
adb tcpip 5555
```

### adb connect

In TCP/IP mode, `adb connect` allows to connect to the Android device.

```
adb connect [device_ip]:[port]
```

### adb forward

`adb forward` allows to set up port forwarding between your computer and Android device.

```
adb forward tcp:5000 tcp:6000
```

### adb backup/restore

`adb backup` can be used to create a backup of the device or of specific apps.

Creating a full backup of all app data :
```
adb backup -all -f backup.ab
```

Creating a backup of a single application
```
adb backup -f backup.ab [package_name]
```

**Useful options and flags**
- `-apk` includes the APK files
- `-system` includes system apps' data
- `-shared` includes the device's shared storage

`adb restore` can then be used to restore an existing backup.

```
adb restore backup.ab
```

### adb sideload

`adb sideload` can be used to flash zip files, especially OTA updates without transferring them first

```
adb sidelod update.zip
```

### adb remount

`adb remount` remounts the `/system`, `/vendor` and `/oem` partitions from read-only (ro) to read-write (rw) mode.

This command requires root access on the device. Need to run `adb root` first.

**Note:** on Android 7.0+ there are security measures that will prevent that. To disable them use `adb disable-verity`, might need `adb reboot` after.

**Alternative:** If `adb remount` fails, you can try the following commands :
```
adb shell
su
mount -o rw,remount /system
```

### adb wait-for-device

`adb wait-for-device` can be used to wait for a device to be connected to run a script. Useful for automation purposes !

```
adb wait-for-device shell [command]
```
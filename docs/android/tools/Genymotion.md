# Genymotion

## Description

**Genymotion** is a fast, powerful, and easy-to-use Android emulator that is used by developers and security professionals to test Android applications in a virtual environment.

## Installation

The **Genymotion Desktop** version is the most common choice.

### Prerequisites
- **Host Operating System:** Windows, macOS, or Linux.
- **Account:** A **Genymotion account** is required, even for the free "Personal Use" edition. Create one [here](https://www-v1.genymotion.com/account/create/)

### Step-by-Step Install Guide (Windows)

1. **Download Genymotion Installer** for Windows from the [official website](https://www.genymotion.com/product-desktop/download/)

2. **Run the Installer**
    - Execute the downloaded installer
    - If you chose the version with Virtualbox, ensure you allow it to install as well
    - Follow on-screen prompts for a standard installation

3. **Launch Genymotion and Log In**
   - Start the Genymotion app
   - Log in using the credentials created on their website
   - When prompted, choose **"Personal Use"** license option

### Step-by-Step Install Guide (Linux)

1. **Download Genymotion Installer** for Linux from the [official website](https://www.genymotion.com/product-desktop/download/)

2. **Launch Genymotion and Log In**
   - Execute the installer from a command line
   - Log in using the credentials created on their website
   - When prompted, choose **"Personal Use"** license option

## Creating a new Virtual Device

- Click the **"+" (Add)** button
- **Choose a Template:** Select an Android device template and an Android API level
- **Select/Install GApps (Optional but Recommended):** When prompted select a version **with** or **without** GApps depending on needs
- **Configure Device Settings:** Set a name, memory/CPU allocation... and click **"Install"**

**Note:** Root Access is enabled by default for Android 5.5-11 but requires a **paying license** for Android 12 and above !

## Rooting Virtual Device (Android 12+)

1. Download [RootToggle APK](https://gist.github.com/zlocate/0602976452215ff84901c1b032e91a4b/raw/86c2ec50995d9415e22ff188f6b68ca494c35c10/RootToggle-signed.apk)

2. Install RootToggle as a System App
    - **Load the NBD (Network Block Device) Module**

        ```sh
        sudo modprobe ndb
        ```

    - **Attach the QCOW2 Disk Image**

        ```sh
        sudo qemu-nbd --connect=/dev/nbd0 ~/.Genymobile/Genymotion/deployed/<device_name>/system.qcow2
        ```

    - **Identify the System Partition**

        Run `fdisk -l` to confirm the correct partition (usually `/dev/nbd0p4` for large partitions) 

    - **Mount the System Partition**

        ```sh
        sudo mkdir -p /mnt/android_system
        sudo mount /dev/nbd0p4 /mnt/android_system
        # You should see directories typical of an Android device in /mnt/android_system. 
        # If not you might have chosen the wrong partition
        ```

    - **Create the App Directory**

        ```sh
        sudo mkdir -p /mnt/android_system/system/priv-app/RootToggle
        ```

    - **Copy the Signed APK**

        ```sh
        sudo cp RootToggle-signed.apk /mnt/android_system/system/priv-app/RootToggle/RootToggle.apk
        ```

    - **Set the Correct Permissions**

        ```sh
        sudo chmod 644 /mnt/android_system/system/priv-app/RootToggle/RootToggle.apk
        ```

    - **Unmount and Disconnect**

        ```sh
        sudo umount /mnt/android_system
        sudo qemu-nbd --disconnect /dev/nbd0
        ```

3. Start the Emulator

Start your **Genymotion** emulator as usual. The `RootToggle` app should now be installed as a system app with the necessary permissions to modify `persist.sys.root_access`.

### Compiling RootToggle from source

1. Download source from [here](https://gist.github.com/zlocate/0602976452215ff84901c1b032e91a4b/raw/86c2ec50995d9415e22ff188f6b68ca494c35c10/RootToggle.zip)

2. Build the APK: Open project in Android Studio and build the APK or use Gradle

```sh
./gradlew assembleRelease
```

3. Locate the unsigned APK: after building it will be in `app/build/outputs/apk/release`

4. Get Platform Keys: `platform.pk8` and `platform.x509.pem` from [here](https://web.archive.org/web/1/https://github.com/Genymobile/genymotion_platform_vendor_genymotion_security_public/archive/refs/heads/master.zip)

```sh
git clone https://github.com/Genymobile/genymotion_platform_vendor_genymotion_security_public
cp genymotion_platform_vendor_genymotion_security_public/release-keys/platform* .
```

5. Sign the APK with the Platform Keys

```sh
/path/to/build-tools/<version>/apksigner sign \
  --key platform.pk8 \
  --cert platform.x509.pem \
  --out RootToggle-signed.apk \
  app/build/outputs/apk/release/app-release-unsigned.apk
```

**Source:** [How to root Genymotion devices.md](https://gist.github.com/zlocate/0602976452215ff84901c1b032e91a4b)


# Intercepting Android App Traffic
- [Prerequisites and Initial Setup](#prerequisites-and-initial-setup)
  - [Burp Suite Setup](#burp-suite-setup)
  - [Android Device Proxy Configuration](#android-device-proxy-configuration)
  - [Export Burp's CA Certificate](#export-burps-ca-certificate)
- [Intercepting Traffic on Android ≤ 6.0](#intercepting-traffic-on-android--60)
- [Intercepting Traffic on Android ≥ 7.0 \& ≤ 13.0](#intercepting-traffic-on-android--70---130)
  - [Method 1: Patching the App](#method-1-patching-the-app)
  - [Method 2: Root \& System CA installation](#method-2-root--system-ca-installation)
- [Intercepting Traffic on Android ≥ 14.0](#intercepting-traffic-on-android--140)
- [Troubleshooting \& Common Issues](#troubleshooting--common-issues)

## Prerequisites and Initial Setup

### Burp Suite Setup

1. **Start Burp Suite**: Ensuire Burp Proxy is running, typically on `127.0.0.1:8080`
2. **Configure Proxy Listener**: In Burp, go to `Proxy` --> `Options`
   - Add a new listener (or modify the default) to bind an IP address accessible by your Android device (e.g., your **host machine's Wi-Fi adapater IP**)
   - Set the **Port** (e.g., `8080`)
   - Set **Bind to address** to `All interfaces` or to the specific IP of your host machine on the same network as the Android device

### Android Device Proxy Configuration

1. **Connect Devices**: Ensure your Burp host machine and the Android device are on the **same Wi-Fi network**
2. **Configure Proxy**: On the Android device, go to Wi-Fi Settings
   - Long press/tap on the connected Wi-Fi network
   - Set the **Proxy** to `Manual`
   - Put the IP address of the Burp host machine as **Proxy hostname** and the port configured in Burp (e.g., `8080`) as **Proxy port**

### Export Burp's CA Certificate

To intercept HTTPS traffic, the Android device must trust Burp's self-signed CA certificate.

1. In Burp, go to `Settings` --> `Tools` --> `Proxy` --> `Proxy Listeners`
2. Click `Import / Export CA Certificate`
3. Select `Export` --> `Certificate in DER format` (or PEM, depending on Android version)
4. Save the file (e.g., `burp.der` or `burp.crt`)
5. Transfer the certificate file to the Android device's storage (e.g., using ADB)

**Convert DER Certificate to PEM**

```sh
openssl x509 -inform DER -in burp.der -out burp.pm
```

## Intercepting Traffic on Android ≤ 6.0

For older Android versions, apps by default trust both **system** CAs and **user-added** CAs (installed by the user or an administrator). This makes interception relatively straightforward.

**Installation Steps**
1. Navigate to the saved Burp CA certificate file (`burp.der` or `burp.crt`) and tap on it
2. You will be prompted to install the certificate
   - Choose a **Certificate Name** (e.g., "Burp Proxy")
   - Select `VPN and apps` (or `Credential use`) as the credential usage
   - You must have a lock screen PIN, pattern or password to install a user certificate
3. Once installed the Burp CA should be added to the device's **user trust store**

## Intercepting Traffic on Android ≥ 7.0 & ≤ 13.0

Starting with Android 7.0 (API level 24), apps no longer trust **user-added** CAs by default for secure connections. They only trust **system** CAs. This is a significant security enhancement.

### Method 1: Patching the App

This is the preferred method for **whitebox testing**.

If you have control over the app's manifest (source code or APK modification), you can tell the app to trust user-added CAs for debugging purposes using the **Network Security Configuration** (NSC) feature.

1. Decompile APK

```sh
apktool d -rs target.apk
```

2. Create or update `network_security_config.xml`

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="user" />
            <certificates src="system" />
        </trust-anchors>
    </base-config>
</network-security-config>
```

3. Add the new NSC in `AndroidManifest.xml` and make the app debuggable

```xml
<application android.debuggable="true" android:networkSecurityConfig="@xml/network_security_config">
...
</application>
```

4. Follow [preceding instructions](#intercepting-traffic-on-android--60) to install the Burp CA as a **user** certificate

5. Re-package and Install

```sh
apktool b target
```

---

### Method 2: Root & System CA installation

This is the preferred method for blackbox testing (when you can't modify the app's code). You must install Burp's CA certificate into the **system trust store**.

This requires a **rooted device** or **emulator**.

1. **Get Certificate Hash** (must be in **PEM** format !)

```sh
openssl x509 -inform PEM -subject_hash_old -in burp.pem | head -1
```

2. **Rename the Certificate**: rename PEM file using the hash and a `.0` extension (e.g., `9a5ba575.0`)

3. **Mount and Copy**: Use ADB with root privileges to remount the system partition as read-write and copy the file to the system's CA directory

```sh
# Push the renamed file
adb push 9a5ba575.0 /sdcard/

# Connect to device shell
adb shell
su

# Remount /system or /vendor (depending on device and Android version)
mount -o rw,remount /system

# Copy certificate to the system CA store
cp /sdcard/9a5ba575.0 /system/etc/security/cacerts/

# Set correct permissions
chmod 644 /system/etc/security/cacerts/9a5ba575.0

# Reboot
reboot
```

**Note 1**: this method can be automated by using [burpDrop](../tools/burpDrop.md)

**Note 2**: this method might not work on devices where the Conscrypt module was updated through a Google Play Services Update. Please refer to the next method below 

## Intercepting Traffic on Android ≥ 14.0

With Android 14, Google moved the core system root certificates into the **Conscrypt Mainline APEX module** (`com.android.conscrypt`). This allows Google to update this component via Google Play System Updates (GPSU) without a full OTA update.

This makes the traditional location (`/system/etc/security/cacerts`) secondary.
- **New Primary Location**: Conscrypt prioritizes certificates found within its APEX module folder : `/apex/com.android.conscrypt/cacerts`
- **Fallback**: The legacy `/system/etc/security/cacerts` folder is now only used as a fallback if the APEX directory is empty or non-existent

To circumvent this use the [AlwaysTrustUserCerts](https://github.com/NVISOsecurity/AlwaysTrustUserCerts) Magisk module.

More info at [Intercepting Traffic on Android with Mainline and Conscrypt](https://blog.nviso.eu/2025/06/05/intercepting-traffic-on-android-with-mainline-and-conscrypt/)

## Troubleshooting & Common Issues

See [Troubleshooting Interception Common Issues](./troubleshooting-interception-common-issues.md)
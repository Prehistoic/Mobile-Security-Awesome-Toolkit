# Resigning an APK
- [Prerequisites](#prerequisites)
- [Step 1: Generate a new Keystore](#step-1-generate-a-new-keystore)
- [Step 2: Zipalign the APK](#step-2-zipalign-the-apk)
- [Step 3: Sign the APK](#step-3-sign-the-apk)
- [Alternative: Uber Apk Signer](#alternative-uber-apk-signer)

## Prerequisites
- **Android SDK Build-Tools** : Grant access to `zipalign` and `apksigner`. You can find them in the `build-tools` directory of your SDK installation (e.g. `C:\Users\Username\AppData\Local\Android\Sdk\build-tools\version` in Windows)
- **Java Development Kit (JDK)**
- **A Signing Key**: You need a keystore containing a private key. We'll see below how to generate a new one if needed

## Step 1: Generate a new Keystore

If you don't already have a keystore, you need to create one.

```
keytool -genkey -v -keystore my-release-key.jks -alias -my-alias -keyalg RSA -keysize 2048 -validity 10000
```

This command will prompt you for a password the keystore, a password for the key itself and some personal information.

## Step 2: Zipalign the APK

```
zipalign -v 4 my-unsigned-app.apk my-aligned-app.apk
```

## Step 3: Sign the APK

```
apksigner sign --ks my-release-key.jsk --out my-signed-app.apk my-aligned-app.apk
```

## Alternative: Uber Apk Signer

See [Uber Apk Signer](../tools/uber-apk-signer.md)
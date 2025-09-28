# Uber Apk Signer
- [Description](#description)
- [Installation](#installation)
- [Usage](#usage)

## Description

Uber Apk Signer is a tool that helps to sign, zip align and verify multiple APKs with either debug or provided release certificates.

It supports all Android signing schemes from v1 to v4.

## Installation

**Requirements**
- JDK 8+
- On Linux 32bit: `zipalign` must be set in PATH

[Grab jar from the latest relase](https://github.com/patrickfav/uber-apk-signer/releases/latest)

## Usage

- Basic usage

```
java -jar uber-apk-signer.jar --apks /path/to/apks
```

- Overriding signature on already signed APK

```
java -jar uber-apk-signer.jar --apks /path/to/signed/apk --allowResign
```

- Signing with a provided key

```
java -jar uber-apk-signer.jar --apks /path/to/apks --ks [keystore] --ksPass [keystore_password] --ksAlias [key_alias] --ksKeyPass [key_password]
```

- Verify APK signature

```
java -jar uber-apk-signer.jar --apks /path/to/apks -y
```
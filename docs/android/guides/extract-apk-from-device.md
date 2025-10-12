# Extract APK from Device
- [Step 1: Find the Package Name](#step-1-find-the-package-name)
- [Step 2: Get the APK File Path](#step-2-get-the-apk-file-path)
- [Step 3: Pull the APK File](#step-3-pull-the-apk-file)

## Step 1: Find the Package Name

```sh
adb shell pm list packages
```

To narrow down the list, can use `grep` (MacOS/Linux) or `findstr` (Windows)

```sh
adb shell pm list packages | grep 'keyword'
adb shell pm list packages | findstr "keyword"
```

## Step 2: Get the APK File Path

```sh
adb shell pm path [package_name]
```

The command will return the full path, which should look like this :

```sh
package:/data/app/com.android.chrome-abcdefg==/base.apk
```

## Step 3: Pull the APK File

```sh
adb pull /data/app/com.android.chrome-abcdefg==/base.apk .
```

Good practice would be to rename `base.apk` to something more specific !
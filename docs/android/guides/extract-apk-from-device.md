# Extract APK from Device

## Step 1: Find the Package Name

```
adb shell pm list packages
```

To narrow down the list, can use `grep` (MacOS/Linux) or `findstr` (Windows)

```
adb shell pm list packages | grep 'keyword'
adb shell pm list packages | findstr "keyword"
```

## Step 2: Get the APK File Path

```
adb shell pm path [package_name]
```

The command will return the full path, which should look like this :

```
package:/data/app/com.android.chrome-abcdefg==/base.apk
```

## Step 3: Pull the APK File

```
adb pull /data/app/com.android.chrome-abcdefg==/base.apk .
```

Good practice would be to rename `base.apk` to something more specific !
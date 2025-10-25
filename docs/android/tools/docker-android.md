# Docker-Android
- [Description](#description)
- [List of Docker images](#list-of-docker-images)
- [List of Devices](#list-of-devices)
- [Usage](#usage)
- [WSL2 Hardware acceleration (Windows 11 only)](#wsl2-hardware-acceleration-windows-11-only)
- [Useful Automation scripts](#useful-automation-scripts)

## Description

**Docker-Android** is a docker image built to be used for everything related to Android. It can be used for Application development and testing (native, web and hybrid-app).

**Github repository :** https://github.com/budtmo/docker-android

## List of Docker images

|Android|API|Image with latest release version|Image with specific release version|
|--|--|--|--|
|9.0|28|budtmo/docker-android:emulator_9.0|budtmo/docker-android:emulator_9.0_<release_version>|
|10.0|29|budtmo/docker-android:emulator_10.0|budtmo/docker-android:emulator_10.0_<release_version>|
|11.0|30|budtmo/docker-android:emulator_11.0|budtmo/docker-android:emulator_11.0_<release_version>|
|12.0|32|budtmo/docker-android:emulator_12.0|budtmo/docker-android:emulator_12.0_<release_version>|
|13.0|33|budtmo/docker-android:emulator_13.0|budtmo/docker-android:emulator_13.0_<release_version>|
|14.0|34|budtmo/docker-android:emulator_14.0|budtmo/docker-android:emulator_14.0_<release_version>|
|-|-|budtmo/docker-android:genymotion|budtmo/docker-android:genymotion_<release_version>|

## List of Devices

|Type|Device Name|
|--|--|
|Phone|Samsung Galaxy S10|
|Phone|Samsung Galaxy S9|
|Phone|Samsung Galaxy S8|
|Phone|Samsung Galaxy S7 Edge|
|Phone|Samsung Galaxy S7|
|Phone|Samsung Galaxy S6|
|Phone|Nexus 4|
|Phone|Nexus 5|
|Phone|Nexus One|
|Phone|Nexus S|
|Tablet|Nexus 7|
|Tablet|Pixel C|

## Usage

**Requirements**: 
- Docker installed
- Virtualization supported and enabled. Can be checked with :

```sh
sudo apt install cpu-checker
kvm-ok
```

1. **Run Docker-Android Container**

```sh
docker run -d -p 6080:6080 -e EMULATOR_DEVICE="Samsung Galaxy S10" -e WEB_VNC=true --device /dev/kvm --name android-container budtmo/docker-android:emulator_11.0
```

2. **Open http://localhost:6080**

3. **Check Emulator Status**

```sh
docker exec -it android-container cat device_status
```

## WSL2 Hardware acceleration (Windows 11 only)

1. Add yourself to the `kvm` usergroup

```sh
sudo usermod -a -G kvm ${USER}
```

2. Add necessary flags to `/etc/wsl.conf`

```
[boot]
command = /bin/bash -c 'chown -v root:kvm /dev/kvm && chmod 660 /dev/kvm'

[wsl2]
nestedVirtualization=true
```

3. Restart WSL2 via CMD prompt or Powershell

```sh
wsl --shutdown
```

## Useful Automation scripts

- [start_docker_android_emulator.sh](../resources/start_docker_android_emulator.sh)
- [stop_docker_android_emulator.sh](../resources/stop_docker_android_emulator.sh)

**Note:** these scripts must be run as root !
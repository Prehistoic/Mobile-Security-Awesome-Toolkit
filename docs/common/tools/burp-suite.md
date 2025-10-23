# Burp Suite
- [Description](#description)
- [Installation](#installation)
- [Usage](#usage)
  - [Android](#android)
  - [iOS](#ios)

## Description

**Burp Suite**, developed by PortSwigger, is a popular and comprehensive software platform for performing security testing of web applications.

When it comes to mobile security testing, we mainly use **Burp Proxy** which is an Intercepting Proxy, allowing us to intercept, inspect and modify the raw HTTP/S traffic passing between the application and its server.

Burp Suite comes with many other features such as **Vulnerability Scanning**, **Target**, **Site Map**, **Repeater**, **Intruder**... which we won't cover for now in this guide.

## Installation

Burp Suite comes in different versions :
- **Community Editon** : free, contains essential manual tools (including Proxy)
- **Professional Edition** : paid, contains additional automated tools like Burp Scanner, Intruder...
- **Enterprise Edition** : higher-tier pricing, designed for DAST at scale

We'll focus on the Community/Professional Edition as they are pretty much the same in terms of the features we want for mobile security testing.

1. **Download the Installer**
   - Go to [PortSwigger website's download page](https://portswigger.net/burp/releases)
   - Select desired version
   - Download the installer file
2. **Run the Installer**
   - Execute the download file. For Linux you might have to use `sudo sh <installer-file.sh> -c` from the command line
   - Follow the on-screen prompts of the installation wizard
3. **Launch and Configure**
   - Once installed, launch Burp Suite
   - If prompted, choose to start with **temporary project** and **Burp Defaults**. If you chose Professional Edition you will be prompted to enter your license key

## Usage

### Android

See [Intercepting Android App Trafic](../../android/guides/intercepting-android-app-traffic.md)

### iOS

TO DO
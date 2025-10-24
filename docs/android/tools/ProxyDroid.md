# ProxyDroid
- [Description](#description)
- [Installation](#installation)
- [Usage](#usage)

## Description

**ProxyDroid** is an Android application designed to help users set a proxy (HTTP/HTTPS/SOCKS4/SOCKS5) on their Android devices. Its key advantage for security analysis is that it forces all internet traffic, or traffic from specific applications, through a specified proxy server by leveraging iptables (a Linux firewall utility).

This is particularly useful because many Android applications ignore the system's global Wi-Fi proxy settings. By using **ProxyDroid** on a rooted device, you can ensure that traffic from a target application is redirected to an intercepting proxy like Burp Suite or mitmproxy for inspection and manipulation.

**IMPORTANT !** ProxyDroid must be run on a rooted Android device as it modifies network settings using `iptables`

## Installation

**ProxyDroid** can be download from the Google Play Store : https://play.google.com/store/apps/details?id=org.proxydroid&hl=en&gl=US

## Usage

The primary use case is forcing application traffic through a testing proxy (e.g., Burp Suite running on your host machine) to intercept and analyze network communication.

1. **Set up Your Intercepting Proxy**

On your computer, launch your proxy tool (e.g., Burp Suite).

Configure the listener (e.g., on port `8080`) to listen on the IP address of your host machine that is reachable by the Android device (e.g., an IP on the same Wi-Fi network).

2. **Install Proxy Certificate**

Before proxying HTTPS traffic, you must install your proxy's CA certificate (e.g., Burp's CA cert) onto the Android device. For modern Android versions and to intercept traffic from apps that don't respect user-installed certificates, you typically need to install the certificate into the System Trust Store, which requires a rooted device.

See [Intercepting Android App Traffic](../guides/intercepting-android-app-traffic.md)

3. **Configure ProxyDroid**

- Open ProxyDroid on the Android device.
- Toggle the main Proxy Switch (at the top) to On. You will be prompted for Superuser/Root access; grant it.
- Configure the following settings:
  - **Host**: Enter the IP address of your intercepting proxy (your computer's IP).
  - **Port**: Enter the Port Number your proxy is listening on (e.g., 8080).
  - **Proxy** Type: Select HTTP.
  - **Individual proxy**: Enable this option. This is the best practice for pentesting. Tap on this setting, and select only the application(s) whose traffic you want to analyze. This avoids system-wide connectivity issues with apps that may perform SSL Pinning checks or that you do not need to monitor.
  - **Global Proxy**: (Optional/Alternative) If you want all traffic from all apps to go through the proxy, enable this instead of "Individual proxy." Use this with caution, as it can be disruptive.
  - **Bypass proxy for**: Optionally list local IP addresses or hostnames that should not use the proxy.

4. **Test and Analyze**

- Launch the target application on the Android device.
- Perform actions that generate network requests.
- Verify that the traffic is being successfully intercepted and displayed in your proxy tool (e.g., Burp Suite's "HTTP History" tab).

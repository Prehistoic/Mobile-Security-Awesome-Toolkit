# WireShark
- [Description](#description)
- [Installation](#installation)
- [Usage](#usage)
  - [Technique 1: Intercepting Traffic from an HTTP/S Proxy (Recommended)](#technique-1-intercepting-traffic-from-an-https-proxy-recommended)
  - [Technique 2: Capturing Traffic Directly from the Network (Ad-hoc Wi-Fi)](#technique-2-capturing-traffic-directly-from-the-network-ad-hoc-wi-fi)
  - [Technique 3: Direct Device Capture (Root/ADB)](#technique-3-direct-device-capture-rootadb)
  - [Advanced Analysis (Post-Capture)](#advanced-analysis-post-capture)

## Description

**Wireshark** is the world's foremost and widely-used network protocol analyzer. It is a free, open-source tool that allows security professionals, network engineers, and developers to capture and interactively browse the traffic running on a computer network.

For mobile application penetration testing, Wireshark is invaluable because it:

- **Captures Raw Packets:** It provides a granular view of network communication, showing the raw data at the Ethernet, IP, TCP, and application layers. This is lower-level than an application-layer proxy (like Burp Suite).
- **Deep Protocol Inspection:** It understands and can dissect (decode) hundreds of protocols, allowing you to see the structure and contents of non-HTTP/HTTPS traffic (e.g., DNS, custom TCP/UDP protocols, control plane signaling).
- **Identifies Custom/Non-Standard Communications:** It helps detect applications using non-standard ports or protocols that bypass a typical HTTP/S proxy configuration.

## Installation

Wireshark is not installed on the mobile device itself (though tools like tcpdump or PCAP apps can be used to generate captures on the device). It is installed on your host computer (the pentest workstation).

1. **System Requirements:** Wireshark runs on all major platforms: Windows, macOS, and Linux (including Kali Linux, where it is often pre-installed)

2. **Download:**

   - Navigate to the [official Wireshark website](wireshark.org)
   - Download the appropriate installer for your operating system

3. **Installation on Windows/macOS:**

   - Run the installer. During the installation process, you will be prompted to install **Npcap** (on Windows) or **Wireshark's supporting services** (on macOS/Linux). This is mandatory as it provides the driver necessary for Wireshark to capture live packets from your network interfaces

4. **Verification:** Launch Wireshark. You should see a list of available network interfaces (e.g., Wi-Fi, Ethernet, Loopback, VPN adapters).

## Usage

The main challenge is getting the mobile device's traffic to flow through an interface that your host machine, running Wireshark, can see.

### Technique 1: Intercepting Traffic from an HTTP/S Proxy (Recommended)

This is the most common and effective method, as it allows you to analyze decrypted application traffic.

1. **Prerequisites:** You must have an intercepting proxy (like Burp Suite) set up and configured on your host machine, and the mobile application traffic must be successfully forced through it (e.g., using ProxyDroid on a rooted Android device, as outlined previously)

2. **Wireshark Capture:**
   - In Wireshark, select the network interface on your host machine that is communicating with the mobile device (e.g., your Wi-Fi or Ethernet interface)
   - Start the capture

3. **Filtering:** To focus on the proxied application data, use a Display Filter to target the proxy's IP and port.

   - **Filter:** `host <mobile_device_ip> and tcp port <proxy_port>`
  - This shows the traffic between the mobile device and your proxy

### Technique 2: Capturing Traffic Directly from the Network (Ad-hoc Wi-Fi)

This is used for analyzing non-HTTP/S traffic or when an application uses a protocol that a standard proxy cannot handle.

1. **Setup:**
   
   - Ensure both your host machine (running Wireshark) and the target mobile device are connected to the same Wi-Fi network.

   - **Crucial Caveat:** On typical switched networks, your PC can only "see" broadcast and its own direct traffic. To see traffic between the phone and the router, you need to use a technique to direct the traffic to your PC, such as:

     - **ARP Spoofing/MITM:** (Advanced, requires tools like [Ettercap](https://www.ettercap-project.org/index.html)) Position your host machine as a Man-in-the-Middle between the mobile device and the gateway. Use with extreme caution and only in dedicated lab environments.
     - **Mobile Hotspot:** (Simple) Set up a mobile hotspot on your host computer (if supported) and connect the Android device to that hotspot. Wireshark can then capture the traffic on the host's virtual hotspot interface.

2. **Wireshark Capture:**
   
   - Select the correct network interface (the one connected to the mobile device).
   - Start the capture, potentially enabling Promiscuous Mode (though this may not work on all Wi-Fi drivers/operating systems).

3. **Filtering:**
   
   - Filter: `host <mobile_device_ip>`

### Technique 3: Direct Device Capture (Root/ADB)

For the most accurate capture of all traffic directly on an Android device:

1. **Prerequisites:** Requires a rooted Android device.
2. **Execute tcpdump:** Run the command-line packet capture utility `tcpdump` on the Android device via ADB and pipe the output to [Wireshark](../../common/tools/WireShark.md) on your host machine:

```sh
# On your host machine:
adb forward tcp:12345 tcp:12345
adb shell "su -c 'tcpdump -i any -p -s 0 -w -' | nc -l -p 12345" &

# On a new host machine terminal:
nc 127.0.0.1 12345 | wireshark -k -i -
```

This command forwards a port, runs tcpdump as root, sends the capture over the network to the host, and pipes it directly into Wireshark's live capture interface.

### Advanced Analysis (Post-Capture)

Once traffic is captured in a `.pcap` or `.pcapng` file, use Wireshark's powerful features:

|Feature|How to|
|--|--|
|**Follow Stream**|Right-click on a TCP/HTTP packet and select "Follow" → "TCP Stream" or "HTTP Stream" to reconstruct and view the entire application-layer conversation|
|**Display Filters**|Filter the massive amount of captured data to focus only on the traffic of interest. Examples: `http.request.method == "POST"` `ip.addr == 10.0.0.5` `dns`|
|**Protocol Hierarchy**|Use Statistics → Protocol Hierarchy to identify all protocols present and see how much traffic they account for. This is a quick way to find non-standard protocols|
|**Decryption (SSL/TLS)**|If you manage to capture encrypted traffic along with the necessary session keys (e.g., from a TLS (Pre)-Master-Secret log file from an emulator or custom app build), Wireshark can decrypt the traffic. `Edit → Preferences → Protocols → TLS → Pre-Master-Secret logfile setting`|
|**Endpoints/Conversations**|Use Statistics → Endpoints or Conversations to quickly identify the top talkers (IP addresses and ports) and data volumes|
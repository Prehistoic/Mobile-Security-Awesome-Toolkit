# Troubleshooting Interception Common Issues

**Source**: https://blog.nviso.eu/2020/11/19/proxying-android-app-traffic-common-issues-checklist/

## Setting up the device

### Is your proxy configured on the device ?

**Sanity Check**

Go to `Settings --> Connections --> Wi-Fi`, select Wi-Fi network that you're on, click `Advanced --> Proxy --> Manual` and enter Proxy details.

---

### Is Burp listening on all interfaces ?

**Sanity Check**

Make sure that `All interfaces` are checked in Burp `Proxy --> Options`

---

### Can your device connect to your proxy ?

Some networks have host/client isolation and won't allow clients to talk to each other. 

**Sanity Check**

Open a browser on the device and navigate to `http//192.168.1.100:8080`. You should see Burp's welcome screen.

**Solution**

- Set up a custom wireless network where host/client isolation is disabled
- Host your proxy on a device that is accessible (e.g., an AWS EC2 instance) 
- Perform an ARP spoofing attack to trick the device into believing you are the router
- Use adb reverse to proxy your traffic over a USB cable
  - Configure proxy on device to go to `127.0.0.1` on port `8080`
  - Connect your device over USB and make sure `adb devices` shows your device
  - Execute `adb reverse tcp:8080 tcp:8080`
  - Browse to `http://127.0.0.1:8080` and see Burp's welcome screen

---

### Can you proxy HTTP traffic ?

The steps for HTTP traffic are usually much easier than HTTPS traffic, so a quick sanity check can allow to be sure that the proxy is set up correctly and reachable by the device.

**Sanity Check**

Navigate to `http://neverssl.com` and check if request can be seen in Burp

**Solution**

- Go over the previous checks again
- Make sure Burp's Intercept is enabled

---

### Is your Burp certificate installed on the device ?

**Sanity Check**

Go to `Settings --> Security --> Trusted credentials --> User` and make sure your certificate is listed.

---

### Is your Burp certificate installed as a root certificate ?

Applications on more recent versions of Android don't trust user certificates by default. While it's possible to repackage apps to trust user certificates, the better option is to have your root CA in the system CA store.

**Sanity Check**

Go to `Settings --> Security --> Encryption & Credentials --> Trusted credentials --> System` and make sure your certificate is listed

**Solution**

- Use the [AlwaysTrustUserCerts](https://github.com/NVISOsecurity/AlwaysTrustUserCerts) Magisk module

---

### Does your Burp certificate have an appropriate lifetime ?

Google (and thus Android) is aggressively shortening the maximum accepted lifetime of leaf certificates. If your leaf certificate's expiration date is too far ahead in the future, Android will not accept it !

**Sanity Check**

Connect to your proxy using a browser and check the certificate lifetime of both the root CA and the leaf certificate. They should be shorter than 1 year. Otherwise create a new CA.

You can also use the latest version of Chrome on Android. If something's wrong chrome will display the following error : `ERR_CERT_VALIDITY_TOO_LONG`

**Solution**

- Make sure you have the latest version of Burp installed, which reduces the lifetime of generated leaf certificates
- [Make your own root CA that's only valid for 365 days](https://blog.nviso.eu/2018/01/31/using-a-custom-root-ca-with-burp-for-inspecting-android-n-traffic/)

---

### Is your Burp certificate still valid ?

When generating your own root CA, the lifetime is shorter than the lifetime of the default Burp certificate. As a result, it will expire at some point. Make sure that the certificate is still valid.

**Sanity Check**

Go to `Settings --> Security --> Encryption & Credentials --> Trusted credentials --> System` and select your certificate. Make sure it hasn't expired yet.

**Solution**

- In Burp, go to Proxy Settings and click `Regenerate CA certificate`
- [Generate a new root CA yourself](https://blog.nviso.eu/2018/01/31/using-a-custom-root-ca-with-burp-for-inspecting-android-n-traffic/) and go through the different setup steps again

---

### Is TLS Pass Through disabled ?

Burp allows you to configure domains which will not be MitM'd thanks to a setting called **TLS Pass Through**.

**Sanity Check**

Go to `Proxy --> Options` and scroll down to **TLS Pass Through**. Make sure that any domain you are trying to MITM is not listed and that the option to automatically add domains is **not enabled**.

**Solution**

If the setting to automatically add entries is enabled, disable it.

If your domain is listed, remove it or click the 'Enabled' flag to disable it.

## Setting up the application

### Is the application proxy aware ?

TO CONTINUE
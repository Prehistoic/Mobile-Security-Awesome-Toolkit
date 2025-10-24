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

Many apps simply ignore the proxy settings of the system. Applications that use standard libraries will typically use them but applications that rely on interpreted language (Xamarin, Unity...) or compiled natively (Flutter) usually require the developer to program proxy support himself into the app.

**Sanity Check**
If you don't see the HTTPS data in Burp's Proxy tab and neither HTTPS connection errors in Burp's Event logs, this means that the app is most likely proxy unaware.

You can also check if the app uses a 3d party framework. If it is writtent in **Flutter** it is definitely proxy unaware and if it's written in **Xamarin** or **Unity** there's also a good chance it will ignore system's proxy settings.

- Decompile with [apktool](../tools/apktool.md) 
  - `apktool d myapp.apk`
- Go through known locations
  - Flutter: `myapp/lib/arm64-v8a/libflutter.so`
  - Xamarin: `myapp/unknown/assemblies/Mono.Android.dll`
  - Unity: `myapp/lib/arm64-v8a/libunity.so`

**Solution**

- Use [ProxyDroid](../tools/ProxyDroid.md)
- Set up a custom hotspot through a 2d wireless interface and use iptables to redirect traffic yourself. See [mitmproxy](https://docs.mitmproxy.org/stable/howto-transparent/)
- Use a VPN setup, as explained in [this article](https://blog.nviso.eu/2020/06/12/intercepting-flutter-traffic-on-ios/) (explained for iOS but very similar for Android)
- Use DNS spoofing to redirect traffic to your machine. Launch [DNSChef](https://github.com/iphelix/dnschef/) and specify `--fakeip <yourhost>`. Next, configure your device to use your custom DNS server by modifying the Wi-Fi settings

In all above cases you have moved from a "proxy aware" to a "transparent proxy" setup. You must then do :
- Disable the proxy on the device (or Burp will receive both proxied and transparent requests)
- Configure Burp to support transparent proxying via `Proxy --> Options --> active proxy --> edit --> Request Handling --> Support invisible proxying`

---

### Did the app fall back to non-proxy mode ?

Depending on which library is used to make the connections, after a failed TLS request it may fall back to a different proxy configuration, or no proxy configuration at all.

For example, Android's built-in okhttp library has the [following code](https://cs.android.com/android/platform/superproject/main/+/main:external/okhttp/repackaged/okhttp/src/main/java/com/android/okhttp/internal/http/RouteSelector.java;l=77?q=routeselector.conn&ss=android)

```java
public Route next() throws IOException {
  // Compute the next route to attempt.
  if (!hasNextInetSocketAddress()) {
    if (!hasNextProxy()) {
      if (!hasNextPostponed()) {
        throw new NoSuchElementException();
      }
      return nextPostponed();
    }
    lastProxy = nextProxy();
  }
  lastInetSocketAddress = nextInetSocketAddress();

  Route route = new Route(address, lastProxy, lastInetSocketAddress);
  if (routeDatabase.shouldPostpone(route)) {
    postponedRoutes.add(route);
    // We will only recurse in order to skip previously failed routes. They will be tried last.
    return next();
  }

  return route;
}
```

After a failed connection, it will call [RouteSelector.connectFailed](https://cs.android.com/android/platform/superproject/main/+/main:external/okhttp/repackaged/okhttp/src/main/java/com/android/okhttp/internal/http/RouteSelector.java;l=104?q=routeselector.conn&ss=android), which will make the next connection use a different route, ignoring proxy settings.

**Solution**

Use the Frida script below to disable the `connectFailed` function.

```js
Java.perform(function() {
    try {
        var RouteSelector = Java.use("com.android.okhttp.internal.http.RouteSelector");
        RouteSelector.connectFailed.implementation = function(route, ioe) {
            console.log("OKHTTP Callback prevented");
        };
    } catch (err) {
        console.error("Failed to hook RouteSelector.connectFailed: " + err);
    }
});
```

---

### Is the application using custom ports ?

This only really applies if the app is not proxy aware. In that case you (or ProxyDroid) will be using `iptables` to intercept traffic. However ProxyDroid only targets ports `80` and `443`. If the app uses a non-standard port it won't be intercepted !

**Sanity Check**

We need to find traffic that isn't going to ports `80` or `443`. The best way to do this is to listen for all traffic leaving the app. We can do this by using `tcpdump` or on the host machine in case you are using a second Wi-Fi hotspot.

```sh
tcpdump -i wlan0 -n -s0 -v
```

Open the app, use it a bit if needed and inspect connections to find which port(s) are used.

Alternatively you can send the output of `tcpdump` to a pcap by using `tcpdump -i wlan0 -n -s0 -w /sdcard/output.pcap`. After retrieving the pcap file from the device it can be opened with [WireShark](../../common/tools/WireShark.md) and inspected.

**Solution**

In this case, ProxyDroid won't help, see options below :
- Set up a second hotspot where the host machine acts as the router and perform a MitM
- Use ARP spoofing to perform an active MitM between the router and the device
- Use `iptables` to forward all traffic to Burp
  - On host: `adb reverse tcp:8080 tcp:8080`
  - On device, as root: `iptables -t nat -A OUTPUT -p tcp -m tcp -dport 8088 -j REDIRECT --to-ports 8080`

---

### Is the application using SSL pinning ?

TO CONTINUE
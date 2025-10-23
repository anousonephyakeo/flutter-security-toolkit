# Flutter Application Penetration Testing Guide

A comprehensive guide for security professionals conducting penetration tests on Flutter applications across iOS and Android platforms.

## Table of Contents

- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [SSL/TLS Certificate Pinning Bypass](#ssltls-certificate-pinning-bypass)
  - [Automated Methods](#automated-methods)
  - [Manual Methods](#manual-methods)
- [Network Traffic Interception](#network-traffic-interception)
- [Static Analysis Techniques](#static-analysis-techniques)
- [Dynamic Analysis](#dynamic-analysis)
- [Common Vulnerabilities](#common-vulnerabilities)
- [Advanced Techniques](#advanced-techniques)
- [Tools & Resources](#tools--resources)

---

## Introduction

Flutter applications present unique security challenges due to their architecture. Unlike traditional native apps, Flutter compiles Dart code into native ARM/x86 code, making reverse engineering more complex. This guide provides methodologies and tools specifically tailored for Flutter app security assessments.

### Flutter Architecture Overview

Flutter apps use the Dart VM in development and compile to native code for production. Key components include:

- **libflutter.so**: Flutter engine library
- **libapp.so**: Compiled Dart application code
- **Snapshot files**: Dart code snapshots (kernel_blob.bin, vm_snapshot_data, isolate_snapshot_data)

---

## Prerequisites

### Required Tools

- **Frida**: Dynamic instrumentation toolkit (v16.0.0+)
- **BurpSuite/mitmproxy**: HTTP/HTTPS proxy tools
- **ADB**: Android Debug Bridge
- **APKTool**: APK decompilation
- **Ghidra/IDA Pro**: Binary analysis
- **iOS-specific**: iFunBox, iProxy, frida-ios-dump
- **Python 3.8+**: For automation scripts

### Environment Setup

```bash
# Install Frida tools
pip3 install frida-tools

# Verify installation
frida --version
```

### Device Requirements

**Android:**
- Rooted device or emulator (recommended: Genymotion, Android Studio AVD)
- USB debugging enabled
- ADB installed and configured

**iOS:**
- Jailbroken device (checkra1n, unc0ver, or Dopamine)
- Frida server installed via Cydia/Sileo
- Valid provisioning profile for app installation

---

## SSL/TLS Certificate Pinning Bypass

Flutter implements certificate pinning at the Dart level, making traditional Android/iOS SSL unpinning methods ineffective. These specialized techniques target Flutter's specific implementation.

### Automated Methods

#### Method 1: NVISO Flutter TLS Bypass (Recommended)

The NVISO script dynamically patches Flutter's SSL validation functions during runtime.

**Installation:**

```bash
# Download the latest script
wget https://raw.githubusercontent.com/NVISOsecurity/disable-flutter-tls-verification/main/disable-flutter-tls.js
```

**Usage:**

```bash
# Basic usage - spawn application
frida -U -f com.example.target -l disable-flutter-tls.js

# Attach to running process
frida -U -n "App Name" -l disable-flutter-tls.js

# With persistent changes
frida -U -f com.example.target -l disable-flutter-tls.js --no-pause
```

**Advantages:**
- No repackaging required
- Works on both Android and iOS
- Regularly maintained and updated
- Supports latest Flutter versions (3.x)

**Troubleshooting:**
- If the script fails, ensure you're using the latest Frida version
- Some apps may implement anti-Frida checks; see [Anti-Instrumentation Bypass](#anti-instrumentation-bypass)
- Check Frida server is running: `frida-ps -U`

#### Method 2: Reflutter (Automated APK Patching)

Reflutter patches Flutter binaries to disable certificate validation at the binary level.

**Installation:**

```bash
pip3 install reflutter
```

**Step-by-Step Process:**

```bash
# 1. Patch the APK (provide your BurpSuite/proxy IP when prompted)
reflutter target_app.apk

# Example output:
# Enter your BurpSuite IP: 192.168.1.100

# 2. Sign the patched APK
# Download uber-apk-signer if not already installed
wget https://github.com/patrickfav/uber-apk-signer/releases/download/v1.3.0/uber-apk-signer-1.3.0.jar

# Sign the APK
java -jar uber-apk-signer-1.3.0.jar --apk release.RE.apk

# 3. Uninstall original app (if installed)
adb uninstall com.example.target

# 4. Install the patched APK
adb install release.RE-aligned-debugSigned.apk
```

**Important Notes:**
- Reflutter modifies the app binary, which may trigger integrity checks
- Backup the original APK before patching
- The app may crash if it implements root/tamper detection
- Works only on Android applications

**Comparison of Automated Methods:**

| Feature | NVISO Script | Reflutter |
|---------|-------------|-----------|
| Platform | Android + iOS | Android only |
| Repackaging | No | Yes |
| Detection Risk | Lower | Higher |
| Setup Complexity | Easy | Moderate |
| Maintenance | Active | Active |

### Manual Methods

#### Binary Patching with Ghidra

For apps with anti-Frida or anti-repackaging measures, manual binary patching provides deeper control.

**Steps:**

1. **Extract libapp.so/App binary**
   ```bash
   # Android
   unzip target_app.apk
   # Binary located at: lib/arm64-v8a/libapp.so
   
   # iOS
   unzip target_app.ipa
   # Binary located at: Payload/AppName.app/Frameworks/App.framework/App
   ```

2. **Load in Ghidra**
   - Open Ghidra and create new project
   - Import libapp.so or App binary
   - Analyze with default options

3. **Locate SSL verification functions**
   
   Search for common certificate validation strings:
   ```
   "certificate verify failed"
   "CERTIFICATE_VERIFY_FAILED"
   "HandshakeException"
   "SecurityContext"
   ```

4. **Patch verification logic**
   
   Common patterns to patch:
   - Change conditional jumps (JNZ → JMP, BNE → B)
   - NOP out validation calls
   - Force return values (MOV R0, #1 for success)

5. **Export and repack**
   ```bash
   # Replace original library
   # Repack APK with APKTool
   apktool d target_app.apk
   # Replace lib/arm64-v8a/libapp.so with patched version
   apktool b target_app -o target_patched.apk
   
   # Sign and install
   java -jar uber-apk-signer-1.3.0.jar --apk target_patched.apk
   adb install target_patched-aligned-debugSigned.apk
   ```

**Advanced: Custom Frida Scripts**

Create targeted Frida scripts for specific Flutter versions:

```javascript
// Custom Flutter SSL bypass
Java.perform(function() {
    // Hook native SSL functions
    var ssl_verify_result = Module.findExportByName("libflutter.so", 
        "ssl_verify_result_t");
    
    if (ssl_verify_result) {
        Interceptor.replace(ssl_verify_result, new NativeCallback(function() {
            console.log("[*] SSL verification bypassed");
            return 0; // X509_V_OK
        }, 'int', []));
    }
    
    // Hook Dart SSL context
    var symbols = Module.enumerateSymbolsSync("libapp.so");
    symbols.forEach(function(symbol) {
        if (symbol.name.includes("SecurityContext") || 
            symbol.name.includes("X509")) {
            console.log("[*] Found symbol: " + symbol.name);
            // Further hooking logic here
        }
    });
});
```

---

## Network Traffic Interception

### VPN-Based Interception (OpenVPN + iptables)

This method is effective when apps detect and block system proxy settings.

#### OpenVPN Server Setup

```bash
# Download and prepare installation script
sudo wget https://git.io/vpn -O openvpn-install.sh

# Fix compatibility issues
sudo sed -i "$(($(grep -ni "debian is too old" openvpn-install.sh | cut -d : -f 1)+1))d" ./openvpn-install.sh

# Make executable
sudo chmod +x openvpn-install.sh

# Run installation
sudo ./openvpn-install.sh
```

**Configuration Prompts:**

```
IPv4 address: [Your PC's local IP, e.g., 192.168.1.100]
Public IPv4/hostname: [Your PC's local IP, e.g., 192.168.1.100]
Protocol: 1 (UDP)
Port: 1194
DNS Server: 1 (Current system resolvers)
Client name: [Any name, e.g., "pentest-client"]
```

#### Traffic Redirection with iptables

```bash
# Start OpenVPN service
sudo systemctl start openvpn@server
sudo systemctl enable openvpn@server

# Verify VPN is running
sudo systemctl status openvpn@server

# Configure iptables rules for traffic redirection
# Replace 192.168.1.50 with your mobile device's IP
# Replace 192.168.1.100 with your proxy server IP

# Redirect HTTP traffic (port 80) to BurpSuite (8080)
sudo iptables -t nat -A PREROUTING -i tun0 -p tcp --dport 80 -j REDIRECT --to-port 8080

# Redirect HTTPS traffic (port 443) to BurpSuite (8080)
sudo iptables -t nat -A PREROUTING -i tun0 -p tcp --dport 443 -j REDIRECT --to-port 8080

# Enable NAT for device traffic
sudo iptables -t nat -A POSTROUTING -s 192.168.1.50/24 -o eth0 -j MASQUERADE

# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -p

# Persist iptables rules (Debian/Ubuntu)
sudo apt-get install iptables-persistent
sudo netfilter-persistent save

# View current rules
sudo iptables -t nat -L -n -v
```

#### Client Configuration

**iOS:**
1. Install OpenVPN Connect from App Store
2. Transfer .ovpn profile via AirDrop or email
3. Import profile and connect
4. Configure BurpSuite to listen on all interfaces (0.0.0.0:8080)

**Android:**
1. Install OpenVPN for Android from Play Store
2. Transfer .ovpn file to device
3. Import and connect
4. Alternatively, use ProxyDroid for system-wide proxy

---

### Android Proxy Configuration

#### ProxyDroid Method (Root Required)

ProxyDroid enforces system-wide proxy at the network layer, bypassing app-level proxy detection.

**Setup:**

1. Install ProxyDroid from Google Play Store or F-Droid
2. Grant root permissions when prompted
3. Configure settings:
   ```
   Host: [BurpSuite IP, e.g., 192.168.1.100]
   Port: [BurpSuite Port, e.g., 8080]
   Proxy Type: HTTP
   Global Proxy: Enabled
   ```
4. Start proxy service

**Alternative: iptables Direct Method**

```bash
# On rooted Android device (via ADB shell)
adb shell

# Become root
su

# Redirect traffic to proxy
iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination 192.168.1.100:8080
iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination 192.168.1.100:8080

# Verify rules
iptables -t nat -L OUTPUT -n -v
```

---

## Static Analysis Techniques

### Extracting Application Assets

#### Android APK Extraction

```bash
# Method 1: Rename and extract
cp target_app.apk target_app.zip
unzip target_app.zip -d apk_contents/

# Method 2: APKTool for full decompilation
apktool d target_app.apk -o apk_decompiled/

# Key files to examine:
# - lib/[arch]/libapp.so (compiled Dart code)
# - lib/[arch]/libflutter.so (Flutter engine)
# - assets/flutter_assets/ (resources, fonts, images)
# - AndroidManifest.xml (permissions, components)
```

#### iOS IPA Extraction

```bash
# Option 1: Use frida-ios-dump (jailbroken device required)
frida-ios-dump -H [device IP] -u [bundle ID]

# Option 2: Use Clutch (for decrypting App Store apps)
# Install Clutch via Cydia
# SSH into device
ssh root@[device IP]
Clutch -d com.example.target

# Extract IPA contents
unzip target_app.ipa -d ipa_contents/

# Navigate to binary
cd ipa_contents/Payload/AppName.app/Frameworks/App.framework/

# Key files:
# - App (main binary)
# - Info.plist (app metadata)
# - Assets.car (compiled assets)
```

### String Analysis

Extract hardcoded credentials, API endpoints, and sensitive data.

```bash
# Extract all strings
strings libapp.so > app_strings.txt
strings App > app_strings.txt

# Filter for common patterns
grep -i "api" app_strings.txt
grep -i "http" app_strings.txt
grep -i "password\|passwd\|pwd" app_strings.txt
grep -i "secret\|token\|key" app_strings.txt
grep -i "amazonaws.com\|firebase\|cloudfront" app_strings.txt

# Search for specific API routes
strings libapp.so | grep -E "/(api|v1|v2|v3|auth|login|user|admin)" > api_routes.txt

# Extract potential secrets with regex
strings libapp.so | grep -E "[A-Za-z0-9]{32,}" > potential_secrets.txt

# Find URLs
strings libapp.so | grep -E "https?://[^\s]+" > urls.txt

# Look for SQL queries
strings libapp.so | grep -i -E "(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP)" > sql_queries.txt
```

### Flutter-Specific Analysis

```bash
# Look for Flutter framework versions
strings libflutter.so | grep -i "version\|flutter"

# Find Dart package dependencies
cat pubspec.yaml  # If available in assets

# Analyze snapshot files (if present)
# These contain compiled Dart code
find . -name "*.snapshot*" -o -name "kernel_blob.bin"

# Decompile Dart snapshots (advanced)
# Use reFlutter or custom tools
```

### Sensitive Data Patterns

Create a comprehensive search:

```bash
#!/bin/bash
# save as analyze_strings.sh

BINARY=$1
OUTPUT="analysis_report.txt"

echo "=== Flutter App Security Analysis ===" > $OUTPUT
echo "Binary: $BINARY" >> $OUTPUT
echo "Date: $(date)" >> $OUTPUT
echo "" >> $OUTPUT

echo "[+] Extracting strings..."
strings $BINARY > all_strings.txt

echo "[*] API Endpoints:" >> $OUTPUT
grep -E "/(api|v[0-9]|auth|user|admin)" all_strings.txt >> $OUTPUT

echo "" >> $OUTPUT
echo "[*] Potential Secrets:" >> $OUTPUT
grep -E "([A-Za-z0-9+/]{40,}={0,2}|[a-f0-9]{32,64})" all_strings.txt | head -20 >> $OUTPUT

echo "" >> $OUTPUT
echo "[*] Hardcoded Credentials:" >> $OUTPUT
grep -iE "(password|passwd|pwd|secret|token|api[_-]?key).*[:=].*" all_strings.txt >> $OUTPUT

echo "" >> $OUTPUT
echo "[*] Cloud Services:" >> $OUTPUT
grep -iE "(amazonaws|azure|firebase|cloudfront|s3\.)" all_strings.txt >> $OUTPUT

echo "" >> $OUTPUT
echo "[*] Database References:" >> $OUTPUT
grep -iE "(SELECT|INSERT|UPDATE|DELETE|sqlite|mongodb|postgresql)" all_strings.txt >> $OUTPUT

echo "[+] Analysis complete. Results saved to $OUTPUT"
```

**Usage:**
```bash
chmod +x analyze_strings.sh
./analyze_strings.sh libapp.so
cat analysis_report.txt
```

---

## Dynamic Analysis

### Frida Hooking Techniques

#### Basic Function Tracing

```javascript
// trace_network.js - Monitor network requests
Java.perform(function() {
    var HttpURLConnection = Java.use("java.net.HttpURLConnection");
    
    HttpURLConnection.getRequestMethod.implementation = function() {
        var method = this.getRequestMethod();
        var url = this.getURL();
        console.log("\n[HTTP Request]");
        console.log("Method: " + method);
        console.log("URL: " + url.toString());
        return method;
    };
    
    HttpURLConnection.getResponseCode.implementation = function() {
        var code = this.getResponseCode();
        var url = this.getURL();
        console.log("\n[HTTP Response]");
        console.log("URL: " + url.toString());
        console.log("Status: " + code);
        return code;
    };
});
```

#### Monitoring Shared Preferences (Android)

```javascript
// monitor_storage.js
Java.perform(function() {
    var SharedPreferences = Java.use("android.content.SharedPreferences");
    var Editor = Java.use("android.content.SharedPreferences$Editor");
    
    Editor.putString.implementation = function(key, value) {
        console.log("\n[SharedPreferences Write]");
        console.log("Key: " + key);
        console.log("Value: " + value);
        return this.putString(key, value);
    };
    
    SharedPreferences.getString.implementation = function(key, defValue) {
        var value = this.getString(key, defValue);
        console.log("\n[SharedPreferences Read]");
        console.log("Key: " + key);
        console.log("Value: " + value);
        return value;
    };
});
```

#### Crypto Operations Monitoring

```javascript
// monitor_crypto.js
Java.perform(function() {
    var Cipher = Java.use("javax.crypto.Cipher");
    
    Cipher.doFinal.overload('[B').implementation = function(input) {
        console.log("\n[Crypto Operation]");
        console.log("Algorithm: " + this.getAlgorithm());
        console.log("Input: " + bytesToHex(input));
        var result = this.doFinal(input);
        console.log("Output: " + bytesToHex(result));
        return result;
    };
    
    function bytesToHex(bytes) {
        var hex = "";
        for (var i = 0; i < Math.min(bytes.length, 32); i++) {
            hex += ("0" + (bytes[i] & 0xFF).toString(16)).slice(-2);
        }
        return hex + (bytes.length > 32 ? "..." : "");
    }
});
```

#### Running Frida Scripts

```bash
# Spawn app with script
frida -U -f com.example.app -l script.js --no-pause

# Attach to running app
frida -U -n "App Name" -l script.js

# Multiple scripts
frida -U -f com.example.app -l script1.js -l script2.js --no-pause

# Interactive mode
frida -U -f com.example.app
```

---

## Common Vulnerabilities

### 1. Insecure Data Storage

**Check for:**
- Unencrypted sensitive data in SharedPreferences/UserDefaults
- Sensitive data in application logs
- Unprotected local databases (SQLite)
- Cached credentials in memory

**Testing:**

```bash
# Android - Check SharedPreferences
adb shell
run-as com.example.app
cd shared_prefs/
cat *.xml

# Android - Check databases
cd databases/
sqlite3 app.db
.tables
.schema [table_name]
SELECT * FROM [sensitive_table];

# iOS - Check UserDefaults
# On jailbroken device
cat /var/mobile/Containers/Data/Application/[UUID]/Library/Preferences/com.example.app.plist
```

### 2. Insufficient Transport Layer Protection

**Indicators:**
- Missing certificate pinning
- Accepting self-signed certificates
- Using HTTP for sensitive operations
- Weak TLS versions (< 1.2)

**Verification:**
```bash
# Check for HTTP URLs in binary
strings libapp.so | grep "http://"

# Monitor network traffic
tcpdump -i any -n -s 0 -w capture.pcap host [device IP]

# Analyze with Wireshark
wireshark capture.pcap
```

### 3. Client-Side Injection

Flutter apps can be vulnerable to:
- SQL Injection (local databases)
- XSS (if using WebView)
- Path Traversal (file operations)

**Example Test:**

```javascript
// Test SQL injection via Frida
Java.perform(function() {
    var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
    
    SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;')
        .implementation = function(sql, args) {
        console.log("\n[SQL Query]");
        console.log("Query: " + sql);
        console.log("Args: " + args);
        
        // Test with malicious input
        // sql = "SELECT * FROM users WHERE id='" + userInput + "'";
        // userInput = "1' OR '1'='1"
        
        return this.rawQuery(sql, args);
    };
});
```

### 4. Insecure Authentication

**Check for:**
- Hardcoded credentials
- Weak session management
- Missing biometric authentication
- JWT tokens stored insecurely

**Testing:**

```bash
# Search for auth-related strings
strings libapp.so | grep -iE "(bearer|authorization|jwt|session|cookie)"

# Monitor authentication flow
frida -U -f com.example.app -l trace_auth.js
```

### 5. Insufficient Binary Protection

**Indicators:**
- Missing obfuscation
- Debug symbols present
- No root/jailbreak detection
- No tamper detection

**Check:**

```bash
# Android - Check for debug symbols
nm -D libapp.so | grep " T "

# Check for obfuscation
jadx -d output/ target_app.apk
# Review decompiled code clarity

# iOS - Check for encryption
otool -l App | grep cryptid
# cryptid 0 = unencrypted, cryptid 1 = encrypted
```

---

## Advanced Techniques

### Anti-Instrumentation Bypass

Many apps detect Frida and other instrumentation tools.

#### Detect Frida Checks

```javascript
// detect_anti_frida.js
Java.perform(function() {
    // Hook common anti-Frida checks
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf("frida") !== -1 || path.indexOf("re.frida") !== -1) {
            console.log("[*] Blocked Frida detection: " + path);
            return false;
        }
        return this.exists();
    };
    
    // Hook port scanning (Frida default port 27042)
    var Socket = Java.use("java.net.Socket");
    Socket.$init.overload('java.lang.String', 'int').implementation = function(host, port) {
        if (port === 27042 || port === 27043) {
            console.log("[*] Blocked Frida port scan: " + port);
            throw new Error("Connection refused");
        }
        return this.$init(host, port);
    };
});
```

#### Rename Frida Server

```bash
# Android
adb push frida-server /data/local/tmp/my_daemon
adb shell "chmod 755 /data/local/tmp/my_daemon"
adb shell "/data/local/tmp/my_daemon &"

# Verify
frida-ps -U
```

#### Root Detection Bypass

```javascript
// bypass_root.js
Java.perform(function() {
    // Hook RootBeer library (common root detection)
    try {
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        RootBeer.isRooted.implementation = function() {
            console.log("[*] Root check bypassed");
            return false;
        };
    } catch(e) {}
    
    // Hook common root check files
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var rootPaths = ["/system/app/Superuser.apk", "/su", "/system/bin/su", 
                        "/system/xbin/su", "/data/local/xbin/su", "/magisk"];
        
        for (var i = 0; i < rootPaths.length; i++) {
            if (path.indexOf(rootPaths[i]) !== -1) {
                console.log("[*] Blocked root path check: " + path);
                return false;
            }
        }
        return this.exists();
    };
    
    // Hook Runtime.exec for su commands
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if (cmd.indexOf("su") !== -1) {
            console.log("[*] Blocked su command: " + cmd);
            throw new Error("Command not found");
        }
        return this.exec(cmd);
    };
});
```

### Memory Dumping

Extract decrypted data and runtime strings from memory.

```bash
# Attach Frida and dump memory
frida -U -n "App Name" -e 'Process.enumerateModules()' | grep libapp

# Dump specific module
frida -U -n "App Name"
# In Frida console:
> var base = Module.findBaseAddress("libapp.so")
> var size = Process.getModuleByName("libapp.so").size
> Memory.dump(base, size).then(function(bytes) {
    var fs = require('fs');
    fs.writeFileSync("libapp_dump.bin", bytes);
  })

# Alternatively, use objection
objection -g com.example.app explore
memory list modules
memory dump all libapp.so /tmp/libapp_dump.bin
```

### Snapshot Analysis

Analyze Dart snapshots for sensitive data.

```bash
# Locate snapshots in APK
unzip -l app.apk | grep -E "(kernel|snapshot|isolate|vm)"

# Extract
unzip app.apk -d app_extracted/
cd app_extracted/assets/

# Analyze with reFlutter (includes snapshot parser)
reflutter app.apk

# Manual analysis: search for strings
strings kernel_blob.bin | grep -E "(api|http|secret|password)"
```

### Custom Protocol Analysis

Many Flutter apps use protobuf, GraphQL, or custom protocols.

**Intercepting Protobuf:**

```javascript
// intercept_protobuf.js
Java.perform(function() {
    var MessageLite = Java.use("com.google.protobuf.MessageLite");
    MessageLite.toByteArray.implementation = function() {
        var bytes = this.toByteArray();
        console.log("\n[Protobuf Serialized]");
        console.log("Message: " + this.$className);
        console.log("Hex: " + bytesToHex(bytes));
        return bytes;
    };
    
    function bytesToHex(bytes) {
        var hex = "";
        for (var i = 0; i < bytes.length; i++) {
            hex += ("0" + (bytes[i] & 0xFF).toString(16)).slice(-2);
        }
        return hex;
    }
});
```

---

## Tools & Resources

### Essential Tools

| Tool | Purpose | Platform | Link |
|------|---------|----------|------|
| Frida | Dynamic instrumentation | Android/iOS | [frida.re](https://frida.re) |
| Reflutter | SSL pinning bypass | Android | [GitHub](https://github.com/ptswarm/reFlutter) |
| Objection | Mobile security toolkit | Android/iOS | [GitHub](https://github.com/sensepost/objection) |
| APKTool | APK decompilation | Android | [ibotpeaches.github.io](https://ibotpeaches.github.io/Apktool/) |
| jadx | Java decompiler | Android | [GitHub](https://github.com/skylot/jadx) |
| Ghidra | Binary analysis | All | [ghidra-sre.org](https://ghidra-sre.org/) |
| BurpSuite | HTTP proxy | All | [portswigger.net](https://portswigger.net/burp) |
| mitmproxy | HTTP proxy | All | [mitmproxy.org](https://mitmproxy.org/) |
| frida-ios-dump | iOS app decryption | iOS | [GitHub](https://github.com/AloneMonkey/frida-ios-dump) |
| MobSF | Mobile security framework | Android/iOS | [GitHub](https://github.com/MobSF/Mobile-Security-Framework-MobSF) |

### Specialized Flutter Tools

- **NVISO Flutter Unpinner**: [GitHub](https://github.com/NVISOsecurity/disable-flutter-tls-verification)
- **reFlutter**: [GitHub](https://github.com/ptswarm/reFlutter)
- **Dart Decompiler**: [GitHub](https://github.com/xtremely-undead/Dart-Decompiler)

### Learning Resources

- **OWASP Mobile Security Testing Guide**: [GitHub](https://github.com/OWASP/owasp-mstg)
- **Mobile Application Penetration Testing Cheat Sheet**: [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Penetration_Testing_Cheat_Sheet.html)
- **Frida CodeShare**: [codeshare.frida.re](https://codeshare.frida.re/)
- **Flutter Security Best Practices**: [flutter.dev/security](https://flutter.dev/security)

### Communities

- **r/AskNetsec** (Reddit)
- **Frida Slack** ([frida.re/slack](https://frida.re/slack/))
- **OWASP Mobile Security Project**

---

## Testing Checklist

Use this checklist to ensure comprehensive coverage during penetration tests.

### Pre-Test Setup
- [ ] Device rooted/jailbroken
- [ ] Frida server installed and running
- [ ] BurpSuite configured with CA certificate
- [ ] APK/IPA obtained (via extraction or legitimate purchase)
- [ ] Testing environment documented

### Static Analysis
- [ ] Decompiled application
- [ ] Extracted and analyzed strings
- [ ] Identified API endpoints
- [ ] Located hardcoded secrets/credentials
- [ ] Reviewed AndroidManifest.xml/Info.plist
- [ ] Analyzed third-party libraries
- [ ] Checked for debug symbols
- [ ] Examined certificate pinning implementation

### Dynamic Analysis
- [ ] SSL/TLS pinning bypassed
- [ ] Network traffic intercepted
- [ ] Authentication flow analyzed
- [ ] Session management tested
- [ ] API endpoints enumerated
- [ ] Input validation tested
- [ ] Crypto operations monitored
- [ ] Local storage examined

### Security Tests
- [ ] Insecure data storage
- [ ] Weak cryptography
- [ ] Insecure communication
- [ ] Authentication bypass attempts
- [ ] Authorization flaws
- [ ] Client-side injection (SQL, XSS, etc.)
- [ ] Business logic flaws
- [ ] Anti-tampering measures evaluated

### Additional Checks
- [ ] Root/jailbreak detection tested
- [ ] Anti-debugging measures identified
- [ ] Code obfuscation assessed
- [ ] Logging sensitive information
- [ ] Backup flag configuration
- [ ] Deep link vulnerabilities
- [ ] WebView security (if applicable)

---

## Reporting Findings

### Severity Classification

Use CVSS or a simplified risk matrix:

| Severity | Criteria |
|----------|----------|
| **Critical** | Remote code execution, full data breach, authentication bypass |
| **High** | Privilege escalation, significant data exposure, weak cryptography |
| **Medium** | Information disclosure, missing security controls, insecure storage |
| **Low** | Best practice violations, minor information leakage |
| **Informational** | Security observations, recommendations |

### Report Structure

1. **Executive Summary**
   - Overview of assessment
   - Key findings
   - Risk summary
   - Recommendations

2. **Technical Details**
   - Testing methodology
   - Tools used
   - Scope and limitations

3. **Findings**
   For each vulnerability:
   - Title and severity
   - Description
   - Proof of concept
   - Impact assessment
   - Remediation recommendations
   - References (CWE, OWASP Mobile Top 10)

4. **Appendices**
   - Testing checklist
   - Tool output
   - Screenshots
   - Code snippets

---

## Best Practices for Secure Flutter Development

### For Developers

**1. Certificate Pinning Implementation**

```dart
// Implement certificate pinning properly
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'dart:io';

class SecureHttpClient {
  static HttpClient createHttpClient() {
    final client = HttpClient();
    
    client.badCertificateCallback = (cert, host, port) {
      // Pin specific certificates
      final expectedSHA256 = 'YOUR_CERT_SHA256_FINGERPRINT';
      final certSHA256 = sha256.convert(cert.der).toString();
      
      return certSHA256 == expectedSHA256 && host == 'api.yourapp.com';
    };
    
    return client;
  }
  
  static http.Client getClient() {
    return IOClient(createHttpClient());
  }
}
```

**2. Secure Storage**

```dart
// Use flutter_secure_storage for sensitive data
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

final storage = FlutterSecureStorage();

// Store sensitive data
await storage.write(key: 'auth_token', value: token);

// Retrieve sensitive data
final token = await storage.read(key: 'auth_token');

// Delete sensitive data
await storage.delete(key: 'auth_token');
```

**3. Code Obfuscation**

```bash
# Build with obfuscation enabled
flutter build apk --obfuscate --split-debug-info=build/app/outputs/symbols

flutter build ios --obfuscate --split-debug-info=build/ios/outputs/symbols
```

**4. Input Validation**

```dart
// Validate all user inputs
String sanitizeInput(String input) {
  // Remove potentially dangerous characters
  return input.replaceAll(RegExp(r'[<>\"\'%;()&+]'), '');
}

// Use parameterized queries
await database.rawQuery(
  'SELECT * FROM users WHERE id = ?',
  [userId] // Parameterized to prevent SQL injection
);
```

**5. Secure API Communication**

```dart
// Always use HTTPS
const String apiBaseUrl = 'https://api.yourapp.com'; // Never HTTP

// Implement proper error handling
try {
  final response = await http.get(
    Uri.parse('$apiBaseUrl/endpoint'),
    headers: {
      'Authorization': 'Bearer $token',
      'Content-Type': 'application/json',
    },
  );
  
  if (response.statusCode == 200) {
    // Process response
  } else {
    // Handle error without exposing sensitive info
    throw Exception('Request failed');
  }
} catch (e) {
  // Log securely, don't expose stack traces to users
  debugPrint('Error: $e');
}
```

**6. Root/Jailbreak Detection**

```dart
// Implement basic tamper detection
import 'package:flutter_jailbreak_detection/flutter_jailbreak_detection.dart';

Future<bool> checkDeviceSecurity() async {
  try {
    bool jailbroken = await FlutterJailbreakDetection.jailbroken;
    bool developerMode = await FlutterJailbreakDetection.developerMode;
    
    if (jailbroken || developerMode) {
      // Handle insecure device
      return false;
    }
    return true;
  } catch (e) {
    // Handle error
    return false;
  }
}
```

**7. Secure Logging**

```dart
// Never log sensitive information
// BAD:
print('User password: $password'); // NEVER DO THIS
debugPrint('Auth token: $token'); // NEVER DO THIS

// GOOD:
debugPrint('Authentication successful'); // Generic message
// Use proper logging framework in production
import 'package:logger/logger.dart';

final logger = Logger(
  printer: PrettyPrinter(
    methodCount: 0,
    errorMethodCount: 5,
    lineLength: 50,
    colors: true,
    printEmojis: true,
    printTime: true,
  ),
);

// In production, disable verbose logging
if (kReleaseMode) {
  logger.level = Level.error;
}
```

**8. Disable Debug Features in Production**

```dart
// Check for release mode
import 'package:flutter/foundation.dart';

if (kDebugMode) {
  // Debug-only features
  print('Debug mode active');
} else {
  // Production settings
  // Disable all debug outputs
  // Enable security hardening
}
```

**9. AndroidManifest.xml Security**

```xml
<!-- Disable backups for sensitive apps -->
<application
    android:allowBackup="false"
    android:fullBackupContent="false"
    android:usesCleartextTraffic="false">
    
    <!-- Prevent screenshots in sensitive screens -->
    <meta-data
        android:name="io.flutter.embedding.android.SplashScreenDrawable"
        android:resource="@drawable/launch_background" />
</application>

<!-- Declare only necessary permissions -->
<uses-permission android:name="android.permission.INTERNET" />
<!-- Avoid dangerous permissions unless absolutely necessary -->
```

**10. iOS Info.plist Security**

```xml
<!-- Prevent arbitrary loads -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <false/>
    <key>NSAllowsArbitraryLoadsInWebContent</key>
    <false/>
</dict>

<!-- Prevent screenshots/screen recording (for sensitive screens) -->
<!-- Implement in code using WindowManager -->
```

---

## Common Pitfalls and Solutions

### Pitfall 1: Over-reliance on Client-Side Security

**Problem**: Implementing all security logic on the client side.

**Solution**: 
- Always validate on server side
- Client-side validation is for UX, not security
- Implement proper authentication/authorization on backend
- Use server-side rate limiting

### Pitfall 2: Hardcoded Secrets

**Problem**: Storing API keys, passwords, or tokens in source code.

**Solution**:
- Use environment variables during build
- Implement secure key management systems
- Rotate secrets regularly
- Use backend proxy for sensitive API keys

```dart
// BAD
const String apiKey = 'sk_live_1234567890abcdef';

// GOOD - Use environment variables
const String apiKey = String.fromEnvironment('API_KEY');

// Build with: flutter build --dart-define=API_KEY=your_key_here
```

### Pitfall 3: Insufficient Error Handling

**Problem**: Exposing stack traces or sensitive information in error messages.

**Solution**:
```dart
try {
  // Operation
} catch (e) {
  // BAD: Exposing raw error to user
  // showDialog(content: Text('Error: $e'));
  
  // GOOD: Generic user message, detailed logging backend
  showDialog(content: Text('An error occurred. Please try again.'));
  logErrorToBackend(e, stackTrace); // Send to monitoring service
}
```

### Pitfall 4: Insecure WebViews

**Problem**: Using WebViews without security configurations.

**Solution**:
```dart
import 'package:webview_flutter/webview_flutter.dart';

WebView(
  javascriptMode: JavascriptMode.unrestricted,
  initialUrl: 'https://yoursite.com',
  onWebViewCreated: (WebViewController controller) {
    // Implement URL filtering
    controller.currentUrl().then((url) {
      if (!url.startsWith('https://yoursite.com')) {
        // Block navigation
      }
    });
  },
  navigationDelegate: (NavigationRequest request) {
    // Whitelist allowed domains
    if (!request.url.startsWith('https://yoursite.com')) {
      return NavigationDecision.prevent;
    }
    return NavigationDecision.navigate;
  },
);
```

### Pitfall 5: Weak Session Management

**Problem**: Sessions never expire or can be easily hijacked.

**Solution**:
- Implement session timeouts
- Use secure, httpOnly cookies (if applicable)
- Implement proper token refresh mechanisms
- Clear sessions on logout

```dart
class SessionManager {
  static const Duration sessionTimeout = Duration(minutes: 30);
  DateTime? _lastActivity;
  
  bool isSessionValid() {
    if (_lastActivity == null) return false;
    
    final now = DateTime.now();
    final difference = now.difference(_lastActivity!);
    
    return difference < sessionTimeout;
  }
  
  void updateActivity() {
    _lastActivity = DateTime.now();
  }
  
  void clearSession() {
    _lastActivity = null;
    // Clear tokens, user data
    SecureStorage().deleteAll();
  }
}
```

---

## Advanced Scenarios

### Scenario 1: Testing Apps with Multiple Layers of Protection

**Challenge**: App has SSL pinning, root detection, Frida detection, and tamper detection.

**Approach**:
1. Use renamed Frida server
2. Patch root detection in binary
3. Use VPN-based interception instead of system proxy
4. Modify anti-Frida checks in libapp.so
5. Consider using Magisk Hide or custom ROMs

**Script combination**:
```bash
# 1. Start renamed Frida
adb push frida-server /data/local/tmp/.daemon
adb shell "chmod 755 /data/local/tmp/.daemon && /data/local/tmp/.daemon &"

# 2. Use multiple bypass scripts
frida -U -f com.target.app \
  -l bypass_root.js \
  -l bypass_frida_detect.js \
  -l disable-flutter-tls.js \
  --no-pause
```

### Scenario 2: Analyzing GraphQL APIs

**Challenge**: App uses GraphQL with complex queries.

**Approach**:
```javascript
// intercept_graphql.js
Java.perform(function() {
    var RequestBody = Java.use("okhttp3.RequestBody");
    var Buffer = Java.use("okio.Buffer");
    
    RequestBody.writeTo.implementation = function(sink) {
        var buffer = Buffer.$new();
        this.writeTo(buffer);
        var body = buffer.readUtf8();
        
        if (body.includes("query") || body.includes("mutation")) {
            console.log("\n[GraphQL Request]");
            console.log(body);
        }
        
        this.writeTo(sink);
    };
});
```

### Scenario 3: Bypassing Binary Integrity Checks

**Challenge**: App verifies its own binary signature.

**Approach**:
1. Locate integrity check function in Ghidra
2. Patch to always return success
3. Or hook at runtime with Frida

```javascript
// bypass_integrity.js
Interceptor.attach(Module.findExportByName("libapp.so", "_checkIntegrity"), {
    onLeave: function(retval) {
        console.log("[*] Integrity check bypassed");
        retval.replace(1); // Return success
    }
});
```

---

## Real-World Case Studies

### Case Study 1: Banking App with Multiple Protections

**Target**: Major banking application
**Protections**: SSL pinning, root detection, emulator detection, Frida detection

**Methodology**:
1. Initial reconnaissance: Extracted strings, identified protection libraries
2. Used physical rooted device (bypassed emulator detection)
3. Renamed Frida server to `.system_daemon`
4. Applied Reflutter for SSL pinning bypass
5. Patched root detection in native libraries
6. Successfully intercepted API traffic

**Findings**:
- JWT tokens stored in SharedPreferences (unencrypted)
- API endpoints vulnerable to IDOR
- Session tokens didn't expire
- Hardcoded API keys in libapp.so

**Impact**: Critical - Unauthorized access to user accounts

### Case Study 2: E-commerce App with Weak Crypto

**Target**: E-commerce application
**Protections**: Basic SSL pinning only

**Methodology**:
1. NVISO script successfully bypassed SSL pinning
2. Intercepted checkout process
3. Analyzed payment API

**Findings**:
- Payment processing used predictable transaction IDs
- Price manipulation possible via client-side parameters
- No server-side validation of cart totals
- Discount codes not properly validated

**Impact**: High - Financial loss potential

### Case Study 3: Social Media App with Insecure Storage

**Target**: Social media application
**Protections**: None

**Methodology**:
1. Simple APK extraction and analysis
2. No SSL pinning present
3. Static analysis of storage mechanisms

**Findings**:
- User credentials stored in plaintext in SharedPreferences
- Private messages cached unencrypted in SQLite
- Session tokens never expired
- API tokens exposed in logs

**Impact**: Critical - Complete account compromise

---

## Automation and Continuous Testing

### Automated Security Scanning

```bash
#!/bin/bash
# automated_flutter_scan.sh

APK_PATH=$1
OUTPUT_DIR="scan_results_$(date +%Y%m%d_%H%M%S)"

mkdir -p $OUTPUT_DIR

echo "[+] Starting automated Flutter security scan..."

# 1. Extract APK
echo "[*] Extracting APK..."
unzip -q $APK_PATH -d $OUTPUT_DIR/apk_contents

# 2. String analysis
echo "[*] Analyzing strings..."
strings $OUTPUT_DIR/apk_contents/lib/arm64-v8a/libapp.so > $OUTPUT_DIR/strings.txt

# 3. Search for sensitive data
echo "[*] Searching for sensitive patterns..."
grep -iE "(password|secret|token|api[_-]?key)" $OUTPUT_DIR/strings.txt > $OUTPUT_DIR/sensitive_strings.txt
grep -E "https?://" $OUTPUT_DIR/strings.txt > $OUTPUT_DIR/urls.txt
grep -E "/(api|v[0-9])" $OUTPUT_DIR/strings.txt > $OUTPUT_DIR/api_endpoints.txt

# 4. Analyze manifest
echo "[*] Analyzing AndroidManifest.xml..."
apktool d -f $APK_PATH -o $OUTPUT_DIR/decompiled
cat $OUTPUT_DIR/decompiled/AndroidManifest.xml > $OUTPUT_DIR/manifest.txt

# 5. Check for security flags
echo "[*] Checking security configurations..."
grep -i "allowBackup\|usesCleartextTraffic\|debuggable" $OUTPUT_DIR/manifest.txt > $OUTPUT_DIR/security_flags.txt

# 6. Generate report
echo "[*] Generating report..."
cat > $OUTPUT_DIR/report.txt << EOF
Flutter Application Security Scan Report
Generated: $(date)
APK: $APK_PATH

=== Summary ===
Total strings found: $(wc -l < $OUTPUT_DIR/strings.txt)
Potential sensitive strings: $(wc -l < $OUTPUT_DIR/sensitive_strings.txt)
URLs found: $(wc -l < $OUTPUT_DIR/urls.txt)
API endpoints: $(wc -l < $OUTPUT_DIR/api_endpoints.txt)

=== Findings ===
See individual files in $OUTPUT_DIR for details.

EOF

echo "[+] Scan complete. Results saved to $OUTPUT_DIR/"
echo "[+] Review $OUTPUT_DIR/report.txt for summary."
```

**Usage**:
```bash
chmod +x automated_flutter_scan.sh
./automated_flutter_scan.sh app.apk
```

### Integration with CI/CD

Add security checks to your development pipeline:

```yaml
# .github/workflows/security-scan.yml
name: Flutter Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup Flutter
      uses: subosito/flutter-action@v2
      with:
        flutter-version: '3.x'
    
    - name: Build APK
      run: flutter build apk --release
    
    - name: Run MobSF Scan
      run: |
        docker pull opensecurity/mobile-security-framework-mobsf
        docker run -d -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
        # Upload and scan APK
    
    - name: Check for hardcoded secrets
      run: |
        flutter pub global activate pubspec_lock
        flutter pub run analyze_hardcoded_secrets
    
    - name: Dependency vulnerability check
      run: flutter pub outdated --show-all
```

---

## Legal and Ethical Considerations

### Authorization

**Critical**: Always obtain written permission before testing:
- Client authorization letter
- Defined scope and boundaries
- Clear start/end dates
- Rules of engagement
- Emergency contact procedures

### Responsible Disclosure

If you discover vulnerabilities:

1. **Report to the vendor immediately**
   - Use official security contact
   - Provide detailed technical information
   - Allow reasonable time to fix (typically 90 days)

2. **Do not publicly disclose**
   - Before vendor has patched
   - Without coordinating with vendor
   - In ways that could cause harm

3. **Follow disclosure guidelines**
   - CERT/CC coordination
   - CVE assignment process
   - Responsible disclosure platforms (HackerOne, Bugcrowd)

### Testing Limitations

**Do not**:
- Test production systems without permission
- Access other users' data
- Perform DoS attacks
- Test third-party services
- Exceed authorized scope

---

## Conclusion

Flutter application security testing requires a specialized approach due to the framework's unique architecture. This guide provides comprehensive methodologies, from basic SSL pinning bypass to advanced binary analysis and automation.

### Key Takeaways

1. **SSL Pinning**: Use NVISO script or Reflutter for reliable bypass
2. **Static Analysis**: Always extract and analyze strings from libapp.so/App binary
3. **Dynamic Analysis**: Frida is essential for runtime instrumentation
4. **Obfuscation**: Expect resistance; prepare multiple bypass techniques
5. **Automation**: Integrate security testing into development workflows

### Next Steps

- Practice on intentionally vulnerable Flutter apps
- Contribute to open-source security tools
- Stay updated with Flutter security updates
- Join security communities
- Continuous learning and skill development

### Additional Resources

- **OWASP Mobile Top 10 2024**
- **Flutter Security Documentation**
- **Frida CodeShare Scripts**
- **Mobile Security Testing Guide (MSTG)**

---

## Contributing

This guide is open source. Contributions are welcome:

1. Fork the repository
2. Create a feature branch
3. Add content or improvements
4. Submit a pull request

### Areas for Contribution

- Additional case studies
- New bypass techniques
- Updated tool versions
- Platform-specific tips
- Automation scripts
- Translations

---

## Changelog

**v2.0.0** - October 2025
- Complete rewrite with improved structure
- Added advanced techniques section
- Included automation scripts
- Expanded security best practices
- Added real-world case studies
- Comprehensive testing checklist

---

## License

MIT License - Free to use, modify, and distribute with attribution.

## Disclaimer

This guide is for educational purposes and authorized security testing only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before conducting security assessments.

---

**Author**:  Anousone Phyakeo  
**Last Updated**: October 2025  
**Version**: 2.0.0  
**Repository**: (https://github.com/anousonephyakeo/flutter-security-toolkit)

---

*For questions, updates, or contributions, please open an issue on GitHub.*

# Static-Android-Testing-Checklist

## **1. APK Extraction & Decompilation**  
- [ ] **Extract APK contents**: `unzip app.apk -d extracted_apk`  
- [ ] **Decompile with apktool**: `apktool d app.apk -o extracted_apk`  
- [ ] **Convert APK to Java code**: `jadx -d jadx_output app.apk`  
- [ ] **Convert APK to Smali code**: `baksmali disassemble classes.dex`  

---

## **2. AndroidManifest.xml Analysis**  
- [ ] **Check for excessive permissions** (`READ_SMS`, `WRITE_EXTERNAL_STORAGE`, etc.)  
- [ ] **Look for exported activities/services/broadcast receivers** (`android:exported="true"`)  
- [ ] **Check if the app is debuggable** (`android:debuggable="true"`)  
- [ ] **Review backup configuration** (`android:allowBackup="true"`)  

---

## **3. Hardcoded Secrets & API Keys**  
- [ ] **Search for API keys/tokens/secrets**:  
  ```
  grep -r "API_KEY" extracted_apk/
  grep -r "password" extracted_apk/
  ```  
- [ ] **Check for hardcoded credentials in Java/Smali code**  
- [ ] **Check for sensitive URLs or internal endpoints**  

---

## **4. Java Code Review (Reversing Java Classes)**  
- [ ] **Look for sensitive functions (authentication, encryption, etc.)**  
- [ ] **Identify hardcoded business logic that can be abused**  
- [ ] **Check for weak encryption usage (e.g., AES in ECB mode)**  
- [ ] **Look for logging/debugging code left in production**  
  ```java
  Log.d("Debug", "User Password: " + password);
  ```  

---

## **5. Smali Code Analysis (For Obfuscated Apps)**  
- [ ] **Search for sensitive function calls in Smali files**  
  ```
  grep -r "getSharedPreferences" smali/
  grep -r "AES/ECB/PKCS5Padding" smali/
  ```  
- [ ] **Identify root detection or anti-tampering mechanisms**  
- [ ] **Check if integrity checks exist (e.g., signature validation)**  

---

## **6. Insecure Data Storage**  
- [ ] **Check for sensitive data in SharedPreferences**  
  ```java
  SharedPreferences pref = getSharedPreferences("MyPrefs", Context.MODE_PRIVATE);
  pref.edit().putString("password", "123456").apply();
  ```  
- [ ] **Look for plaintext storage in databases (`.db` files)**  
- [ ] **Check for sensitive files stored in external storage (`/sdcard/`)**  
- [ ] **Scan extracted APK for sensitive information**:  
  ```
  find extracted_apk/ -name "*.xml" | xargs grep -i "password"
  ```  

---

## **7. SSL/TLS Security Issues**  
- [ ] **Check for insecure TrustManager implementation (accepting all certs)**  
  ```java
  @Override
  public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
      // Do nothing (Vulnerable!)
  }
  ```  
- [ ] **Check if SSL Pinning is disabled or bypassable**  
- [ ] **Look for HTTP instead of HTTPS calls in API endpoints**  

---

## **8. Third-Party Libraries & Dependency Analysis**  
- [ ] **Extract the `lib/` folder and check for outdated libraries**  
- [ ] **Use MobSF or Androguard to analyze libraries for known CVEs**  
  ```
  androguard analyze -i app.apk
  ```  
- [ ] **Look for embedded analytics or tracking SDKs (privacy concerns)**  

---

## **9. Code Obfuscation & Protections**  
- [ ] **Check if ProGuard or R8 is enabled (or missing!)**  
- [ ] **Look for ProGuard mapping files (`assets/mapping.txt`)**  
- [ ] **Verify if decompiled Java code is readable (if so, obfuscation is weak)**  

---

## **10. Android Components Security (Deeplinks & Intent Manipulation)**  
- [ ] **Check for exported activities (`android:exported="true"`)**  
- [ ] **Test for intent-based attacks (passing malicious data to activities)**  
- [ ] **Analyze deeplinks (`android:host="*"`, unvalidated input risks)**  
- [ ] **Look for insecure Broadcast Receivers (`android:exported="true"`)**  

---

## **11. Root Detection & Anti-Tampering**  
- [ ] **Check for root detection methods in Java/Smali code**  
  ```java
  new File("/system/bin/su").exists();
  ```  
- [ ] **Look for hooks to prevent tampering/debugging**  
- [ ] **Identify potential Frida/Instrumentation detection methods**  

---

## **12. WebView Security (If Used in the App)**  
- [ ] **Check if JavaScript is enabled (`setJavaScriptEnabled(true)`)**  
- [ ] **Look for `addJavascriptInterface()` (potential RCE vulnerability)**  
- [ ] **Verify if WebView allows loading untrusted content (`file://`, `http://`)**  

---

## **13. Local File Inclusion & Path Traversal Risks**  
- [ ] **Check for file operations that might allow directory traversal**  
  ```java
  File file = new File("/data/data/com.app/files/" + userInput);
  ```  
- [ ] **Look for improper validation of file paths in file read/write functions**  

---

## **14. Automated Static Analysis Tools (For Fast Testing)**  
- [ ] **Run MobSF for static analysis**  
  ```
  python3 mobsf.py -s app.apk
  ```  
- [ ] **Use Quark-Engine to detect malware-like behavior**  
  ```
  quark -a app.apk
  ```  
- [ ] **Analyze APK with `androguard`**  
  ```
  androguard analyze -i app.apk
  ```  

---

## **15. Checking for Debugging Symbols & Extra Files**  
- [ ] **Check for `.pdb` files (debugging symbols)**  
- [ ] **Look for leftover `.bak` and `.swp` files in the extracted APK**  
- [ ] **Identify any unnecessary development/testing files**  

---
## **Advanced Static Analysis Checks**  

### **16. IPC (Inter-Process Communication) Security**  
- [ ] **Check for insecure `Binder` IPC calls**  
- [ ] **Look for `ContentProvider` leaks (`android:grantUriPermissions="true"`)**  
- [ ] **Verify exported `AIDL` interfaces that could be exploited**  
- [ ] **Identify weak or missing access control for `Service` components**  

---

### **17. Custom Encryption Implementation Issues**  
- [ ] **Look for weak encryption algorithms (e.g., Base64 instead of AES)**  
- [ ] **Identify hardcoded encryption keys in Java/Smali**  
- [ ] **Check if AES uses ECB mode (which is insecure)**  
  ```java
  Cipher.getInstance("AES/ECB/PKCS5Padding");
  ```  
- [ ] **Check for improper key storage (e.g., hardcoded keys in SharedPreferences)**  

---

### **18. Unused or Hidden Permissions**  
- [ ] **Look for hidden permissions that are not used in the app but declared in `AndroidManifest.xml`**  
- [ ] **Check if any third-party SDK is requesting excessive permissions**  
- [ ] **Verify if the app asks for system-level (`SYSTEM_ALERT_WINDOW`) permissions**  

---

### **19. Android Debug Bridge (ADB) Security**  
- [ ] **Check if the app can be launched with ADB (debuggable mode enabled)**  
  ```bash
  adb shell am start -n com.example.app/.MainActivity
  ```  
- [ ] **Try bypassing authentication via ADB commands**  

---

### **20. Firebase & Cloud Misconfigurations**  
- [ ] **Check if Firebase database is publicly accessible (`/.json` files accessible)**  
- [ ] **Look for hardcoded Firebase API keys in `google-services.json`**  
- [ ] **Analyze network requests for exposed cloud storage endpoints**  

---

### **21. Checking for Weak JWT or Token Usage**  
- [ ] **Extract JWT tokens from Java code**  
- [ ] **Check if tokens are weak (e.g., missing expiration, signed with `none` algorithm)**  
- [ ] **Verify if the app stores JWT tokens insecurely (e.g., in SharedPreferences)**  

---

### **22. Native Code & JNI Security (If the App Uses NDK)**  
- [ ] **Check if native libraries (`lib/*.so`) have insecure functions like `strcpy()`**  
- [ ] **Look for hardcoded cryptographic keys in JNI code**  
- [ ] **Check for buffer overflow vulnerabilities in C/C++ code**  

---
### **Top Tools for Static Analysis in Android Pentesting** 🚀  

Here’s a list of the **best tools** to help you **automate vulnerability identification** in Android apps during **static analysis**.  

---

## 🔍 **1. MobSF (Mobile Security Framework)**
✅ **Best for:** Automated static & dynamic analysis.  
🔹 **Features:**  
- Scans for **hardcoded secrets, weak permissions, and misconfigurations**.  
- Identifies **insecure exported components** (Activities, Services, etc.).  
- Analyzes **third-party libraries for CVEs**.  
- Supports **both APK and IPA (iOS) analysis**.  

🔹 **Usage:**  
```bash
python3 mobsf.py -s app.apk
```
🔹 **Download:** [https://github.com/MobSF/Mobile-Security-Framework-MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)  

---

## 📜 **2. Apktool**
✅ **Best for:** Reverse-engineering and modifying Android apps.  
🔹 **Features:**  
- **Decompiles APKs** to **Smali code**.  
- Reconstructs `AndroidManifest.xml` and resource files.  
- Allows **modification and re-compilation** of APKs.  

🔹 **Usage:**  
```bash
apktool d app.apk -o extracted_apk
```
🔹 **Download:** [https://github.com/iBotPeaches/Apktool](https://github.com/iBotPeaches/Apktool)  

---

## 🏗 **3. JADX (Java Decompiler)**
✅ **Best for:** Decompiling APKs into **readable Java code**.  
🔹 **Features:**  
- Converts **DEX** files into **Java**.  
- Useful for finding **hardcoded secrets & logic flaws**.  
- GUI version available (**Jadx-GUI**).  

🔹 **Usage:**  
```bash
jadx -d jadx_output app.apk
```
🔹 **Download:** [https://github.com/skylot/jadx](https://github.com/skylot/jadx)  

---

## 🛠 **4. Androguard**
✅ **Best for:** **Automated** APK static analysis with Python scripting.  
🔹 **Features:**  
- Extracts **AndroidManifest.xml** for permission analysis.  
- Identifies **insecure API calls** in decompiled code.  
- Can be used for **malware detection**.  

🔹 **Usage:**  
```bash
androguard analyze -i app.apk
```
🔹 **Download:** [https://github.com/androguard/androguard](https://github.com/androguard/androguard)  

---

## 🔑 **5. TruffleHog / GitLeaks (Secret Scanners)**
✅ **Best for:** **Finding API keys, tokens, and credentials** inside APKs.  
🔹 **Features:**  
- Scans for **AWS keys, API tokens, Firebase secrets, and more**.  
- Works on **source code and extracted APKs**.  

🔹 **Usage:**  
```bash
trufflehog filesystem extracted_apk/
gitleaks detect --source extracted_apk/
```
🔹 **Download:**  
- [TruffleHog](https://github.com/trufflesecurity/trufflehog)  
- [GitLeaks](https://github.com/zricethezav/gitleaks)  

---

## 🕵️ **6. Quark-Engine**
✅ **Best for:** **Malware behavior analysis**.  
🔹 **Features:**  
- Detects **malicious patterns** in APKs.  
- Identifies **risky API calls & behaviors**.  
- Supports **custom rules for threat detection**.  

🔹 **Usage:**  
```bash
quark -a app.apk
```
🔹 **Download:** [https://github.com/quark-engine/quark-engine](https://github.com/quark-engine/quark-engine)  

---

## 🏴‍☠️ **7. APKiD**
✅ **Best for:** Detecting **packing, obfuscation, and anti-tampering**.  
🔹 **Features:**  
- Identifies **ProGuard, R8, DexGuard, and other obfuscation techniques**.  
- Helps determine **if an APK is protected against reverse engineering**.  

🔹 **Usage:**  
```bash
apkid app.apk
```
🔹 **Download:** [https://github.com/rednaga/APKiD](https://github.com/rednaga/APKiD)  

---

## 🔥 **8. Bytecode Viewer**
✅ **Best for:** Multi-decompiler support for **Java & Smali**.  
🔹 **Features:**  
- Supports **JADX, CFR, FernFlower, Procyon** decompilers.  
- Allows **editing and patching Smali code**.  
- Useful for **manual review of decompiled Java/Smali**.  

🔹 **Download:** [https://github.com/Konloch/bytecode-viewer](https://github.com/Konloch/bytecode-viewer)  

---

## 📦 **9. ClassyShark**
✅ **Best for:** Analyzing APK structure, DEX, and third-party libraries.  
🔹 **Features:**  
- **Lightweight and fast** APK analysis.  
- Allows **browsing app structure and dependencies**.  
- Can **identify embedded third-party SDKs**.  

🔹 **Download:** [https://github.com/google/android-classyshark](https://github.com/google/android-classyshark)  

---

## 🔍 **10. Super Security Scanner - APKiD + VirusTotal**
✅ **Best for:** **Quick APK malware & obfuscation checks**.  
🔹 **Features:**  
- Combines **APKiD (for obfuscation detection) + VirusTotal API**.  
- Detects **potential malware signatures** inside APKs.  
- Works as a **quick pre-check tool** before deep analysis.  

🔹 **Usage:**  
```bash
apkid app.apk | tee output.txt
curl -F "file=@app.apk" https://www.virustotal.com/api/v3/files
```
🔹 **Website:** [https://www.virustotal.com](https://www.virustotal.com)  

---

# **🔥 Recommended Setup for Maximum Efficiency**
✅ **Step 1:** Install essential tools  
```bash
pip install androguard quark-engine apkid
```
✅ **Step 2:** Use **MobSF** for an **automated static scan**  
```bash
python3 mobsf.py -s app.apk
```
✅ **Step 3:** Use **JADX & Apktool** for **manual analysis**  
```bash
jadx -d jadx_output app.apk
apktool d app.apk -o extracted_apk
```
✅ **Step 4:** Find **hardcoded secrets** using `TruffleHog`  
```bash
trufflehog filesystem extracted_apk/
```
✅ **Step 5:** Check for **malware patterns** with `Quark`  
```bash
quark -a app.apk
```
✅ **Step 6:** Use **APKiD** to detect obfuscation  
```bash
apkid app.apk
```

---

### **🚀 Conclusion: Which Tool Should You Use?**
- **For complete automation:** ✅ `MobSF`  
- **For deep APK modification:** ✅ `Apktool`  
- **For reading Java code:** ✅ `JADX`  
- **For secret detection:** ✅ `TruffleHog`  
- **For malware detection:** ✅ `Quark-Engine`  
- **For obfuscation checks:** ✅ `APKiD`  

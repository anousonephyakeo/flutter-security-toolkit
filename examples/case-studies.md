# Real-World Case Studies

> **Note:** All case studies are anonymized to protect confidentiality.

## Case Study 1: Banking Application

**Protection Mechanisms:**
- SSL certificate pinning (custom implementation)
- Root detection (multiple checks)
- Emulator detection
- Frida detection
- Binary integrity checks

**Testing Approach:**
1. Used physical rooted device (Pixel 6 Pro)
2. Renamed Frida server to `.system_daemon`
3. Applied NVISO SSL bypass script
4. Patched root detection in libapp.so
5. Successfully intercepted all API traffic

**Key Findings:**
- ❌ JWT tokens stored unencrypted in SharedPreferences
- ❌ API vulnerable to IDOR (Insecure Direct Object References)
- ❌ Session tokens never expired
- ❌ Hardcoded API keys found in binary
- ❌ No server-side rate limiting

**Impact:** Critical - Full account compromise possible

**Remediation:**
- Implement secure storage (KeyStore/Keychain)
- Add server-side authorization checks
- Implement proper session management
- Use environment variables for secrets
- Add rate limiting on backend

---

## Case Study 2: E-Commerce Application

**Protection Mechanisms:**
- Basic SSL pinning only

**Testing Approach:**
1. Used Reflutter for automated SSL bypass
2. Intercepted checkout process with BurpSuite
3. Analyzed payment API endpoints

**Key Findings:**
- ❌ Predictable transaction IDs (sequential)
- ❌ Client-side price calculation trusted by server
- ❌ Discount codes not validated server-side
- ❌ Cart manipulation possible

**Impact:** High - Financial fraud potential

**Remediation:**
- Implement server-side price validation
- Use UUIDs for transaction IDs
- Validate all discounts on backend
- Add integrity checks for cart data

---

## Case Study 3: Social Media Application

**Protection Mechanisms:**
- None

**Testing Approach:**
1. Simple APK extraction and static analysis
2. No SSL pinning detected
3. Direct traffic interception

**Key Findings:**
- ❌ User credentials in plaintext (SharedPreferences)
- ❌ Private messages unencrypted in SQLite
- ❌ Session tokens never expire
- ❌ API tokens in application logs
- ❌ Profile pictures cached without encryption

**Impact:** Critical - Complete privacy breach

**Remediation:**
- Never store credentials locally
- Encrypt all local data
- Implement session timeouts
- Disable logging in production
- Use secure storage APIs

---

## Contributing Your Case Studies

Have a case study to share? Please:
1. **Anonymize** all sensitive information
2. **Get permission** if testing client apps
3. Submit via pull request
4. Follow responsible disclosure
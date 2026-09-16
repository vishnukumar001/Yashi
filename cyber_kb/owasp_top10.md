# OWASP Top 10 2021 - Complete Reference

## A01:2021 – Broken Access Control
**Description**: Users can act outside their intended permissions.

### Common Vulnerabilities
- Vertical privilege escalation (user → admin)
- Horizontal privilege escalation (user A → user B data)
- Missing function-level access control
- Insecure direct object references (IDOR)
- Path traversal
- CORS misconfiguration

### Detection
```bash
# Test IDOR
curl -H "Authorization: Bearer USER_A_TOKEN" https://api.example.com/users/123/profile
# Should only return user A's data

# Test path traversal
curl https://example.com/files/../../etc/passwd
```

### Prevention
- Deny by default
- Implement access control checks at every endpoint
- Use centralized authorization logic
- Test with automated tools (OWASP ZAP, Burp Suite)

---

## A02:2021 – Cryptographic Failures
**Description**: Failure to properly protect sensitive data.

### Common Vulnerabilities
- Transmitting data in cleartext (HTTP, FTP, SMTP)
- Weak encryption algorithms (MD5, SHA1, DES, RC4)
- Default/weak crypto keys
- Missing encryption for sensitive data at rest
- Improper certificate validation

### Detection
```bash
# Check for HTTPS
curl -I https://example.com | grep -i strict-transport-security

# Test weak ciphers
nmap --script ssl-enum-ciphers -p 443 example.com

# Check for sensitive data in logs/URLs
grep -r "password\|api_key\|secret" /var/log/
```

### Prevention
- Classify data sensitivity
- Encrypt all sensitive data in transit (TLS 1.2+) and at rest (AES-256)
- Use strong, up-to-date algorithms
- Disable caching for sensitive responses
- Proper key management

---

## A03:2021 – Injection
**Description**: Untrusted data sent to interpreter as part of command/query.

### Types
- **SQL Injection** (SQLi)
- **NoSQL Injection**
- **OS Command Injection**
- **LDAP Injection**
- **XPath Injection**
- **Expression Language Injection**

### Detection
```bash
# SQLi test
curl "https://example.com/search?q=test' OR '1'='1"

# Command injection
curl "https://example.com/ping?host=8.8.8.8;id"

# NoSQL injection
curl -X POST -H "Content-Type: application/json" \
  -d '{"username": {"$ne": null}, "password": {"$ne": null}}' \
  https://api.example.com/login
```

### Prevention
- Parameterized queries / prepared statements
- ORM with built-in protection
- Input validation & sanitization
- Least privilege database accounts
- WAF rules

---

## A04:2021 – Insecure Design
**Description**: Missing or ineffective control design.

### Common Issues
- Missing threat modeling
- Business logic flaws
- Insufficient security controls by design
- Insecure default configurations

### Prevention
- Threat modeling (STRIDE, PASTA)
- Security requirements in design phase
- Secure design patterns
- Security architecture reviews

---

## A05:2021 – Security Misconfiguration
**Description**: Insecure default configurations, incomplete configurations.

### Common Vulnerabilities
- Default credentials unchanged
- Unnecessary features enabled (ports, services, pages)
- Error messages revealing stack traces
- Missing security headers
- Outdated software/components
- Cloud storage public access

### Detection
```bash
# Check security headers
curl -I https://example.com | grep -E "X-Frame-Options|X-Content-Type-Options|Content-Security-Policy|Strict-Transport-Security"

# Scan for misconfigurations
nikto -h example.com

# Check cloud configs
aws s3 ls --recursive | grep -i public
```

### Prevention
- Hardening guides (CIS Benchmarks)
- Automated configuration management
- Minimal platform installation
- Regular patching
- Security headers implementation

---

## A06:2021 – Vulnerable and Outdated Components
**Description**: Using components with known vulnerabilities.

### Common Issues
- Outdated frameworks/libraries
- Unpatched OS/software
- Unsupported/end-of-life software
- No dependency tracking

### Detection
```bash
# npm audit
npm audit

# Python safety
pip install safety && safety check

# OWASP Dependency Check
dependency-check --project "MyApp" --scan .

# Trivy for containers
trivy image myimage:latest
```

### Prevention
- Inventory all components
- Monitor for vulnerabilities (CVE databases)
- Automated patching
- Remove unused dependencies
- Software Bill of Materials (SBOM)

---

## A07:2021 – Identification and Authentication Failures
**Description**: Weak authentication mechanisms.

### Common Vulnerabilities
- Permitting weak passwords
- Brute force attacks not prevented
- Default/weak credentials
- Session fixation
- Exposed session IDs in URLs
- Missing MFA

### Detection
```bash
# Test brute force protection
for i in {1..10}; do curl -X POST -d "user=admin&pass=wrong" https://example.com/login; done

# Check password policy
curl -X POST -d "password=123" https://example.com/register

# Session fixation
# 1. Get session ID before login
# 2. Login
# 3. Check if session ID changed
```

### Prevention
- Multi-factor authentication (MFA)
- Strong password policies
- Rate limiting / account lockout
- Secure session management
- Credential stuffing protection
- Breached password checking (HaveIBeenPwned API)

---

## A08:2021 – Software and Data Integrity Failures
**Description**: Code/infrastructure not protected against integrity violations.

### Common Vulnerabilities
- Unverified software updates
- CI/CD pipeline compromise
- Insecure deserialization
- Auto-update without verification
- Unsigned dependencies

### Prevention
- Digital signatures for updates
- Signed commits/tags
- SBOM verification
- CI/CD security (SLSA)
- Integrity checks for dependencies

---

## A09:2021 – Security Logging and Monitoring Failures
**Description**: Insufficient logging/monitoring for detection.

### Common Issues
- Missing logs for security events
- Logs not monitored
- Logs stored locally only
- No alerting on anomalies
- Insufficient log retention

### Prevention
- Centralized logging (SIEM)
- Log all security events (auth, access control, errors)
- Real-time alerting
- Log integrity protection
- Retention policies
- Regular log review

---

## A10:2021 – Server-Side Request Forgery (SSRF)
**Description**: Server fetches user-supplied URL without validation.

### Common Vulnerabilities
- Fetching internal metadata services (AWS IMDS, GCP Metadata)
- Accessing internal services
- Port scanning internal network
- Cloud credential theft

### Detection
```bash
# Test SSRF
curl "https://example.com/fetch?url=http://169.254.169.254/latest/meta-data/"
curl "https://example.com/fetch?url=http://localhost:8080/admin"
curl "https://example.com/fetch?url=file:///etc/passwd"
```

### Prevention
- Allowlist URLs/domains
- Block private IP ranges (RFC 1918)
- Disable unnecessary URL schemas (file://, gopher://)
- Network segmentation
- Validate/sanitize user-supplied URLs

---

## OWASP API Security Top 10 2023

1. **API1:2023** - Broken Object Level Authorization (BOLA)
2. **API2:2023** - Broken Authentication
3. **API3:2023** - Broken Object Property Level Authorization
4. **API4:2023** - Unrestricted Resource Consumption
5. **API5:2023** - Broken Function Level Authorization
6. **API6:2023** - Unrestricted Access to Sensitive Business Flows
7. **API7:2023** - Server Side Request Forgery (SSRF)
8. **API8:2023** - Security Misconfiguration
9. **API9:2023** - Improper Inventory Management
10. **API10:2023** - Unsafe Consumption of APIs

---

## Testing Checklist for Each Category

### Automated Tools
- **SAST**: SonarQube, CodeQL, Semgrep, Bandit
- **DAST**: OWASP ZAP, Burp Suite, Nikto
- **SCA**: OWASP Dependency Check, Snyk, Trivy
- **Container**: Trivy, Clair, Anchore
- **IaC**: Checkov, tfsec, Terrascan

### Manual Testing
- Authentication/Authorization testing
- Business logic testing
- Input validation testing
- Session management testing
- Error handling testing

---

## References
- OWASP Top 10: https://owasp.org/Top10/
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- OWASP Cheat Sheets: https://cheatsheetseries.owasp.org/
- OWASP Testing Guide: https://owasp.org/www-project-testing-guide/
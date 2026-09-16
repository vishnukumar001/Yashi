# CWE (Common Weakness Enumeration) Top 25 + Key Categories

## 2023 CWE Top 25 Most Dangerous Software Weaknesses

### 1. CWE-787: Out-of-bounds Write
Memory corruption allowing write past buffer boundary.

### 2. CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)
Cross-site scripting - untrusted data rendered in browser.

### 3. CWE-89: Improper Neutralization of Special Elements used in an SQL Command (SQLi)
SQL injection - user input interpreted as SQL commands.

### 4. CWE-20: Improper Input Validation
Input not validated before use.

### 5. CWE-125: Out-of-bounds Read
Read past buffer boundary - information disclosure.

### 6. CWE-78: Improper Neutralization of Special Elements used in an OS Command (Command Injection)
OS command injection - user input executed as commands.

### 7. CWE-416: Use After Free
Memory accessed after being freed - corruption/crash.

### 8. CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)
Directory traversal - access files outside intended directory.

### 9. CWE-352: Cross-Site Request Forgery (CSRF)
Forced authenticated requests from victim's browser.

### 10. CWE-434: Unrestricted Upload of File with Dangerous Type
File upload without type validation - RCE risk.

### 11. CWE-476: NULL Pointer Dereference
Dereferencing null pointer - crash/DoS.

### 12. CWE-502: Deserialization of Untrusted Data
Insecure deserialization - remote code execution.

### 13. CWE-190: Integer Overflow or Wraparound
Integer overflow leading to buffer allocation errors.

### 14. CWE-287: Improper Authentication
Authentication bypass or weakness.

### 15. CWE-798: Use of Hard-coded Credentials
Embedded passwords/keys in source code.

### 16. CWE-862: Missing Authorization
Authorization check missing - privilege escalation.

### 17. CWE-77: Improper Neutralization of Special Elements used in a Command (Command Injection)
Similar to CWE-78.

### 18. CWE-306: Missing Authentication for Critical Function
Critical function accessible without auth.

### 19. CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer
Buffer overflow/underflow.

### 20. CWE-276: Incorrect Default Permissions
Insecure default file/directory permissions.

### 21. CWE-918: Server-Side Request Forgery (SSRF)
Server forced to make requests to internal resources.

### 22. CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization (Race Condition)
TOCTOU race conditions.

### 23. CWE-269: Improper Privilege Management
Privilege escalation through poor management.

### 24. CWE-94: Improper Control of Generation of Code (Code Injection)
Code injection - eval/injection of executable code.

### 25. CWE-863: Incorrect Authorization
Authorization logic flawed - bypass possible.

---

## Key CWE Categories for Cybersecurity Students

### Input Validation & Sanitization
- **CWE-20**: Improper Input Validation
- **CWE-116**: Improper Encoding/Escaping
- **CWE-138**: Improper Neutralization of Special Elements
- **CWE-172**: Encoding Error

### Injection Flaws
- **CWE-89**: SQL Injection
- **CWE-78**: OS Command Injection
- **CWE-79**: Cross-site Scripting (XSS)
- **CWE-94**: Code Injection
- **CWE-564**: SQL Injection: Hibernate
- **CWE-943**: Improper Neutralization of Special Elements in Data Query Logic

### Memory Safety
- **CWE-119**: Buffer Overflow
- **CWE-120**: Buffer Copy without Size Check
- **CWE-121**: Stack-based Buffer Overflow
- **CWE-122**: Heap-based Buffer Overflow
- **CWE-125**: Out-of-bounds Read
- **CWE-170**: Improper Null Termination
- **CWE-416**: Use After Free
- **CWE-415**: Double Free
- **CWE-476**: NULL Pointer Dereference

### Authentication & Session Management
- **CWE-287**: Improper Authentication
- **CWE-306**: Missing Authentication
- **CWE-307**: Improper Restriction of Excessive Authentication Attempts
- **CWE-384**: Session Fixation
- **CWE-613**: Insufficient Session Expiration
- **CWE-259**: Use of Hard-coded Password
- **CWE-798**: Use of Hard-coded Credentials

### Authorization
- **CWE-862**: Missing Authorization
- **CWE-863**: Incorrect Authorization
- **CWE-269**: Improper Privilege Management
- **CWE-276**: Incorrect Default Permissions
- **CWE-284**: Improper Access Control

### Cryptographic Issues
- **CWE-327**: Use of Broken/Risky Cryptographic Algorithm
- **CWE-326**: Inadequate Encryption Strength
- **CWE-329**: Not Using Random IV with CBC Mode
- **CWE-330**: Insufficiently Random Values
- **CWE-331**: Insufficient Entropy
- **CWE-338**: Use of Cryptographically Weak PRNG
- **CWE-798**: Use of Hard-coded Cryptographic Key

### Information Exposure
- **CWE-200**: Exposure of Sensitive Information
- **CWE-209**: Generation of Error Message Containing Sensitive Information
- **CWE-497**: Exposure of System Data to Unauthorized Control Sphere
- **CWE-532**: Insertion of Sensitive Information into Log File
- **CWE-598**: Information Exposure Through Query Strings in GET Request

### Web Application Security
- **CWE-79**: XSS
- **CWE-352**: CSRF
- **CWE-601**: URL Redirection to Untrusted Site (Open Redirect)
- **CWE-434**: Unrestricted File Upload
- **CWE-918**: SSRF
- **CWE-113**: Improper Neutralization of CRLF Sequences (HTTP Response Splitting)

### Path & File Handling
- **CWE-22**: Path Traversal
- **CWE-23**: Relative Path Traversal
- **CWE-36**: Absolute Path Traversal
- **CWE-41**: Improper Resolution of Path Equivalence
- **CWE-59**: Improper Link Resolution Before File Access

### Deserialization
- **CWE-502**: Deserialization of Untrusted Data
- **CWE-915**: Improperly Controlled Modification of Dynamically-Determined Object Attributes

### Concurrency & Race Conditions
- **CWE-362**: Race Condition
- **CWE-367**: Time-of-check Time-of-use (TOCTOU)
- **CWE-366**: Race Condition within a Thread

### Configuration & Deployment
- **CWE-16**: Configuration
- **CWE-260**: Password in Configuration File
- **CWE-526**: Exposure of Sensitive Information Through Environmental Variables
- **CWE-538**: Insertion of Sensitive Information into Externally-Accessible File
- **CWE-547**: Use of Hard-coded, Security-relevant Constants

---

## CWE to ATT&CK Mapping (Key Examples)

| CWE | ATT&CK Technique |
|-----|------------------|
| CWE-78 | T1059.004 (Unix Shell), T1059.003 (Windows Command Shell) |
| CWE-89 | T1190 (Exploit Public-Facing Application) |
| CWE-79 | T1189 (Drive-by Compromise) |
| CWE-22 | T1083 (File and Directory Discovery) |
| CWE-502 | T1129 (Shared Modules), T1203 (Exploitation for Client Execution) |
| CWE-798 | T1552 (Unsecured Credentials) |
| CWE-287 | T1078 (Valid Accounts) |
| CWE-862 | T1548 (Abuse Elevation Control Mechanism) |
| CWE-918 | T1190 (Exploit Public-Facing Application) |
| CWE-434 | T1190 (Exploit Public-Facing Application) |

---

## Learning Resources
- CWE Official: https://cwe.mitre.org/
- CWE Top 25: https://cwe.mitre.org/top25/archive/2023/2023_cwe_top25.html
- CWE View: https://cwe.mitre.org/data/definitions/1000.html
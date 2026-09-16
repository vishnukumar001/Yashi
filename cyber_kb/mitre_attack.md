# MITRE ATT&CK Knowledge Base

## Enterprise Matrix - Tactics & Techniques

### TA0001: Initial Access
- **T1190**: Exploit Public-Facing Application
- **T1133**: External Remote Services
- **T1078**: Valid Accounts
- **T1189**: Drive-by Compromise
- **T1195**: Supply Chain Compromise
- **T1199**: Trusted Relationship
- **T1200**: Hardware Additions
- **T1566**: Phishing
  - T1566.001: Spearphishing Attachment
  - T1566.002: Spearphishing Link
  - T1566.003: Spearphishing via Service

### TA0002: Execution
- **T1059**: Command and Scripting Interpreter
  - T1059.001: PowerShell
  - T1059.003: Windows Command Shell
  - T1059.004: Unix Shell
  - T1059.005: Visual Basic
  - T1059.006: Python
  - T1059.007: JavaScript/JScript
- **T1053**: Scheduled Task/Job
  - T1053.005: Scheduled Task
  - T1053.003: Cron
- **T1559**: Inter-Process Communication
- **T1129**: Shared Modules
- **T1203**: Exploitation for Client Execution
- **T1204**: User Execution

### TA0003: Persistence
- **T1547**: Boot or Logon Autostart Execution
  - T1547.001: Registry Run Keys / Startup Folder
  - T1547.009: Shortcut Modification
- **T1505**: Server Software Component
  - T1505.003: Web Shell
- **T1556**: Modify Authentication Process
- **T1554**: Compromise Client Software Binary
- **T1546**: Event Triggered Execution
- **T1136**: Create Account
- **T1137**: Office Application Startup

### TA0004: Privilege Escalation
- **T1068**: Exploitation for Privilege Escalation
- **T1055**: Process Injection
- **T1548**: Abuse Elevation Control Mechanism
  - T1548.002: Bypass User Account Control
- **T1547**: Boot or Logon Autostart Execution

### TA0005: Defense Evasion
- **T1070**: Indicator Removal
  - T1070.001: Clear Windows Event Logs
  - T1070.004: File Deletion
- **T1562**: Impair Defenses
  - T1562.001: Disable or Modify Tools
  - T1562.004: Disable or Modify System Firewall
- **T1027**: Obfuscated Files or Information
  - T1027.002: Software Packing
  - T1027.005: Steganography
- **T1055**: Process Injection
- **T1574**: Hijack Execution Flow
  - T1574.001: DLL Search Order Hijacking
  - T1574.002: DLL Side-Loading

### TA0006: Credential Access
- **T1003**: OS Credential Dumping
  - T1003.001: LSASS Memory
  - T1003.008: /etc/passwd and /etc/shadow
- **T1110**: Brute Force
  - T1110.001: Password Guessing
  - T1110.003: Password Spraying
- **T1555**: Credentials from Password Stores
- **T1552**: Unsecured Credentials
- **T1056**: Input Capture
  - T1056.001: Keylogging

### TA0007: Discovery
- **T1082**: System Information Discovery
- **T1083**: File and Directory Discovery
- **T1057**: Process Discovery
- **T1049**: System Network Connections Discovery
- **T1018**: Remote System Discovery
- **T1069**: Permission Groups Discovery
- **T1087**: Account Discovery
- **T1518**: Software Discovery
- **T1016**: System Network Configuration Discovery
- **T1124**: System Time Discovery

### TA0008: Lateral Movement
- **T1021**: Remote Services
  - T1021.001: Remote Desktop Protocol
  - T1021.004: Pass the Hash
  - T1021.005: Pass the Ticket
- **T1550**: Use Alternate Authentication Material
- **T1210**: Exploitation of Remote Services
- **T1534**: Internal Spearphishing

### TA0009: Collection
- **T1005**: Data from Local System
- **T1039**: Data from Network Shared Drive
- **T1074**: Data Staged
- **T1560**: Archive Collected Data
- **T1115**: Clipboard Data
- **T1123**: Audio Capture
- **T1125**: Video Capture

### TA0010: Exfiltration
- **T1041**: Exfiltration Over Command and Control Channel
- **T1048**: Exfiltration Over Alternative Protocol
- **T1020**: Automated Exfiltration
- **T1567**: Exfiltration Over Web Service
  - T1567.002: Exfiltration to Cloud Storage

### TA0011: Command and Control
- **T1071**: Application Layer Protocol
  - T1071.001: Web Protocols
  - T1071.002: File Transfer Protocols
  - T1071.003: Mail Protocols
  - T1071.004: DNS
- **T1090**: Proxy
  - T1090.001: Internal Proxy
  - T1090.002: External Proxy
- **T1573**: Encrypted Channel
- **T1001**: Data Obfuscation

### TA0040: Impact
- **T1486**: Data Encrypted for Impact
- **T1485**: Data Destruction
- **T1491**: Defacement
- **T1490**: Inhibit System Recovery
- **T1499**: Endpoint Denial of Service

---

## Mobile Matrix
- **T1471**: Network Service Scanning
- **T1472**: Network Sniffing
- **T1473**: Rogue Wi-Fi Access Point
- **T1474**: Man-in-the-Middle Attack

## ICS Matrix
- **T0818**: Default Credentials
- **T0859**: Valid Accounts
- **T0881**: Exploitation for Privilege Escalation
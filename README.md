# 🕵️  Devices-Exposed-to-the-Internet

## 1️⃣ Preparation
### 🎯 Goal
Set up the hunt by defining what you're looking for.

During routine maintenance, the security team investigated VMs in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) to identify any mistakenly exposed VMs. The goal was to find misconfigurations and check for potential brute-force login attempts from external sources.

### 🔍 Hypothesis
Given the exposure of certain devices to the public internet, it is possible that brute-force login attempts were successful, particularly on older devices lacking account lockout protections.

---

## 2️⃣ Data Collection
### 🎯 Goal
Gather relevant data from logs, network traffic, and endpoints.

### 📊 Relevant Data Sources:
- **DeviceInfo**: Identifies exposed devices.
- **DeviceLogonEvents**: Tracks login attempts.

#### 📜 Query: Identify Internet-Facing Devices
```sql
DeviceInfo
| where DeviceName == "windows-target-1"
| where IsInternetFacing == true
| order by Timestamp desc
```
⏳ **Last internet-facing time:** Mar 27, 2025, 12:58:01 PM

---

## 3️⃣ Data Analysis
### 🎯 Goal
Analyze data to test the hypothesis.

#### 🚨 Query: Identify Brute Force Attempts
```sql
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```

![image](https://github.com/user-attachments/assets/9ee9089c-1f39-4898-8769-c8ba9684c11d)


👨‍💻 **Findings:** Several bad actors attempted logins but were unsuccessful.

#### 🔎 Query: Check for Successful Logins from Malicious IPs
```sql
let RemoteIPsInQuestion = dynamic(["218.92.0.186","218.92.0.187", "58.33.67.164", "185.7.214.14"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```
⚠️ **No successful logins detected from top failed login sources.**

---

## 4️⃣ Investigation
### 🎯 Goal
Dig deeper into detected threats, determine scope, and escalate if necessary.

#### ✅ Query: Verify Successful Logins
```sql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
| summarize count()
```
🔍 **Total successful logins for 'labuser': 14**

#### ✅ Query: Verify Failed Logins for 'labuser'
```sql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where AccountName == "labuser"
| summarize count()
```
✔️ **0 failed login attempts for 'labuser', suggesting no brute-force success.**

#### 🌍 Query: Check Login Locations for 'labuser'
```sql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
| summarize LoginCount = count() by DeviceName, ActionType, AccountName, RemoteIP
```

![image](https://github.com/user-attachments/assets/acd0c09c-9426-4662-839d-7c328c48cb1a)


✅ **All login sources appear legitimate.**

📌 **Conclusion:** Though the device was internet-facing, no unauthorized access was detected.

---

## 5️⃣ Response
### 🎯 Goal
Mitigate any confirmed threats.

### 🔧 Actions Taken:
- 🔒 Hardened NSG to block public internet access.
- 🔄 Implemented **account lockout policy**.
- 🔑 Enforced **Multi-Factor Authentication (MFA)**.

---

## 6️⃣ Documentation
### 🎯 Goal
Record findings for future reference.

**Summary:**
- **No successful brute-force logins detected.**
- **Legitimate logins confirmed.**
- **Preventive measures implemented.**

---

## 7️⃣ Improvement
### 🎯 Goal
Enhance security for future threat hunting.

🔹 **Future Enhancements:**
- Implement additional **threat intelligence monitoring**.
- Automate **alerts for unusual login attempts**.
- Conduct periodic **security reviews**.

---

## 🔥 MITRE ATT&CK TTPs Identified:
- **T1190** – Exploit Public-Facing Application
- **T1078** – Valid Accounts
- **T1110** – Brute Force

🎯 **Final Verdict:** No successful brute-force attack was observed, and security measures were reinforced. 🚀


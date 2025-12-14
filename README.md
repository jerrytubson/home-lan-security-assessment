# home-lan-security-assessment
Black-box security assessment of a Windows host on a home LAN, focusing on network exposure, SMB hardening, and defensive analysis


# Home LAN Security Assessment & Windows Host Hardening Analysis

## 📌 Project Overview

This project documents a **black-box security assessment of a Windows workstation on a home LAN**, focusing on network exposure, service behavior, and legacy vulnerability validation. The goal was not exploitation, but **accurate interpretation of reconnaissance results** and confirmation of host hardening against common attack vectors.

The assessment demonstrates practical understanding of **why modern, well-configured systems resist classic network attacks**, and how to distinguish between *open ports* and *actual exploitability*.

---

## 🎯 Scope & Environment

* **Target**: Windows 10/11 desktop workstation
* **Network**: Private home LAN
* **Assessment type**: Black-box, unauthenticated
* **Intent**: Defensive security analysis (no service weakening)
* **Testing boundary**: Single host, owned environment

---

## 🛠 Tools & Techniques Used

* Nmap (service detection, NSE scripts)
* CrackMapExec (SMB / WinRM validation)
* Gobuster (HTTP enumeration attempts)
* Curl & Netcat (manual service probing)
* SMB client utilities

---

## 🔍 Methodology

1. **Network Discovery & Port Scanning**

   * Identified exposed TCP services (135, 139, 445, 80)
   * Observed ICMP filtering vs TCP reachability

2. **Service Enumeration**

   * SMB protocol negotiation analysis
   * HTTP behavior testing (connection resets)
   * WinRM reachability validation

3. **Legacy Vulnerability Validation**

   * Tested for classic SMB vulnerabilities:

     * MS08-067
     * MS17-010 (EternalBlue)
     * Conficker
     * MS06-025
     * MS10-061
   * Used `nmap smb-vuln*` scripts for validation

4. **Firewall & Hardening Analysis**

   * Interpreted script execution failures
   * Correlated results with modern Windows security controls

---

## 📊 Key Findings

### SMB Exposure

* SMB ports (135, 139, 445) were reachable at the TCP level
* Application-layer access was **restricted and controlled**
* Anonymous and legacy SMB behaviors were not permitted

### Vulnerability Assessment Results

* All major legacy SMB exploits failed to execute
* Most NSE scripts terminated early due to hardened protocol behavior
* Explicit checks (e.g. MS10-054) confirmed **NOT vulnerable** status

### HTTP & WinRM Services

* HTTP connections consistently reset by the host
* WinRM ports were not reachable, indicating disabled service or firewall restriction

---

## 🧠 Analysis & Interpretation

Script execution failures were **not indicators of vulnerability**, but evidence of:

* SMBv1 deprecation
* Enforced SMB signing
* Hardened RPC responses
* Host-based firewall enforcement

This highlights an important security principle:

> *An open port does not imply an exploitable service.*

Modern, well-patched systems often cause scanners to fail silently because unsafe legacy behavior is no longer present.

---

## 🔒 Security Conclusions

* No unauthenticated remote code execution vectors identified
* Legacy SMB vulnerabilities effectively mitigated
* Firewall and protocol hardening functioning as intended
* System posture consistent with a secure Windows client endpoint

---

## ✅ Defensive Best Practices Validated

* SMBv1 disabled
* Legacy RPC attack surface reduced
* Service exposure limited to private network scope
* Host firewall enforcing application-layer filtering

---

## 📚 Lessons Learned

* Scanner failures require interpretation, not assumption
* Exploitability depends on service behavior, not port state
* Secure systems often appear "unresponsive" to offensive tooling
* Responsible testing avoids weakening real production systems

---

## 🧪 Ethical Note

All testing was performed on personally owned systems within a controlled home environment. No production or third-party systems were targeted.

---

## 🚀 Future Work

* Build an isolated vulnerable lab for exploit comparison
* Side-by-side analysis: hardened vs intentionally vulnerable Windows systems
* Expand assessment to Active Directory lab environments

---

## 📁 Repository Usage

This repository serves as:

* A portfolio demonstration of defensive security analysis
* A reference for interpreting reconnaissance results on hardened systems
* Documentation of safe, responsible security testing practices

---

## 🧾 Author

Security-focused software engineer with interest in penetration testing, Windows internals, and network defense.

## Scope & Authorization

- Assessment Type: Internal / Home LAN security assessment
- Target System: Windows workstation
- Network: Private home network
- Authorization: System owned by tester; testing permitted
- Testing Style: Black-box

This assessment was conducted for educational purposes on a self-owned system.


## Objectives

- Identify exposed network services
- Enumerate SMB, RPC, and HTTP services
- Assess exploitability of common Windows vulnerabilities
- Evaluate host hardening and firewall behavior
- Document both attack attempts and defensive controls


## Tools Used

- Nmap
- Gobuster
- CrackMapExec
- smbclient
- Netcat
- curl
- Windows Defender Firewall
- PowerShell


## High-Level Findings

- SMB service was accessible but restricted
- No legacy SMB vulnerabilities were exploitable
- Anonymous access was denied
- HTTP connections were actively reset
- Firewall and OS protections were effective


## Attack Attempts & Observations

### 1. Network and Service Enumeration

Initial enumeration was performed using Nmap to identify exposed services.

Observed open ports included:
- 135/tcp (MSRPC)
- 139/tcp (NetBIOS)
- 445/tcp (SMB)
- 80/tcp (HTTP)

The presence of SMB and RPC indicated a Windows host, making it a candidate for common Windows-focused attacks.


### 2. SMB Enumeration and Vulnerability Checks

SMB enumeration and vulnerability scripts were executed targeting port 445.

The following were tested:
- MS08-067
- MS17-010 (EternalBlue)
- Conficker-related checks
- SMB anonymous access

Results:
- All legacy SMB vulnerability checks failed to execute or returned non-vulnerable results
- Anonymous SMB sessions were denied
- No exploitable SMB shares were exposed

This indicates that the target system is patched and does not expose legacy SMB weaknesses.


### 3. HTTP Service Interaction

Attempts to interact with the HTTP service on port 80 resulted in connection resets.

Tools used included:
- curl
- Gobuster
- Nmap HTTP scripts

Observation:
- TCP connections were accepted and immediately reset
- No web content or directories were disclosed

This behavior suggests either a protected service, a local-only binding, or active firewall filtering of HTTP requests.


### 4. Authentication and Remote Access Testing

Authentication-based enumeration tools were used to assess remote access exposure.

Tools:
- CrackMapExec (SMB / WinRM modules)
- smbclient
- Netcat

Results:
- SMB connections timed out or were rejected
- No credential-less access paths were identified
- WinRM did not accept unauthenticated connections

No remote administrative access was achievable without valid credentials.

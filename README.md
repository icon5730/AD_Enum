A Kali Linux based Bash script designed for automating the process of scanning, enumerating and exploiting networks that are managed by an Active Directory.

Key features of this script:
- Timestamped output folder
- Built-in Menu page for easy navigation between the various functions.
- Built-in Help Manual in order to explain the various features of this tool to new users.
- Built-in Variables page in order to support some of the script's more advanced features.

The script is divided into 3 sections (Scanning, Enumeration, Exploitation), that preform the following:

1. Scanning:
- Basic - Performs a regular nmap scan on the user-provided network range with the -Pn flag in order to bypass the discovery phase.
- Intermediate - Performs a full nmap TCP Port range scan on the network.
- Advanced - Performs a full nmap TCP Port scan on the network, while also performing a full masscan UDP Port range scan, for a complete picture.

2. Enumeration:
- Basic - Nmap scans the network for services (-sV), while also detecting the Domain Controller and DHCP server IP's.
- Intermediate - Enumerates IP's for key services (FTP, SSH, SMB, WinRM, LDAP, RDP) as well as deploying 3 .nse scripts (smb-enum-domains.nse, smb-enum-groups.nse, smb-enum-users.nse), while also enumerating the Domain Controller's shared folders.
- Advanced - Extracts all users, groups, shares, as well as the password policy. This mode also finds disabled and never-expired accounts. Lastly, it displays the accounts that are members of the Administrators group.

3. Exploitation:
- Basic - Nmap scans the network with its Vulnerability Scanning script.
- Intermediate - Executes a Password Spray attack on the Domain Controller based on a user-given password list.
- Advanced - Extracts and attempts to crack the Domain Controller's password hashes with a user-given password list (keep in mind: this exploitation method will delete your john.pot file for password display and documnetation. Make sure you back it up before use in order to avoid losing previously cracked passwords).

All of the generated output is converted into IP-marked PDF files for convenience.

Notes: The PDF conversion process requires enscript to be installed. When the script is launched, it would check if the tool is installed on your Kali, and if the tool is missing - the script will install it for you.

<b>Main Menu:</b>
![1](https://github.com/icon5730/AD_Enum/assets/166230648/6817bdf6-f365-46fc-b5c0-254fe134733c)
<b>Help Manual:</b>
![2](https://github.com/icon5730/AD_Enum/assets/166230648/02855ecf-307e-40bf-bd60-4ee7f7b2ffcf)
<b>Scanning:</b>
![3](https://github.com/icon5730/AD_Enum/assets/166230648/cf6c6d66-6f2c-433c-a453-dd2b3c362bcc)
<b>Enumeration:</b>
![4](https://github.com/icon5730/AD_Enum/assets/166230648/b2d35416-c37e-4e12-a64a-f151b48d69f8)
![5](https://github.com/icon5730/AD_Enum/assets/166230648/524ac67e-ff48-4f07-9f6a-84f1960bb4bc)
<b>Exploitation:</b>
![6](https://github.com/icon5730/AD_Enum/assets/166230648/cf830d67-1527-4b8b-adcd-cb44eef18a4b)
![7](https://github.com/icon5730/AD_Enum/assets/166230648/ceae2946-5070-4540-9ad2-169256035331)
<b>Variable Input:</b>
![8](https://github.com/icon5730/AD_Enum/assets/166230648/2c7b6de3-0059-4665-878a-401814265fd2)
<b>Output:</b>
![9](https://github.com/icon5730/AD_Enum/assets/166230648/19d8ea9b-f641-4125-aaad-d880793e17bd)
![10](https://github.com/icon5730/AD_Enum/assets/166230648/9546e68e-d29e-4902-a14a-588b42476fae)
![11](https://github.com/icon5730/AD_Enum/assets/166230648/47097b9b-9879-4da8-a47d-d1ad96b5e7f1)
![12](https://github.com/icon5730/AD_Enum/assets/166230648/103915b0-123f-4310-b515-607eab96ae53)





# check-ad-for-leaked-password
find_weak_users.py is a quick tool to compare your users password to a known list of leaked passwords.
# How to Use
```
usage: find_weak_users.py [-h] [--ntds-file NTDS_FILE] [--nthash-file NTHASH_FILE] [--ntds-format {hashcat,secretsdump}] [--stdin] [--export-xlsx EXPORT_XLSX]

Simple tool to compare ntds dump with leaked nthash file

optional arguments:
  -h, --help            show this help message and exit
  --ntds-file NTDS_FILE
                        Path of ntds secrets dump
  --nthash-file NTHASH_FILE
                        Path of leaked nthash list file
  --ntds-format {hashcat,secretsdump}
                        The format of the ntds dump, hashcat or secretsdump.py. if not specified try to detect automatically
  --stdin               Get ntds secrets dump from stdin
  --export-xlsx EXPORT_XLSX
                        Path where to save the result as Excel file
```
##### stdin method using secretsdump.py

`python3.8 secretsdump.py <DOMAIN_NAME>/<USERNAME_OF_DOMAIN_ADMIN>@<SPECIFIC_DC_FQDN> -just-dc-ntlm -k | python3.8 find_weak_users.py --stdin --nthash-file <LOCATION_OF_LEAKED_PASSWORD_TXT_FILE> --export-xlsx <REPORT_XLSX_FILE>`

##### if you can't resolve the FQDN to ip you can specify it directly

`python3.8 secretsdump.py <DOMAIN_NAME>/<USERNAME_OF_DOMAIN_ADMIN>@<SPECIFIC_DC_FQDN> -just-dc-ntlm -k -target-ip <DC_IP> -dc-ip <DC_IP> | python3.8 find_weak_users.py --stdin --nthash-file <LOCATION_OF_LEAKED_PASSWORD_TXT_FILE> --export-xlsx <REPORT_XLSX_FILE>`

##### using ntds dump file

`python3.8 find_weak_users.py --ntds-file <LOCATION_OF_NTDS_DUMP_FILE> --nthash-file <LOCATION_OF_LEAKED_PASSWORD_TXT_FILE> --export-xlsx <REPORT_XLSX_FILE>`

# Install and prepare
## Install script dependency's

find_weak_users.py was tested on python3.8 and use tqdm and xlsxwriter modules

install using pip

`pip3 install tqdm xlsxwriter`

OR install using the requirements.txt file

`pip3 install -r requirements.txt`

## Download the leaked passwords DB:

https://haveibeenpwned.com/Passwords

We want the one with NTLM hashes
## Extract the file

Its a 7zip file, extract it
### Windows

Download the 7zip program and extract the file

https://www.7-zip.org/download.html
### Linux
#### On yum systems (RedHat, Fedora,…)
`sudo yum install p7zip`
#### On apt-get systems (Ubuntu, Debian,…)
`sudo apt-get install p7zip`
#### Extract
`7zr e pwned-passwords-ntlm-ordered-by-hash-v6.7z`
## Get the ntds hashes

**Warning! the ntds hashes are very sensitive, an attacker can use them as password in many cases across the AD ecosystem (SMB, RDP,…). I recommend using the stdin method to minimize the risk of the hashes will remain on disk. if you prefer the file method remember to wipe them as soon as possible after the test.**
### secretsdump.py

secretsdump.py is a very nice script from the [impacket](https://github.com/SecureAuthCorp/impacket/) python package allowing exporting all sorts of hashes from DC (Kerberos keytabs, NTLM hashes, and some more). In the Default configuration the script use the DRSUAPI (DC replication API).
install the impacket package

#### install from the pip repository or directly from [github](https://github.com/SecureAuthCorp/impacket/)
`pip3 install impacket`
#### get secretsdump.py

after installing impacket, secretdump.py should be mapped to your path but if not, you can download it from https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py
### hashcat

hashcat is a format many other tools that extract ntds hashes use.
#### DSinternals

a powershell module allowing the extraction of ntds hashes

https://www.dsinternals.com/en/dumping-ntds-dit-files-using-powershell/
#### Other methods

https://pentestlab.blog/tag/ntds-dit/

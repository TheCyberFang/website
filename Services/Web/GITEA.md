# Crack Password
```
sqlite> select email,salt,passwd,passwd_hash_algo from user;
bash> /usr/share/hashcat/tools/gitea2hashcat.py <salt>:<passwd hash>
bash> hashcat -m 10900 hash.txt rockyou.txt
```
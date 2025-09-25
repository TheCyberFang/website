#oscp #rpc

# To Check
```
brute force
enumerate various info
check for weak or default creds
```

# Basic Enumeration
```
rpcinfo -p <ip>
impacket-rpcdump <ip> -p <port>
```

# Null Authentication
```
rpcclient --user="" -N $ip
```

# Guest Authentication
```
rpcclient --user="guest" $ip
```

# User Authentication
```
rpcclient --user=<username> $ip
```

# RPC Client Enumeration Commands


| **Command**                               | **Description**                  |
| ----------------------------------------- | -------------------------------- |
| srvinfo                                   | server information               |
| querydispinfo                             | list userd and their description |
| enumdomuser                               | list users                       |
| queryuser <\rid>                          | details of a user                |
| queryusergroups <\rid>                    | list groups of a user            |
| lookupnames  <\username>                  | list user's SID                  |
| queryuseraliases [builtin\|domain] <\sid> | list aliases of a user           |
| enumdomgroups                             | list groups                      |
| querygroup <\rid>                         | details of a group               |
| querygroupmem <\rid>                      | list group members               |
| enumalsgroups [builtin\|domain]           | list group alias                 |
| queryaliasmem [builtin\|domain] <\rid>    | list members of an alias group   |
| enumdomains                               | list domain                      |
| lsaquery                                  | list domain's SID                |
| querydominfo                              | list domain information          |
| netshareenumall                           | list all available shares        |
| netsharegetinfo <\share>                  | list information of a share      |
| lookupnames <\username>                   | list SID by username             |
| lsaenumsid                                | enumerate SIDs                   |
| lookupsids <\sid>                         | RID cycling to check more SIDs   |

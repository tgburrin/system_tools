# block_ssh_hack
The purpose of this script is to detect a limited number of brute force ssh attacks and discourage the attack by blocking the source IP for a limited amount of time.  The purpose in doing this is to make automated attacks more difficult, but to allow password mistakes to not be permanent.

### Configuration
Sample yaml files are included, but the use of an existing nft ruleset is advised.  An example would be something like the following:
```
add chain ip filter INPUT { type filter hook input priority 0; policy drop; }
add chain ip filter SSH

add set ip filter SSH_RATE_BLOCK { type ipv4_addr; flags dynamic, timeout; timeout 15m; }
add set ip filter SSH_LOG_BLOCK { type ipv4_addr; flags dynamic, timeout; }

add rule ip filter SSH iifname "bond0" ct state related,established counter accept
add rule ip filter SSH iifname "bond0" ip saddr @SSH_RATE_BLOCK log prefix "rate limit block " drop
add rule ip filter SSH iifname "bond0" ip saddr @SSH_LOG_BLOCK log prefix "application log block " drop
add rule ip filter SSH iifname "bond0" ct state new, untracked limit rate over 10/minute add @SSH_RATE_BLOCK { ip saddr }
add rule ip filter SSH counter accept

add rule ip filter INPUT iifname "bond0" tcp dport 22 counter jump SSH
```
The above assumes that `bond0` is the external interface.

For tohse that use systemd a service such as the following may be created:
```
[Unit]
Description=A script for blocking bad ssh logins
After=networking.service nftables.service
Requires=nftables.service
Before=network-online.target
RequiresMountsFor=/var/lib

[Install]
WantedBy=multi-user.target
WantedBy=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /var/lib/blockssh/block_ssh_hack.py
TimeoutStartSec=2
```
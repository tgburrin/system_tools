# block_ssh_hack
The purpose of this script is to detect a limited number of brute force ssh attacks and discourage the attack by blocking the source IP for a limited amount of time.  The purpose in doing this is to make automated attacks more difficult, but to allow password mistakes to not be permanent.

### Configuration
Sample yaml files are included, but the use of an existing nft ruleset is advised.  An example would be something like the following:
```
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
	set ssh_rate_block { type ipv4_addr; flags dynamic, timeout; timeout 15m; }
	set ssh_log_block { type ipv4_addr; flags dynamic, timeout; }

	chain input_v4 {
		ip protocol icmp counter accept
		ip saddr 192.168.1.0/24 counter accept

		ip saddr @ssh_rate_block log prefix "rate limit block " drop
		ip saddr @ssh_log_block log prefix "application log block " drop
		iifname "bond1" tcp dport 22 ct state new, untracked limit rate over 10/minute add @ssh_rate_block { ip saddr }

	}
	chain input_v6 {
	}

	chain input {
		type filter hook input priority 0; policy drop;
		ct state vmap { established: accept, related: accept, invalid: drop }
		iifname lo accept
		meta protocol vmap { ip: jump input_v4, ip6: jump input_v6 }
		tcp dport 22 counter accept
	}
	chain forward {
		type filter hook forward priority 0; policy accept;
	}
	chain output {
		type filter hook output priority 0; policy accept;
	}
}

table inet nat {
	chain prerouting {
		type nat hook prerouting priority -100; policy accept;
	}
	chain postrouting {
		type nat hook postrouting priority 100; policy accept;
		oifname "bond1" ip saddr 192.168.1.0/24 counter masquerade
	}
	chain input {
	}
	chain output {
	}
}
```
The above assumes that `bond1` is the external interface.

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

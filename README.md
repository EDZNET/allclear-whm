<img src="allclear.png" width="48" height="48" alt="" align="left">

# AllClear for WHM

Find an IP in every firewall layer on a cPanel & WHM server and unblock it from all of them in one go.

CSF's "Search for IP" / "Unblock" only covers CSF. On a server that also runs BitNinja, fail2ban or cPHulk, an IP can stay blocked after CSF says it's clear, often through ipset entries left behind (e.g. `IPSET: Set:bitninja-local-incident Match:203.0.113.17`). AllClear searches every layer, shows you exactly what is blocking the IP, and removes it everywhere.

The story behind it: [Unblocked in CSF but still blocked? Why we built AllClear](https://edznet.io/blog/allclear-unblock-ip-every-firewall-whm).

## Install

As root:

```sh
curl -sL https://github.com/EDZNET/allclear-whm/releases/latest/download/allclear-whm.tar.gz | tar xz -C /root && sh /root/allclear-whm/install.sh
```

Then open **WHM > Plugins > AllClear (IP unblock)**. Running the same command again upgrades it.

This installs `/usr/local/cpanel/whostmgr/docroot/cgi/addon_allclear.cgi`, registers the WHM AppConfig, and symlinks the `allclear` shell command into `/usr/local/sbin`. To remove it: `sh /root/allclear-whm/uninstall.sh`.

## Requirements

- cPanel & WHM. Tested on cPanel 138.0.19 with CloudLinux 8.10.
- Root access. The plugin only appears for root (all ACLs).
- Any combination of CSF, BitNinja, fail2ban, cPHulk, ipset, iptables and nftables. Tools that aren't installed are skipped.
- No extra dependencies: it uses cPanel's bundled Perl.

## What it checks and clears

| Layer | Search | Unblock |
|---|---|---|
| CSF / LFD | `csf -g IP` | `csf -dr IP`, `csf -trd IP` |
| BitNinja | its `bitninja-*` / `heimdall-*` ipsets | `bitninjacli --blacklist --del=IP`, `--greylist --del=IP`, then ipset cleanup |
| fail2ban | `fail2ban-client status <jail>` | `fail2ban-client unban IP` |
| cPHulk | blacklist, brutes, excessive brutes, failed logins (whmapi1) | `delete_cphulk_record list_name=black`, `flush_cphulk_login_history_for_ips` |
| ipset | `ipset save`, every set of the right family | `ipset del SET ENTRY` |
| iptables / ip6tables | `iptables-save`, `-s/-d/--src-range/--dst-range` | `iptables -w -t TABLE -D CHAIN <rule>` |
| nftables (native) | `nft -j list ruleset`, rules and set elements | `nft delete rule ... handle N`, `nft delete element ...` |

The unblock order matters. The managers (CSF, BitNinja, fail2ban, cPHulk) go first so they don't put the IP straight back. Then ipset, iptables and nft are **re-scanned** and anything left over is deleted directly. The form only sends the IP and the options. Every rule to delete comes from that fresh server-side scan, never from the browser.

Optional follow-ups help when the IP keeps getting re-blocked: a temporary CSF allow (24h, `csf -ta`) and a permanent BitNinja whitelist.

## Safety

- Allow rules (`ACCEPT`/`RETURN`, or nft rules without drop/reject) are listed but never deleted. So are non-blocking targets such as `LOG`, and anything in an ipset, nft set or chain whose name contains `white`, `allow`, `trust`, `ignore` or `accept`.
- CIDR or range entries that contain the IP (e.g. `203.0.113.0/24` in `chain_DENY`) are listed but only deleted if you tick *Also delete CIDR / range entries*. Deleting one unblocks the whole range.
- If iptables runs on the nf_tables backend, its tables are handled in the iptables section and skipped in the nft section, so nothing is deleted twice.
- Only root (all ACLs) can use it, and it refuses to run if the WHM ACL modules can't be loaded.
- Every unblock is logged to `/var/log/allclear.log` (mode 0600) with the WHM user, source IP, each command and its exit code.

## Shell use

```sh
allclear search 203.0.113.17
allclear unblock 203.0.113.17 [--ranges] [--csf-allow] [--bitninja-whitelist]
```

## Notes

- Removing an IP from a BitNinja ipset is immediate. BitNinja will re-add it if the IP triggers a new incident; use the whitelist option if you trust it.
- `csf -dr` only removes exact-IP lines. CIDR lines in `/etc/csf/csf.deny` are reported but need editing by hand (or a `csf -r`).
- Imunify360 and firewalld are not handled as managers. Their runtime rules are still cleared via iptables/nft, but their own config may re-apply them.

## Disclaimer

AllClear runs as root and deletes firewall entries. Review what it will remove (the search page lists everything first) and use it at your own risk. See [LICENSE](LICENSE) (MIT, no warranty).

Security issues: see [SECURITY.md](SECURITY.md). Bug reports and pull requests are welcome; support is best effort.

Made by [EDZNET](https://edznet.io).

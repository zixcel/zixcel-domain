# Registered DNS and FreeDNS

The official domain API reference distinguishes two inventories:

- `GET /domains/{domain}/dns` reads DNS settings for a registered domain, selected from `/domains`. The documented response is `valuedomain1` or `valuedomain11`; under another configured NS provider it can return stored `valuedomain11` settings.
- `GET /freedns/{domain}` reads a domain belonging to the separate `/freedns` inventory. Using ns1–ns5 alone does not establish membership of that inventory.
- `PUT /domains/{domain}/dns` changes a registered domain’s records and `ns_type`; `PUT /freedns/{domain}` changes records in the separate FreeDNS service. Neither is a nameserver delegation change.
- `PUT /domains/{domain}/nameserver` changes registrar nameservers. Copy and verify the full active DNS records before using it.

Reference: https://www.value-domain.com/api/doc/domain/ (v1). The current tool uses the fixed v2 origin documented at https://one.value-domain.com/doc/api/v2/domain. It never forwards a v2 credential to the legacy v1 origin or automatically falls back across issuers.

`bash playground/diagnose-dns-local.sh coela.org` uses the installed release binary to compare registered settings, FreeDNS and public NS read-only. It asks for the existing v2 credential once, saves full observations only under private `.local/`, and prints only namespace/record counts and safe errors. No DNS, NS or Cloudflare writes occur. A 400 response alone does not establish missing permission or unavailable DNS.

The migration session follows parent referrals from fixed DNS root servers and chooses the namespace from that delegation. Child-zone NS and SOA names are retained as observations, not used to select a namespace. Registered DNS matching the delegated service is preferred; FreeDNS is queried only for delegated ns1–ns5 when the registered export has another namespace. Parent delegation is included in the one-use plan snapshot and read again before writes. Mail/DNSSEC/source-drift checks still apply. Public recursive MX/TXT queries are not a complete zone export.

`zixcel-domain public-delegation coela.org` performs the same credential-free observation. The DNS wire format is handled by hickory-proto; traversal allows at most eight advancing referrals, three IPv4 servers per hop and 18 seconds, with a 4096-byte response cap. Only matching questions/IDs and public IPv4 glue for the referred NS are accepted. Missing glue, IPv6-only delegation, truncation and inaccessible UDP/53 fail closed. This observation is not DNSSEC validation; it does not claim a complete zone inventory.

# Domain security evidence

```sh
zix domain dns audit --domain example.org
zix domain dns audit --domain example.org --authority true
zix domain registrar inspect --domain example.org
```

Public DNS commands subtract credential/runtime environment variables. Registrar
inspection needs the explicitly selected ValueDomain credential. Standalone
commands are `dns-security-audit DOMAIN [--authority]` and
`securitytxt-preview DOMAIN` (UTF-8 file contents on stdin). They do not write.

Registrar settings, Cloudflare assignments, recursive answers, iterated parent
referrals and direct authoritative replies are separate evidence. Direct DNS
requires matching transaction/question/owner, authoritative status, no truncation
and a relevant SOA for empty answers. Only public parent-derived IPv4 glue is used.
Missing glue, IPv6-only paths, UDP filtering/truncation and budget limits remain
unobserved. No shell resolver or downloaded code is executed. The authority
operation has a 24-second deadline and at most 27 DNS requests; the transport
reserves its budget or refuses. The provider also keeps shared caller deadlines
and byte/request limits, with no proxy, redirect or retry.

Resolver AD is a resolver assertion. Parent DS and child NS/SOA observations are
not local cryptographic DNSSEC validation. No query is a complete zone export.
CI uses synthetic packets, not real accounts, DNS writes or host changes.

`_dmarc` is a valid DNS service owner without becoming a valid registrar hostname.
The RFC 7489 diagnostic profile joins quoted strings within one TXT RR, never
distinct RRs; it checks version/policy order, duplicate tags, policy, alignment
mode and percentage. Unknown extension tags/reporting destinations are retained.
It is not a complete receiver, public-suffix lookup, SPF/DKIM alignment test or
external reporting authorization acceptance. Unsupported CNAME answers fail closed.

`p=none` is valid monitoring. Quarantine/reject needs sender inventory and owner
approval. Existing one-use record plans reject malformed/new duplicate DMARC
policies. Explicit repairs bind the exact full zone snapshot, preserve unrelated
mail/metadata, check drift and consume approval before execution. Unknown outcomes
cannot be blindly replayed. NS/DS/DNSSEC changes are not automatically applied.

The bounded RFC 9116 field checker checks Contact/Expires/Canonical, expiry and
size/line limits. Signed-document extraction requires separate verification.
Syntax proves neither authenticity, contact delivery nor permission to test.
The real security intake belongs to the corporate contact owner; no invented
mailbox or unfinished URL is published here.

Standards: https://www.rfc-editor.org/rfc/rfc7489.html and
https://www.rfc-editor.org/rfc/rfc9116.html .

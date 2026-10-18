# zixcel-domain — local registrar and DNS administration

One Rust crate owns the library,
provider adapters and JSON CLI; NERP and Codex can consume the same implementation.
It provides account inventory, offline previews and scoped local DNS migration
sessions with one-use plan approvals. The [record editing library](docs/record-editor.md)
adds separately reviewed A/AAAA/CNAME/TXT/MX changes. That library source is not yet
part of an accepted released binary or NERP UI. Registry publication and deployment
acceptance remain separate work.

The library implements bounded ValueDomain v2 inventory,
registrar NS/stored DNS inspection, Cloudflare account-scoped zone and record
inventory, explicit organization/domain manifest validation, and offline DNS
source/import previews. It does **not**
implement arbitrary DNS edits, provider permission discovery, NERP integration or full live acceptance.
Unknown Cloudflare record fields and ValueDomain DNS text are preserved. Registrar
DNS is never described as authoritative DNS without independent verification.

## Local use

The GitHub release contains a Linux x86_64 musl binary for Linux/WSL, its license
files and SHA256 checksums. Tag releases are built/tested by GitHub Actions;
provider credentials are not used by release CI. `version` reports the package
version and the exact release source SHA. No Cargo registry publication is needed
to use the binary package.

After installing the binary in `~/.local/bin`, retrieve the domains returned by
your ValueDomain v2 credential using only that credential:

```sh
bash playground/list-domains-local.sh
```

The command stores a successful response privately in `.local/valuedomain-domains.json`.
It does not require a Cloudflare credential or make DNS changes. The list reflects
the provider response under the supplied credential; it does not prove write
permission or provide a complete token-scope audit.

```sh
cargo build --locked
target/debug/zixcel-domain capabilities
target/debug/zixcel-domain validate-bindings < playground/bindings.json
```

Credentials are resolved from the trusted host environment. Do not put them in
CLI arguments, model prompts, source, Issue comments or transcripts. From a local
Bash terminal, enter existing credentials without echo or shell-history exposure:

```sh
read -rsp 'ValueDomain v2 access token: ' VALUEDOMAIN_ACCESS_TOKEN
echo
export VALUEDOMAIN_ACCESS_TOKEN
read -rsp 'Cloudflare API token: ' CLOUDFLARE_API_TOKEN
echo
export CLOUDFLARE_API_TOKEN
umask 077
mkdir -p .local
target/debug/zixcel-domain inventory 00000000000000000000000000000001 > .local/inventory.json
unset VALUEDOMAIN_ACCESS_TOKEN CLOUDFLARE_API_TOKEN
```

The ValueDomain credential must be for VDAPI **v2**, not an assumed-compatible v1
key. An authorization/IP restriction failure is returned as an error, never an
empty inventory. Consult the provider's current account/API configuration.
Cloudflare requires access to the selected account's zones; record inspection
also requires DNS Read. A successful read is not proof of write authorization.
Use `valuedomain-settings DOMAIN` and `cloudflare-records ZONE_ID` for individual
targets. Review saved DNS data locally before sharing it; inventories are not
automatically uploaded or made public.

After inventory, inspect registrar NS/stored DNS for every listed domain and the
existing Cloudflare zone records with one bounded read-only operation:

```sh
bash playground/inspect-local.sh 00000000000000000000000000000001
```

This prompts for existing credentials only if absent from the caller environment,
keeps them in process memory, and saves observations to `.local/inspection.json`
with private file permissions. Exit 0 means all requested resource reads completed;
exit 2 means explicit unavailable observations remain and `complete_for_dns_plan`
is false. Neither authorizes a write. Failure before inventory completion does not
overwrite an earlier snapshot and saves the redacted failure to `.local/inspection-error.json`.
Errors include provider/operation labels but no raw provider message, URL or credential.
When registrar NS exactly match the account's assigned Cloudflare NS, inspection
uses Cloudflare records and marks registrar storage `not_applicable`; it does not
send an unsupported storage request or require broader registrar permissions.
Mixed NS remain incomplete even if registrar storage can be read.
`public-nameservers DOMAIN` also observes NS through Cloudflare's recursive DoH
resolver without credentials. It labels this as recursive evidence, not direct
authoritative-server validation or final propagation acceptance. NXDOMAIN and
SERVFAIL remain distinct from empty results; neither cancels registrar ownership.

`mapping-preview` reads a JSON object with `bindings`, `registrar_domains`,
`cloudflare_zones` and `cloudflare_account_id` from stdin. It matches declared
ownership without performing network access or changes. A zone absent from the
current credential's visible inventory requires visibility/permission review;
it is never automatic authorization to create or delete a zone.

`dns-source-preview` reads `nameservers` and optional `assigned_cloudflare` lists
from stdin and compares exact normalized names. Mixed ValueDomain/external NS and
lookalike vendor suffixes remain untrusted. This describes configured NS, not
authoritative-server verification.

`dns-import-preview` reads `{ "domain": "example.test", "ttl": 3600,
"records": "a @ 192.0.2.1" }` from stdin. It prepares DNS-only A/AAAA/CNAME/MX/TXT/SRV
records without sending requests. MX priorities, TXT quotation bytes, SRV fields,
wildcards and TTLs are retained. Unknown directives, outside-zone owners, invalid
addresses, unsupported TXT encodings or TTLs reject the entire import. Preview
conversion is not provider acceptance or authorization. No implicit deletion,
NS/DS change, proxy activation or token creation occurs. Public examples and test
identifiers are synthetic; real profiles and observations belong outside source.

## Boundaries and tests

Live HTTPS origins are fixed. Redirects and ambient proxies are disabled. Budgets:
90 seconds per transport, 15 seconds per request, 100 requests, 1 MiB per response,
8 MiB aggregate. Cancellation currently means terminating the CLI; no write can
be started. Partial inventory pages, duplicate identifiers, inconsistent totals,
wrong accounts and malformed records fail closed. Individual resource read
failures are explicitly recorded and block complete DNS planning. Raw HTTP
errors/bodies are not logged. ValueDomain's official stored-DNS GET supports
`valuedomain1` and `valuedomain11`; a failure is not evidence that no DNS exists.
There is no automatic retry or token persistence.

```sh
cargo fmt --all --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Tests use in-memory provider fixtures and the actual CLI. They require no live
credentials. Plan/apply must bind exact account/zone/snapshot/manifest/expiry and
one-use approval; drift, uncertain writes and preservation of non-owned/mail DNS
must be tested before enabling writes. Public source reflection requires review;
real DNS/NS changes and site deployment remain separate acceptance steps (#110).

## Official contracts

- [ValueDomain API entry](https://one.value-domain.com/service/api)
- [ValueDomain v2 domain OpenAPI](https://one.value-domain.com/doc/api/v2/domain/spec.yaml)
- [Cloudflare zones](https://developers.cloudflare.com/api/resources/zones/methods/list/)
- [Cloudflare DNS records](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/)

Contracts inspected on 2026-10-14. The OpenAPI descriptions were inspected for
endpoint/authentication/pagination facts; no provider implementation was copied.

`public-dns DOMAIN TYPE` inspects NS/SOA/DS/MX/TXT/A/AAAA/CAA through the fixed
recursive resolver. It distinguishes failed DNS answers from successful NODATA
and always reports `zone_inventory_complete: false`. Apex queries cannot enumerate
all subdomains or establish which administrative system holds the full zone.

### Exclude domains with automatic renewal disabled

```sh
bash playground/list-domains-local.sh --exclude-auto-renew-disabled
# Or, with the existing credential supplied through the environment:
zixcel-domain valuedomain-domains --exclude-auto-renew-disabled
```

The helper saves the filtered result separately to
`.local/valuedomain-domains-auto-renew.json`, preserving the full inventory.
The CLI reads each domain's effective setting through VDAPI v2: individual
`9` disables renewal, `10` enables it, and `0` inherits the account setting
(`0`/`9` disabled, `10`/`11` enabled). Missing or unknown values, wrong domains,
partial responses and request budget exhaustion fail without returning a
partial filtered list. This flag reads settings; it never changes them.
Contract: https://one.value-domain.com/doc/api/v2/domain/spec.yaml

## Scoped DNS migration session (Linux/WSL)

Use the existing provider credentials in a trusted local terminal. The helper
holds them only in its process environment; the socket carries intents/results,
not tokens. The socket directory must be private (0700), the socket is 0600,
and the session expires in 20 minutes. Only the selected domain and account
can be operated on. Local processes running as the same OS user are trusted.

```sh
bash playground/domain-session-local.sh example.org CLOUDFLARE_ACCOUNT_ID
# Keep that terminal open. From a second terminal:
zixcel-domain domain-control .local/domain-control.sock observe
zixcel-domain domain-control .local/domain-control.sock plan prepare_zone
zixcel-domain domain-control .local/domain-control.sock apply PLAN_SHA256
zixcel-domain domain-control .local/domain-control.sock plan change_nameservers
zixcel-domain domain-control .local/domain-control.sock apply SECOND_PLAN_SHA256
zixcel-domain domain-control .local/domain-control.sock stop
```

Plans expire after 10 minutes and bind the source export, registrar/public NS and parent delegation,
SOA, parent DS observation, domain/account, zone snapshot, preserved records
and a random session nonce. Apply re-reads snapshots, rejects drift and consumes
the issued hash even on failure. Another or restarted session cannot accept it.
Plan approval is an explicit trusted-operator action, not a provider permission
or an automatic human approval. Only execute plans authorized for your task.

The current write phases create a Cloudflare zone if needed, append missing
preservation records without overwriting/deleting existing ones, and update
ValueDomain registrar NS after DNS read-back. Web apex A/AAAA/CNAME records are
reserved for a separate site binding; direct MX/SPF dependencies on that apex
block the migration. Parent DS requires a separate DNSSEC transition. Unknown
syntax, incompatible RRsets or budgets fail closed. Partial/uncertain writes
return receipts and must be reconciled with reads before a fresh plan; they
are never blindly retried. A verified registrar update is not public DNS
propagation or site acceptance. Rollback requires a separately reviewed plan.

Parent referrals from fixed root servers select the source service, independently
of stale child NS/SOA names. Registered DNS (`GET /domains/{domain}/dns`) matching
that delegation is preferred. The separate FreeDNS export (`GET /freedns/{domain}`)
is used for delegated ns1..ns5 only when the registered namespace does not match.
A registrar storage snapshot alone is not authoritative evidence. See
[the API distinction and bounded delegation checks](docs/valuedomain-dns-api.md).

## Empty registered domains with SERVFAIL (0.3)

The default migration still requires public DNS observations. For a new domain
whose registered ValueDomain DNS is empty and public DNS returns SERVFAIL, the
owner can explicitly start a scoped session with
`--allow-empty-registered-unserved`. This is not an empty authoritative export:
plans identify `source_mode: empty_registered_unserved`, leave public SOA/mail
observations unavailable, and use the owner's empty registered configuration.

Admission requires authenticated domain inventory and an empty registered configuration.
The stored service must match the complete registrar/direct-parent set:
`valuedomain11` uses ns11/ns12/ns13; `valuedomain1` uses ns1/ns2/ns3/ns4/ns5.
Admission also requires
no observed parent DS, and no pre-existing target-zone records. Nonempty source,
mixed delegation, unknown DNS errors, DNSSEC or target data are rejected. Inputs
are re-read before each one-use hash applies; drift consumes the plan without a
write. NS updates still require separate propagation/Cloudflare/HTTPS acceptance.
This source-mode addition uses a new minor CLI/library version, not a silent
relaxation of existing sessions. Provider credentials never enter the plan.

For owner-selected domains, `playground/domain-batch-local.sh ACCOUNT DOMAIN...`
enters existing credentials once and opens one narrowly scoped session at a time.
It advances only after the operator closes the current session explicitly;
expiry or failure stops the batch. An optional
`--allow-empty-registered-unserved` before the domain list explicitly selects the
empty-domain policy. It does not auto-apply plans or bypass hash, DNSSEC, source,
account or target-zone checks. Each session keeps the original 20-minute limit.


### Explicit retirement of unused mail

Mail remains preserved by default. Only after the owner confirms that mail is
unused, start a scoped session with `--retire-unused-mail`. The plan includes
`retire_unused_mail`, exact `records_to_retire`, retained records and
`records_to_add` in its one-use hash. MX and mail authentication records
(SPF/DKIM/DMARC/MTA-STS declarations) are omitted from the new zone; unrelated
verification TXT, addresses and other supported records remain. The new zone
receives an apex Null MX, SPF `-all` and DMARC reject declaration. Existing target
mail is never overwritten or deleted: conflicting target mail requires a separate
review. Original registrar settings remain in the private source snapshot for
rollback; the effective retirement occurs when delegation switches to Cloudflare.
Public/source consistency, DNSSEC and drift/replay checks remain mandatory.

For an explicitly selected subset of a batch, use
`--retire-unused-mail=incus.jp,ihat.online` before the domain list. Every retirement
domain must be in that list; other selected domains retain the preserve policy.
This option can be combined with `--allow-empty-registered-unserved`. Version
0.4.0 adds these policy/plan fields; no previous issued plan is accepted by a new
session.


## タグからの独立リリース

Cargo.tomlのversionを更新してmain CIの成功を待ち、同じcommitへ `v<version>` タグをpushします。`.github/tag-release.json` がowner・version正本・必須CIを宣言し、タグがmainの履歴に属することと同じSHAのCI成功を確認してから既存のstatic Linux build/test/hash付きGitHub Releaseへ進みます。中央管理repoのcheckout、Cloudflare/ValueDomainの資格情報、他組織のprivate sourceは不要です。crate registry公開とは別経路で、既存のpublish設定は変更しません。

## Common Zix entry

[Native read adapter](docs/native-zix.md) reuses ValueDomain inventory and renewal
filtering through `zix domain list`. This is source-only until native artifact
acceptance; the existing standalone CLI and DNS execution path remain separate.

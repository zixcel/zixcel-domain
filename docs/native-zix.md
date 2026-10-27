# Domain operations through Zixcel CLI

The standard entry is `zix domain …`. There is no `zixcel value-domain` namespace.
The native `zix-domain` executable is an explicitly installed extension, not a user
entry point or a wrapper around the legacy executable. It calls the existing Domain
library. Zixcel CLI owns manifest/executable integrity, bounded process execution
and interactive operator approval. Domain owns provider semantics, state checks,
plan expiry, journals and readback. Exchange stays under `zix microsoft …`.

Native 0.3.0 requires zix >=0.2.4 (manifest v2 plus per-command environments).
The shared SDK/CLI/operation contracts are pinned to public source 8fbd566a.
A source build is a development candidate; it is not an official owner release.

## Command coverage and migration

| Legacy capability | Standard command | Notes |
| --- | --- | --- |
| valuedomain-domains | `zix domain list` | Existing renewal filter retained |
| valuedomain-settings / nameservers | `zix domain registrar inspect --domain example.org` and `dns export --profile FILE` | Export keeps service namespace explicit |
| valuedomain-free-dns | `zix domain dns export --profile FILE` | `namespace: free`; no registered/FreeDNS fallback |
| public-dns | `zix domain dns inspect --domain example.org --type MX` | A/AAAA/CNAME/NS/SOA/DS/DNSKEY/MX/TXT/CAA; recursive evidence |
| public-delegation | `zix domain dns delegation --domain example.org` | Bounded parent referrals; not DNSSEC validation |
| record-session | `zix domain dns records plan` / `apply` | Cloudflare typed edit, or ValueDomain line delta |
| domain-session / domain-control | `zix domain nameservers inspect` / `plan` / `apply` | Migration profile; prepare_zone and change_nameservers remain separate |
| DNS security / reconciliation | `zix domain dns audit` / `reconcile` | Existing behavior retained |
| mapping/import/security.txt offline previews | Library and compatibility CLI | No new executable permission implied; not required for record operations |

Legacy CLI/socket interfaces remain compatible during migration. Existing legacy
in-memory approvals cannot be imported into native apply. New operational scripts
must use the common entry. No sibling checkout is required at runtime.

## Private profiles and credentials

Provision one stable private profile and journal per operational domain. Directory
0700, files 0600; use canonical absolute paths outside source control. Do not create
another journal to bypass a consumed plan or unresolved lock. Same-user local
processes remain trusted; these files are not a cryptographic authority.

ValueDomain profile:

```json
{"domain":"example.org","target":{"provider":"valuedomain","namespace":"registered"},"journal_directory":"/absolute/private/domain/journal"}
```

Use `namespace: free` only for the separate FreeDNS namespace. An authenticated
export is storage evidence, not proof that these servers are authoritative.
Before changing records compare registrar NS, parent delegation and public DNS.

Cloudflare profile:

```json
{"domain":"example.org","target":{"provider":"cloudflare","account":"00000000000000000000000000000001","zone":"00000000000000000000000000000002"},"journal_directory":"/absolute/private/domain/journal"}
```

Migration profile:

```json
{"domain":"example.org","target":{"provider":"migration","account":"00000000000000000000000000000001","allow_empty_registered_unserved":false,"retire_unused_mail":false},"journal_directory":"/absolute/private/domain/journal"}
```

Only the selected existing credentials are needed: `ZIX_VALUEDOMAIN_ACCESS_TOKEN`
(VDAPI v2), `ZIX_CLOUDFLARE_API_TOKEN`, or both for migration. Resolve them through
the existing trusted custody boundary, never arguments, JSON, source or logs.
No old-variable fallback, implicit login, token minting or permission grant exists.
The shared profile commands allow both declared credential variables into their
trusted child; leave an unrelated provider's variable unset. Inventory inherits
only the ValueDomain variable; public DNS inherits neither.

## Export, plan, apply

```sh
umask 077
zix domain dns export --profile /absolute/private/domain/profile.json > /absolute/private/domain/before.json
zix domain dns records plan --profile /absolute/private/domain/profile.json --change-file /absolute/private/domain/change.json > /absolute/private/domain/planned.json
jq '.result.plan' /absolute/private/domain/planned.json > /absolute/private/domain/plan.json
jq -r '.result.sha256' /absolute/private/domain/planned.json
zix domain dns records apply --profile /absolute/private/domain/profile.json --plan-file /absolute/private/domain/plan.json --approval-sha256 REVIEWED_SHA256 --journal-directory /absolute/private/domain/journal
```

Inspect the full envelope, profile, before/after or typed edit and hash. Apply
requires a real terminal and asks the operator to enter the exact reviewed hash.
The profile bytes, executable, package/version, manifest, operation and inner
payload are bound to the plan. Profile edits require a fresh plan. Record plans
expire after five minutes, migration plans after ten. Each apply re-reads state.

ValueDomain change JSON uses exact existing lines for removal and reviewed new
lines for addition. Replacement is remove+add, not a full replacement text input:

```json
{"add":["txt _dmarc \"v=DMARC1; p=none\""],"remove":[]}
```

Registered DNS PUT preserves `ns_type` and TTL. FreeDNS PUT omits `ns_type` and
preserves TTL. Unselected line bytes remain intact. Unknown directives are never
silently dropped; additions fail when unrecognized non-comment syntax prevents
conflict analysis. Removal of recognized exact lines may retain unknown lines.
A/AAAA/CNAME/TXT/MX edits only; no implicit NS, DNSSEC or TTL change. Whole-zone
PUT cannot exclude another external administrator racing after the pre-read.
Readback must match the complete desired snapshot; even formatting differences
require reconciliation. Max 50 selected lines, 100 KB source/target text.

Cloudflare change JSON retains the existing typed create/update/delete contract:

```json
{"action":"create","record":{"type":"TXT","name":"_dmarc.example.org","content":"v=DMARC1; p=none","ttl":3600,"proxied":false}}
```

Existing DNS record validation, DMARC checks and metadata preservation are reused.

Migration uses `nameservers inspect --profile FILE`, then
`nameservers plan --profile FILE --phase prepare_zone`, followed by
`nameservers apply` with the same approval/file/journal flags. Independently review
a second `change_nameservers` plan after copy verification. Mail preservation,
DNSSEC checks, source export/parent delegation, target account checks and explicit
empty-domain/mail-retirement policy remain enforced. No automatic phase advance.

The common provider response limit is 128 KiB. Oversized plans are rejected
before any write; do not truncate the source/export to fit the budget.

## Receipts, failures and acceptance

A durable attempt marker is consumed before provider access; a domain lock blocks
concurrent native applies using this profile's journal. Verified completion writes
a private receipt and releases the lock. Unknown effects, process termination or
provider errors retain the lock. Inspect receipts and independently export/read
provider state before operator-led reconciliation; never delete markers or switch
journals merely to retry. No automatic cleanup or blind retry command exists.

Provider readback is not public propagation, DNSSEC validation, website or email
acceptance. Check authoritative/public DNS and external mail delivery separately.
Rollback is a fresh reviewed inverse change using the saved export, never a replay.
Live token rights and provider effects are not established by synthetic tests.

## Build and distribution

Development verification:

```sh
cargo fmt --all --check
cargo test --locked --workspace --all-targets --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo build --locked --release -p zixcel-domain-cli --bin zix-domain --target x86_64-unknown-linux-musl
```

Owner releases use `native/domain/v0.3.1` after the same source passes main native
CI. The existing packaging workflow binds manifest, binary hashes and notices.
Use the official immutable archive, verify SHA256SUMS and CONTENTS.sha256, compare
`zix-domain --manifest` with `domain.extension.json`, and explicitly replace the
old registration using `extensions inspect` / `extensions replace` with the
observed previous hashes and verified new hashes (zix >=0.2.5). Do not remove the
old registration first. Disabled state is preserved. Do not overwrite old release assets. Candidate testing uses an
isolated `XDG_CONFIG_HOME`; a missing official asset is not a source-install fallback.

For an explicitly selected official version, `bash playground/install-native-local.sh
0.3.1` downloads the archive, checks its archive/content hashes and manifest, keeps
a private previous-registration snapshot and replaces only the Domain registration.
A failed download or check stops before registry changes. The helper requires
zix >=0.2.5, including for fresh installations, and supports both v1 and v2 Domain
release manifests for explicit rollback. Failed replacement preflight leaves the
old registration untouched; no snapshot overwrite or separate remove/add is used. Checksums alone do not
establish cryptographic provenance; also inspect the owner CI/release record.

The installer acceptance script `tests/installer-lifecycle.py` takes an official
released zix executable (with RELEASE.json) and two verified cached Domain releases.
It checks fresh registration, disabled upgrades, explicit downgrade/re-upgrade and
corrupt archive refusal in an isolated registry without provider credentials. Native
CI runs it with CLI 0.2.5 and Domain 0.2.0/0.3.0 release archives. Production
acceptance should additionally select the newly published Domain release.

## Recover a ValueDomain MX priority normalization

Native 0.3.2 supports `zix domain dns records resolve plan --profile FILE --original-plan-file ORIGINAL` followed by `dns records resolve apply --profile FILE --plan-file PLAN --journal-directory DIRECTORY [-y|--yes]` (zix >=0.5.0); without `--yes`, confirm with y/yes. Save the returned LocalPlan envelope as a private file.

This local-only resolution accepts only the observed loss of priority 0 from an MX line added by the original acknowledged DNS write. It verifies the original private plan, profile, permanent attempt, unknown readback-mismatch receipt, and active domain lock, then independently reads the complete zone in both phases. Any other difference is refused. The immutable resolution and archived lock preserve the original unknown result and prohibit replay. No provider write occurs during resolution. A subsequent fresh `dns records plan/apply` can replace the exact malformed MX line with a nonzero priority; all other bytes, TTL and namespace remain fixed.

The ValueDomain line editor rejects new zero-priority MX additions because the observed API cannot round-trip them safely. Historical plan inspection still recognizes the original plan. The general DNS import parser and other provider paths retain priority 0 support. A crash during local archival retains evidence and permits retrying only the same still-valid resolution plan, without repeating a remote write.

## Reconcile an acknowledged Cloudflare write

Native 0.3.3 extends the same `dns records resolve plan/apply` commands to
Cloudflare profiles. Resolution requires an acknowledged record ID, the exact
historical LocalPlan and profile, and the original permanent attempt, unknown
receipt, and active domain lock. Both phases independently read two complete,
identical inventories. The common record verifier checks the requested outcome,
all unrelated records, zone identity, and update metadata. A missing provider
acknowledgement, snapshot drift, wrong record ID, or expired resolution plan stops
resolution. This does not extend the original write approval or retry a write.

Only the local journal changes: the original attempt and unknown receipt remain,
a resolution receipt is appended, and the active lock is archived before release.
Keep using the original profile and journal. Do not delete a lock or switch
journals to continue past an unknown outcome. Any later DNS change requires a
new reviewed plan with a new complete baseline.

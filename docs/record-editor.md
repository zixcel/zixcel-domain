# Scoped DNS record editing library

`record_editor::Editor` handles one Cloudflare DNS record per approval. This is
source/development acceptance for coela-release #148. It is separate from the
existing registrar/zone migration session and is not yet a released CLI command,
NERP UI, installed package or live-account acceptance. Version metadata is unchanged.

## Consumer flow

1. Construct a closed `Scope { account, zone, domain }` and an `Editor` owned by
   the trusted local host. Resolve a Cloudflare credential in `HttpTransport`;
   credentials never enter the scope, plan, hash or receipt.
2. Call `plan(Edit::Create/Update/Delete, &mut transport)`. This only reads. Inspect
   `PlannedEdit.plan` locally and present the exact edit, scope, expiry and SHA256
   in the host's approval UI. DNS inventories may contain sensitive values; never
   upload the full plan to a public Issue or let an LLM silently approve itself.
3. Retain the same Editor in the host, obtain independent approval of that hash,
   then call `apply(&approved_hash, &mut transport)`. Serialized plans or hashes
   cannot reconstruct an executable session. A new plan invalidates the old one.
4. Persist the receipt privately. An `outcome_unknown` requires fresh inspection
   and reconciliation, not an automatic retry, rollback, or replay of the hash.

`cargo build --locked --example record-plan` compiles a concrete typed consumer.
The example uses account/zone/domain and an existing token from the local host's
environment, creates only a read-only TXT plan, and prints no full DNS inventory.
It is compiled in development checks but is not executed against a real account.
A transport has its own bounded lifetime; the host may create a fresh trusted
transport for apply while retaining the same Editor and approved scope.
The editor is library-only: it does not add a credential/session service or a
new auto-approval CLI. Existing migration capabilities keep their current meaning.

## Admission and verification

- Only A, AAAA, CNAME, TXT and MX. Names are absolute ASCII/Punycode owners within
  the selected zone; `_` labels and a leading wildcard follow the existing import
  parser. Address/target names are normalized before review, TXT bytes preserved.
- TTL is 1 (automatic) or 60–86400. Proxied A/AAAA/CNAME require TTL 1. TXT/MX are
  never proxied; MX requires a u16 priority. Empty/multiline or >2048-byte content,
  unknown fields/types and record type conversion are refused. Convert types only
  through separately reviewed delete/create, not an implicit multi-write action.
- Every plan verifies the zone's ID, account, name and active state. Existing IDs,
  owners and any returned zone references are checked; pagination and ID uniqueness
  use the existing bounded inventory reader. The full snapshot is sorted by ID and
  limited to 2 MiB. Zone evidence retains ID/account/name/status, not unrelated
  vendor metadata such as account names or zone modification timestamps. CNAME conflicts, duplicates, missing IDs and no-ops are refused.
- The plan binds implementation version and optional build source SHA, zone-identity/full-record before snapshot,
  normalized intent, scope, 256-bit OS nonce and five-minute expiration. Apply
  consumes it before any provider access, checks wall-clock and monotonic expiry,
  and re-reads the full scope/snapshot before attempting exactly one write.
- Create uses POST, update uses PATCH, delete uses DELETE through the existing
  fixed-origin, no-proxy, bounded HTTP transport. Automatic HTTP retries and
  redirects are disabled. The new PATCH/DELETE methods reject other providers.
- Read-back must match the desired record, preserve update metadata (including
  comments/tags/settings), preserve every other record and retain the same zone identity.
  Only the target's `modified_on` timestamp is excluded from metadata comparison.
- A timeout, malformed response, verification error or collateral change after
  attempting the write yields `outcome_unknown`; the approval remains consumed.
  Receipts contain IDs/hash/static errors, not record contents or provider secrets.

Cloudflare does not provide a transaction/CAS for this sequence. Another writer
can race between preflight and mutation; read-back detects observed conflicts but
cannot undo effects or prove there was no transient race. Coordinate writers.
`provider_verified` means API state at read-back, not DNS propagation, DNSSEC,
public reachability, token-scope discovery or site deployment acceptance.

## Evidence and limits

The complete source suite has 81 passing tests, zero skips (28 added here).
Synthetic API state tests cover all 15 type/action combinations, drift/replay,
expiry, cross-session and account/zone/record boundaries, input limits, metadata,
collateral change, read-back failure, and lost response after an actual simulated
state mutation. Separate trusted-transport tests refuse wrong providers/paths
before network access. These are not live Cloudflare or ValueDomain tests.
Formatting, strict Clippy, source-admission tests, the compiled example, archive
verification and a separate offline consumer of the extracted archive also pass.
The consumer exercises plan/PATCH/readback/metadata/replay using a synthetic API;
it uses the existing Cargo cache, not a new clean network environment.
No token, real DNS, registrar NS/DS, renewal, release or registry is changed.

Official references checked on 2026-10-16:
[create](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/create/),
[PATCH](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/edit/),
[delete](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/delete/),
[zone details](https://developers.cloudflare.com/api/resources/zones/methods/get/).

# Source scope and completion

This repository owns registrar/DNS inventory, configured NS classification,
explicit organization/domain matching and record import previews for administrator
tools. One crate supplies the library and JSON CLI. Real profiles, snapshots,
credentials and approval/operation receipts must remain outside public source.

The current read/preview milestone requires frozen builds, fmt, Clippy, fixture and
CLI failure tests, package rebuild, and read-only provider observations recorded
separately from fixture evidence. A failed optional registrar-storage read must
not erase successful NS/authoritative-provider observations. Missing authoritative
data must never be replaced with an empty zone or deletion proposal.

Version 0.2 adds a scoped local session with snapshot-bound, expiring, one-use
approval for zone preparation and registrar NS changes. This is not arbitrary
DNS write support. The full #148 scope remains incomplete: permission discovery,
all-provider operation/rollback contracts, NERP opt-in, independent remote
operation routes and full live acceptance. Package/fixture success does not
complete an actual migration or prove external DNS propagation.

Before any actual DNS/NS or site change, fix the selected targets, explicit diff,
mail/service preservation, DNSSEC/delegation checks, exact artifact and rollback
path, then obtain the applicable owner approval. Mixed authoritative providers
require reconciliation before migration. Registry/public source reflection and
live production operations are distinct approval and acceptance steps.

Library 0.7 / native adapter 0.3 standardizes the operator entry on `zix domain`
through zixcel/cli. It adds registered/FreeDNS exact-line edits and detached
Cloudflare record/migration plans with provider-owned durable journals. Zixcel CLI
retains integrity, bounded execution and interactive manifest-v2 admission; no
second vendor client, central login or generic HTTP write mechanism is added.
Legacy interfaces remain compatible. Official distribution and live DNS/mail
acceptance are separate from local synthetic acceptance; see `native-zix.md`.

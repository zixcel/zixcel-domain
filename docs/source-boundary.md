# Source scope and completion

This repository candidate owns registrar/DNS inventory, configured NS classification,
explicit organization/domain matching and record import previews for administrator
tools. One crate supplies the library and JSON CLI. Real profiles, snapshots,
credentials and approval/operation receipts must remain outside public source.

The current read/preview milestone requires frozen builds, fmt, Clippy, fixture and
CLI failure tests, package rebuild, and read-only provider observations recorded
separately from fixture evidence. A failed optional registrar-storage read must
not erase successful NS/authoritative-provider observations. Missing authoritative
data must never be replaced with an empty zone or deletion proposal.

The full #148 scope remains incomplete: credential permission discovery, exact
snapshot/manifest/source-bound plan and approval, one-use bounded writes, drift
checks, uncertain-result handling and read-back, NERP opt-in, independently owned
CI/release/deploy routes and live acceptance. Preview commands do not implement
these controls and cannot be used to claim source/operation completion.

Before any actual DNS/NS or site change, fix the selected targets, explicit diff,
mail/service preservation, DNSSEC/delegation checks, exact artifact and rollback
path, then obtain the applicable owner approval. Mixed authoritative providers
require reconciliation before migration. Registry/public source reflection and
live production operations are distinct approval and acceptance steps.

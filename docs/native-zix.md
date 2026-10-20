# ValueDomain through the common Zix entry

The source adds `zix-domain`, a read-only `zix-provider/v1` adapter over the
existing inventory/renewal library. The existing `zixcel-domain` CLI, DNS editing
and one-use migration plans keep their own interfaces. No second registrar
client or schema interpretation is introduced.

Build with the current Rust toolchain: `cargo build --locked -p zixcel-domain-cli --bin zix-domain`.
Read `zix-domain --manifest`, then register verified manifest/binary hashes in
Zix. `zix domain list --exclude-auto-renew-disabled true` reuses the existing
strict page consistency and effective-renewal checks. Credentials are only
`ZIX_VALUEDOMAIN_ACCESS_TOKEN` in the selected environment; no old-variable
fallback or Cloudflare credential is needed. Never put the token in arguments.
The transport deadline only narrows and the outer Crowsi process budget remains
in force. Unknown filters/mutations are refused before credentials/HTTP.

Returned domains are credential-visible observations, not proof of all account
rights, authoritative DNS, or permission to change anything. Native CI uses
synthetic data and missing-credential checks, and prepares a candidate with notices/checksums. Immutable
`native/domain/v*` tags publish accepted artifacts through the owner release
workflow and reviewer. Source acceptance, formal distribution and real-account
validation are separate. No DNS, credential
or registry operation is performed by source tests.

The adapter lives in `crates/domain-cli` as a separate native package.
The registrar/DNS library keeps its existing Cargo packaging independently.

Original JNI license files omitted by their crate archives are retained under
`tools/native-release/notices`, with exact upstream commit/URL/hash provenance.
Both the native candidate and the existing standalone release workflow use the
same fail-closed notice collector; existing release bytes are not rewritten.

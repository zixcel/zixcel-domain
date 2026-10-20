# Scoped DNS record CLI

The standalone `zixcel-domain` CLI provides scoped DNS record sessions in its
`v*` releases. The native `zix domain` adapter is independently versioned and
advertises inventory only. Development acceptance uses synthetic providers; it
does not verify live token permissions, public DNS propagation or a NERP UI.

Build with the existing Rust toolchain: `cargo build --locked`.
Run `zixcel-domain record-session ACCOUNT_ID ZONE_ID example.test` from a trusted
local host with its existing `CLOUDFLARE_API_TOKEN` environment binding. Never pass
the token in arguments, JSON requests, logs, source files or model context.
Do not use a real account to run the synthetic tests below.

## Protocol and lifecycle

Stdin/stdout carry one protocol-1 JSON object per line, sequentially. Scope is
fixed at startup. Only plan/apply create a fresh fixed-origin Cloudflare transport;
status does not prove authentication or permission. The same in-memory Editor
retains approval across those transport instances. EOF/stop/process exit discards
all outstanding approvals. There is no persisted plan-import or automatic retry.

```json
{"protocol":1,"command":{"action":"status"}}
{"protocol":1,"command":{"action":"plan","edit":{"action":"create","record":{"type":"A","name":"app.example.test","content":"192.0.2.7","ttl":3600,"proxied":false}}}}
```

Inspect `result.plan` before sending a separate apply request using its returned
`result.sha256`. The examples use documentation-only identities and addresses.

```json
{"protocol":1,"command":{"action":"apply","sha256":"RETURNED_PLAN_SHA256"}}
{"protocol":1,"command":{"action":"stop"}}
```

Update uses `edit.action=update` with record_id and the complete typed record;
delete uses `edit.action=delete` with record_id. A/AAAA/CNAME/TXT/MX use the existing
RecordData validation. This is not a second DNS implementation or a zix dispatcher.

Input is limited to 8 KiB per line, output to 1 MiB per response and intake to 100
requests. The 20-minute command-admission deadline is checked after reading each
request; an idle process may remain blocked on stdin, but cannot apply after that
deadline. A plan expires after five minutes using the Editor's wall/monotonic
checks. Per-operation HTTP budgets remain enforced. A caller must also bound
process lifetime and reads when using this CLI as an unattended child.

Invalid framing/protocol/unknown fields or exhausted wire budgets close the
session. Domain errors return an error envelope without echoing requests or
credentials. Apply consumes its hash before provider access. Drift stops writes;
an ambiguous write/read-back returns outcome_unknown with blind replay disabled.
Do not infer success from EOF or the process exit code: inspect every envelope
and receipt. Provider verification is distinct from public DNS propagation.

## Development acceptance

The actual JSON-lines handler is exercised over local Unix socket pairs with the
existing synthetic provider, including all five record types through create,
update and delete, hash replay/cross-session refusal, lost-response refusal,
closed input schemas and request/byte bounds. These sockets are test plumbing,
not a new production socket service. A CLI subprocess verifies capability output
and scope validation before credentials. No live HTTP write is performed.

The owner Release binds its source and binary checksums; verify those before
installation. Public source and binary availability do not authorize real DNS
operations. Live provider acceptance remains a separately approved operation.

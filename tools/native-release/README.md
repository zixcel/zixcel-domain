# Native module release

The native `zixcel-domain-cli` module is independent of npm, images and legacy binaries.
Its tag is `native/domain/v<version>`; the version comes from its Cargo manifest.
Only the exact source with successful main native-provider CI is admitted.

The owner tag workflow builds without publication credentials, verifies executable
manifest/content/notices and retains the archive. Publication requires the
`NATIVE_PUBLISH_ENABLED` variable and `native-public` reviewer protection, configured
only after explicit approval. The publish job executes no checked-out build code.
It releases the prepared bytes once, refuses blind retry and independently downloads
the released archive. Existing release assets and tags are never overwritten.

Run `bash tools/native-release/test-admission.sh` for synthetic admission refusal
cases. Actual musl builds, protected environments, provenance and anonymous
dispatcher acceptance are owner CI/release checks, not implied by these fixtures.
No cloud token or real resource operation is needed to build or publish this module.

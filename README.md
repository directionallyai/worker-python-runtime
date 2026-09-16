# worker-python-runtime

A relocatable, self-contained Python runtime -- the interpreter itself
(musl, [python-build-standalone](https://github.com/astral-sh/python-build-standalone)
via `uv`), its trimmed stdlib, and worker.py's own dial-out dependencies
(`h2`/`hpack`/`hyperframe`/`tlslite-ng`/`cryptography`) -- packaged as a
single `runtime.tar.gz`. Built and published from here so that
[aci-worker](https://github.com/directionallyai/aci-worker)'s own image
no longer needs any of this baked in: that image now only carries
`session_master` + `bubblewrap` + the bare OS underneath them, and this
tarball is fetched fresh, by content hash, at session start (same
fetch-verify-extract-and-bind mechanism `session_master.rs`'s own
`fetch_worker_bundle()` already uses) -- getting the Python interpreter
itself out of the CCE-measured trusted computing base, not just the
application code that runs on top of it.

## What's NOT in here

`worker.py`/`storage.py` themselves -- those stay backend's own
canonical, human-reviewed source (a separate, private repo), and change
far more often than an interpreter/dependency pin should. Instead of a
second bundle layered on top at request time, backend's own publish step
takes exactly the tarball this repo produces, extracts it, drops
`worker.py`/`storage.py` straight into `lib/python3.12/site-packages/`
(already on `sys.path`, no `PYTHONPATH` wiring needed), re-tars the
combined result, and publishes *that* single artifact by its own content
hash. One fetch per session, not two.

## `runtime`

The tarball's one stable entry point -- a small shell script, not a bare
symlink to `bin/python3.12`, so a caller (`session_master.rs`) never
needs to know this tree's own internal layout or how `worker.py` is
actually invoked:

```sh
#!/bin/sh
set -e
here="$(cd "$(dirname "$0")" && pwd)"
exec "$here/bin/python3.12" -c "import worker; worker.main()"
```

Extract the tarball anywhere (a fresh, hash-named `/tmp` directory
picked at session start, never a fixed location) and run `./runtime` --
no environment variables, no flags. This repo's own build never carries
`worker.py`, so its own verify stage confirms the *other* half: that
`runtime` correctly reaches Python and fails specifically on
`ModuleNotFoundError: No module named 'worker'`, both as root and as the
unprivileged uid (10001) `worker.py` itself always runs as inside
`session_master.rs`'s bwrap sandbox.

## Why tar.gz, not a mountable image

An EROFS image (mount instead of extract, letting a shared-pool
container skip re-extraction between reused sessions) was tried and
abandoned: mounting one needs `CAP_SYS_ADMIN` (a real loop mount) or
`/dev/fuse` (`erofsfuse`), and neither is a capability a Confidential
ACI container is known to have -- there's no way to verify either
assumption without a real deployment, the same category of dead end
Landlock turned out to be for `aci-worker`'s own sandboxing. A plain
tar.gz needs no special privilege to extract, the same non-requirement
the original worker_bundle zip already relied on.

## Why python-build-standalone, not Alpine's own apk python3

Has to be genuinely relocatable to an arbitrary path chosen at
extraction time, which a normal system Python install was never built
to support. Confirmed empirically that a stdlib `venv` (even
`--copies`) is NOT sufficient for this -- it still resolves the stdlib
and `libpython` back to the base install's own path via `pyvenv.cfg`'s
`home` key, so it only isolates third-party `site-packages`, not the
interpreter itself. `python-build-standalone`'s own binaries carry no
such reference; a real build was relocated to an arbitrary path and run
cold to confirm it before this repo was built.

## Building

```bash
docker build -t worker-python-runtime .
```

The Dockerfile's own multi-stage build extracts, runs, and verifies the
tarball (interpreter version, every pinned dependency import, an
AESGCM roundtrip, a real `h2.connection.H2Connection`, `runtime`'s own
exec chain, all as both root and uid 10001) before the final
distribution stage -- a build failure anywhere in that chain fails the
whole build, nothing about correctness is asserted only by comment.

## Reproducibility

`uv` itself is fetched by a pinned version + hand-verified SHA-256 (its
own published `.sha256` sidecar), not `latest`. Pinning `UV_VERSION` is
what makes the `python-build-standalone` resolution reproducible: a
given `uv` release embeds a fixed mapping from a version string like
`cpython-3.12.14-linux-x86_64-musl` to one specific
`python-build-standalone` release tag, so pinning `uv` pins that
resolution too. `PYTHON_SPEC`'s own patch version, and the five pinned
wheel versions, still need bumping by hand, deliberately -- same
"human-reviewed pin, not fetched trust" posture as `agent.py`'s own
`AZURE_MAA_EXPECTED_ISSUER`/`ACI_WORKER_BUNDLE_SHA256` (backend, a
separate, private repo).

## Distribution

Published to GHCR as `ghcr.io/directionallyai/worker-python-runtime/worker-python-runtime`,
a distribution-only image (`busybox:1.37.0-musl` + one file,
`/runtime.tar.gz`) -- pullers need retrieve one known file, not the
builder image, package indexes, or the verify stage's own extracted
tree. Backend's own publish step pulls it, extracts `/runtime.tar.gz`,
layers in `worker.py`/`storage.py`, and republishes the combined result
by content hash the same way it already does for the reviewer bundle
(`ensure_worker_bundle()`, `packages/api/src/main.rs`).

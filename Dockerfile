# Builds a relocatable, self-contained Python runtime -- the interpreter
# itself, its stdlib (trimmed), worker.py's own dial-out dependencies
# (h2/hpack/hyperframe/tlslite-ng/cryptography), and worker.py/storage.py
# themselves -- as a single tar.gz, never baked into aci-worker's own
# image. That image now only needs to carry session_master + bubblewrap
# + the bare OS underneath them; this tarball is fetched fresh by
# content hash at session start (fetch_worker_bundle()-shaped: verify
# SHA-256, extract to /tmp, bind into the bwrap sandbox). Moving the
# interpreter+deps here too gets Python itself out of the CCE-measured
# TCB, not just the application code sitting on top of it.
#
# worker.py/storage.py ARE committed here, as real source, not fetched
# or layered in by a separate downstream publish step (an earlier
# revision of this Dockerfile tried that split -- runtime here,
# worker.py/storage.py added afterward by backend -- and abandoned it).
# They're inseparable parts of what actually runs, not a
# user-selectable/tunable payload: the trust boundary this whole system
# rests on is "which exact worker_bundle hash is running," verified via
# MAA/CCE attestation plus the hash itself, not "keep the workload
# source private." Committing them here instead keeps that boundary
# honest -- a third party checking `ACI_WORKER_BUNDLE_SHA256` against
# real, running code can actually read what they're trusting, the same
# reasoning that already applies to aci-worker's own session_master.rs being
# public. This repository is now the sole source; downstream images copy the
# reviewed files from this distribution image.
#
# An EROFS image (mount instead of extract) was tried first and
# abandoned: mounting one needs CAP_SYS_ADMIN (a real loop mount) or
# /dev/fuse (erofsfuse) -- neither is anything a Confidential ACI
# container is known to grant, and this repo has no way to verify either
# assumption without a real deployment. A plain tar.gz needs no special
# privilege to extract at all, the same non-requirement the existing
# worker_bundle mechanism already relies on -- so this uses that instead,
# even though it gives up EROFS's mount-not-extract property.
#
# python-build-standalone (fetched via `uv python install`, the same
# mechanism/artifacts astral's own uv uses for itself) instead of
# Alpine's own apk python3: needs to be genuinely relocatable to an
# arbitrary runtime path chosen by whatever extracts it
# (/tmp/worker-runtime-<hash>, not a fixed location), which Alpine's own
# system Python installation was never built to support -- confirmed
# this session that a stdlib venv layered on top of a system Python is
# NOT sufficient for this (still references the base install's
# stdlib/libpython by absolute path); python-build-standalone's own
# binaries carry no such reference, confirmed empirically by relocating
# a real build to an arbitrary path and running it cold.
#
# uv itself fetched by a pinned version + hand-verified SHA-256 (its own
# published .sha256 sidecar file, not just trusting whatever `latest`
# resolves to) -- same "human-reviewed pin, not fetched trust" posture
# as agent.py's own AZURE_MAA_EXPECTED_ISSUER/ACI_WORKER_BUNDLE_SHA256.
# Pinning UV_VERSION is what actually makes the python-build-standalone
# resolution reproducible: a given uv release embeds a fixed mapping
# from a version string like "cpython-3.12.14-linux-x86_64-musl" to one
# specific python-build-standalone release tag, so pinning uv pins that
# resolution too, without needing to separately track python-build-
# standalone's own release tags by hand. PYTHON_SPEC's own patch version
# still has to be bumped deliberately, same as any other dependency pin
# in this repo.

FROM alpine:3.22 AS build

RUN apk add --no-cache curl ca-certificates

ARG UV_VERSION=0.12.15
ARG UV_SHA256=999c0c3da986953e508985c3932d283d2c62eb167b4f8d81e79f565e34104959
ARG PYTHON_SPEC=cpython-3.12.14-linux-x86_64-musl

RUN curl -fsSL -o /tmp/uv.tar.gz \
      "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-x86_64-unknown-linux-musl.tar.gz" \
    && echo "${UV_SHA256}  /tmp/uv.tar.gz" | sha256sum -c - \
    && mkdir -p /tmp/uv-extracted \
    && tar -C /tmp/uv-extracted -xzf /tmp/uv.tar.gz \
    && install -m 0755 /tmp/uv-extracted/*/uv /usr/local/bin/uv \
    && rm -rf /tmp/uv.tar.gz /tmp/uv-extracted

ENV UV_PYTHON_INSTALL_DIR=/opt/uv-python

RUN uv python install "${PYTHON_SPEC}" \
    && mkdir -p /build \
    && cp -a "/opt/uv-python/${PYTHON_SPEC}" /build/runtime

# Trim what worker.py/storage.py never need. idlelib/lib2to3/ensurepip
# are dev-only stdlib modules; tcl/tk is the Tkinter GUI toolkit
# (nothing in this sandbox ever has a display); share/include are
# man pages/C headers, meaningless for a runtime that's only ever
# imported into, never compiled against.
RUN rm -rf \
      /build/runtime/lib/python3.12/idlelib \
      /build/runtime/lib/python3.12/lib2to3 \
      /build/runtime/lib/python3.12/ensurepip \
      /build/runtime/lib/tcl9* \
      /build/runtime/lib/tk9.0 \
      /build/runtime/lib/itcl4.3.8 \
      /build/runtime/lib/thread3.0.6 \
      /build/runtime/lib/libtcl9* \
      /build/runtime/share \
      /build/runtime/include \
      /build/runtime/bin/idle3* \
      /build/runtime/bin/2to3*

# worker.py's own dial-out to backend's REGISTER_CALLBACK_PATH mechanism
# (make_local_callback()) needs a real h2c client and AES-GCM -- same
# pins as aci-worker's own Dockerfile used to carry when these were
# baked into the base image instead of shipped here. cryptography's own
# compiled extension (cffi/_cffi_backend) needs installing natively on
# this musl builder -- confirmed the hard way that pip refuses a
# musllinux-tagged wheel from a glibc host without forcing the platform
# tags, which building natively here avoids needing at all.
#
# `uv export` resolves pyproject.toml's own 5 direct pins against
# uv.lock -- the lock is what actually pins the transitive dependencies
# too (cffi/ecdsa/pycparser/six), which listing only the five direct
# versions by hand never did. `--no-deps` on the install itself is
# deliberate belt-and-suspenders: every version is already fully
# resolved by the lock, so pip is never allowed to resolve anything on
# its own at install time, on this or any future rebuild.
COPY pyproject.toml uv.lock /tmp/lockfile/
RUN uv export --project /tmp/lockfile --frozen --no-hashes --no-emit-project \
      -o /tmp/requirements.txt \
    && /build/runtime/bin/python3.12 -m pip install --no-cache-dir --no-deps \
      --target /build/runtime/lib/python3.12/site-packages \
      -r /tmp/requirements.txt \
    && rm -rf /tmp/lockfile /tmp/requirements.txt \
    && find /build/runtime -name "__pycache__" -type d -exec rm -rf {} + \
    && find /build/runtime -name "*.dist-info" -exec rm -rf {} + \
    && rm -rf /build/runtime/lib/python3.12/site-packages/pip*

# worker.py imports storage.py directly (`import storage`) -- both have
# to land in the same importable location, already on sys.path, no
# PYTHONPATH wiring needed by session_master.rs's own run_worker().
COPY worker.py storage.py /build/runtime/lib/python3.12/site-packages/

# The one stable entry point session_master.rs's own run_worker() execs
# -- a script, not a bare symlink to bin/python3.12, so callers never
# need to know this tree's own internal layout or the exact `-c` form
# worker.py is invoked with; that knowledge lives here, once, next to
# the interpreter it's paired with. `$(dirname "$0")` rather than a
# hardcoded path: this tree gets extracted to a fresh, hash-named
# /tmp directory picked at session start, never a fixed location.
RUN printf '%s\n' \
      '#!/bin/sh' \
      'set -e' \
      'here="$(cd "$(dirname "$0")" && pwd)"' \
      'exec "$here/bin/python3.12" -c "import worker; worker.main()"' \
      > /build/runtime/runtime \
    && chmod 0755 /build/runtime/runtime

RUN tar -C /build -czf /runtime.tar.gz runtime

# ---------------------------------------------------------------------------
# verify stage: prove the tarball actually extracts and runs correctly,
# including as the same unprivileged uid worker.py itself runs as inside
# session_master.rs's bwrap sandbox (WORKER_UID/WORKER_GID default
# 10001) -- mirrors backend's own tools/reviewer-agent/Dockerfile verify
# stage.
# ---------------------------------------------------------------------------
FROM alpine:3.22 AS verify
COPY --from=build /runtime.tar.gz /runtime.tar.gz
RUN mkdir -p /extracted \
    && tar -C /extracted -xzf /runtime.tar.gz \
    && /extracted/runtime/bin/python3.12 --version \
    && /extracted/runtime/bin/python3.12 -c "import h2, hpack, hyperframe, tlslite, cryptography; print('deps import OK')" \
    && /extracted/runtime/bin/python3.12 -c "from cryptography.hazmat.primitives.ciphers.aead import AESGCM; import os; k=AESGCM.generate_key(256); a=AESGCM(k); n=os.urandom(12); ct=a.encrypt(n, b'hi', None); assert a.decrypt(n, ct, None) == b'hi'; print('AESGCM roundtrip OK')" \
    && /extracted/runtime/bin/python3.12 -c "import h2.connection; c = h2.connection.H2Connection(); c.initiate_connection(); print('h2 connection OK')"
# `runtime` itself, with worker.py's own real main() behind it now:
# main() does `json.loads(sys.stdin.read())` before anything else (see
# worker.py), so piping empty stdin is a deterministic way to prove the
# whole chain -- runtime's own exec, worker.py's import (which pulls in
# storage.py alongside it), and worker.main() itself actually running --
# without needing a real storage_grant/content key to exercise here.
RUN output="$(echo -n '' | /extracted/runtime/runtime 2>&1)"; ec=$?; echo "$output" \
    && [ "$ec" -ne 0 ] \
    && echo "$output" | grep -q "json.decoder.JSONDecodeError" \
    && echo "runtime entry point OK (worker.main() reached real stdin parsing)"
RUN addgroup -S -g 10001 worker \
    && adduser -S -D -H -s /sbin/nologin -u 10001 -G worker worker
USER 10001:10001
RUN /extracted/runtime/bin/python3.12 -c "print('unprivileged run OK')" \
    && output="$(echo -n '' | /extracted/runtime/runtime 2>&1)"; ec=$?; echo "$output" \
    && [ "$ec" -ne 0 ] \
    && echo "$output" | grep -q "json.decoder.JSONDecodeError" \
    && echo "runtime entry point OK as unprivileged uid too"

# ---------------------------------------------------------------------------
# Distribution-only image, mirrors backend's own reviewer-agent Dockerfile
# (tools/reviewer-agent/Dockerfile, a separate private repo) -- pullers
# need retrieve one known file; none of the builder image, package
# indexes, or the verify stage's own extracted tree survive here.
# ---------------------------------------------------------------------------
FROM busybox:1.37.0-musl
COPY --from=verify /runtime.tar.gz /runtime.tar.gz

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
# GNU/glibc target, not musl -- this was musl (matching an Alpine-based
# aci-worker) until aci-worker's own image moved to a digest-pinned
# Ubuntu base for reproducibility (apk has no equivalent to apt's own
# snapshot mirrors, so a bare `apk add` always resolves against
# Alpine's *live* package index no matter how precisely the base image
# is pinned -- confirmed the actual, root-caused source of a real
# reproducibility bug elsewhere in this same effort). session_master.rs's
# own run_worker() execs this tarball's own `runtime` entry point
# inside a bwrap sandbox built from `--ro-bind /lib /lib` (and /usr,
# /bin) straight off aci-worker's own host image -- confirmed live,
# this session: the musl build's own python3.12 has ELF interpreter
# /lib/ld-musl-x86_64.so.1 and does NOT bundle it (`readelf -d` shows
# `NEEDED libc.so` with no matching file anywhere in the extracted
# tree), so it depended entirely on aci-worker's own image providing
# musl's loader at that path -- true on the old Alpine aci-worker,
# false on the new Ubuntu one. Rather than bolt a musl compatibility
# shim onto a glibc host, this tarball's own interpreter now matches:
# cpython-3.12.14-linux-x86_64-gnu, ELF interpreter
# /lib64/ld-linux-x86-64.so.2 -- confirmed live that Ubuntu provides
# this at its standard path, no shim needed, and that pip installing
# this project's own dependencies from a glibc builder onto a
# glibc-target interpreter is the ordinary case (manylinux wheels, not
# musllinux) rather than the workaround the previous musl setup needed.
#
# uv itself fetched by a pinned version + hand-verified SHA-256 (its own
# published .sha256 sidecar file, not just trusting whatever `latest`
# resolves to) -- same "human-reviewed pin, not fetched trust" posture
# as agent.py's own AZURE_MAA_EXPECTED_ISSUER/ACI_WORKER_BUNDLE_SHA256.
# Pinning UV_VERSION is what actually makes the python-build-standalone
# resolution reproducible: a given uv release embeds a fixed mapping
# from a version string like "cpython-3.12.14-linux-x86_64-gnu" to one
# specific python-build-standalone release tag, so pinning uv pins that
# resolution too, without needing to separately track python-build-
# standalone's own release tags by hand. PYTHON_SPEC's own patch version
# still has to be bumped deliberately, same as any other dependency pin
# in this repo.
#
# Ubuntu, not Alpine, for the build/verify stages too -- apt pinned to a
# fixed snapshot.ubuntu.com date instead of the live archive, same
# recipe extra/build-attest-api/Dockerfile already uses in
# directionallyai/linuxkit-attestable-ami and
# directionallyai/aci-worker's own aci/Dockerfile now uses. Whether
# uv/pip's own network fetches (uv's release tarball, python-build-
# standalone's release tarball, PyPI wheels) are themselves reproducible
# is a separate question this doesn't solve -- each is pinned by an
# exact version plus a hash check where one exists (uv, uv.lock), which
# is the strongest guarantee available without vendoring those fetches
# too.
ARG SOURCE_DATE_EPOCH=1788613323

FROM ubuntu:24.04@sha256:a61567bd31828687156d735ea8eb01ba4e37636e225dd6a48ba94136a70d9d61 AS base
ARG SOURCE_DATE_EPOCH
ENV DEBIAN_FRONTEND=noninteractive
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    snapshot="$(/bin/bash -euc "printf \"%(%Y%m%dT%H%M%SZ)T\n\" \"${SOURCE_DATE_EPOCH}\"")" && \
    sed -i -e '/Types: deb/ a\Snapshot: true' /etc/apt/sources.list.d/ubuntu.sources && \
    sed -i "s/archive.ubuntu.com\/ubuntu\//snapshot.ubuntu.com\/ubuntu\/${snapshot}/" /etc/apt/sources.list.d/ubuntu.sources && \
    sed -i "s/security.ubuntu.com\/ubuntu\//snapshot.ubuntu.com\/ubuntu\/${snapshot}/" /etc/apt/sources.list.d/ubuntu.sources && \
    rm -f /etc/apt/apt.conf.d/docker-clean && \
    echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' >/etc/apt/apt.conf.d/keep-cache && \
    apt-get install --update -o Acquire::Check-Valid-Until=false -o Acquire::https::Verify-Peer=false -y \
      ca-certificates curl && \
    rm -rf /var/log/* /var/cache/ldconfig/aux-cache

# ---------------------------------------------------------------------------
# build stage
# ---------------------------------------------------------------------------
FROM base AS build
ARG SOURCE_DATE_EPOCH

ARG UV_VERSION=0.12.15
ARG UV_SHA256=f97935763c04be3e692460a7aaeaaab8fc3b78fcf8b389da820b38ae7423a638
ARG PYTHON_SPEC=cpython-3.12.14-linux-x86_64-gnu

RUN curl -fsSL -o /tmp/uv.tar.gz \
      "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/uv-x86_64-unknown-linux-gnu.tar.gz" \
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
# this glibc builder, same reasoning the previous musl setup already
# followed for musllinux wheels -- installing from a glibc builder onto
# a glibc-target interpreter picks up ordinary manylinux wheels instead.
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

# Reproducibility: this tarball's own bytes are a separate concern from
# the OCI layer wrapping it -- BuildKit's rewrite-timestamp (image
# export) only normalizes the outer layer's own tar/timestamps, not the
# content of a file that happens to itself be a tar.gz being copied
# into that layer. Confirmed live, this session: without the flags
# below, two --no-cache builds of identical source produced different
# runtime.tar.gz bytes (differing layer digest AND size), because plain
# `tar -czf` records each file's real on-disk mtime (which varies
# build-to-build -- when pip wrote a wheel's files, when uv extracted
# the interpreter, etc.) and directory read order (not guaranteed
# stable across separate builds), and gzip's own header embeds a
# modification timestamp by default. --mtime/--sort fix the first two;
# `gzip -n` (no name/timestamp in the gzip header, piped in rather than
# tar's own -z) fixes the third.
RUN tar --sort=name --mtime="@${SOURCE_DATE_EPOCH}" --owner=0 --group=0 --numeric-owner \
      -C /build -cf - runtime | gzip -n > /runtime.tar.gz

# ---------------------------------------------------------------------------
# verify stage: prove the tarball actually extracts and runs correctly,
# including as the same unprivileged uid worker.py itself runs as inside
# session_master.rs's bwrap sandbox (WORKER_UID/WORKER_GID default
# 10001) -- mirrors backend's own tools/reviewer-agent/Dockerfile verify
# stage.
# ---------------------------------------------------------------------------
FROM base AS verify
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
RUN groupadd --system --gid 10001 worker \
    && useradd --system --no-create-home --no-user-group \
         --gid worker --shell /usr/sbin/nologin --uid 10001 worker
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
# Nothing in this stage is ever executed (backend republishes
# /runtime.tar.gz's own bytes by content hash, never runs this image),
# so unlike the build/verify stages above, this base's own libc family
# is not a correctness constraint -- kept as musl/busybox, just pinned
# by digest for the same reproducibility reason every other base image
# in this file is.
# ---------------------------------------------------------------------------
FROM busybox:1.37.0-musl@sha256:5cec3fc171c87218698e85a52af7087de727372aae264a787b8112901a5b0092
COPY --from=verify /runtime.tar.gz /runtime.tar.gz

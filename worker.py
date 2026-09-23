#!/usr/bin/env python3
"""The standard worker: runs one attested-python-execution request.

The attested EC2 instance doesn't care what it runs -- NitroTPM attests the
boot chain, not the workload. This file is the workload: the one program
every request actually runs, so that what an attestation vouches for is a
known, reviewable script rather than "whatever code arrived that time."
Whatever dispatches to a verified worker (see attestation.py; that dispatch
itself is still unbuilt) launches this, writes one request to its stdin, and
reads one response from its stdout.

Stdin/stdout are meant to be encrypted end-to-end to/from the caller once the
key exchange in main.rs's attested_python_execution() exists; this file reads
and writes plain JSON today because nothing performs that handshake yet --
same placeholder-not-final-shape caveat as everywhere else that's been said.
Encryption and decryption happen around this process, not inside it: by the
time bytes reach this script's stdin they should already be plaintext again,
the same way a request has already been through TLS decryption by the time
it reaches a normal HTTP handler.

Request (stdin, one JSON object):
    {
      "storage_grant": {...},   # same shape as circle.py's $DIRECTIONALLY_STORAGE
      "content_keys": [...],    # plaintext only inside the attested session
      "mode": "eval" | "repl",
      "code": "...",
      "world": true,            # optional, default true -- see handle()'s own
                                 # docstring for the "worldless" false case
      "queue_token": "...",     # optional, injected by session_master.rs --
      "queue_addr": "...",      # see make_queue_eval()'s own docstring
      "callback_id": "...",     # optional, from the client's own request --
      "aes_key": "...",         # see make_local_callback()'s own docstring
      "callback_addr": "..."    # optional, injected by session_master.rs
    }
One workload shape, always -- a queued tail call (see make_queue_eval()'s
own docstring) is just another request of this exact same shape, run
through this exact same handle(); "eval"/"repl" plus whatever capability
the submitted code calls (e.g. `world._run_reviewer_agent()`, in
backend's own world.py, or raw `bucket` for a "worldless" repair -- see
handle()'s own docstring) is expressive enough that this file never
needs a workload-specific mode of its own.

This file has no business knowing what a "reviewer" is, what a "circle"
is, or anything else product-shaped -- that is what `world`/`local`
being opaque, submitted-code-only capabilities is for. A concern that is
really about a specific account's own data or workflow (an API base to
talk to, a model to run, a schedule) belongs in `world.py` or in
account-level KV storage, read by whatever eval already runs there --
never threaded into this file's own request shape or `handle()`'s own
signature as a named field. Confirmed the wrong way once already this
repo's history: `api_base` was briefly added here as a `World(...)`
constructor kwarg, then reverted in favor of `circle.review.api_base`
living in the account's own storage instead, read by `world.py` itself.
If a change here would only make sense for one product's workload, it
almost certainly belongs one layer up.

Response (stdout, one JSON object), matching what agent.py's
_print_remote_result() already expects:
    {"ok": true,  "stdout": "...", "result": "<repr or null>"}
    {"ok": false, "stdout": "...", "error": "..."}

`result` is non-null whenever the submitted code's last top-level
statement is a bare expression that evaluates to something other than
None -- the same rule for both modes, "eval" applying it to the whole
(usually one-line) submission and "repl" applying it to a whole program's
last line, the same Jupyter/IPython-style auto-display convention. See
run_repl()'s docstring for why that matters here specifically.

`storage_grant` is handed in, not minted here, and there is no `issue`
callable behind it -- the same non-renewable-grant discipline
tools/circle/circle.py already runs on, and for the same reason: a worker
able to mint its own storage credential could go on reaching the account
after whoever dispatched this request meant it to stop. If the grant expires
mid-run, that's a failure to report, not something to work around.

Deployment note: this script needs storage.py copied in beside it (this
image's own Dockerfile does that). No bundled world.py in this image --
see load_world_module() below, which reads whatever this account has
most recently published and repointed via tools/circle/circle.py
straight out of its own prefix in the object store (the request's own
storage_grant already grants that read), and raises if nothing has ever
been repointed. Backend is responsible for seeding an account's world.py
before ever dispatching a session here. Two different accounts'
storage_grants resolve to two different world.py bodies -- this is
per-account, not a mechanism shared across every caller.
"""

import ast
import base64
import contextlib
import datetime
import hashlib
import importlib.util
import io
import json
import os
import socket
import struct
import sys
import time
import traceback


def load_module(name, filename):
    """`filename` from beside this script.

    Not importable normally -- nothing puts this directory on sys.path.
    Same reason and same technique circle.py uses to load storage.py: by
    path, because the two files are copied in together at deploy time, not
    installed as a package.
    """
    path = os.path.join(os.path.dirname(os.path.realpath(__file__)), filename)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {filename} from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_module_from_source(name, source):
    """Load content-addressed Python and expose it to later imports."""
    spec = importlib.util.spec_from_loader(name, loader=None)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        exec(compile(source, f"<{name}:live>", "exec"), module.__dict__)
    except Exception:
        sys.modules.pop(name, None)
        raise
    return module


# Matches circle.py's own WORLD_PY_POINTER_KEY -- a plain KV key, resolved
# through bucket.kv_get() the same as any other per-account key (own_prefix
# + "kv/" + this name). Deliberately NOT under a shared/global prefix: each
# account's world.py is its own, not one pointer every account resolves the
# same way.
WORLD_PY_POINTER_KEY = "circle.world_py"
WORLD_CORE_POINTER_KEY = "circle.world_core"
WORLD_CORE_SHARED_KEY = "world_core"


def _sha256_pointer(value, label):
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    digest = str(value or "").strip().lower()
    if len(digest) != 64 or not all(c in "0123456789abcdef" for c in digest):
        raise RuntimeError(f"{label} is not a valid sha256 pointer: {value!r}")
    return digest


def _verified_asset(bucket, digest, label):
    body = bucket.asset_get(digest)
    if body is None:
        raise RuntimeError(f"{label} {digest} was not found in storage")
    if hashlib.sha256(body).hexdigest() != digest:
        raise RuntimeError(f"{label} {digest} failed its content hash")
    return body


def load_world_core_module(bucket):
    """Load this account's selected core, falling back to the shared offer."""
    pointer, _ = bucket.kv_get(WORLD_CORE_POINTER_KEY)
    source = WORLD_CORE_POINTER_KEY
    if not pointer:
        pointer, _ = bucket.get(bucket.shared_prefix + WORLD_CORE_SHARED_KEY)
        source = f"shared {WORLD_CORE_SHARED_KEY}"
    digest = _sha256_pointer(pointer, source)
    body = _verified_asset(bucket, digest, "world_core.py")
    return load_module_from_source("directionally_world_core", body.decode("utf-8"))


def load_world_module(bucket):
    """This account's own live world.py -- read straight from the object
    store through this call's own `bucket`, the same per-account kv/asset
    mechanism (`own_prefix`) every other capability already uses, not a
    mechanism shared across accounts. Two different accounts calling this
    get two different world.py bodies; that is the point, not an edge case.

    This runtime ships no bundled account world.py. Backend is responsible for seeding this account's
    world.py (via tools/circle/circle.py's publish/repoint) before ever
    dispatching a session here; an unset pointer, an unreadable pointer, a
    missing body, or a body that fails to even exec is this call's own
    failure to surface, not something to paper over with a shared
    baseline that would silently run different code than backend thinks
    it seeded.

    This is also the actual live-swap mechanism: a reviewing agent's
    `circle.py repoint` takes effect on the very next call this function
    runs in, for that account only -- nothing here caches across
    processes, so a rollback is visible exactly as fast as a repoint was.
    """
    pointer, _ = bucket.kv_get(WORLD_PY_POINTER_KEY)
    if not pointer:
        raise RuntimeError(f"no {WORLD_PY_POINTER_KEY} set for this account -- backend must seed world.py before dispatching a session")
    sha256 = _sha256_pointer(pointer, WORLD_PY_POINTER_KEY)
    body = _verified_asset(bucket, sha256, "world.py")
    return load_module_from_source("directionally_world", body.decode("utf-8"))


class _Kv:
    """world.py's kv contract (kv_get/kv_set/now_iso), over a storage.py-shaped bucket.

    world.py wants value-based compare-and-swap: `if_match` is the value last
    read. storage.py's Bucket wants etag-based compare-and-swap: `if_match`
    is whatever the store handed back with the read. This adapter is the
    translation between them -- the same one network.py used to do for the
    retired local-execution path, ported here rather than imported, since
    network.py itself is retired and this is the only piece of it anything
    still needs.

    Takes `bucket` directly rather than a storage grant, so tests can hand it
    an in-memory fake instead of talking to real S3. build_bucket_and_kv()
    below is the thin wrapper that constructs the real thing.
    """

    def __init__(self, bucket, conflict_cls):
        self._bucket = bucket
        self._conflict_cls = conflict_cls

    def now_iso(self):
        return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")

    def kv_get(self, key):
        value, _ = self._bucket.kv_get(str(key))
        return (value, value is not None)

    def kv_set(self, key, value, if_match=None, if_absent=False):
        if if_absent and if_match is not None:
            raise ValueError("if_match and if_absent cannot both be given")
        current, etag = self._bucket.kv_get(str(key))
        if if_absent:
            if current is not None:
                return (False, current)
        elif if_match is not None and current != str(if_match):
            return (False, current)
        try:
            self._bucket.kv_set(
                str(key),
                str(value),
                if_match=None if if_absent else etag,
                if_absent=if_absent,
            )
        except self._conflict_cls:
            # Lost between the read and the write. Report what is there now,
            # not what was there a moment ago.
            latest, _ = self._bucket.kv_get(str(key))
            return (False, latest)
        return (True, str(value))

    def shared_get(self, key):
        """Raw bytes at this account's `v4/all/<key>` -- the shared,
        not-per-account prefix every storage_grant already reads (see
        storage.py's own `Bucket` docstring) -- or `None` if absent. Not
        part of kv_get()'s own namespacing (`kv/<key>` under this
        account's own prefix): a capability that needs to find something
        every account resolves the same way (e.g. World's own
        `_run_reviewer_agent()`, reading backend's published reviewer
        bundle pointer) reaches for this instead.
        """
        body, _ = self._bucket.get(self._bucket.shared_prefix + str(key))
        return body

    def asset_get(self, sha256):
        """A content-addressed body by hash -- this account's own copy,
        else the global one (see `Bucket.asset_get()`'s own docstring).
        `None` if not found under either.
        """
        return self._bucket.asset_get(str(sha256))

    def content_keys_wire(self):
        """This session's own installed CEK generations, in the same
        `[{key_version, cek (base64), current}, ...]` shape a worker
        request's own `content_keys` field already carries -- the reverse of
        what `build_bucket_and_kv()` above consumes. For a caller that needs
        to hand this session's keys to another process it spawns (e.g.
        World's own `_run_reviewer_agent()`, over an environment variable,
        the same way `storage_grant` already crosses that boundary) rather
        than use them directly through this same `kv`.
        """
        return [
            {"key_version": version, "cek": base64.b64encode(cek).decode("ascii"), "current": is_current}
            for version, cek, is_current in self._bucket.content_key_generations()
        ]


def build_bucket_and_kv(storage_grant, content_keys=None):
    """(bucket, kv) sharing one Bucket -- load_world_module() reads the
    world.py pointer/body through the same `bucket` `_Kv` uses for
    world.py's own kv_get/kv_set, rather than each minting its own
    storage.py import and Bucket instance.
    """
    storage = load_module("directionally_storage", "storage.py")
    keyring = storage.ContentKeys()
    content_keys = content_keys or []
    current_count = sum(item.get("current") is True for item in content_keys if isinstance(item, dict))
    if content_keys and current_count != 1:
        raise RuntimeError("content_keys must identify exactly one current generation")
    for item in content_keys:
        if not isinstance(item, dict):
            raise RuntimeError("content_keys contains a malformed generation")
        try:
            cek = base64.b64decode(item["cek"], validate=True)
            keyring.install(item["key_version"], cek, current=item.get("current") is True)
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError(f"content_keys contains a malformed generation: {exc}") from exc
    bucket = storage.Bucket(None, storage_grant, content_keys=keyring)
    return bucket, _Kv(bucket, storage.Conflict)


def force_worldcore_update(storage_grant, content_keys=None):
    """CAS-adopt the shared world_core.py without loading the current world."""
    bucket, kv = build_bucket_and_kv(storage_grant, content_keys or [])
    candidate_raw, _ = bucket.get(bucket.shared_prefix + WORLD_CORE_SHARED_KEY)
    candidate = _sha256_pointer(candidate_raw, f"shared {WORLD_CORE_SHARED_KEY}")
    _verified_asset(bucket, candidate, "world_core.py")
    before, exists = kv.kv_get(WORLD_CORE_POINTER_KEY)
    if before == candidate:
        return {"before": before, "after": candidate, "changed": False}
    ok, current = kv.kv_set(
        WORLD_CORE_POINTER_KEY,
        candidate,
        if_match=before if exists else None,
        if_absent=not exists,
    )
    if not ok:
        raise RuntimeError(f"{WORLD_CORE_POINTER_KEY} changed concurrently; now {current!r}")
    return {"before": before, "after": candidate, "changed": True}


def _read_frame(sock):
    """Mirrors session_protocol.rs's own read_frame/h2_read_frame framing:
    a 4-byte big-endian length prefix, then exactly that many payload
    bytes. Used only for the loopback queue socket below -- see
    make_queue_eval()'s own docstring.
    """
    length_bytes = _recv_exact(sock, 4)
    length = struct.unpack(">I", length_bytes)[0]
    return _recv_exact(sock, length)


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RuntimeError("connection closed while reading a frame")
        buf += chunk
    return buf


def _write_frame(sock, payload):
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def make_queue_eval(
    queue_addr, queue_token, default_storage_grant, default_pattern_delegate, default_content_keys
):
    """Returns a `queue_eval(code, mode="eval", storage_grant=None,
    pattern_delegate=None)` callable -- the "tail call" primitive: code
    running inside this same sandboxed session can ask session_master.rs
    (session_master.rs's own spawn_queue_listener(), reachable over the
    container's shared network namespace on 127.0.0.1) to run one more
    {mode, code, storage_grant, pattern_delegate} job *after* this
    session's primary response has already been sent back to the caller.
    The queued job runs inside the same attested container, still
    unprivileged/sandboxed the same way this call itself is (run via the
    same run_worker() on the Rust side) -- it is not run in-process here.

    queue_token is this session's own one-time credential for that
    socket (injected into this session's own request by
    run_callback_session(), never minted here) -- presenting it is what
    proves to session_master.rs that this call, not some other process,
    is the one it handed the token to. storage_grant/pattern_delegate
    default to this call's own (the common case: keep using the same
    credential), but can be overridden per queued job.

    Returns a no-op-that-raises callable, not None, when this session's
    own request carried no queue_addr/queue_token -- an older
    attester-service build, or a listener that failed to bind -- so
    calling code gets a clear error at the call site instead of an
    AttributeError somewhere unrelated.
    """
    if not queue_addr or not queue_token:
        def _unavailable(code="", mode="eval", storage_grant=None, pattern_delegate=None, **extra):
            raise RuntimeError("background eval queueing is not available for this session")

        return _unavailable

    host, _, port_str = queue_addr.rpartition(":")
    port = int(port_str)

    def queue_eval(code="", mode="eval", storage_grant=None, pattern_delegate=None, **extra):
        """`code`/`mode` are the ordinary eval/repl tail-call shape.
        `**extra` rides straight into the queued request untouched -- e.g.
        `mode="reviewer"` (see run_reviewer()'s own docstring) sends
        `delegate`/`openrouter_key`/`storage`/`model`/`timeout_secs`
        instead of `code`, and session_master.rs's own queue listener
        never inspects fields it doesn't need, so this stays a thin
        pass-through rather than something that has to know every mode's
        own shape.
        """
        request = {
            "queue_token": queue_token,
            "mode": mode,
            "code": code,
            "storage_grant": storage_grant if storage_grant is not None else default_storage_grant,
            "pattern_delegate": pattern_delegate if pattern_delegate is not None else default_pattern_delegate,
            "content_keys": default_content_keys,
        }
        request.update(extra)
        with socket.create_connection((host, port), timeout=10) as sock:
            _write_frame(sock, json.dumps(request).encode("utf-8"))
            response = json.loads(_read_frame(sock))
        if not response.get("ok"):
            raise RuntimeError(f"could not queue background eval: {response.get('error')}")

    return queue_eval


# -- reaching back to a third party's own "local" runtime ------------------
#
# attested_session.rs's own REGISTER_CALLBACK_PATH (this repo,
# attested_session.rs's handle_register_callback()/relay_tcp_and_h2()) lets
# a third party register itself as the waiting side of a callback under an
# id it picks; code running here can dial back into it presenting that same
# id and exchange messages under an AES key the two sides already share --
# handed to this session only inside its own encrypted primary request
# (callback_addr/callback_id/aes_key, see handle()'s own docstring), never
# over this dial-out itself. Genuinely leaves the container, unlike
# queue_eval's own loopback socket to session_master.rs -- this is how code
# running inside the sandbox reaches something outside it entirely (a
# debug/log sink, a progress channel, whatever the registering caller is),
# without going through the primary request/response exchange at all.
#
# Real, installed dependencies (aci/Dockerfile), not runtime-fetched wheels
# the way agent.py's own H2_WHEELS bootstrap works: this image is built by
# us, so there is no arbitrary end-user Python environment to bootstrap
# around, only a "should an ordinary eval/repl call that never uses this
# pay for importing h2/hpack/hyperframe/tlslite" question -- answered by
# importing lazily, inside _h2c_imports()/_aesgcm_new(), the same isolation
# agent.py's own _h2_imports() already applies for the same reason.

_CALLBACK_PATH = "/callback"
_CALLBACK_TOKEN_HEADER = "x-callback-token"
_LOCAL_CALLBACK_DOMAIN_SEPARATOR = b"directionally-worker-local-callback-v1"


def _h2c_imports():
    import h2.config
    import h2.connection
    import h2.events

    return h2.connection, h2.config, h2.events


def _aesgcm_new():
    from tlslite.utils.python_aesgcm import new as aesgcm_new

    return aesgcm_new


def _local_seal(aes_key, plaintext, aad):
    nonce = os.urandom(12)
    ciphertext = bytes(
        _aesgcm_new()(aes_key).seal(
            bytearray(nonce),
            bytearray(plaintext),
            bytearray(_LOCAL_CALLBACK_DOMAIN_SEPARATOR + b"|" + aad),
        )
    )
    return nonce + ciphertext


def _local_open(aes_key, framed, aad):
    nonce, ciphertext = framed[:12], framed[12:]
    plaintext = _aesgcm_new()(aes_key).open(
        bytearray(nonce),
        bytearray(ciphertext),
        bytearray(_LOCAL_CALLBACK_DOMAIN_SEPARATOR + b"|" + aad),
    )
    if plaintext is None:
        raise RuntimeError("local callback message failed AEAD authentication")
    return bytes(plaintext)


class _LocalCallbackFrameReader:
    """Same reassembly shape as agent.py's own _H2FrameReader (backend
    repo) -- h2 hands back exactly the bytes that arrived on the wire, not
    aligned to whatever length-prefixed frame boundaries this protocol
    agrees on above it, so this buffers across as many socket recv() calls
    as one frame actually needs. Kept as its own copy rather than shared:
    agent.py isn't on this image's own path, and the two connections speak
    genuinely different transports (TLS+ALPN there, plain h2c here) even
    though the frame-reassembly logic is identical. Also tracks the
    response's own :status pseudo-header -- agent.py's own reader never
    needed to (its server is a dumb byte relay), but this one does: 200
    means callback_id matched a pending registration, 404 means it never
    will (lambda_callback.rs's own handle_callback_stream()).
    """

    def __init__(self, sock, conn, stream_id, h2_events, recv_size=65536):
        self._sock = sock
        self._conn = conn
        self._stream_id = stream_id
        self._h2_events = h2_events
        self._recv_size = recv_size
        self._buffer = b""
        self._ended = False
        self.response_status = None

    def _pump(self):
        data = self._sock.recv(self._recv_size)
        if not data:
            self._ended = True
            return
        events = self._conn.receive_data(data)
        outbound = self._conn.data_to_send()
        if outbound:
            self._sock.sendall(outbound)
        for event in events:
            if isinstance(event, self._h2_events.ResponseReceived):
                for name, value in event.headers:
                    name = name.decode("ascii") if isinstance(name, bytes) else name
                    if name == ":status":
                        self.response_status = int(value)
            elif isinstance(event, self._h2_events.DataReceived):
                self._buffer += event.data
                self._conn.acknowledge_received_data(len(event.data), event.stream_id)
            elif isinstance(event, (self._h2_events.StreamEnded, self._h2_events.ConnectionTerminated)):
                self._ended = True

    def wait_for_status(self):
        while self.response_status is None:
            if self._ended:
                raise RuntimeError("callback stream ended before response headers arrived")
            self._pump()
        return self.response_status

    def read_frame(self):
        while len(self._buffer) < 4:
            if self._ended:
                raise RuntimeError("callback stream ended before a frame length arrived")
            self._pump()
        (length,) = struct.unpack("!I", self._buffer[:4])
        while len(self._buffer) < 4 + length:
            if self._ended:
                raise RuntimeError("callback stream ended mid-frame")
            self._pump()
        payload = self._buffer[4 : 4 + length]
        self._buffer = self._buffer[4 + length :]
        return payload


class _LocalCallbackUnavailable:
    """`make_local_callback()`'s stand-in when callback_addr/callback_id/
    aes_key weren't in this session's own request -- an ordinary call that
    never asked for this. Raises at the call site rather than exposing
    `None` as `local`, the same convention make_queue_eval() already
    established for queue_eval.
    """

    def send(self, message):
        raise RuntimeError("the local callback channel is not available for this session")

    def recv(self):
        raise RuntimeError("the local callback channel is not available for this session")


class _LocalCallback:
    """`local`, exposed to submitted eval/repl code -- `local.send(message)`
    (str or bytes) seals it and writes it as one frame; `local.recv()`
    blocks for the next one and returns decrypted bytes. Connects lazily,
    on first use of either: code that never calls `local.*` never pays for
    a socket, an h2 handshake, or importing h2/hpack/hyperframe/tlslite at
    all -- see this section's own header comment.
    """

    def __init__(self, callback_addr, callback_id, aes_key):
        self._callback_addr = callback_addr
        self._callback_id = callback_id
        self._aes_key = aes_key
        self._reader = None
        self._sock = None
        self._conn = None
        self._stream_id = None

    def _ensure_connected(self):
        if self._reader is not None:
            return
        h2_connection, h2_config, h2_events = _h2c_imports()
        host, _, port_str = self._callback_addr.rpartition(":")
        port = int(port_str)

        sock = socket.create_connection((host, port), timeout=10)
        conn = h2_connection.H2Connection(config=h2_config.H2Configuration(client_side=True))
        conn.initiate_connection()
        stream_id = conn.get_next_available_stream_id()
        conn.send_headers(
            stream_id,
            [
                (":method", "POST"),
                (":path", _CALLBACK_PATH),
                (":scheme", "http"),
                (":authority", self._callback_addr),
                (_CALLBACK_TOKEN_HEADER, self._callback_id),
            ],
            end_stream=False,
        )
        sock.sendall(conn.data_to_send())

        reader = _LocalCallbackFrameReader(sock, conn, stream_id, h2_events)
        status = reader.wait_for_status()
        if status != 200:
            sock.close()
            raise RuntimeError(f"callback {self._callback_id} was not matched: server returned {status}")

        self._reader, self._sock, self._conn, self._stream_id = reader, sock, conn, stream_id

    def send(self, message):
        self._ensure_connected()
        if isinstance(message, str):
            message = message.encode("utf-8")
        framed = _local_seal(self._aes_key, message, b"worker-to-local")
        self._conn.send_data(self._stream_id, struct.pack("!I", len(framed)) + framed)
        self._sock.sendall(self._conn.data_to_send())

    def recv(self):
        self._ensure_connected()
        framed = self._reader.read_frame()
        return _local_open(self._aes_key, framed, b"local-to-worker")


def make_local_callback(callback_addr, callback_id, aes_key_b64):
    """Returns the `local` object exposed to submitted code -- see
    _LocalCallback's own docstring for what it does once connected, and
    this section's own header comment for the mechanism it dials into.
    """
    if not callback_addr or not callback_id or not aes_key_b64:
        return _LocalCallbackUnavailable()
    return _LocalCallback(callback_addr, callback_id, base64.b64decode(aes_key_b64))


def run_eval(scope_vars, code, queue_eval):
    """Mirrors what agent.py's cmd_eval used to run locally, before -e moved
    behind the wire: if the snippet's last top-level statement is a bare
    expression, its repr becomes the response's `result` -- the same
    Jupyter/IPython-style auto-display run_repl() already gives a trailing
    expression, extended here to cover a multi-statement -e snippet
    (`s = world.pattern_matcher.ask(...); {"started": s, ...}`), not just a
    single bare expression on its own. Confirmed live as a real bug this
    fixes: that exact two-statement shape ran successfully (exit 0) and
    produced completely empty output, because the old implementation only
    ever tried `compile(code, "eval")` -- which requires the *entire*
    snippet to be one expression -- and silently discarded the result on
    any SyntaxError, including "this is more than one statement," not just
    genuine syntax errors. Anything else (an assignment with no trailing
    expression, a loop, no statements at all) still returns None: no
    result, only whatever was printed.

    Same AST-splicing technique run_repl() uses and for the same reason:
    text-based rewriting can corrupt a multi-line string literal, AST
    manipulation can't, since it never touches what's inside a string
    node. No async wrapper here, unlike run_repl() -- -e's own contract
    has never included top-level await.

    `queue_eval` is make_queue_eval()'s own callable, exposed to the
    submitted code the same way everything in `scope_vars` is -- see that
    function's own docstring for what it does. `scope_vars` is normally
    `{"world": world}` (handle()'s ordinary path), but a "worldless"
    request (see handle()'s own docstring) hands over `{"storage_grant":
    request["storage_grant"]}` instead, without ever loading storage.py,
    building a `Bucket`, or constructing a `World` at all -- this function
    has no opinion on which; it just splices whatever it's given into the
    exec scope alongside `queue_eval`.
    """
    scope = {**scope_vars, "queue_eval": queue_eval, "__name__": "__main__"}
    try:
        body = ast.parse(code, mode="exec").body
    except SyntaxError:
        # A genuine syntax error, not just "more than one statement" --
        # let it surface exactly as it would without this rewrite.
        exec(compile(code, "<eval>", "exec"), scope)
        return None

    capture = bool(body) and isinstance(body[-1], ast.Expr)
    if capture:
        last = body.pop()
        assign = ast.Assign(
            targets=[ast.Name(id="__directionally_result__", ctx=ast.Store())],
            value=last.value,
        )
        ast.copy_location(assign, last)
        body.append(assign)

    module = ast.Module(body=body or [ast.Pass()], type_ignores=[])
    ast.fix_missing_locations(module)
    exec(compile(module, "<eval>", "exec"), scope)
    if capture:
        result = scope.get("__directionally_result__")
        return repr(result) if result is not None else None
    return None


def run_repl(scope_vars, program, queue_eval):
    """Mirrors what agent.py's cmd_repl used to run locally: the whole
    program runs inside one `async def`, so top-level `await` and
    `asyncio.gather`/`TaskGroup` work without the caller wrapping anything.

    If the program's last top-level statement is a bare expression -- the
    same shape a Jupyter/IPython cell auto-displays -- its value is
    captured and returned the same way run_eval()'s single expression
    already is, instead of silently discarding it. Anything else (an
    assignment, a loop, an import, a function def) behaves exactly as
    before: no result, only whatever was printed. This matters for a model
    driving this over `repl`: a huge share of its Python training data is
    Jupyter-style, where a trailing bare expression auto-displays, and
    without this a program ending in `result` instead of `print(result)`
    would silently produce nothing.

    Built by splicing the caller's own parsed statements into a small
    fixed template's AST, not by re-indenting program text: an
    indentation-based version of this wrapper corrupted any multi-line
    string literal in the program (inserting spaces into the string's
    actual content, not just around it, since text-based indentation
    cannot tell a string literal's contents from code) -- AST manipulation
    can't do that, since it never touches what's inside a string node.

    `ast.parse()` (not `compile()`) accepts a top-level `await` without
    raising -- "await outside a function" is a compile-time check against
    the symbol table, not a grammar restriction -- confirmed empirically,
    not assumed, since a repl program using top-level await is the whole
    point of this function and a false SyntaxError here would break the
    common case, not just the unusual one.

    `queue_eval` is make_queue_eval()'s own callable, exposed to the
    submitted program the same way everything in `scope_vars` is -- see
    run_eval()'s own docstring for what `scope_vars` normally holds and
    when it doesn't.
    """
    scope = {**scope_vars, "queue_eval": queue_eval, "__name__": "__main__"}
    try:
        body = ast.parse(program, mode="exec").body
    except SyntaxError:
        # Let the caller's own SyntaxError surface exactly as it would
        # without this rewrite -- same source, same error.
        exec(compile(program, "<repl>", "exec"), scope)
        return None

    capture = bool(body) and isinstance(body[-1], ast.Expr)
    if capture:
        last = body.pop()
        assign = ast.Assign(
            targets=[ast.Name(id="__directionally_result__", ctx=ast.Store())],
            value=last.value,
        )
        ast.copy_location(assign, last)
        body.append(assign)

    wrapper = ast.parse(
        "import asyncio\n"
        "async def __directionally_program__():\n"
        "    pass\n"
        "asyncio.run(__directionally_program__())\n"
    )
    async_def = wrapper.body[1]
    async_def.body = (
        ([ast.Global(names=["__directionally_result__"])] if capture else [])
        + (body or [ast.Pass()])
    )
    ast.fix_missing_locations(wrapper)

    exec(compile(wrapper, "<repl>", "exec"), scope)
    if capture:
        result = scope.get("__directionally_result__")
        return repr(result) if result is not None else None
    return None


def handle(request):
    """Pure-ish: takes a parsed request, returns a response dict. No stdin/
    stdout here -- kept separate from main() so it's callable from a test
    without piping JSON through real file descriptors.

    `request["profile"]` (bool, absent/false by default): times this
    function's own major phases and returns them as response["timings"],
    {phase_name: seconds}, in the order they ran. Exists because
    session_master.rs's own execution_duration_ms already brackets this
    entire call from outside, as one undifferentiated number -- confirmed
    live to run ~1.1-1.6s for even a trivial eval, dominated by something
    other than interpreter/import cost, with no way to tell which phase
    from that single number alone. Zero cost when absent: `_mark()` below
    doesn't call time.perf_counter() at all unless profile is set.
    """
    profile = bool(request.get("profile"))
    timings = {} if profile else None
    phase_start = time.perf_counter() if profile else None

    def _mark(name):
        nonlocal phase_start
        if not profile:
            return
        now = time.perf_counter()
        timings[name] = now - phase_start
        phase_start = now

    # queue_token/queue_addr are injected by session_master.rs's own
    # run_callback_session() before this process is even spawned -- not
    # part of worker.py's documented request shape, since ordinary
    # callers (the test suite, run_worker_subprocess()'s own predecessor)
    # never set them. make_queue_eval() already degrades to a
    # raise-on-call stand-in when either is absent. Built before World so
    # it can be handed to World's own constructor below -- World's own
    # `_maybe_trigger_review()` (backend repo) uses it to queue a tail
    # call (e.g. `world._run_reviewer_agent()`) instead of an HTTP POST
    # that has no route to the attestor's private address from inside
    # this sandbox. Every queued job is an ordinary eval/repl request
    # like any other -- worker.py has exactly one workload shape, not a
    # special mode per kind of tail call; see _Kv's own asset_get()/
    # shared_get() for the storage capability that gave World's own
    # `_run_reviewer_agent()` somewhere to fetch a bundle from without
    # worker.py needing to know anything about reviewers specifically.
    # Takes `storage_grant` as a plain value, not `bucket`/`kv` -- doesn't
    # need storage.py loaded to exist, which matters for the worldless
    # path just below.
    queue_eval = make_queue_eval(
        request.get("queue_addr"),
        request.get("queue_token"),
        request["storage_grant"],
        request.get("pattern_delegate"),
        request.get("content_keys") or [],
    )
    _mark("make_queue_eval")

    # Built before World for the same reason queue_eval is -- so it can
    # be handed to World's own constructor below and reach `World`'s own
    # internal methods (e.g. a future `_run_reviewer_agent()` progress
    # report), not just top-level submitted code. See
    # make_local_callback()'s own doc comment for the mechanism;
    # callback_id/aes_key ride in the client's own encrypted request,
    # callback_addr is injected by session_master.rs, the same way
    # queue_addr is.
    local = make_local_callback(
        request.get("callback_addr"),
        request.get("callback_id"),
        request.get("aes_key"),
    )
    _mark("make_local_callback")

    # "worldless": request.get("world") defaults to True (the ordinary
    # path) -- explicitly False skips storage.py/Bucket/load_world_module()/
    # World(...) entirely, all of it, and hands the code the raw
    # `storage_grant` value instead of anything already built from it.
    # This exists for exactly one situation: an account's published
    # world.py is broken (a bad publish, a syntax error, an exception
    # World.__init__ itself raises) and *every* ordinary eval now fails
    # before user code ever runs, including whatever code would try to
    # fix it -- load_world_module() raises before this function gets
    # anywhere near executing the submitted code. Not loading storage.py
    # either is deliberate, not laziness: worldless mode's whole point is
    # doing the least possible before handing control to submitted code,
    # in case *storage.py itself* is ever what needs bypassing -- a
    # scenario `bucket` being pre-built here would have foreclosed.
    # Worldless code isn't special in any other way: same run_eval()/
    # run_repl(), same AST-splicing, same queue_eval -- only what's in
    # scope differs. Repair is then whatever the code needs: to reach
    # storage at all, it loads storage.py itself the same way this file's
    # own load_module() does (it's still mounted read-only at
    # /opt/worker/storage.py) and builds `Bucket(None, storage_grant)`
    # directly, then uses ordinary Bucket calls -- the same ones
    # circle.py's own publish/repoint already use -- to read the current
    # WORLD_PY_POINTER_KEY/its body and diagnose, `bucket.asset_put(fixed)`
    # to publish a corrected body, `bucket.kv_set(WORLD_PY_POINTER_KEY,
    # new_hash, if_match=old_hash)` to repoint.
    if request.get("world", True):
        bucket, kv = build_bucket_and_kv(
            request["storage_grant"], request.get("content_keys") or []
        )
        _mark("build_bucket_and_kv")
        load_world_core_module(bucket)
        _mark("load_world_core")
        world_module = load_world_module(bucket)
        _mark("load_world_module")
        # agent.py's _issue_delegation_for_call() mints a fresh, short-lived
        # pattern:query delegate for every eval/repl call and sends it here
        # alongside storage_grant, purely as part of this one request -- never
        # written anywhere durable. world.py's own PatternMatcher (running
        # inside this sandbox, which correctly has no real CLI credential of
        # its own to mint one with) only ever holds it for this call's
        # lifetime. "" (World's own default) when the request carried none --
        # a caller other than agent.py's attested_remote_eval, or one that
        # couldn't mint one for this call -- and PatternMatcher raises on
        # first use rather than silently doing nothing.
        world = world_module.World(
            kv, str(request.get("pattern_delegate") or "").strip(), queue_eval=queue_eval, local=local
        )
        _mark("build_world")
        scope_vars = {"world": world}
    else:
        scope_vars = {
            "storage_grant": request["storage_grant"],
            "content_keys": request.get("content_keys") or [],
            "force_worldcore_update": lambda: force_worldcore_update(
                request["storage_grant"], request.get("content_keys") or []
            ),
        }
        _mark("worldless_setup")

    # Also added directly to scope_vars (not only reachable via
    # `world`/World's own internals above) -- top-level submitted code
    # gets `local` as a bare name the same way it gets `world`, worldless
    # code included, since scope_vars is already the generic "whatever
    # goes into the exec scope" dict and `local` doesn't need
    # special-casing there any more than `world`/`bucket` do.
    scope_vars["local"] = local

    mode = request.get("mode", "eval")
    code = request["code"]
    runner = run_repl if mode == "repl" else run_eval

    captured = io.StringIO()
    response = {"ok": True}
    try:
        with contextlib.redirect_stdout(captured):
            result = runner(scope_vars, code, queue_eval)
        response["result"] = result
    except Exception:
        # The caller's code failed, not this script -- a full traceback is
        # what a REPL would show, and it's the caller's own program being
        # debugged, so there is nothing here to redact.
        response["ok"] = False
        response["error"] = traceback.format_exc()
    _mark("run")
    response["stdout"] = captured.getvalue()
    if profile:
        response["timings"] = timings
    return response


def main():
    request = json.loads(sys.stdin.read())
    response = handle(request)
    sys.stdout.write(json.dumps(response))


if __name__ == "__main__":
    main()

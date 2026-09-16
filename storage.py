"""Direct access to the account's own corner of the bucket.

The circle's data -- its key/value entries and the module bodies they name --
used to travel through the management API, which read and wrote the same
objects on the caller's behalf. That indirection bought nothing: the API had no
judgement to apply, it was a proxy that had to be kept in step with every
client, and it turned a store that already does compare-and-swap into an
endpoint that had to re-implement it.

So the caller goes to the bucket. It holds a credential scoped to
`v4/users/<user_id>/own/` for writing and `v4/all/` plus `v4/assets/` for
reading, which is issued by the API and expires within the hour. What stayed
behind the API is the part that is not data: minting that credential, minting a
model key, the delegation ledger that revokes an agent, and the plan that says
what the account is entitled to. Those are decisions. This is storage.

Nothing here is specific to one provider beyond the signature: it is plain S3,
signed with SigV4, over urllib.
"""

import base64
import datetime
import hashlib
import hmac
import json
import os
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ElementTree

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

TIMEOUT = 30
# S3 lists at most this many keys per response and says so with IsTruncated.
PAGE_SIZE = 1000
# Refresh a credential before it actually expires. A request signed at the
# boundary can still arrive after it, and the failure then looks like a
# permission problem rather than a clock.
EXPIRY_MARGIN_SECS = 120
OBJECT_PROTOCOL_IDENTIFIER = "directionally-object-aes256gcm-v1"
CEK_BYTES = 32
NONCE_BYTES = 12


class StorageError(RuntimeError):
    """A request to the bucket failed, with the provider's own words kept."""


class Conflict(StorageError):
    """A compare-and-swap lost. The object was not written."""


class ContentKeys:
    """In-memory CEK generations used to seal account-owned objects.

    The caller is responsible for unwrapping these keys before constructing
    the bucket. This class never persists a plaintext CEK. Keeping old
    generations installed allows reads across rotation while only the current
    generation is used for new writes.
    """

    def __init__(self):
        self._keys = {}
        self._current = None

    def install(self, key_version, cek, current=True):
        if not isinstance(key_version, int) or isinstance(key_version, bool) or key_version < 1:
            raise ValueError("invalid content-key version")
        cek = bytes(cek)
        if len(cek) != CEK_BYTES:
            raise ValueError("invalid content-key length")
        self._keys[key_version] = cek
        if current:
            self._current = key_version

    @property
    def current_version(self):
        return self._current

    def current(self):
        if self._current is None:
            return None
        return (self._current, self._keys[self._current])

    def get(self, key_version):
        return self._keys.get(key_version)

    def items(self):
        """(key_version, cek, is_current) for every installed generation --
        the reverse of `install()`, for a caller that needs to hand this
        keyring's own contents to another process (e.g. a subprocess given
        credentials by environment variable, the same way a storage grant
        already is) rather than consume them directly."""
        return [(version, cek, version == self._current) for version, cek in self._keys.items()]


def _object_key(cek, object_path):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=CEK_BYTES,
        salt=b"",
        info=str(object_path).encode("utf-8"),
    ).derive(bytes(cek))


def encrypt_object(cek, key_version, object_path, plaintext, nonce=None):
    """Return the JSON envelope shared with the browser implementation."""
    if len(bytes(cek)) != CEK_BYTES:
        raise ValueError("invalid content-key length")
    if not isinstance(key_version, int) or isinstance(key_version, bool) or key_version < 1:
        raise ValueError("invalid content-key version")
    nonce = os.urandom(NONCE_BYTES) if nonce is None else bytes(nonce)
    if len(nonce) != NONCE_BYTES:
        raise ValueError("invalid object nonce length")
    aad = str(object_path).encode("utf-8")
    ciphertext = AESGCM(_object_key(cek, object_path)).encrypt(nonce, bytes(plaintext), aad)
    return {
        "algorithm": OBJECT_PROTOCOL_IDENTIFIER,
        "key_version": key_version,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def decrypt_object(cek, object_path, envelope):
    """Open one versioned object envelope, including its path as AAD."""
    if not isinstance(envelope, dict) or envelope.get("algorithm") != OBJECT_PROTOCOL_IDENTIFIER:
        raise ValueError("unsupported object-encryption algorithm")
    try:
        nonce = base64.b64decode(envelope["nonce"], validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("malformed encrypted object") from exc
    if len(nonce) != NONCE_BYTES:
        raise ValueError("invalid object nonce length")
    aad = str(object_path).encode("utf-8")
    return AESGCM(_object_key(cek, object_path)).decrypt(nonce, ciphertext, aad)


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def _sha256_hex(payload):
    return hashlib.sha256(payload or b"").hexdigest()


def _sign(key, message):
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret, datestamp, region, service):
    key = _sign(("AWS4" + secret).encode("utf-8"), datestamp)
    key = _sign(key, region)
    key = _sign(key, service)
    return _sign(key, "aws4_request")


class Bucket:
    """One account's view of the store, refreshing its own credential.

    `issue` is called to get a grant and called again when the one in hand is
    close to expiring. It returns the dict the API's storage-credential
    endpoint answers with. Passing a callable rather than a credential is what
    lets an agent run longer than the hour its key is good for without every
    caller having to think about it.

    `issue` is None inside a review container, which is handed a grant it
    cannot renew: the endpoint that mints these refuses a delegation, because a
    container able to mint its own would go on reaching the account long after
    the delegation it was given had run out. The credential's hour is a bound
    on the review, in the same way the delegation is, so running past it is a
    failure to report rather than something to work around.
    """

    def __init__(self, issue=None, grant=None, content_keys=None):
        self._issue = issue
        self._grant = grant
        self._content_keys = content_keys or ContentKeys()

    def install_content_key(self, key_version, cek, current=True):
        """Install a plaintext CEK for this process lifetime only."""
        self._content_keys.install(key_version, cek, current=current)

    def content_key_generations(self):
        """(key_version, cek, is_current) for every generation installed on
        this bucket -- see ContentKeys.items()."""
        return self._content_keys.items()

    def _encode_owned(self, path, body):
        current = self._content_keys.current()
        if current is None:
            # Attested or nothing: never write account data unencrypted.
            # Matches storage.js's encodeForStorage -- refuse rather than
            # silently fall back to plaintext when no CEK is installed.
            raise StorageError(
                f"no content key is installed; refusing to write {path} as plaintext"
            )
        key_version, cek = current
        envelope = encrypt_object(cek, key_version, path, body)
        return json.dumps(envelope, separators=(",", ":")).encode("utf-8")

    def _decode_owned(self, path, body):
        try:
            envelope = json.loads(body)
        except (TypeError, ValueError, UnicodeDecodeError):
            return body
        if not isinstance(envelope, dict) or envelope.get("algorithm") != OBJECT_PROTOCOL_IDENTIFIER:
            return body
        key_version = envelope.get("key_version")
        if not isinstance(key_version, int) or isinstance(key_version, bool) or key_version < 1:
            raise StorageError(f"encrypted object {path} has an invalid key version")
        cek = self._content_keys.get(key_version)
        if cek is None:
            raise StorageError(f"content key version {key_version} is not available")
        try:
            return decrypt_object(cek, path, envelope)
        except (InvalidTag, ValueError, TypeError) as exc:
            raise StorageError(f"could not decrypt {path}: {exc}") from exc

    # -- credential ------------------------------------------------------

    @property
    def grant(self):
        if self._grant is None or self._expiring():
            if self._issue is None:
                raise StorageError(
                    "the storage credential has expired and this process cannot mint "
                    "another. Stop and report this; it cannot be renewed from here."
                )
            self._grant = self._issue()
            if not isinstance(self._grant, dict) or not self._grant.get("access_key_id"):
                raise StorageError("no storage credential was issued")
        return self._grant

    def _expiring(self):
        raw = (self._grant or {}).get("expires_at")
        if not raw:
            return False
        try:
            expires = datetime.datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except ValueError:
            return False
        return (expires - _utcnow()).total_seconds() <= EXPIRY_MARGIN_SECS

    @property
    def own_prefix(self):
        return self.grant.get("own_prefix") or ""

    @property
    def shared_prefix(self):
        return self.grant.get("shared_prefix") or "v4/all/"

    @property
    def asset_prefix(self):
        return self.grant.get("asset_prefix") or "v4/assets/"

    # -- signing ---------------------------------------------------------

    def _request(self, method, key, body=None, headers=None, query=None):
        grant = self.grant
        endpoint = str(grant["endpoint"]).rstrip("/")
        parsed = urllib.parse.urlparse(endpoint)
        host = parsed.netloc
        region = grant.get("region") or "auto"
        service = "s3"

        # The bucket is a path segment, and every key segment is escaped except
        # the separators. An email in the prefix means keys carry an "@", which
        # has to survive into the signature exactly as it appears in the URL.
        path = "/" + grant["bucket"] + "/" + urllib.parse.quote(key, safe="/~")
        canonical_query = ""
        if query:
            canonical_query = "&".join(
                f"{urllib.parse.quote(k, safe='~')}={urllib.parse.quote(str(v), safe='~')}"
                for k, v in sorted(query.items())
            )

        now = _utcnow()
        amzdate = now.strftime("%Y%m%dT%H%M%SZ")
        datestamp = now.strftime("%Y%m%d")
        payload_hash = _sha256_hex(body)

        send = {
            "host": host,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amzdate,
        }
        for name, value in (headers or {}).items():
            send[name.lower()] = value

        signed_names = ";".join(sorted(send))
        canonical_headers = "".join(f"{n}:{send[n]}\n" for n in sorted(send))
        canonical_request = "\n".join(
            [method, path, canonical_query, canonical_headers, signed_names, payload_hash]
        )
        scope = f"{datestamp}/{region}/{service}/aws4_request"
        to_sign = "\n".join(
            ["AWS4-HMAC-SHA256", amzdate, scope, _sha256_hex(canonical_request.encode("utf-8"))]
        )
        signature = hmac.new(
            _signing_key(grant["secret_access_key"], datestamp, region, service),
            to_sign.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        url = f"{parsed.scheme}://{host}{path}"
        if canonical_query:
            url += "?" + canonical_query
        request = urllib.request.Request(url, data=body, method=method)
        for name, value in send.items():
            if name != "host":
                request.add_header(name, value)
        request.add_header(
            "Authorization",
            f"AWS4-HMAC-SHA256 Credential={grant['access_key_id']}/{scope}, "
            f"SignedHeaders={signed_names}, Signature={signature}",
        )
        # Header names are folded to lower case here, not read case-insensitively
        # at each use. urllib's own message object is case-insensitive and a
        # plain dict of it is not, which is a difference that shows up as an
        # ETag that reads back as None -- and a compare-and-swap with no ETag
        # is an unconditional write that quietly wins every race it should
        # have lost.
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
                return (response.status, response.read(), _lower(response.headers))
        except urllib.error.HTTPError as exc:
            return (exc.code, exc.read(), _lower(exc.headers))
        except urllib.error.URLError as exc:
            raise StorageError(f"could not reach {host}: {exc.reason}")

    # -- objects ---------------------------------------------------------

    def get(self, key):
        """Return (bytes, etag) or (None, None) when the object is not there."""
        status, body, headers = self._request("GET", key)
        if status == 404:
            return (None, None)
        if status != 200:
            raise StorageError(f"GET {key}: HTTP {status} {_detail(body)}")
        return (body, (headers.get("etag") or "").strip() or None)

    def put(self, key, body, if_match=None, if_absent=False):
        """Write, optionally only if the object is unchanged or absent.

        The conditional headers are what makes a read-modify-write safe without
        a lock, and they are why the key/value space never needed a server in
        front of it: S3 arbitrates the race itself. Raises `Conflict` when the
        condition fails, so a caller can re-read and try again.
        """
        if if_absent and if_match is not None:
            raise ValueError("if_match and if_absent cannot both be given")
        headers = {"content-type": "application/octet-stream"}
        if if_absent:
            headers["if-none-match"] = "*"
        elif if_match is not None:
            headers["if-match"] = str(if_match)
        status, payload, response_headers = self._request("PUT", key, body=body, headers=headers)
        # 412 is If-Match losing; some S3-compatible stores answer a lost
        # conditional create with 409 instead.
        if status in (409, 412):
            raise Conflict(f"PUT {key}: the object changed underneath")
        if status not in (200, 201, 204):
            raise StorageError(f"PUT {key}: HTTP {status} {_detail(payload)}")
        return (response_headers.get("etag") or "").strip() or None

    def delete(self, key):
        status, body, _ = self._request("DELETE", key)
        if status not in (200, 204, 404):
            raise StorageError(f"DELETE {key}: HTTP {status} {_detail(body)}")
        return status != 404

    def list(self, prefix):
        """Every key under `prefix`, following the store's own paging."""
        keys = []
        token = None
        while True:
            query = {"list-type": "2", "prefix": prefix, "max-keys": str(PAGE_SIZE)}
            if token:
                query["continuation-token"] = token
            status, body, _ = self._request("GET", "", query=query)
            if status != 200:
                raise StorageError(f"LIST {prefix}: HTTP {status} {_detail(body)}")
            try:
                root = ElementTree.fromstring(body)
            except ElementTree.ParseError as exc:
                raise StorageError(f"LIST {prefix}: malformed response ({exc})")
            namespace = root.tag[: root.tag.index("}") + 1] if "}" in root.tag else ""
            for contents in root.findall(f"{namespace}Contents"):
                name = contents.findtext(f"{namespace}Key")
                if name:
                    keys.append(name)
            if (root.findtext(f"{namespace}IsTruncated") or "").strip().lower() != "true":
                break
            token = root.findtext(f"{namespace}NextContinuationToken")
            if not token:
                break
        return keys

    # -- the account's own namespaces ------------------------------------

    def kv_key(self, key):
        return f"{self.own_prefix}kv/{key}"

    def kv_get(self, key):
        """Return (value, etag). `value` is None when the key is not set."""
        path = self.kv_key(key)
        body, etag = self.get(path)
        if body is None:
            return (None, None)
        body = self._decode_owned(path, body)
        return (body.decode("utf-8", "replace"), etag)

    def kv_set(self, key, value, if_match=None, if_absent=False):
        path = self.kv_key(key)
        return self.put(
            path,
            self._encode_owned(path, str(value).encode("utf-8")),
            if_match=if_match,
            if_absent=if_absent,
        )

    def kv_delete(self, key):
        return self.delete(self.kv_key(key))

    def kv_list(self, prefix=""):
        """Key names, with the storage prefix taken back off."""
        base = f"{self.own_prefix}kv/"
        return [k[len(base) :] for k in self.list(base + prefix) if k.startswith(base)]

    def asset_get(self, sha256):
        """A module body by hash: the account's own copy, else the global one.

        Same order the API used. An account that has published its own version
        of a participant gets that; everybody else reads the shared body, which
        is the same object every account resolves the hash to.
        """
        own_path = f"{self.own_prefix}assets/{sha256}"
        body, _ = self.get(own_path)
        if body is not None:
            body = self._decode_owned(own_path, body)
        if body is None:
            body, _ = self.get(f"{self.asset_prefix}{sha256}")
        return body

    def asset_put(self, body):
        """Store a body under its own hash and return it."""
        if isinstance(body, str):
            body = body.encode("utf-8")
        digest = hashlib.sha256(body).hexdigest()
        path = f"{self.own_prefix}assets/{digest}"
        self.put(path, self._encode_owned(path, body))
        return digest


def _lower(headers):
    return {str(name).lower(): value for name, value in (headers or {}).items()}


def _detail(payload):
    """The provider's error, trimmed to something worth putting in a message."""
    if not payload:
        return ""
    text = payload.decode("utf-8", "replace").strip()
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return text[:200]
    code = root.findtext("Code") or root.findtext(".//Code") or ""
    message = root.findtext("Message") or root.findtext(".//Message") or ""
    return f"{code} {message}".strip() or text[:200]


def from_json(path, issue):
    """A Bucket seeded from a grant the installer saved, refreshed by `issue`."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            grant = json.load(handle)
    except (OSError, ValueError):
        grant = None
    return Bucket(issue, grant if isinstance(grant, dict) else None)

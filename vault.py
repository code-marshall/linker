"""Encrypted collection storage.

Each collection lives in one file under collections/<slug>.enc and is fully
encrypted with a key derived from the collection's password. Nothing readable
is stored on disk: link names, addresses and notes all live inside the
ciphertext. Without the password the file cannot be decrypted, and there is no
recovery path.
"""

import base64
import json
import os
import re
import unicodedata
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

COLLECTIONS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "collections")

FORMAT_VERSION = 1
KDF_NAME = "pbkdf2-sha256"
KDF_ITERATIONS = 600_000
SALT_BYTES = 16
NONCE_BYTES = 12
KEY_BYTES = 32


class VaultError(Exception):
    """Base class for vault problems."""


class BadPassword(VaultError):
    """Raised when a password fails to decrypt a collection."""


class CollectionExists(VaultError):
    pass


class CollectionMissing(VaultError):
    pass


def _b64e(raw):
    return base64.b64encode(raw).decode("ascii")


def _b64d(text):
    return base64.b64decode(text.encode("ascii"))


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def slugify(name):
    """Turn a display name into a safe, collision-resistant file stem."""
    normalized = unicodedata.normalize("NFKD", name)
    ascii_only = normalized.encode("ascii", "ignore").decode("ascii")
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", ascii_only).strip("-").lower()
    return slug[:64]


def _path(slug):
    return os.path.join(COLLECTIONS_DIR, slug + ".enc")


def _derive_key(password, salt, iterations=KDF_ITERATIONS):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def _encrypt(payload, password, salt=None, iterations=KDF_ITERATIONS):
    salt = salt or os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    key = _derive_key(password, salt, iterations)
    plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return {
        "v": FORMAT_VERSION,
        "kdf": {"name": KDF_NAME, "iterations": iterations, "salt": _b64e(salt)},
        "nonce": _b64e(nonce),
        "ciphertext": _b64e(ciphertext),
    }


def _decrypt(envelope, password):
    kdf = envelope.get("kdf", {})
    salt = _b64d(kdf["salt"])
    iterations = int(kdf.get("iterations", KDF_ITERATIONS))
    key = _derive_key(password, salt, iterations)
    try:
        plaintext = AESGCM(key).decrypt(
            _b64d(envelope["nonce"]), _b64d(envelope["ciphertext"]), None
        )
    except InvalidTag:
        raise BadPassword("wrong password")
    return json.loads(plaintext.decode("utf-8"))


def list_collections():
    """Return the slugs on disk with their last-modified time. Names only."""
    if not os.path.isdir(COLLECTIONS_DIR):
        return []
    out = []
    for entry in os.listdir(COLLECTIONS_DIR):
        if not entry.endswith(".enc"):
            continue
        slug = entry[: -len(".enc")]
        full = os.path.join(COLLECTIONS_DIR, entry)
        out.append(
            {
                "slug": slug,
                "size": os.path.getsize(full),
                "modified": datetime.fromtimestamp(
                    os.path.getmtime(full), timezone.utc
                ),
            }
        )
    return sorted(out, key=lambda c: c["slug"])


def exists(slug):
    return os.path.isfile(_path(slug))


def create(name, password):
    slug = slugify(name)
    if not slug:
        raise VaultError("Collection name must contain at least one letter or number.")
    if exists(slug):
        raise CollectionExists("A collection with that name already exists.")
    payload = {"name": name.strip(), "created": _now(), "links": []}
    _write(slug, payload, password)
    return slug


def read(slug, password):
    """Decrypt and return a collection payload, or raise BadPassword."""
    try:
        with open(_path(slug), "r", encoding="utf-8") as fh:
            envelope = json.load(fh)
    except FileNotFoundError:
        raise CollectionMissing("No such collection.")
    return _decrypt(envelope, password)


def _write(slug, payload, password):
    envelope = _encrypt(payload, password)
    os.makedirs(COLLECTIONS_DIR, exist_ok=True)
    tmp = _path(slug) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(envelope, fh)
    os.replace(tmp, _path(slug))


def save(slug, payload, password):
    """Re-encrypt a whole payload. A fresh salt and nonce are used every time."""
    if not exists(slug):
        raise CollectionMissing("No such collection.")
    _write(slug, payload, password)


def change_password(slug, old_password, new_password):
    payload = read(slug, old_password)
    _write(slug, payload, new_password)


def delete(slug, password):
    """Verify the password before removing the file, so deletes need the key."""
    read(slug, password)
    os.remove(_path(slug))

"""SHA-256 commitments and Ed25519 signing/verification helpers."""

import hashlib
import json
import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

# Runtime outputs live in backend/data/, regardless of the current working directory.
DATA_DIR = Path(__file__).resolve().parents[2] / "data"


# ---------------------------------------------------------------- hashing

def sha256_hex(data: bytes | str) -> str:
    """SHA-256 of bytes or a UTF-8 string, as a hex string."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj) -> str:
    """Deterministic JSON (sorted keys, no extra whitespace) so equal data hashes equally."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# ---------------------------------------------------------------- Merkle commitment
# Leaves are salted, so nobody can guess an item by hashing candidates and comparing
# against the published root. Revealing (item, salt, proof) later proves membership.

def _leaf(item: str, salt: str) -> str:
    return sha256_hex(salt + item)


def commit_items(items: list[str]) -> dict:
    """Commit to a list of strings. Publish `root`; keep `salts` secret until reveal."""
    salts = [secrets.token_hex(16) for _ in items]
    leaves = [_leaf(item, salt) for item, salt in zip(items, salts)]
    return {"root": merkle_root(leaves), "leaves": leaves, "salts": salts}


def merkle_root(leaf_hashes: list[str]) -> str:
    """Hash pairs level by level until one hash remains (odd count: duplicate the last)."""
    if not leaf_hashes:
        return sha256_hex("")
    level = list(leaf_hashes)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        level = [sha256_hex(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def merkle_proof(leaf_hashes: list[str], index: int) -> list[tuple[str, str]]:
    """Sibling hashes from leaf to root. `side` says where the sibling sits: 'left' or 'right'."""
    proof = []
    level = list(leaf_hashes)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        if index % 2 == 0:
            proof.append((level[index + 1], "right"))
        else:
            proof.append((level[index - 1], "left"))
        level = [sha256_hex(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        index //= 2
    return proof


def verify_proof(item: str, salt: str, proof: list[tuple[str, str]], root: str) -> bool:
    """Recompute the path from (item, salt) up to the root and compare."""
    h = _leaf(item, salt)
    for sibling, side in proof:
        h = sha256_hex(sibling + h) if side == "left" else sha256_hex(h + sibling)
    return h == root


def recompute_root(items: list[str], salts: list[str]) -> str:
    """Rebuild the root from revealed items + salts (what a verifier does after the run)."""
    return merkle_root([_leaf(item, salt) for item, salt in zip(items, salts)])


# ---------------------------------------------------------------- file fingerprints

def hash_files(paths: list[str]) -> str:
    """Deterministic fingerprint of files and/or directories (e.g. blue's defense, model weights).

    Each file contributes "relative/path:sha256(contents)"; entries are sorted and
    use forward slashes so the result is identical on Windows, Mac and Linux.
    """
    entries = []
    for p in paths:
        root = Path(p)
        files = [f for f in root.rglob("*") if f.is_file()] if root.is_dir() else [root]
        for f in files:
            rel = f.relative_to(root).as_posix() if root.is_dir() else root.name
            label = f"{root.name}/{rel}" if root.is_dir() else rel
            entries.append(f"{label}:{sha256_hex(f.read_bytes())}")
    return sha256_hex("\n".join(sorted(entries)))


# ---------------------------------------------------------------- Ed25519 signatures

def load_or_create_keypair(path: str | os.PathLike = DATA_DIR / "signing_key.pem"):
    """Load the PEM private key at `path`, or create and save one. Returns (private_key, public_key_hex)."""
    path = Path(path)
    if path.exists():
        private_key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    else:
        private_key = Ed25519PrivateKey.generate()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    public_raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return private_key, public_raw.hex()


def sign(private_key: Ed25519PrivateKey, message: str) -> str:
    """Sign a UTF-8 message; returns the signature as hex."""
    return private_key.sign(message.encode("utf-8")).hex()


def verify_signature(public_key_hex: str, message: str, signature_hex: str) -> bool:
    """True only if `signature_hex` is a valid signature of `message` by that public key."""
    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        public_key.verify(bytes.fromhex(signature_hex), message.encode("utf-8"))
        return True
    except (InvalidSignature, ValueError):
        return False

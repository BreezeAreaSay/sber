#!/usr/bin/env python3
"""Vault v0.3 - keeps the launch code safe (allegedly)."""
import sys, hashlib, os

HERE = os.path.dirname(os.path.abspath(__file__))
KEY_PARTS = ["vault", "key", "2026"]


def _key():
    return "-".join(KEY_PARTS).encode()


def _unlock(blob: bytes) -> bytes:
    k = _key()
    return bytes(b ^ k[i % len(k)] for i, b in enumerate(blob))


def main():
    if len(sys.argv) != 2:
        print("usage: vault.py <password>")
        return 1
    pw = sys.argv[1].encode()
    if hashlib.sha256(pw).hexdigest() != "8f6c1d0d1c0c8d2e9a2fc0a4b2b1d7e6d8c0a3f5f1e2d3c4b5a69788796a5b4c":
        print("wrong password")
        return 1
    blob = open(os.path.join(HERE, "secret.bin"), "rb").read()
    print(_unlock(blob).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

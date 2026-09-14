#!/usr/bin/env python3
"""Deployment gate — prints the release token when unlocked."""
import hashlib, sys

def token(pw: str) -> str:
    h = hashlib.sha256(("gate:" + pw).encode()).hexdigest()
    return "ACP{" + h[:20] + "}"

def main():
    if len(sys.argv) != 2:
        print("usage: gate.py <password>")
        return 2
    pw = sys.argv[1]
    if hashlib.md5(pw.encode()).hexdigest() != "bc4325b0ac5a5938c556f08ad2f2751a":
        print("access denied")
        return 1
    print("release token:", token(pw))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

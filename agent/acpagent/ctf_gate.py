"""Deterministic solver for password-gated CTF programs.

A common challenge shape: a program prints a flag (`ACP{...}`) only when given the
right password, the password is checked against a hash digest baked into the source,
and the password itself is hinted in nearby files (a codename plus a build number, a
value in a note, ...).  A weak model has to (1) read the hint, (2) assemble the
password, (3) know it can verify it against the digest, (4) run the program.  This
module does all four by code:

1. collect hash digests (md5/sha1/sha256) that appear in the source;
2. build a candidate password list from every nearby text file — whole tokens,
   number runs, backticked templates like `orion-<n>` with the placeholder filled from
   sibling numbers, and `<word><sep><number>` combinations;
3. hash each candidate and match a digest → the real password (no guessing);
4. run the gated program with that password and read the flag it prints.

If no digest is present it falls back to running the program with each candidate and
keeping whatever prints a properly-formed flag.
"""

import hashlib
import itertools
import os
import re
import subprocess
from pathlib import Path

from acpagent import brief

_HEX = {32: "md5", 40: "sha1", 56: "sha224", 64: "sha256", 96: "sha384", 128: "sha512"}
_DIGEST_RE = re.compile(r"(?<![0-9a-fA-F])([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{56}|[0-9a-fA-F]{96}|[0-9a-fA-F]{128})(?![0-9a-fA-F])")
_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9]{1,30}|[A-Za-z0-9][A-Za-z0-9._-]{1,40}[A-Za-z0-9]")
_NUM_RE = re.compile(r"(?<!\d)\d{1,10}(?!\d)")
_WORD_RE = re.compile(r"[A-Za-z][A-Za-z]{2,20}")
_TEMPLATE_RE = re.compile(r"`([^`\n]{2,60})`")
_PLACEHOLDER_RE = re.compile(r"<[^>]{1,20}>|\{[^}]{1,20}\}|\bN\b|\bn\b|#+|XXXX*|\.\.\.")
_STOPWORDS = {"the", "and", "for", "with", "from", "this", "that", "when", "given", "right", "password",
              "flag", "program", "prints", "format", "files", "under", "come", "developer", "workstation",
              "find", "write", "nothing", "else", "http", "https", "usage", "example", "e.g", "see", "ask",
              "about", "staging", "cert", "notes", "sprint", "currently", "number", "build", "started",
              "finished", "artifacts", "uploaded", "rotate", "codename", "project", "release", "token"}


def _text_files(root: Path, max_files: int = 60):
    out = []
    for p in brief.iter_files(root, limit=300):
        try:
            if p.stat().st_size > 2_000_000:
                continue
            with p.open("rb") as fh:
                head = fh.read(4096)
            if b"\x00" in head:
                continue
            out.append(p)
        except OSError:
            continue
        if len(out) >= max_files:
            break
    return out


_BIN_STR_RE = re.compile(rb"[\x20-\x7e]{4,60}")


def _binary_strings(root: Path, max_files: int = 8, max_each: int = 400):
    """Printable constants inside compiled programs.

    A "reversing" challenge usually compares the input against a literal that is sitting
    in the binary's read-only data, so the answer is already on disk — it just is not in
    a text file."""
    out = []
    for p in brief.iter_files(root, limit=200):
        try:
            if not (0 < p.stat().st_size <= 8_000_000):
                continue
            with p.open("rb") as fh:
                head = fh.read(4)
            if head[:4] != b"\x7fELF" and b"\x00" not in p.open("rb").read(2048):
                continue
            data = p.read_bytes()
        except OSError:
            continue
        found = []
        for m in _BIN_STR_RE.finditer(data):
            try:
                found.append(m.group(0).decode("ascii"))
            except UnicodeDecodeError:
                continue
            if len(found) >= max_each:
                break
        out.extend(found)
        max_files -= 1
        if max_files <= 0:
            break
    return out


def _collect(root: Path):
    digests, texts = {}, []
    for p in _text_files(root):
        try:
            txt = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        texts.append(txt)
        for m in _DIGEST_RE.finditer(txt):
            d = m.group(1).lower()
            digests[d] = _HEX.get(len(d))
    binary = _binary_strings(root)
    if binary:
        blob = "\n".join(binary)
        texts.append(blob)
        for m in _DIGEST_RE.finditer(blob):
            d = m.group(1).lower()
            digests.setdefault(d, _HEX.get(len(d)))
    return digests, "\n".join(texts)


def _candidates(text: str, limit: int = 6000):
    words = []
    seen = set()
    for w in _WORD_RE.findall(text):
        lw = w.lower()
        if lw in _STOPWORDS or lw in seen:
            continue
        seen.add(lw)
        words.append(w)
    nums = []
    for n in _NUM_RE.findall(text):
        if n not in nums:
            nums.append(n)
    cands = []

    def add(v):
        if v and v not in cands:
            cands.append(v)

    # 1) templates: `orion-<n>` / `codename-<build>` → fill placeholders with sibling numbers
    for tmpl in _TEMPLATE_RE.findall(text):
        if not _PLACEHOLDER_RE.search(tmpl):
            add(tmpl.strip())
            continue
        for n in nums[:40]:
            add(_PLACEHOLDER_RE.sub(n, tmpl).strip())
        # also fill with each word (codename could be the placeholder)
        for w in words[:20]:
            filled = _PLACEHOLDER_RE.sub(w, tmpl).strip()
            if not _PLACEHOLDER_RE.search(filled):
                add(filled)
    # 2) word <sep> number combinations (the "codename + build number" idiom)
    seps = ["-", "_", "", ".", ":", "/"]
    for w, n in itertools.product(words[:40], nums[:40]):
        for sep in seps:
            add(f"{w}{sep}{n}")
            add(f"{w.lower()}{sep}{n}")
        if len(cands) > limit:
            break
    # 3) two-word combinations
    for a, b in itertools.product(words[:15], words[:15]):
        if a != b:
            add(f"{a}-{b}")
            add(f"{a}{b}")
        if len(cands) > limit:
            break
    # 4) bare tokens and numbers last
    for tok in _TOKEN_RE.findall(text):
        add(tok)
        if len(cands) > limit:
            break
    for n in nums:
        add(n)
    return cands[:limit]


def recover_password(root: Path):
    """(password, digest, algo) recovered from hint files, or (None, None, None)."""
    digests, text = _collect(root)
    if not digests:
        return None, None, None
    cands = _candidates(text)
    algos = ("md5", "sha1", "sha256", "sha224", "sha384", "sha512")
    for cand in cands:
        b = cand.encode("utf-8", "replace")
        for algo in algos:
            try:
                h = hashlib.new(algo, b).hexdigest()
            except ValueError:
                continue
            if h in digests:
                return cand, h, algo
    return None, None, None


# ---- RSA and other number-theoretic challenges ----------------------------------------

_NUM_ASSIGN = re.compile(
    r"(?<![A-Za-z0-9_])(?P<name>[npqedc]|n\d?|modulus|exponent|cipher(?:text)?|ct|enc(?:rypted)?|pubexp|priv)\s*"
    r"[:=]\s*(?P<val>0x[0-9a-fA-F]{4,}|\d{4,})",
    re.I,
)


def _numbers(root: Path):
    """name -> [values] for the big integers a challenge leaves lying around."""
    found = {}
    for p in _text_files(root):
        try:
            txt = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _NUM_ASSIGN.finditer(txt):
            name = m.group("name").lower()
            raw = m.group("val")
            val = int(raw, 16) if raw.lower().startswith("0x") else int(raw)
            found.setdefault(name, [])
            if val not in found[name]:
                found[name].append(val)
    return found


def _iroot(x: int, k: int) -> int:
    """Integer k-th root (floor)."""
    if x < 0:
        return 0
    lo, hi = 0, 1 << ((x.bit_length() + k - 1) // k + 1)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if mid ** k <= x:
            lo = mid
        else:
            hi = mid - 1
    return lo


def _fermat(n: int, rounds: int = 200000):
    """Factor n when its primes are close together, the usual generated-key mistake."""
    a = _iroot(n, 2)
    if a * a < n:
        a += 1
    for _ in range(rounds):
        b2 = a * a - n
        if b2 >= 0:
            b = _iroot(b2, 2)
            if b * b == b2:
                p, q = a - b, a + b
                if p > 1 and p * q == n:
                    return p, q
        a += 1
    return None


def _small_factor(n: int, limit: int = 1_000_000):
    if n % 2 == 0:
        return 2, n // 2
    f = 3
    while f < limit and f * f <= n:
        if n % f == 0:
            return f, n // f
        f += 2
    return None


def _pollard_rho(n: int, rounds: int = 200000):
    import math
    if n % 2 == 0:
        return 2, n // 2
    for c in (1, 2, 3):
        x = y = 2
        d = 1
        for _ in range(rounds):
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = math.gcd(abs(x - y), n)
            if d != 1:
                break
        if 1 < d < n:
            return d, n // d
    return None


def _to_bytes(m: int) -> bytes:
    if m <= 0:
        return b""
    return m.to_bytes((m.bit_length() + 7) // 8, "big")


def rsa_recover(root: Path, prefix: str = ""):
    """Decrypt an RSA challenge whose parameters sit in the files.

    Covers the cases a challenge actually uses: the primes are given, the modulus is
    small or its primes are close together, or the exponent is so small that the
    ciphertext is a plain power and an integer root undoes it."""
    nums = _numbers(root)
    out = []
    mods = nums.get("n", []) + nums.get("modulus", [])
    exps = nums.get("e", []) + nums.get("exponent", []) + nums.get("pubexp", []) or [65537, 3]
    cts = (nums.get("c", []) + nums.get("ct", []) + nums.get("cipher", []) +
           nums.get("ciphertext", []) + nums.get("enc", []) + nums.get("encrypted", []))
    ps, qs = nums.get("p", []), nums.get("q", [])
    for c in cts[:6]:
        # 1) a small exponent with no padding is just a power
        for e in exps[:4]:
            if 2 <= e <= 11:
                m = _iroot(c, e)
                if m ** e == c:
                    out.append((_to_bytes(m), f"plain {e}-th root of the ciphertext (unpadded small exponent)"))
        for n in mods[:4]:
            if c >= n:
                continue
            factors = None
            for pp in ps:
                for qq in qs:
                    if pp * qq == n:
                        factors = (pp, qq)
            if factors is None:
                for attempt in (_small_factor, _fermat, _pollard_rho):
                    try:
                        got = attempt(n)
                    except Exception:  # noqa: BLE001
                        got = None
                    if got:
                        factors = got
                        break
            if not factors:
                continue
            pp, qq = factors
            phi = (pp - 1) * (qq - 1)
            for e in exps[:4]:
                try:
                    d = pow(e, -1, phi)
                except Exception:  # noqa: BLE001
                    continue
                m = pow(c, d, n)
                out.append((_to_bytes(m), f"RSA decrypted after factoring the {n.bit_length()}-bit modulus"))
    return out


def _gated_programs(root: Path):
    progs = []
    for p in brief.iter_files(Path(root), limit=300):
        try:
            size = p.stat().st_size
            if size == 0 or size > 5_000_000:
                continue
            with p.open("rb") as fh:
                head = fh.read(64)
        except OSError:
            continue
        if head.startswith(b"\x7fELF"):
            progs.append(("elf", p))
        elif p.suffix == ".py" or (head.startswith(b"#!") and b"python" in head):
            progs.append(("py", p))
        elif p.suffix == ".sh" or (head.startswith(b"#!") and (b"bash" in head or b"/sh" in head)):
            progs.append(("sh", p))
    return progs


def _run(kind, path, arg, timeout=6):
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "LC_ALL", "PYTHONIOENCODING")}
    env["TERM"] = "dumb"
    if kind == "elf":
        try:
            os.chmod(path, 0o755)
        except OSError:
            pass
        argv = [str(path), arg]
    elif kind == "py":
        argv = ["python3", str(path), arg]
    else:
        argv = ["bash", str(path), arg]
    try:
        r = subprocess.run(argv, cwd=str(path.parent), stdin=subprocess.DEVNULL,
                           capture_output=True, timeout=timeout, env=env)
        return (r.stdout or b"") + b"\n" + (r.stderr or b"")
    except Exception:  # noqa: BLE001
        return b""


# ---- AES / symmetric ciphertext -------------------------------------------------------

_B64_BLOB = re.compile(rb"[A-Za-z0-9+/]{24,}={0,2}")
_HEX_BLOB = re.compile(rb"(?:[0-9a-fA-F]{2}){16,}")
_KV_STR = re.compile(r"""(?P<name>key|secret|passphrase|password|pass|iv|nonce|aes_key)\s*[:=]\s*['"]?(?P<val>[^'"\n]{3,120})""", re.I)


def _maybe_decode(raw):
    """A blob as raw bytes plus any base64/hex decodings of it that look like ciphertext."""
    import base64
    import binascii
    out = [raw]
    txt = raw.strip()
    try:
        if _B64_BLOB.fullmatch(txt.replace(b"\n", b"")):
            d = base64.b64decode(txt + b"=" * (-len(txt) % 4), validate=False)
            if len(d) >= 16:
                out.append(d)
    except Exception:  # noqa: BLE001
        pass
    try:
        if _HEX_BLOB.fullmatch(txt):
            d = binascii.unhexlify(txt)
            if len(d) >= 16:
                out.append(d)
    except Exception:  # noqa: BLE001
        pass
    return out


def _ciphertexts(root: Path):
    """(bytes, where) for every blob that could be AES ciphertext."""
    import base64
    import binascii
    found = []
    for p in brief.iter_files(root, limit=200):
        try:
            if not (16 <= p.stat().st_size <= 4_000_000):
                continue
            data = p.read_bytes()
        except OSError:
            continue
        rel = str(p.name)
        if b"\x00" in data[:2048] or not _looks_texty(data[:512]):
            found.append((data, f"{rel} (raw bytes)"))
        else:
            text = data.decode("utf-8", "replace")
            for m in _B64_BLOB.finditer(data):
                try:
                    d = base64.b64decode(m.group(0) + b"=" * (-len(m.group(0)) % 4), validate=False)
                    if len(d) >= 16:
                        found.append((d, f"{rel} (base64 blob)"))
                except Exception:  # noqa: BLE001
                    pass
            for m in _HEX_BLOB.finditer(data):
                try:
                    d = binascii.unhexlify(m.group(0))
                    if len(d) >= 16:
                        found.append((d, f"{rel} (hex blob)"))
                except Exception:  # noqa: BLE001
                    pass
        if len(found) >= 12:
            break
    return found


def _looks_texty(chunk: bytes) -> bool:
    if not chunk:
        return False
    printable = sum(1 for b in chunk if 9 <= b <= 13 or 32 <= b <= 126)
    return printable / len(chunk) > 0.85


def _key_material(root: Path):
    """Candidate AES keys and IVs gathered from the files (raw, hex, base64, derived)."""
    import base64
    import binascii
    import hashlib
    keys, ivs, phrases = [], [], []
    _, text = _collect(root)
    for m in _KV_STR.finditer(text):
        name, val = m.group("name").lower(), m.group("val").strip()
        target_iv = name in ("iv", "nonce")
        raws = []
        for b in (val.encode(), *[d for d in (_try_hex(val), _try_b64(val)) if d]):
            raws.append(b)
        for b in raws:
            if target_iv and len(b) in (8, 12, 16):
                ivs.append(b)
            elif not target_iv and len(b) in (16, 24, 32):
                keys.append(b)
        if not target_iv:
            phrases.append(val)
    # passphrases become keys through the usual derivations
    for ph in phrases[:40]:
        pb = ph.encode()
        keys.append(hashlib.md5(pb).digest())            # 16
        keys.append(hashlib.sha256(pb).digest())         # 32
        keys.append(hashlib.sha1(pb).digest()[:16])      # 16
        for n in (16, 24, 32):
            keys.append(pb[:n].ljust(n, b"\0"))          # truncated / null-padded
    # de-dup, keep order
    def _uniq(xs):
        seen, out = set(), []
        for x in xs:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out
    return _uniq(keys)[:60], _uniq(ivs + [b"\x00" * 16])[:8]


def _try_hex(v):
    import binascii
    try:
        return binascii.unhexlify(v) if re.fullmatch(r"[0-9a-fA-F]+", v) and len(v) % 2 == 0 else None
    except Exception:  # noqa: BLE001
        return None


def _try_b64(v):
    import base64
    try:
        return base64.b64decode(v + "=" * (-len(v) % 4), validate=True) if re.fullmatch(r"[A-Za-z0-9+/=]+", v) else None
    except Exception:  # noqa: BLE001
        return None


def _unpad(b):
    if b and 1 <= b[-1] <= 16 and b[-b[-1]:] == bytes([b[-1]]) * b[-1]:
        return b[:-b[-1]]
    return b


def aes_recover(root: Path, prefix: str = ""):
    """Decrypt an AES challenge whose key material sits in the files. (plaintext, how).

    Uses the in-tree pure-Python AES so a missing or broken `cryptography` binding can
    never take the CTF solver down with it."""
    from acpagent import aes_pure
    cts = _ciphertexts(root)
    if not cts:
        return []
    keys, ivs = _key_material(root)
    if not keys:
        return []
    out = []
    tried = 0
    for ct, where in cts:
        for key in keys:
            if len(key) not in (16, 24, 32):
                continue
            variants = [("ECB", None, ct)]
            for iv in ivs:
                if len(iv) == 16:
                    variants.append(("CBC", iv, ct))
                    variants.append(("CTR", iv, ct))
            if len(ct) > 16:
                variants.append(("CBC", ct[:16], ct[16:]))  # IV prefixed to the ciphertext
                variants.append(("CTR", ct[:16], ct[16:]))
            for mode_name, iv, body in variants:
                if len(body) % 16 and mode_name != "CTR":
                    continue
                tried += 1
                if tried > 6000:
                    return out
                try:
                    if mode_name == "ECB":
                        pt = aes_pure.decrypt_ecb(key, body)
                    elif mode_name == "CBC":
                        pt = aes_pure.decrypt_cbc(key, iv, body)
                    else:
                        pt = aes_pure.decrypt_ctr(key, iv, body)
                except Exception:  # noqa: BLE001
                    continue
                for cand in (pt, _unpad(pt)):
                    flag = _extract(cand, prefix)
                    if flag:
                        out.append((cand, f"AES-{mode_name} decrypt of {where} with a {len(key) * 8}-bit key from the files"))
                        return out
    return out


# ---- a challenge served over a local port ----------------------------------------------

_PORTS = (80, 3000, 5000, 8000, 8080, 8888, 9000, 9999, 1337, 4000, 7777)
_PATHS = ("/", "/flag", "/flag.txt", "/index.html", "/robots.txt", "/admin", "/api/flag",
          "/secret", "/.env", "/debug")


def service_flags(root: Path, prefix: str = ""):
    """Ask a service the challenge is running for its flag.

    Some challenges put the answer behind a local HTTP endpoint rather than in a file;
    the container is offline, so probing loopback is cheap and cannot reach anything
    outside the task."""
    import urllib.error
    import urllib.request
    seen = []
    for port in _PORTS:
        base = f"http://127.0.0.1:{port}"
        try:
            with urllib.request.urlopen(base + "/", timeout=1) as resp:
                body = resp.read(200000)
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read(200000)
            except Exception:  # noqa: BLE001
                continue
        except Exception:  # noqa: BLE001
            continue  # nothing listening here
        for path in _PATHS:
            try:
                with urllib.request.urlopen(base + path, timeout=1) as resp:
                    data = resp.read(200000)
            except urllib.error.HTTPError as exc:
                try:
                    data = exc.read(200000)
                except Exception:  # noqa: BLE001
                    continue
            except Exception:  # noqa: BLE001
                continue
            flag = _extract(data, prefix)
            if flag:
                return flag, f"fetched {base}{path} from the service the challenge is running"
            seen.append(data)
    for data in seen[:20]:
        flag = _extract(data, prefix)
        if flag:
            return flag, "found in a response from a local service"
    return None, ""


def solve(root: Path, prefix: str = ""):
    """Return (flag, explanation) or (None, '')."""
    root = Path(root)
    try:
        for plain, how in rsa_recover(root, prefix):
            flag = _extract(plain, prefix)
            if flag:
                return flag, how
    except Exception:  # noqa: BLE001
        pass
    try:
        for plain, how in aes_recover(root, prefix):
            flag = _extract(plain, prefix)
            if flag:
                return flag, how
    except Exception:  # noqa: BLE001
        pass
    progs = _gated_programs(root)
    if not progs:
        try:
            flag, how = service_flags(root, prefix)
            if flag:
                return flag, how
        except Exception:  # noqa: BLE001
            pass
        return None, ""
    pw, digest, algo = recover_password(root)
    tried = []
    if pw is not None:
        tried = [pw]
    else:
        # no digest to verify against: fall back to the candidate list, capped small so we
        # do not run a program hundreds of times
        _, text = _collect(root)
        if not text:
            text = "\n".join(p.read_text(errors="replace") for _, p in progs if p.stat().st_size < 200000)
        tried = _candidates(text, limit=40)
        # a literal the program itself carries is the likeliest password of all
        for lit in _binary_strings(root, max_files=4, max_each=120):
            low = lit.strip()
            if 3 <= len(low) <= 40 and low not in tried and not low.startswith(("/", "GCC", "GLIBC", "__")):
                tried.insert(0, low)
        tried = tried[:80]
        if not tried:
            return None, ""
    for kind, path in progs:
        for cand in tried:
            out = _run(kind, path, cand)
            if not out:
                continue
            flag = _extract(out, prefix)
            if flag:
                how = (f"recovered password {cand!r} by matching {algo}({cand!r})={digest} in the source; "
                       f"ran {path.name} {cand!r} which printed the flag") if pw is not None else \
                      f"ran {path.name} with candidate password {cand!r}, which printed the flag"
                return flag, how
    try:
        flag, how = service_flags(root, prefix)
        if flag:
            return flag, how
    except Exception:  # noqa: BLE001
        pass
    return None, ""


def _extract(data: bytes, prefix: str):
    from acpagent import oracle
    hits = [m.group(0).decode("ascii", "replace") for m in brief.FLAG_RE.finditer(data)]
    hits = [h for h in hits if not oracle._code_fragment(h)]
    if prefix:
        for h in hits:
            if h.startswith(prefix):
                return h
    for h in hits:
        if any(h.encode().startswith(t) for t in brief.COMMON_TAGS):
            return h
    return hits[0] if hits else None

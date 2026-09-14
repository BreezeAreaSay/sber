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
    progs = _gated_programs(root)
    if not progs:
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
        tried = _candidates(text, limit=60)
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

#!/usr/bin/env python3
"""
cryptus.py — simple file encrypt/decrypt CLI that encodes ciphertext as Roman numerals.
⚠️ Educational prototype — not audited cryptography. Do not rely on this for high-stakes security.

Usage:
  Encrypt:   python cryptus.py -e -i input.file -o output.cry --pass "secret" -l 5 --block 80
  Decrypt:   python cryptus.py -d -i output.cry -o original.file --pass "secret"

Flags:
  -e / -d        Encrypt or Decrypt (mutually exclusive)
  -i / -o        Input / Output files
  -l             Level (1–10): raises PBKDF2 work factor. Default 4.
  --pass         Passphrase (otherwise will prompt securely)
  --block        Wrap Roman output to this many characters per line (encrypt only). Default 80.
"""

import argparse
import getpass
import hashlib
import hmac
import os
import sys
from typing import Tuple

MAGIC = b"CRY1"
SALT_LEN = 16
NONCE_LEN = 12
TAG_LEN = 32
BASE_ITER = 200_000
MAX_LEVEL = 10
MIN_LEVEL = 1

# ------------------ Roman helpers ------------------

_ROMAN_MAP = [
    (1000, "M"), (900, "CM"), (500, "D"), (400, "CD"),
    (100, "C"), (90, "XC"), (50, "L"), (40, "XL"),
    (10, "X"), (9, "IX"), (5, "V"), (4, "IV"), (1, "I")
]

_ROMAN_VALUES = {
    "I": 1, "V": 5, "X": 10, "L": 50,
    "C": 100, "D": 500, "M": 1000
}

def to_roman(n: int) -> str:
    if n == 0:
        return "N"  # nulla
    if n < 0 or n > 255:
        raise ValueError("Roman encoder expects 0..255")
    res = []
    value = n
    for val, sym in _ROMAN_MAP:
        while value >= val:
            res.append(sym)
            value -= val
    return "".join(res)

def from_roman(s: str) -> int:
    s = s.strip().upper()
    if s == "N":
        return 0
    if not s:
        raise ValueError("Empty Roman token")
    total = 0
    i = 0
    while i < len(s):
        if i+1 < len(s) and _ROMAN_VALUES.get(s[i], 0) < _ROMAN_VALUES.get(s[i+1], 0):
            total += _ROMAN_VALUES[s[i+1]] - _ROMAN_VALUES[s[i]]
            i += 2
        else:
            if s[i] not in _ROMAN_VALUES:
                raise ValueError(f"Invalid Roman symbol: {s[i]}")
            total += _ROMAN_VALUES[s[i]]
            i += 1
    if total < 0 or total > 255:
        raise ValueError("Roman value out of byte range")
    return total

def bytes_to_roman_text(data: bytes, block_width: int = 80) -> str:
    tokens = [to_roman(b) for b in data]
    text = " ".join(tokens)
    if block_width and block_width > 0:
        out_lines = []
        line = []
        line_len = 0
        for tok in tokens:
            tok_len = len(tok)
            if line_len == 0:
                line.append(tok)
                line_len = tok_len
            elif line_len + 1 + tok_len <= block_width:
                line.append(tok)
                line_len += 1 + tok_len
            else:
                out_lines.append(" ".join(line))
                line = [tok]
                line_len = tok_len
        if line:
            out_lines.append(" ".join(line))
        return "\n".join(out_lines)
    return text

def roman_text_to_bytes(text: str) -> bytes:
    tokens = text.split()
    return bytes(from_roman(tok) for tok in tokens)

# ------------------ KDF / keystream / MAC ------------------

def derive_keys(passphrase: bytes, salt: bytes, level: int) -> Tuple[bytes, bytes]:
    level = max(MIN_LEVEL, min(MAX_LEVEL, level))
    iters = BASE_ITER * level
    dk = hashlib.pbkdf2_hmac("sha256", passphrase, salt, iters, dklen=64)
    return dk[:32], dk[32:64]

def keystream(enc_key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        ctr_bytes = counter.to_bytes(8, "big")
        block = hmac.new(enc_key, nonce + ctr_bytes, hashlib.sha256).digest()
        need = min(len(block), length - len(out))
        out.extend(block[:need])
        counter += 1
    return bytes(out)

def encrypt_bytes(plaintext: bytes, passphrase: bytes, level: int) -> bytes:
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    enc_key, mac_key = derive_keys(passphrase, salt, level)
    stream = keystream(enc_key, nonce, len(plaintext))
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, stream))
    header = MAGIC + salt + nonce + level.to_bytes(4, "big")
    tag = hmac.new(mac_key, header + ciphertext, hashlib.sha256).digest()
    return header + ciphertext + tag

def decrypt_bytes(blob: bytes, passphrase: bytes) -> bytes:
    if len(blob) < 4 + SALT_LEN + NONCE_LEN + 4 + TAG_LEN:
        raise ValueError("Ciphertext too short.")
    if blob[:4] != MAGIC:
        raise ValueError("Bad magic header.")
    salt = blob[4:4+SALT_LEN]
    nonce = blob[4+SALT_LEN:4+SALT_LEN+NONCE_LEN]
    level = int.from_bytes(blob[4+SALT_LEN+NONCE_LEN:4+SALT_LEN+NONCE_LEN+4], "big")
    tag = blob[-TAG_LEN:]
    ciphertext = blob[4+SALT_LEN+NONCE_LEN+4:-TAG_LEN]
    enc_key, mac_key = derive_keys(passphrase, salt, level)
    header = MAGIC + salt + nonce + level.to_bytes(4, "big")
    calc_tag = hmac.new(mac_key, header + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, calc_tag):
        raise ValueError("Authentication failed (bad password or corrupted file).")
    stream = keystream(enc_key, nonce, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, stream))

# ------------------ CLI ------------------

def parse_args():
    p = argparse.ArgumentParser(description="cryptus.py — Encrypt/Decrypt files; ciphertext as Roman numerals.")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("-e", "--encrypt", action="store_true", help="Encrypt input to Roman-encoded ciphertext")
    g.add_argument("-d", "--decrypt", action="store_true", help="Decrypt Roman-encoded ciphertext")
    p.add_argument("-i", "--input", required=True)
    p.add_argument("-o", "--output", required=True)
    p.add_argument("-l", "--level", type=int, default=4, help="Security level 1–10")
    p.add_argument("--pass", dest="password", help="Passphrase")
    p.add_argument("--block", type=int, default=80, help="Wrap width for Roman output")
    return p.parse_args()

def main():
    args = parse_args()
    level = max(MIN_LEVEL, min(MAX_LEVEL, args.level))
    pw = args.password or getpass.getpass("Passphrase: ")
    passphrase = pw.encode("utf-8")
    with open(args.input, "rb") as f:
        data = f.read()
    if args.encrypt:
        blob = encrypt_bytes(data, passphrase, level)
        roman_text = bytes_to_roman_text(blob, block_width=args.block)
        with open(args.output, "w", encoding="utf-8") as out:
            out.write(roman_text)
    else:
        roman_text = data.decode("utf-8")
        blob = roman_text_to_bytes(roman_text)
        plain = decrypt_bytes(blob, passphrase)
        with open(args.output, "wb") as out:
            out.write(plain)
    print(f"Done. Wrote: {args.output}")

if __name__ == "__main__":
    main()


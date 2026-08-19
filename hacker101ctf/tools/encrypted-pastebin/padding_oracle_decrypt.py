#!/usr/bin/env python3
"""Decrypt an authorized Encrypted Pastebin token with its padding oracle.

Use this only with a CTF instance or another system you are explicitly
authorized to test. This script decrypts a supplied token; it does not forge
new plaintext or attempt the later challenge stages.
"""

from __future__ import annotations

import base64
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


BLOCK_SIZE = 16
USER_AGENT = "Hacker101-padding-oracle-learning-script/1.0"


def custom_decode(token: str) -> bytes:
    """Decode the challenge's URL-safe Base64 variant into ciphertext bytes."""
    normal_b64 = token.replace("~", "=").replace("!", "/").replace("-", "+")
    try:
        return base64.b64decode(normal_b64, validate=True)
    except Exception as exc:  # binascii.Error varies across Python versions
        raise ValueError("The post token is not valid custom Base64 data.") from exc


def custom_encode(ciphertext: bytes) -> str:
    """Encode ciphertext using the challenge's URL-safe Base64 variant."""
    return (
        base64.b64encode(ciphertext)
        .decode("ascii")
        .replace("=", "~")
        .replace("/", "!")
        .replace("+", "-")
    )


def unpad_pkcs7(data: bytes) -> bytes:
    """Remove and validate PKCS#7 padding from a decrypted message."""
    if not data:
        raise ValueError("The recovered plaintext is empty.")
    padding_length = data[-1]
    if not 1 <= padding_length <= BLOCK_SIZE:
        raise ValueError("Recovered plaintext does not have valid PKCS#7 padding.")
    if data[-padding_length:] != bytes([padding_length]) * padding_length:
        raise ValueError("Recovered plaintext has inconsistent PKCS#7 padding.")
    return data[:-padding_length]


def printable(byte_value: int) -> str:
    return chr(byte_value) if 32 <= byte_value <= 126 else "."


def timestamp() -> str:
    return time.strftime("%H:%M:%S")


@dataclass
class PaddingOracle:
    base_url: str
    delay_seconds: float
    timeout_seconds: float = 15.0
    retries: int = 3

    def query(self, ciphertext: bytes) -> bool:
        """Return True only when the server reaches a stage after unpadding."""
        token = custom_encode(ciphertext)
        url = f"{self.base_url}/?post={quote(token, safe='-!~')}"
        request = Request(url, headers={"User-Agent": USER_AGENT})

        for attempt in range(1, self.retries + 1):
            try:
                with urlopen(request, timeout=self.timeout_seconds) as response:
                    body = response.read().decode("utf-8", errors="replace")
                break
            except HTTPError as exc:
                body = exc.read().decode("utf-8", errors="replace")
                break
            except URLError as exc:
                if attempt == self.retries:
                    raise RuntimeError(f"Network error after {self.retries} attempts: {exc}") from exc
                print(
                    f"[{timestamp()}] Network error; retrying ({attempt}/{self.retries})...",
                    file=sys.stderr,
                )
                time.sleep(max(self.delay_seconds, 1.0))

        if self.delay_seconds:
            time.sleep(self.delay_seconds)

        lowered = body.lower()
        if "incorrect padding" in lowered:
            raise RuntimeError("Crafted ciphertext unexpectedly failed Base64 decoding.")
        return "paddingexception" not in lowered and "padding error" not in lowered


def confirmed_valid_padding(oracle: PaddingOracle, crafted_previous: bytearray, target: bytes, position: int) -> bool:
    """Reject accidental longer-padding matches while solving a byte."""
    if not oracle.query(bytes(crafted_previous) + target):
        return False

    # If changing a byte just before the desired padding breaks validity, the
    # first response was caused by a longer accidental padding pattern.
    if position == 0:
        return True
    confirmation = bytearray(crafted_previous)
    confirmation[position - 1] ^= 1
    return oracle.query(bytes(confirmation) + target)


def decrypt_block(oracle: PaddingOracle, previous: bytes, target: bytes, block_number: int) -> bytes:
    """Recover one plaintext block by learning its AES intermediate bytes."""
    intermediate = bytearray(BLOCK_SIZE)
    plaintext = bytearray(BLOCK_SIZE)

    print(f"\n[{timestamp()}] [*] Decrypting block {block_number}")
    for position in range(BLOCK_SIZE - 1, -1, -1):
        padding_length = BLOCK_SIZE - position
        crafted_previous = bytearray(BLOCK_SIZE)

        # Force every already-solved trailing byte to the new padding value.
        for solved_position in range(position + 1, BLOCK_SIZE):
            crafted_previous[solved_position] = intermediate[solved_position] ^ padding_length

        for guess in range(256):
            crafted_previous[position] = guess
            if not confirmed_valid_padding(oracle, crafted_previous, target, position):
                continue

            intermediate[position] = guess ^ padding_length
            plaintext[position] = intermediate[position] ^ previous[position]
            print(
                f"[{timestamp()}]   byte {position:02d}: 0x{plaintext[position]:02x} "
                f"({printable(plaintext[position])})"
            )
            break
        else:
            raise RuntimeError(
                f"No valid-padding candidate found for block {block_number}, byte {position}. "
                "Check the oracle response rules and target token."
            )

    return bytes(plaintext)


def prompt_float(message: str, default: float) -> float:
    value = input(f"{message} [{default}]: ").strip()
    return default if not value else float(value)


def prompt_int(message: str, default: int) -> int:
    value = input(f"{message} [{default}]: ").strip()
    result = default if not value else int(value)
    if result < 1:
        raise ValueError("The worker count must be at least 1.")
    return result


def main() -> None:
    print("Encrypted Pastebin padding-oracle decryptor (authorized CTF use only)\n")
    base_url = input("CTF base URL (for example, https://<id>.ctf.hacker101.com): ").strip().rstrip("/")
    token = input("Valid post token (the value after ?post=): ").strip()
    delay_seconds = prompt_float("Delay between requests in seconds", 0.05)
    workers = prompt_int("Parallel block workers (1 = sequential; use 2-4 conservatively)", 2)

    if not base_url.startswith(("http://", "https://")):
        raise ValueError("The base URL must start with http:// or https://")
    if delay_seconds < 0:
        raise ValueError("The delay cannot be negative.")

    ciphertext = custom_decode(token)
    if len(ciphertext) < BLOCK_SIZE * 2 or len(ciphertext) % BLOCK_SIZE:
        raise ValueError(
            "Decoded token must contain an IV plus at least one 16-byte ciphertext block."
        )

    blocks = [ciphertext[index : index + BLOCK_SIZE] for index in range(0, len(ciphertext), BLOCK_SIZE)]
    print(f"\n[{timestamp()}] [*] Decoded {len(ciphertext)} bytes into {len(blocks)} blocks (including the IV).")
    print(
        f"[{timestamp()}] [*] Decrypting {len(blocks) - 1} block(s) with up to {workers} worker(s). "
        "Ctrl-C stops it safely.\n"
    )

    oracle = PaddingOracle(base_url=base_url, delay_seconds=delay_seconds)
    plaintext_blocks: List[Optional[bytes]] = [None] * (len(blocks) - 1)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(decrypt_block, oracle, blocks[index - 1], blocks[index], index): index
            for index in range(1, len(blocks))
        }
        for future in as_completed(futures):
            index = futures[future]
            plaintext_blocks[index - 1] = future.result()
            print(f"[{timestamp()}] [+] Block {index} complete.")

    if any(block is None for block in plaintext_blocks):
        raise RuntimeError("One or more plaintext blocks were not recovered.")
    plaintext = unpad_pkcs7(b"".join(block for block in plaintext_blocks if block is not None))
    decoded = plaintext.decode("utf-8", errors="replace")

    print("\n[+] Recovered plaintext:")
    print(decoded)
    flags = re.findall(r"\^FLAG\^.*?\$FLAG\$", decoded)
    if flags:
        print("\n[+] Flag marker(s) found:")
        print("\n".join(flags))
    else:
        print("\n[!] No flag marker was found in the recovered plaintext.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.", file=sys.stderr)
    except Exception as exc:
        print(f"\n[!] {exc}", file=sys.stderr)
        raise SystemExit(1)

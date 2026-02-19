"""
RAPPOR Customer Logger
======================
Logs customer first/last names with local differential privacy
using the RAPPOR (Randomized Aggregatable Privacy-Preserving
Ordinal Response) algorithm.

Pipeline per name:
  1. Bloom Filter encoding  →  128-bit vector
  2. Permanent Randomised Response (PRR)  →  f parameter
  3. Instantaneous Randomised Response (IRR)  →  p, q parameters

Usage:
    python rappor_logger.py
    python rappor_logger.py --f 0.5 --p 0.75 --q 0.5
"""

import argparse
import hashlib
import json
import math
import os
import random
import sys
from datetime import datetime

# ──────────────────────────────────────────────────────────────
# RAPPOR Core
# ──────────────────────────────────────────────────────────────

BLOOM_SIZE = 128   # number of bits in the Bloom filter
NUM_HASHES = 4     # hash functions per value


def _hash_index(value: str, seed: int) -> int:
    """Return a Bloom filter index for (value, seed)."""
    raw = f"{seed}:{value.lower()}".encode()
    digest = hashlib.sha256(raw).digest()
    # Use first 2 bytes as index
    return (digest[0] << 8 | digest[1]) % BLOOM_SIZE


def bloom_encode(value: str) -> list[int]:
    """Encode a string into a BLOOM_SIZE-bit Bloom filter."""
    bits = [0] * BLOOM_SIZE

    # Hash the whole string with multiple seeds
    for seed in range(NUM_HASHES):
        idx = _hash_index(value, seed)
        bits[idx] = 1

    # Also hash individual characters for richer signal
    for i, ch in enumerate(value):
        for seed in range(2):
            idx = _hash_index(ch, seed * 31 + i)
            bits[idx] = 1

    return bits


def permanent_rr(bloom_bits: list[int], f: float) -> list[int]:
    """
    Permanent Randomised Response (PRR) — Step 1.

    Each bit b_i:
        with prob f/2  → flip to 1  (noise)
        with prob f/2  → flip to 0  (noise)
        with prob 1-f  → keep original value

    The PRR is meant to be stored permanently and reused across
    multiple reports, binding the noise to the user's identity
    without revealing the true value.
    """
    prr = []
    for b in bloom_bits:
        r = random.random()
        if r < f / 2:
            prr.append(1)
        elif r < f:
            prr.append(0)
        else:
            prr.append(b)
    return prr


def instantaneous_rr(prr_bits: list[int], p: float, q: float) -> list[int]:
    """
    Instantaneous Randomised Response (IRR) — Step 2.

    Each bit b_i of the PRR:
        if b_i == 1  →  report 1 with prob q, else 0
        if b_i == 0  →  report 1 with prob p, else 0

    This adds a second layer of noise so the server cannot even
    infer the PRR from repeated observations.
    """
    irr = []
    for b in prr_bits:
        r = random.random()
        if b == 1:
            irr.append(1 if r < q else 0)
        else:
            irr.append(1 if r < p else 0)
    return irr


def rappor(value: str, f: float, p: float, q: float) -> dict:
    """Full RAPPOR pipeline. Returns encoded bits and hex string."""
    bloom = bloom_encode(value)
    prr   = permanent_rr(bloom, f)
    irr   = instantaneous_rr(prr, p, q)
    return {
        "bits": irr,
        "hex":  bits_to_hex(irr),
        "ones": sum(irr),   # number of set bits (for diagnostics)
    }


def bits_to_hex(bits: list[int]) -> str:
    """Pack a bit list into a hex string (MSB first)."""
    hex_str = ""
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits):
                byte |= (bits[i + j] << (7 - j))
        hex_str += format(byte, "02X")
    return hex_str


def estimate_epsilon(f: float, p: float, q: float) -> str:
    """
    Estimate the per-bit privacy budget ε using the RAPPOR formula:
        ε ≈ 2 · ln( q*(1-p) / (p*(1-q)) )  (after combining PRR & IRR)
    """
    try:
        p_star = (1 - f / 2) * p + (f / 2) * (1 - q)
        q_star = (1 - f / 2) * q + (f / 2) * (1 - p)
        if q_star <= p_star or p_star <= 0 or q_star >= 1:
            return "∞"
        eps = 2 * math.log(q_star * (1 - p_star) / (p_star * (1 - q_star)))
        return f"{eps:.4f}"
    except (ValueError, ZeroDivisionError):
        return "∞"


# ──────────────────────────────────────────────────────────────
# Logger
# ──────────────────────────────────────────────────────────────

class RAPPORLogger:
    """Logs customer names after applying RAPPOR privatisation."""

    def __init__(self, f: float = 0.5, p: float = 0.75, q: float = 0.5,
                 log_file: str = "rappor_log.jsonl"):
        assert 0 <= f <= 1, "f must be in [0, 1]"
        assert 0 <= p <= 1, "p must be in [0, 1]"
        assert 0 <= q <= 1, "q must be in [0, 1]"

        self.f = f
        self.p = p
        self.q = q
        self.log_file = log_file
        self._counter = self._load_counter()

    def _load_counter(self) -> int:
        """Count existing entries to continue ID sequence."""
        if not os.path.exists(self.log_file):
            return 0
        with open(self.log_file) as fh:
            return sum(1 for _ in fh)

    def log(self, first_name: str, last_name: str) -> dict:
        """Apply RAPPOR to both names and append to the log file."""
        self._counter += 1
        entry = {
            "id":         self._counter,
            "timestamp":  datetime.now().isoformat(timespec="seconds"),
            "params":     {"f": self.f, "p": self.p, "q": self.q,
                           "epsilon": estimate_epsilon(self.f, self.p, self.q)},
            "first_name": rappor(first_name, self.f, self.p, self.q)["hex"],
            "last_name":  rappor(last_name,  self.f, self.p, self.q)["hex"],
        }

        with open(self.log_file, "a") as fh:
            fh.write(json.dumps(entry) + "\n")

        return entry

    def show_log(self, n: int = 20) -> None:
        """Pretty-print the last n entries."""
        if not os.path.exists(self.log_file):
            print("  (log is empty)")
            return

        with open(self.log_file) as fh:
            lines = fh.readlines()

        recent = lines[-n:]
        for line in recent:
            e = json.loads(line)
            print(f"  #{e['id']:04d}  {e['timestamp']}  "
                  f"ε≈{e['params']['epsilon']}")
            print(f"         FIRST → {e['first_name']}")
            print(f"         LAST  → {e['last_name']}")
            print()

    def clear_log(self) -> None:
        """Delete the log file."""
        if os.path.exists(self.log_file):
            os.remove(self.log_file)
            self._counter = 0
            print("  Log cleared.")
        else:
            print("  Nothing to clear.")


# ──────────────────────────────────────────────────────────────
# Interactive CLI
# ──────────────────────────────────────────────────────────────

BANNER = r"""
  ██████╗  █████╗ ██████╗ ██████╗  ██████╗ ██████╗
  ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔═══██╗██╔══██╗
  ██████╔╝███████║██████╔╝██████╔╝██║   ██║██████╔╝
  ██╔══██╗██╔══██║██╔═══╝ ██╔═══╝ ██║   ██║██╔══██╗
  ██║  ██║██║  ██║██║     ██║     ╚██████╔╝██║  ██║
  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝      ╚═════╝ ╚═╝  ╚═╝
  Customer Logger — Privacy-Preserving via RAPPOR
"""

MENU = """
  [1] Log a customer
  [2] View recent entries
  [3] Change RAPPOR parameters
  [4] Clear log
  [q] Quit
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="RAPPOR Customer Logger")
    parser.add_argument("--f",    type=float, default=0.5,
                        help="Permanent noise probability (default 0.5)")
    parser.add_argument("--p",    type=float, default=0.75,
                        help="False-positive rate for IRR (default 0.75)")
    parser.add_argument("--q",    type=float, default=0.5,
                        help="True-positive rate for IRR (default 0.5)")
    parser.add_argument("--log",  type=str,   default="rappor_log.jsonl",
                        help="Output log file (default rappor_log.jsonl)")
    return parser.parse_args()


def prompt(msg: str) -> str:
    try:
        return input(msg).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)


def main() -> None:
    args = parse_args()
    logger = RAPPORLogger(f=args.f, p=args.p, q=args.q, log_file=args.log)

    print(BANNER)
    print(f"  Parameters: f={logger.f}  p={logger.p}  q={logger.q}")
    print(f"  Estimated ε (privacy budget): "
          f"{estimate_epsilon(logger.f, logger.p, logger.q)}")
    print(f"  Log file: {os.path.abspath(logger.log_file)}\n")

    while True:
        print(MENU)
        choice = prompt("  > ").lower()

        if choice == "1":
            first = prompt("  First name: ")
            last  = prompt("  Last name : ")
            if not first or not last:
                print("  ✗ Both names are required.\n")
                continue
            entry = logger.log(first, last)
            print(f"\n  ✓ Logged #{entry['id']:04d}")
            print(f"    FIRST  (encoded) → {entry['first_name']}")
            print(f"    LAST   (encoded) → {entry['last_name']}")
            print(f"    ε ≈ {entry['params']['epsilon']}\n")

        elif choice == "2":
            n_str = prompt("  How many entries to show? [20] ") or "20"
            try:
                n = int(n_str)
            except ValueError:
                n = 20
            print()
            logger.show_log(n)

        elif choice == "3":
            print(f"\n  Current: f={logger.f}  p={logger.p}  q={logger.q}")
            try:
                f = float(prompt("  New f (0–1): ") or logger.f)
                p = float(prompt("  New p (0–1): ") or logger.p)
                q = float(prompt("  New q (0–1): ") or logger.q)
                logger.f = max(0.0, min(1.0, f))
                logger.p = max(0.0, min(1.0, p))
                logger.q = max(0.0, min(1.0, q))
                print(f"  ✓ Updated. ε ≈ {estimate_epsilon(logger.f, logger.p, logger.q)}\n")
            except ValueError:
                print("  ✗ Invalid input — parameters unchanged.\n")

        elif choice == "4":
            confirm = prompt("  Delete all log entries? (yes/no): ").lower()
            if confirm == "yes":
                logger.clear_log()
            else:
                print("  Cancelled.\n")

        elif choice in ("q", "quit", "exit"):
            print("  Goodbye.\n")
            sys.exit(0)

        else:
            print("  Unknown option.\n")


if __name__ == "__main__":
    main()

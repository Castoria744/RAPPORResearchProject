"""
Updated Email, DOB, Address
"""
import argparse
import hashlib
import json
import math
import os
import re
import random
import sys
from datetime import datetime

# RAPPOR Core
import re
BLOOM_SIZE = 128   # number of bits in the Bloom filter
NUM_HASHES = 4     # hash functions per value


def _hash_index(value: str, seed: int) -> int:
    """Return a Bloom filter index for (value, seed)."""
    raw = f"{seed}:{value.lower()}".encode()
    digest = hashlib.sha256(raw).digest()
    return (digest[0] << 8 | digest[1]) % BLOOM_SIZE


def bloom_encode(value: str) -> list[int]:
    """Encode a string into a BLOOM_SIZE-bit Bloom filter."""
    bits = [0] * BLOOM_SIZE

    for seed in range(NUM_HASHES):
        idx = _hash_index(value, seed)
        bits[idx] = 1

    for i, ch in enumerate(value):
        for seed in range(2):
            idx = _hash_index(ch, seed * 31 + i)
            bits[idx] = 1

    return bits


def permanent_rr(bloom_bits: list[int], f: float) -> list[int]:
    """
    Permanent Randomised Response (PRR) — Step 1.

    Each bit b_i:
        with prob f/2  -> flip to 1  (noise)
        with prob f/2  -> flip to 0  (noise)
        with prob 1-f  -> keep original value
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
        if b_i == 1  ->  report 1 with prob q, else 0
        if b_i == 0  ->  report 1 with prob p, else 0
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
    Estimate the per-bit privacy budget epsilon:
        epsilon ~= 2 * ln( q*(1-p) / (p*(1-q)) )
    """
    try:
        p_star = (1 - f / 2) * p + (f / 2) * (1 - q)
        q_star = (1 - f / 2) * q + (f / 2) * (1 - p)
        if q_star <= p_star or p_star <= 0 or q_star >= 1:
            return "inf"
        eps = 2 * math.log(q_star * (1 - p_star) / (p_star * (1 - q_star)))
        return f"{eps:.4f}"
    except (ValueError, ZeroDivisionError):
        return "inf"


# Validation helpers

def validate_email(email: str) -> bool:
    """Basic email format check."""
    pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    return bool(re.match(pattern, email))


def validate_dob(dob: str) -> bool:
    """Expect YYYY-MM-DD format and a sensible year range."""
    try:
        dt = datetime.strptime(dob, "%Y-%m-%d")
        return 1900 <= dt.year <= datetime.now().year
    except ValueError:
        return False

# Logger

class RAPPORLogger:
    """Logs customer details after applying RAPPOR privatisation."""

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
        if not os.path.exists(self.log_file):
            return 0
        with open(self.log_file) as fh:
            return sum(1 for _ in fh)

    def _encode(self, value: str) -> str:
        return rappor(value, self.f, self.p, self.q)["hex"]

    def log(self, first_name: str, last_name: str,
            email: str, dob: str, address: str) -> dict:
        """Apply RAPPOR to all fields and append to the log file."""
        self._counter += 1
        entry = {
            "id":         self._counter,
            "timestamp":  datetime.now().isoformat(timespec="seconds"),
            "params": {
                "f": self.f, "p": self.p, "q": self.q,
                "epsilon": estimate_epsilon(self.f, self.p, self.q),
            },
            "first_name": self._encode(first_name),
            "last_name":  self._encode(last_name),
            "email":      self._encode(email),
            "dob":        self._encode(dob),
            "address":    self._encode(address),
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
            sep = "  " + "-" * 62
            print(sep)
            print(f"  #{e['id']:04d}  {e['timestamp']}  "
                  f"epsilon={e['params']['epsilon']}  "
                  f"f={e['params']['f']} p={e['params']['p']} q={e['params']['q']}")
            print(sep)
            print(f"  FIRST_NAME → {e['first_name']}")
            print(f"  LAST_NAME  → {e['last_name']}")
            print(f"  EMAIL      → {e['email']}")
            print(f"  DOB        → {e['dob']}")
            print(f"  ADDRESS    → {e['address']}")
            print()

    def clear_log(self) -> None:
        if os.path.exists(self.log_file):
            os.remove(self.log_file)
            self._counter = 0
            print("  Log cleared.")
        else:
            print("  Nothing to clear.")


# Interactive CLI

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
    parser.add_argument("--f",   type=float, default=0.5,
                        help="Permanent noise probability (default 0.5)")
    parser.add_argument("--p",   type=float, default=0.75,
                        help="False-positive rate for IRR (default 0.75)")
    parser.add_argument("--q",   type=float, default=0.5,
                        help="True-positive rate for IRR (default 0.5)")
    parser.add_argument("--log", type=str,   default="rappor_log.jsonl",
                        help="Output log file (default rappor_log.jsonl)")
    return parser.parse_args()


def prompt(msg: str) -> str:
    try:
        return input(msg).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)


def collect_customer() -> dict | None:
    """Interactively collect and validate all customer fields."""
    print()

    first = prompt("  First name     : ")
    if not first:
        print("  ✗ First name is required.\n")
        return None

    last = prompt("  Last name      : ")
    if not last:
        print("  ✗ Last name is required.\n")
        return None

    email = prompt("  Email          : ")
    if not validate_email(email):
        print("  ✗ Invalid email — expected format: user@domain.com\n")
        return None

    dob = prompt("  Date of birth  : (YYYY-MM-DD) ")
    if not validate_dob(dob):
        print("  ✗ Invalid date — use YYYY-MM-DD, e.g. 1990-07-23\n")
        return None

    address = prompt("  Street address : ")
    if not address:
        print("  ✗ Address is required.\n")
        return None

    return dict(first_name=first, last_name=last,
                email=email, dob=dob, address=address)


def main() -> None:
    args = parse_args()
    logger = RAPPORLogger(f=args.f, p=args.p, q=args.q, log_file=args.log)

    print(BANNER)
    print(f"  Parameters : f={logger.f}  p={logger.p}  q={logger.q}")
    print(f"  Privacy    : epsilon ~= {estimate_epsilon(logger.f, logger.p, logger.q)}")
    print(f"  Log file   : {os.path.abspath(logger.log_file)}\n")

    while True:
        print(MENU)
        choice = prompt("  > ").lower()

        if choice == "1":
            data = collect_customer()
            if data is None:
                continue

            entry = logger.log(**data)
            sep = "  " + "-" * 62
            print(f"\n  Logged entry #{entry['id']:04d}")
            print(sep)
            print(f"  FIRST_NAME → {entry['first_name']}")
            print(f"  LAST_NAME  → {entry['last_name']}")
            print(f"  EMAIL      → {entry['email']}")
            print(f"  DOB        → {entry['dob']}")
            print(f"  ADDRESS    → {entry['address']}")
            print(f"  epsilon    ~= {entry['params']['epsilon']}\n")

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
                f = float(prompt("  New f (0-1): ") or logger.f)
                p = float(prompt("  New p (0-1): ") or logger.p)
                q = float(prompt("  New q (0-1): ") or logger.q)
                logger.f = max(0.0, min(1.0, f))
                logger.p = max(0.0, min(1.0, p))
                logger.q = max(0.0, min(1.0, q))
                print(f"  Updated. epsilon ~= "
                      f"{estimate_epsilon(logger.f, logger.p, logger.q)}\n")
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

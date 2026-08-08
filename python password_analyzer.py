#!/usr/bin/env python3
"""
Password Security Analyzer
---------------------------
Checks a password's strength using:
  - Length and character variety
  - Entropy estimation
  - Common password / dictionary word detection
  - Pattern detection (sequences, repeats, keyboard walks)
  - Estimated crack time

Usage:
    python password_analyzer.py
    python password_analyzer.py --password "MyP@ssw0rd"
"""

import re
import math
import argparse
import getpass

# A small sample of very common passwords.
# For real-world use, load a full list (e.g. rockyou.txt or the
# "10k-most-common" list) from a file instead of this tiny sample.
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345",
    "qwerty", "abc123", "111111", "123123", "letmein",
    "welcome", "admin", "iloveyou", "password1", "monkey",
    "dragon", "football", "trustno1", "1234567890", "qwertyuiop",
}

KEYBOARD_ROWS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
]


def build_keyboard_sequences(min_len=4):
    """Generate forward/backward substrings of keyboard rows to detect walks."""
    sequences = set()
    for row in KEYBOARD_ROWS:
        for length in range(min_len, len(row) + 1):
            for i in range(len(row) - length + 1):
                chunk = row[i:i + length]
                sequences.add(chunk)
                sequences.add(chunk[::-1])
    return sequences


KEYBOARD_SEQUENCES = build_keyboard_sequences()


def has_sequential_chars(password, run_length=4):
    """Detect ascending/descending sequences like '1234' or 'abcd'."""
    lowered = password.lower()
    for i in range(len(lowered) - run_length + 1):
        chunk = lowered[i:i + run_length]
        codes = [ord(c) for c in chunk]
        ascending = all(codes[j] + 1 == codes[j + 1] for j in range(len(codes) - 1))
        descending = all(codes[j] - 1 == codes[j + 1] for j in range(len(codes) - 1))
        if ascending or descending:
            return True
    return False


def has_repeated_chars(password, run_length=3):
    """Detect repeated characters like 'aaa' or '111'."""
    for i in range(len(password) - run_length + 1):
        if len(set(password[i:i + run_length])) == 1:
            return True
    return False


def has_keyboard_walk(password, min_len=4):
    lowered = password.lower()
    for i in range(len(lowered) - min_len + 1):
        if lowered[i:i + min_len] in KEYBOARD_SEQUENCES:
            return True
    return False


def character_pool_size(password):
    """Estimate the size of the character set used, for entropy calc."""
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32  # rough estimate for common symbols
    return pool or 1


def calculate_entropy(password):
    """Shannon-style entropy estimate: length * log2(pool size)."""
    pool = character_pool_size(password)
    return len(password) * math.log2(pool)


def estimate_crack_time(entropy_bits, guesses_per_second=1e10):
    """
    Rough offline brute-force estimate assuming a fast attacker
    (1e10 guesses/sec is typical for GPU cracking of weak hashes).
    Returns a human-readable string.
    """
    total_guesses = 2 ** entropy_bits
    seconds = total_guesses / guesses_per_second

    if seconds < 1:
        return "instantly"
    intervals = (
        ("years", 60 * 60 * 24 * 365),
        ("days", 60 * 60 * 24),
        ("hours", 60 * 60),
        ("minutes", 60),
        ("seconds", 1),
    )
    for name, count in intervals:
        value = seconds / count
        if value >= 1:
            if value > 1e6:
                return f"{value:.2e} {name}"
            return f"{value:.1f} {name}"
    return "instantly"


def analyze_password(password):
    issues = []
    score = 0
    max_score = 100

    length = len(password)

    # --- Length checks ---
    if length < 8:
        issues.append("Too short — use at least 8 characters (12+ recommended).")
    elif length < 12:
        score += 15
        issues.append("Decent length, but 12+ characters is stronger.")
    else:
        score += 25

    # --- Character variety ---
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))
    variety_count = sum([has_lower, has_upper, has_digit, has_symbol])

    score += variety_count * 10  # up to 40 points

    if not has_upper:
        issues.append("Add uppercase letters.")
    if not has_lower:
        issues.append("Add lowercase letters.")
    if not has_digit:
        issues.append("Add numbers.")
    if not has_symbol:
        issues.append("Add symbols (e.g. ! @ # $ %).")

    # --- Common password check ---
    if password.lower() in COMMON_PASSWORDS:
        issues.append("This is one of the most common passwords in the world — change it immediately.")
        score = min(score, 5)

    # --- Pattern checks ---
    if has_repeated_chars(password):
        issues.append("Avoid repeated characters (e.g. 'aaa', '111').")
        score -= 10
    if has_sequential_chars(password):
        issues.append("Avoid sequential characters (e.g. 'abcd', '1234').")
        score -= 10
    if has_keyboard_walk(password):
        issues.append("Avoid keyboard patterns (e.g. 'qwerty', 'asdf').")
        score -= 10

    score = max(0, min(score, max_score))

    entropy = calculate_entropy(password)
    crack_time = estimate_crack_time(entropy)

    if score >= 80:
        rating = "Very Strong"
    elif score >= 60:
        rating = "Strong"
    elif score >= 40:
        rating = "Medium"
    elif score >= 20:
        rating = "Weak"
    else:
        rating = "Very Weak"

    if not issues:
        issues.append("No major issues found. Nice password!")

    return {
        "score": score,
        "rating": rating,
        "entropy_bits": round(entropy, 1),
        "estimated_crack_time": crack_time,
        "issues": issues,
    }


def print_report(password, result):
    print("\n" + "=" * 50)
    print(" PASSWORD SECURITY REPORT")
    print("=" * 50)
    print(f"Length:            {len(password)} characters")
    print(f"Entropy:           {result['entropy_bits']} bits")
    print(f"Estimated crack time (fast GPU attack): {result['estimated_crack_time']}")
    print(f"Score:             {result['score']}/100")
    print(f"Rating:            {result['rating']}")
    print("-" * 50)
    print("Feedback:")
    for issue in result["issues"]:
        print(f"  • {issue}")
    print("=" * 50 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze password strength and security."
    )
    parser.add_argument(
        "--password",
        "-p",
        help="Password to analyze."
    )
    args = parser.parse_args()

    # If a password was provided through the command line,
    # analyze it once.
    if args.password:
        result = analyze_password(args.password)
        print_report(args.password, result)
        return

    # Otherwise, keep asking for passwords.
    while True:
        password = input(
            "\nEnter password to analyze (type 'exit' to quit): "
        )

        if password.lower() == "exit":
            print("Exiting Password Security Analyzer.")
            break

        if not password:
            print("No password entered. Please try again.")
            continue

        result = analyze_password(password)
        print_report(password, result)


if __name__ == "__main__":
    main()
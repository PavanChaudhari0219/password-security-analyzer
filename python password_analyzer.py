import re
import math
import argparse
import msvcrt
import time


# =========================================================
# COMMON PASSWORDS
# =========================================================

COMMON_PASSWORDS = {
    "123456",
    "password",
    "123456789",
    "12345678",
    "12345",
    "qwerty",
    "abc123",
    "111111",
    "123123",
    "letmein",
    "welcome",
    "admin",
    "iloveyou",
    "password1",
    "monkey",
    "dragon",
    "football",
    "trustno1",
    "1234567890",
    "qwertyuiop",
}


# =========================================================
# KEYBOARD PATTERNS
# =========================================================

KEYBOARD_ROWS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
]


def build_keyboard_sequences(min_len=4):
    """Generate keyboard sequences in both directions."""

    sequences = set()

    for row in KEYBOARD_ROWS:

        for length in range(min_len, len(row) + 1):

            for i in range(len(row) - length + 1):

                chunk = row[i:i + length]

                sequences.add(chunk)
                sequences.add(chunk[::-1])

    return sequences


KEYBOARD_SEQUENCES = build_keyboard_sequences()


# =========================================================
# SEQUENTIAL CHARACTER CHECK
# =========================================================

def has_sequential_chars(password, run_length=4):
    """
    Detect sequences such as:
    1234
    abcd
    dcba
    4321
    """

    lowered = password.lower()

    for i in range(len(lowered) - run_length + 1):

        chunk = lowered[i:i + run_length]

        codes = [ord(c) for c in chunk]

        ascending = all(
            codes[j] + 1 == codes[j + 1]
            for j in range(len(codes) - 1)
        )

        descending = all(
            codes[j] - 1 == codes[j + 1]
            for j in range(len(codes) - 1)
        )

        if ascending or descending:
            return True

    return False


# =========================================================
# REPEATED CHARACTER CHECK
# =========================================================

def has_repeated_chars(password, run_length=3):
    """
    Detect repeated characters such as:
    aaa
    111
    $$$
    """

    for i in range(len(password) - run_length + 1):

        if len(set(password[i:i + run_length])) == 1:
            return True

    return False


# =========================================================
# KEYBOARD WALK CHECK
# =========================================================

def has_keyboard_walk(password, min_len=4):
    """
    Detect keyboard patterns such as:
    qwerty
    asdf
    1234
    """

    lowered = password.lower()

    for i in range(len(lowered) - min_len + 1):

        if lowered[i:i + min_len] in KEYBOARD_SEQUENCES:
            return True

    return False


# =========================================================
# CHARACTER POOL
# =========================================================

def character_pool_size(password):
    """
    Estimate the number of possible characters
    used by the password.
    """

    pool = 0

    if re.search(r"[a-z]", password):
        pool += 26

    if re.search(r"[A-Z]", password):
        pool += 26

    if re.search(r"[0-9]", password):
        pool += 10

    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32

    return pool or 1


# =========================================================
# ENTROPY
# =========================================================

def calculate_entropy(password):
    """
    Calculate an estimated password entropy.
    """

    pool = character_pool_size(password)

    return len(password) * math.log2(pool)


# =========================================================
# CRACK TIME
# =========================================================

def estimate_crack_time(entropy_bits, guesses_per_second=1e10):
    """
    Rough offline brute-force estimate.

    This is only an estimate and does not represent
    every real-world password attack.
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


# =========================================================
# PASSWORD ANALYZER
# =========================================================

def analyze_password(password):

    issues = []

    score = 0

    max_score = 100

    length = len(password)

    # -----------------------------------------------------
    # LENGTH
    # -----------------------------------------------------

    if length < 8:

        issues.append(
            "Too short — use at least 8 characters (12+ recommended)."
        )

    elif length < 12:

        score += 15

        issues.append(
            "Decent length, but 12+ characters is stronger."
        )

    else:

        score += 25

    # -----------------------------------------------------
    # CHARACTER VARIETY
    # -----------------------------------------------------

    has_lower = bool(
        re.search(r"[a-z]", password)
    )

    has_upper = bool(
        re.search(r"[A-Z]", password)
    )

    has_digit = bool(
        re.search(r"[0-9]", password)
    )

    has_symbol = bool(
        re.search(r"[^a-zA-Z0-9]", password)
    )

    variety_count = sum(
        [
            has_lower,
            has_upper,
            has_digit,
            has_symbol
        ]
    )

    score += variety_count * 10

    if not has_upper:

        issues.append(
            "Add uppercase letters."
        )

    if not has_lower:

        issues.append(
            "Add lowercase letters."
        )

    if not has_digit:

        issues.append(
            "Add numbers."
        )

    if not has_symbol:

        issues.append(
            "Add symbols (e.g. ! @ # $ %)."
        )

    # -----------------------------------------------------
    # COMMON PASSWORD
    # -----------------------------------------------------

    if password.lower() in COMMON_PASSWORDS:

        issues.append(
            "This is a very common password — change it immediately."
        )

        score = min(score, 5)

    # -----------------------------------------------------
    # REPEATED CHARACTERS
    # -----------------------------------------------------

    if has_repeated_chars(password):

        issues.append(
            "Avoid repeated characters (e.g. 'aaa', '111')."
        )

        score -= 10

    # -----------------------------------------------------
    # SEQUENTIAL CHARACTERS
    # -----------------------------------------------------

    if has_sequential_chars(password):

        issues.append(
            "Avoid sequential characters (e.g. 'abcd', '1234')."
        )

        score -= 10

    # -----------------------------------------------------
    # KEYBOARD PATTERNS
    # -----------------------------------------------------

    if has_keyboard_walk(password):

        issues.append(
            "Avoid keyboard patterns (e.g. 'qwerty', 'asdf')."
        )

        score -= 10

    # -----------------------------------------------------
    # KEEP SCORE BETWEEN 0 AND 100
    # -----------------------------------------------------

    score = max(
        0,
        min(score, max_score)
    )

    # -----------------------------------------------------
    # ENTROPY
    # -----------------------------------------------------

    entropy = calculate_entropy(password)

    # -----------------------------------------------------
    # CRACK TIME
    # -----------------------------------------------------

    crack_time = estimate_crack_time(entropy)

    # -----------------------------------------------------
    # RATING
    # -----------------------------------------------------

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

    # -----------------------------------------------------
    # NO ISSUES
    # -----------------------------------------------------

    if not issues:

        issues.append(
            "No major issues found. Nice password!"
        )

    return {
        "score": score,
        "rating": rating,
        "entropy_bits": round(entropy, 1),
        "estimated_crack_time": crack_time,
        "issues": issues,
    }


# =========================================================
# PRINT REPORT
# =========================================================

def print_report(password, result):

    print()

    print("=" * 55)

    print("              PASSWORD SECURITY REPORT")

    print("=" * 55)

    print(
        f"Length:            {len(password)} characters"
    )

    print(
        f"Entropy:           {result['entropy_bits']} bits"
    )

    print(
        f"Estimated crack time: "
        f"{result['estimated_crack_time']}"
    )

    print(
        f"Score:             {result['score']}/100"
    )

    print(
        f"Rating:            {result['rating']}"
    )

    print("-" * 55)

    print("Feedback:")

    for issue in result["issues"]:

        print(
            f"  • {issue}"
        )

    print("=" * 55)

    print()


# =========================================================
# PASSWORD INPUT WITH TEMPORARY CHARACTER VISIBILITY
# =========================================================

def masked_input(
    prompt="Enter password: ",
    delay=0.3
):
    """
    Reads a password from the Windows console.

    Each character is briefly visible and then
    replaced with an asterisk.
    """

    print(
        prompt,
        end="",
        flush=True
    )

    password = ""

    while True:

        char = msvcrt.getwch()

        # -------------------------------------------------
        # ENTER
        # -------------------------------------------------

        if char in ("\r", "\n"):

            print()

            break

        # -------------------------------------------------
        # BACKSPACE
        # -------------------------------------------------

        elif char == "\b":

            if password:

                password = password[:-1]

                print(
                    "\b \b",
                    end="",
                    flush=True
                )

        # -------------------------------------------------
        # SPECIAL KEYS
        # -------------------------------------------------

        elif char in ("\x00", "\xe0"):

            msvcrt.getwch()

        # -------------------------------------------------
        # NORMAL CHARACTER
        # -------------------------------------------------

        else:

            password += char

            # Show character
            print(
                char,
                end="",
                flush=True
            )

            # Keep character visible briefly
            time.sleep(delay)

            # Replace character with *
            print(
                "\b*",
                end="",
                flush=True
            )

    return password


# =========================================================
# MAIN PROGRAM
# =========================================================

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

    # -----------------------------------------------------
    # COMMAND-LINE PASSWORD
    # -----------------------------------------------------

    if args.password:

        result = analyze_password(
            args.password
        )

        print_report(
            args.password,
            result
        )

        return

    # -----------------------------------------------------
    # CONTINUOUS PASSWORD ANALYSIS
    # -----------------------------------------------------

    while True:

        password = masked_input(
            "\nEnter password to analyze "
            "(type 'exit' to quit): "
        )

        # -------------------------------------------------
        # EXIT
        # -------------------------------------------------

        if password.lower() == "exit":

            print(
                "\nExiting Password Security Analyzer."
            )

            break

        # -------------------------------------------------
        # EMPTY PASSWORD
        # -------------------------------------------------

        if not password:

            print(
                "\nNo password entered. Please try again."
            )

            continue

        # -------------------------------------------------
        # ANALYZE
        # -------------------------------------------------

        result = analyze_password(
            password
        )

        print_report(
            password,
            result
        )


# =========================================================
# START PROGRAM
# =========================================================

if __name__ == "__main__":

    main()
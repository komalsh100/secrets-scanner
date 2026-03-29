"""
Shannon entropy analysis for detecting high-entropy strings
that may represent secrets, keys, or tokens.
"""

import math
import re
from typing import List, Tuple

# Character sets for entropy analysis
BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "1234567890abcdefABCDEF"

# Thresholds
ENTROPY_THRESHOLD_BASE64 = 4.5
ENTROPY_THRESHOLD_HEX = 3.0
MIN_STRING_LENGTH = 20
MAX_STRING_LENGTH = 200


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    freq = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    for count in freq.values():
        probability = count / len(data)
        entropy -= probability * math.log2(probability)
    return entropy


def get_strings_of_set(word: str, charset: str) -> List[str]:
    """Extract contiguous substrings consisting only of chars in charset."""
    count = 0
    letters = ""
    strings = []
    for char in word:
        if char in charset:
            letters += char
            count += 1
        else:
            if count > MIN_STRING_LENGTH:
                strings.append(letters)
            letters = ""
            count = 0
    if count > MIN_STRING_LENGTH:
        strings.append(letters)
    return strings


def find_high_entropy_strings(line: str, line_number: int, file_path: str) -> List[dict]:
    """Find high-entropy strings in a line that may be secrets."""
    findings = []

    # Skip comment lines
    stripped = line.strip()
    if stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('*'):
        return findings

    words = line.split()
    for word in words:
        # Skip short or very long words
        if len(word) < MIN_STRING_LENGTH or len(word) > MAX_STRING_LENGTH:
            continue

        # Check base64 entropy
        for b64_string in get_strings_of_set(word, BASE64_CHARS):
            entropy = shannon_entropy(b64_string)
            if entropy > ENTROPY_THRESHOLD_BASE64:
                findings.append({
                    "type": "entropy",
                    "name": "High Entropy String (Base64)",
                    "severity": "HIGH",
                    "description": f"High-entropy base64-like string detected (entropy: {entropy:.2f})",
                    "file": file_path,
                    "line": line_number,
                    "match": b64_string[:50] + "..." if len(b64_string) > 50 else b64_string,
                    "entropy": round(entropy, 2)
                })

        # Check hex entropy
        for hex_string in get_strings_of_set(word, HEX_CHARS):
            entropy = shannon_entropy(hex_string)
            if entropy > ENTROPY_THRESHOLD_HEX:
                findings.append({
                    "type": "entropy",
                    "name": "High Entropy String (Hex)",
                    "severity": "HIGH",
                    "description": f"High-entropy hex string detected (entropy: {entropy:.2f})",
                    "file": file_path,
                    "line": line_number,
                    "match": hex_string[:50] + "..." if len(hex_string) > 50 else hex_string,
                    "entropy": round(entropy, 2)
                })

    return findings

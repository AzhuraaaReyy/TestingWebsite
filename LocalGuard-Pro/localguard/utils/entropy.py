"""Shannon entropy calculation for secret detection."""

import math
from collections import Counter


def shannon_entropy(data: str | bytes) -> float:
    """
    Calculate Shannon entropy of a string or bytes.

    Higher entropy indicates more randomness, typical of secrets/keys.
    Typical thresholds:
    - < 3.0: Low entropy (likely not a secret)
    - 3.0 - 4.5: Medium entropy (possible secret)
    - > 4.5: High entropy (likely a secret/key)

    Args:
        data: Input string or bytes

    Returns:
        Shannon entropy value (bits per character)
    """
    if not data:
        return 0.0

    if isinstance(data, str):
        data = data.encode("utf-8")

    # Count byte frequencies
    counter = Counter(data)
    length = len(data)

    # Calculate entropy
    entropy = 0.0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def normalized_entropy(data: str | bytes) -> float:
    """
    Calculate normalized entropy (0.0 to 1.0).

    Normalized by maximum possible entropy for the alphabet size.
    """
    if not data:
        return 0.0

    if isinstance(data, str):
        data = data.encode("utf-8")

    counter = Counter(data)
    length = len(data)
    alphabet_size = len(counter)

    if alphabet_size <= 1:
        return 0.0

    # Calculate actual entropy
    entropy = 0.0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    # Maximum possible entropy for this alphabet
    max_entropy = math.log2(alphabet_size)

    return entropy / max_entropy if max_entropy > 0 else 0.0


def is_high_entropy(data: str | bytes, threshold: float = 4.5) -> bool:
    """
    Check if data has high entropy (likely a secret).

    Args:
        data: Input string or bytes
        threshold: Entropy threshold (default 4.5 bits/char)

    Returns:
        True if entropy exceeds threshold
    """
    return shannon_entropy(data) >= threshold


def analyze_string_entropy(
    text: str, window_size: int = 20, step: int = 1
) -> list[tuple[int, float]]:
    """
    Analyze entropy in sliding windows across a string.

    Useful for finding high-entropy substrings within larger text.

    Args:
        text: Input text
        window_size: Size of sliding window
        step: Step size for sliding window

    Returns:
        List of (position, entropy) tuples
    """
    results = []
    for i in range(0, len(text) - window_size + 1, step):
        window = text[i : i + window_size]
        entropy = shannon_entropy(window)
        results.append((i, entropy))
    return results


def find_high_entropy_substrings(
    text: str, min_length: int = 20, threshold: float = 4.5
) -> list[tuple[str, float, int]]:
    """
    Find high-entropy substrings in text.

    Args:
        text: Input text to analyze
        min_length: Minimum substring length
        threshold: Entropy threshold

    Returns:
        List of (substring, entropy, position) tuples
    """
    results = []
    for i in range(len(text) - min_length + 1):
        for length in range(min_length, min(100, len(text) - i + 1)):
            substring = text[i : i + length]
            entropy = shannon_entropy(substring)
            if entropy >= threshold:
                results.append((substring, entropy, i))
    return results

import hashlib
import re
from typing import Any, Iterable, List, Optional


class RedactionLevel:
    NONE = "none"
    PARTIAL = "partial"
    FULL = "full"


# IPv4 pattern
IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Device-like pattern (simple heuristic: words with dash + digits)
DEVICE_REGEX = re.compile(r"\b[a-zA-Z]+-\d+\b")


def _hash_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def _mask_ip(ip: str, level: str) -> str:
    if level == RedactionLevel.NONE:
        return ip

    if level == RedactionLevel.PARTIAL:
        parts = ip.split(".")
        if len(parts) == 4:
            return ".".join(parts[:3] + ["x"])
        return ip

    if level == RedactionLevel.FULL:
        return _hash_value(ip)

    return ip


def _mask_string(value: str, level: str) -> str:
    if level == RedactionLevel.NONE:
        return value

    if level == RedactionLevel.PARTIAL:
        if len(value) <= 4:
            return "****"
        return value[:2] + "****" + value[-2:]

    if level == RedactionLevel.FULL:
        return _hash_value(value)

    return value


def _normalize_secrets(secrets: Optional[Iterable[str]]) -> List[str]:
    if not secrets:
        return []
    out: List[str] = []
    for s in secrets:
        if not s:
            continue
        s = str(s).strip()
        if not s:
            continue
        out.append(s)
    # longer first to avoid partial masking of longer strings
    out.sort(key=len, reverse=True)
    return out


def _redact_known_secrets(text: str, secrets: List[str], level: str) -> str:
    """
    Replace known sensitive values inside free-form strings using whole-word matching.
    """
    if level == RedactionLevel.NONE:
        return text
    if not secrets:
        return text

    for secret in secrets:
        # Whole-word match where possible; still works for simple usernames like "ken"
        pattern = re.compile(rf"\b{re.escape(secret)}\b")
        replacement = _mask_string(secret, level)
        text = pattern.sub(replacement, text)

    return text


def _redact_string_content(text: str, level: str, secrets: List[str]) -> str:
    if level == RedactionLevel.NONE:
        return text

    # Mask IPv4 addresses
    text = IPV4_REGEX.sub(lambda m: _mask_ip(m.group(0), level), text)

    # Mask device-like identifiers
    text = DEVICE_REGEX.sub(lambda m: _mask_string(m.group(0), level), text)

    # Mask known secrets (usernames, etc.)
    text = _redact_known_secrets(text, secrets, level)

    return text


def _apply_field_rule(key: str, value: Any, level: str, secrets: List[str]) -> Any:
    if not isinstance(value, str):
        return value

    key_lower = key.lower()

    if "ip" in key_lower:
        return _mask_ip(value, level)

    if any(s in key_lower for s in ["device", "session", "token", "id"]):
        return _mask_string(value, level)

    if "user" in key_lower or "email" in key_lower:
        return _mask_string(value, level)

    # For any other string field, still apply string-aware redaction
    return _redact_string_content(value, level, secrets)


def _redact_value(value: Any, level: str, secrets: List[str]) -> Any:
    if isinstance(value, dict):
        return {
            k: _redact_value(_apply_field_rule(k, v, level, secrets), level, secrets)
            for k, v in value.items()
        }

    if isinstance(value, list):
        return [_redact_value(v, level, secrets) for v in value]

    if isinstance(value, str):
        return _redact_string_content(value, level, secrets)

    return value


def redact(data: Any, level: str, secrets: Optional[Iterable[str]] = None) -> Any:
    """
    Redact structured + string fields. Optionally pass known secrets (e.g., raw username)
    to ensure narrative/summary strings are sanitized too.
    """
    if level == RedactionLevel.NONE:
        return data

    secret_list = _normalize_secrets(secrets)
    return _redact_value(data, level, secret_list)

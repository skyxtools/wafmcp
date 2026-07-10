"""Offline tests for JWT audit."""
import base64
import hashlib
import hmac
import json as jsonlib
import time

from wafmcp.jwt_audit import analyze


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _make_hs256(payload: dict, secret: str = "secret", header_extra: dict | None = None) -> str:
    h = {"alg": "HS256", "typ": "JWT"}
    if header_extra:
        h.update(header_extra)
    hb = _b64url(jsonlib.dumps(h, separators=(",", ":")).encode())
    pb = _b64url(jsonlib.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), f"{hb}.{pb}".encode(), hashlib.sha256).digest()
    return f"{hb}.{pb}.{_b64url(sig)}"


def test_malformed_token():
    r = analyze("not-a-jwt").to_dict()
    assert not r["valid_shape"]


def test_alg_none_declared_and_forged_provided():
    tok = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhIn0."
    r = analyze(tok).to_dict()
    types = [f["type"] for f in r["findings"]]
    assert "alg_none_declared" in types
    assert r["forged_none_token"].endswith(".")
    assert any("Critical" in s or "Replay" in s for s in r["next_steps"])


def test_weak_hmac_secret_cracked():
    tok = _make_hs256({"sub": "u", "exp": int(time.time()) + 3600}, secret="secret")
    r = analyze(tok).to_dict()
    assert r["cracked_secret"] == "secret"
    assert any(f["type"] == "weak_hmac_secret" for f in r["findings"])


def test_strong_secret_not_cracked():
    tok = _make_hs256({"sub": "u", "exp": int(time.time()) + 3600},
                      secret="9F7q!bXvR2@nZ8sP_kL5%eM4tYc")
    r = analyze(tok).to_dict()
    assert r["cracked_secret"] is None


def test_no_expiry_flagged():
    tok = _make_hs256({"sub": "u"}, secret="secret")  # no exp
    r = analyze(tok).to_dict()
    assert any(f["type"] == "no_expiry" for f in r["findings"])


def test_kid_injection_surface():
    tok = _make_hs256({"sub": "u"}, secret="secret", header_extra={"kid": "../../../etc/passwd"})
    r = analyze(tok).to_dict()
    assert any(f["type"] == "kid_injection_surface" for f in r["findings"])


def test_forged_token_elevates_role():
    tok = _make_hs256({"sub": "u", "role": "user"}, secret="secret")
    r = analyze(tok).to_dict()
    forged = r["forged_none_token"]
    # decode payload of forged token
    _, payload_b64, _ = forged.split(".")
    payload_b64 += "=" * (-len(payload_b64) % 4)
    payload = jsonlib.loads(base64.urlsafe_b64decode(payload_b64))
    assert payload["role"] == "admin"

"""Offline regression tests for the PortSwigger-aligned JWT audit."""
import base64
import hashlib
import hmac
import json as jsonlib
import time

from wafmcp.jwt_audit import analyze
from wafmcp.server import analyze_jwt as analyze_jwt_tool


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _decode(value: str) -> dict:
    value += "=" * (-len(value) % 4)
    return jsonlib.loads(base64.urlsafe_b64decode(value))


def _make_token(header: dict, payload: dict, signature: bytes = b"signature") -> str:
    hb = _b64url(jsonlib.dumps(header, separators=(",", ":")).encode())
    pb = _b64url(jsonlib.dumps(payload, separators=(",", ":")).encode())
    return f"{hb}.{pb}.{_b64url(signature)}"


def _make_hs256(
    payload: dict,
    secret: str = "secret",
    header_extra: dict | None = None,
) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    if header_extra:
        header.update(header_extra)
    hb = _b64url(jsonlib.dumps(header, separators=(",", ":")).encode())
    pb = _b64url(jsonlib.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), f"{hb}.{pb}".encode(), hashlib.sha256).digest()
    return f"{hb}.{pb}.{_b64url(sig)}"


def _finding_types(result: dict) -> set[str]:
    return {item["type"] for item in result["findings"]}


def _signal_types(result: dict) -> set[str]:
    return {item["type"] for item in result["signals"]}


def test_malformed_token_is_an_error_not_a_vulnerability():
    result = analyze("not-a-jwt").to_dict()
    assert not result["valid_shape"]
    assert result["errors"]
    assert result["findings"] == []


def test_jwe_is_recognized_and_not_given_jws_mutations():
    result = analyze("a.b.c.d.e").to_dict()
    assert result["valid_shape"]
    assert result["token_kind"] == "JWE"
    assert "encrypted_jwe" in _signal_types(result)
    assert result["mutations"] == {}


def test_alg_none_is_candidate_until_server_accepts_modified_claims():
    token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhIn0."
    result = analyze(token).to_dict()
    finding = next(item for item in result["findings"] if item["type"] == "alg_none_declared")
    assert finding["status"] == "candidate"
    assert result["forged_none_token"].endswith(".")
    assert set(result["mutations"]["alg_none_tokens"]) == {"none", "None", "NONE", "nOnE"}
    assert any("server acceptance" in step.lower() for step in result["next_steps"])


def test_normal_token_does_not_report_forgery_surface_as_a_finding():
    token = _make_hs256({"sub": "user", "exp": int(time.time()) + 3600}, "strong-secret")
    result = analyze(token, wordlist=[]).to_dict()
    assert "alg_none_forgery_surface" not in _finding_types(result)
    assert "tampered_signature_token" in result["mutations"]
    assert "alg_none_tokens" in result["mutations"]
    assert result["methodology"] == "https://portswigger.net/web-security/jwt"


def test_tampered_signature_mutation_changes_claim_but_keeps_invalid_signature():
    token = _make_hs256({"sub": "user", "role": "user"}, "strong-secret")
    result = analyze(token, wordlist=[]).to_dict()
    original_parts = token.split(".")
    mutated_parts = result["mutations"]["tampered_signature_token"].split(".")
    assert mutated_parts[0] == original_parts[0]
    assert mutated_parts[2] == original_parts[2]
    assert _decode(mutated_parts[1])["role"] == "admin"


def test_claim_overrides_are_used_for_mutations():
    token = _make_hs256({"sub": "alice", "role": "user"}, "strong-secret")
    result = analyze(
        token,
        wordlist=[],
        claim_overrides={"sub": "administrator", "role": "admin"},
    ).to_dict()
    payload = _decode(result["mutations"]["tampered_signature_token"].split(".")[1])
    assert payload["sub"] == "administrator"
    assert payload["role"] == "admin"


def test_weak_hmac_secret_is_offline_confirmed_and_forge_is_valid():
    token = _make_hs256(
        {"sub": "user", "role": "user", "exp": int(time.time()) + 3600},
        secret="secret",
    )
    result = analyze(token).to_dict()
    finding = next(item for item in result["findings"] if item["type"] == "weak_hmac_secret")
    assert finding["status"] == "offline_confirmed"
    assert result["cracked_secret"] == "secret"

    forged = result["mutations"]["weak_hmac_token"]
    hb, pb, sb = forged.split(".")
    expected = hmac.new(b"secret", f"{hb}.{pb}".encode(), hashlib.sha256).digest()
    assert hmac.compare_digest(_b64url(expected), sb)
    assert _decode(pb)["role"] == "admin"


def test_strong_secret_not_cracked_with_bounded_wordlist():
    token = _make_hs256(
        {"sub": "user", "exp": int(time.time()) + 3600},
        secret="9F7q!bXvR2@nZ8sP_kL5%eM4tYc",
    )
    result = analyze(token).to_dict()
    assert result["cracked_secret"] is None
    assert "weak_hmac_secret" not in _finding_types(result)


def test_custom_wordlist_can_confirm_nondefault_weak_secret():
    token = _make_hs256({"sub": "user"}, secret="company-demo-key")
    result = analyze(token, wordlist=["wrong", "company-demo-key"]).to_dict()
    assert result["cracked_secret"] == "company-demo-key"


def test_no_expiry_is_best_practice_signal_not_auth_bypass():
    token = _make_hs256({"sub": "user"}, secret="strong-secret")
    result = analyze(token, wordlist=[]).to_dict()
    signal = next(item for item in result["signals"] if item["type"] == "no_expiry")
    assert signal["status"] == "best_practice"
    assert "no_expiry" not in _finding_types(result)


def test_kid_path_candidate_generates_dev_null_mutation():
    token = _make_hs256(
        {"sub": "user"},
        secret="strong-secret",
        header_extra={"kid": "../../../keys/current"},
    )
    result = analyze(token, wordlist=[]).to_dict()
    assert "kid_injection_candidate" in _signal_types(result)
    forged = result["mutations"]["kid_dev_null_token"]
    hb, pb, sb = forged.split(".")
    header = _decode(hb)
    assert header["kid"].endswith("/dev/null")
    assert header["alg"] == "HS256"
    expected = hmac.new(b"", f"{hb}.{pb}".encode(), hashlib.sha256).digest()
    assert hmac.compare_digest(_b64url(expected), sb)


def test_jwk_and_jku_are_surfaces_not_confirmed_findings():
    token = _make_token(
        {
            "alg": "RS256",
            "jwk": {"kty": "RSA", "n": "abc", "e": "AQAB"},
            "jku": "http://keys.attacker.example/jwks.json",
        },
        {"sub": "user"},
    )
    result = analyze(token).to_dict()
    assert {"jwk_header", "jku_header"}.issubset(_signal_types(result))
    assert all(item["status"] == "attack_surface" for item in result["signals"]
               if item["type"] in {"jwk_header", "jku_header"})
    assert "jwk_header" not in _finding_types(result)


def test_rs_to_hs_confusion_token_uses_exact_public_key_bytes():
    public_key = "-----BEGIN PUBLIC KEY-----\nTESTKEY\n-----END PUBLIC KEY-----\n"
    token = _make_token(
        {"alg": "RS256", "typ": "JWT", "kid": "key-1"},
        {"sub": "user", "role": "user"},
    )
    result = analyze(token, public_key_pem=public_key).to_dict()
    forged = result["mutations"]["algorithm_confusion_token"]
    hb, pb, sb = forged.split(".")
    assert _decode(hb)["alg"] == "HS256"
    expected = hmac.new(public_key.encode(), f"{hb}.{pb}".encode(), hashlib.sha256).digest()
    assert hmac.compare_digest(_b64url(expected), sb)
    assert _decode(pb)["role"] == "admin"
    assert "rs_hs_confusion_surface" in _signal_types(result)
    assert "rs_hs_confusion_candidate" in _signal_types(result)


def test_rsa_token_without_public_key_explains_confusion_prerequisite():
    token = _make_token({"alg": "RS256"}, {"sub": "user"})
    result = analyze(token).to_dict()
    signal = next(item for item in result["signals"]
                  if item["type"] == "rs_hs_confusion_surface")
    assert signal["status"] == "attack_surface"
    assert "algorithm_confusion_token" not in result["mutations"]


def test_duplicate_alg_header_is_a_parser_candidate():
    raw_header = b'{"alg":"RS256","alg":"HS256","typ":"JWT"}'
    token = f"{_b64url(raw_header)}.{_b64url(b'{\"sub\":\"user\"}')}.c2ln"
    result = analyze(token, wordlist=[]).to_dict()
    finding = next(
        item for item in result["findings"]
        if item["type"] == "duplicate_header_parameters"
    )
    assert finding["status"] == "candidate"
    assert "alg" in finding["detail"]


def test_invalid_base64url_is_rejected_cleanly():
    result = analyze("not+base64.eyJzdWIiOiJ1In0.sig").to_dict()
    assert not result["valid_shape"]
    assert result["errors"]


def test_invalid_exp_type_and_future_iat_are_signals():
    token = _make_hs256(
        {"sub": "user", "exp": "tomorrow", "iat": int(time.time()) + 3600},
        secret="strong-secret",
    )
    result = analyze(token, wordlist=[]).to_dict()
    assert {"invalid_exp_type", "future_iat"}.issubset(_signal_types(result))


def test_mcp_tool_accepts_custom_wordlist_and_claim_overrides():
    token = _make_hs256({"sub": "user", "role": "user"}, secret="team-demo-key")
    result = jsonlib.loads(analyze_jwt_tool(
        token,
        wordlist_json='["wrong", "team-demo-key"]',
        claim_overrides_json='{"sub":"administrator","role":"admin"}',
    ))
    assert result["cracked_secret"] == "team-demo-key"
    payload = _decode(result["mutations"]["weak_hmac_token"].split(".")[1])
    assert payload["sub"] == "administrator"
    assert payload["role"] == "admin"


def test_mcp_tool_rejects_wrong_json_container_types():
    token = _make_hs256({"sub": "user"})
    assert "JSON array" in analyze_jwt_tool(token, wordlist_json='{"secret":true}')
    assert "JSON object" in analyze_jwt_tool(token, claim_overrides_json='["admin"]')

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use codex_protocol::auth::KnownPlan;
use codex_protocol::auth::PlanType as AuthPlanType;
use jsonwebtoken::Algorithm;
use jsonwebtoken::EncodingKey;
use jsonwebtoken::Header;
use pretty_assertions::assert_eq;
use ring::rand::SystemRandom;
use ring::signature::RSA_PKCS1_2048_8192_SHA256;
use ring::signature::RSA_PKCS1_SHA256;
use ring::signature::RsaKeyPair;
use ring::signature::UnparsedPublicKey;

use crate::AGENT_IDENTITY_JWT_AUDIENCE;
use crate::AGENT_IDENTITY_JWT_ISSUER;
use crate::AgentIdentityJwtClaims;
use crate::decode_agent_identity_jwt;

/// jsonwebtoken 9.3.1 signed and verified RS256 with `ring`. Version 10 dropped
/// `ring` and requires `aws_lc_rs` or `rust_crypto`. `rust_crypto` pulls `rsa`,
/// which has no fix for RUSTSEC-2023-0071, so verification uses aws-lc-rs.
/// These tests check that RS256 tokens still cross that boundary.
#[test]
fn rs256_token_signed_with_ring_verifies_with_aws_lc() {
    let claims = sample_claims();
    let jwt = sign_rs256_with_ring(&claims_json(&claims));

    assert_eq!(
        decode_agent_identity_jwt(&jwt, Some(&test_jwks("test-key")))
            .expect("ring-signed RS256 token should verify"),
        claims
    );
}

#[test]
fn rs256_token_signed_with_aws_lc_verifies_with_ring() {
    let claims = sample_claims();
    let jwt = jsonwebtoken::encode(
        &test_header(),
        &claims_json(&claims),
        &test_rsa_encoding_key(),
    )
    .expect("aws-lc RS256 token should encode");

    verify_rs256_with_ring(&jwt);
    assert_eq!(
        decode_agent_identity_jwt(&jwt, Some(&test_jwks("test-key")))
            .expect("aws-lc RS256 token should verify"),
        claims
    );
}

fn sample_claims() -> AgentIdentityJwtClaims {
    AgentIdentityJwtClaims {
        iss: AGENT_IDENTITY_JWT_ISSUER.to_string(),
        aud: AGENT_IDENTITY_JWT_AUDIENCE.to_string(),
        iat: 1_700_000_000,
        exp: 4_000_000_000,
        agent_runtime_id: "agent-runtime-id".to_string(),
        agent_private_key: "private-key".to_string(),
        account_id: "account-id".to_string(),
        chatgpt_user_id: "user-id".to_string(),
        email: Some("user@example.com".to_string()),
        plan_type: AuthPlanType::Known(KnownPlan::Pro),
        chatgpt_account_is_fedramp: false,
    }
}

fn claims_json(claims: &AgentIdentityJwtClaims) -> serde_json::Value {
    serde_json::json!({
        "iss": claims.iss,
        "aud": claims.aud,
        "iat": claims.iat,
        "exp": claims.exp,
        "agent_runtime_id": claims.agent_runtime_id,
        "agent_private_key": claims.agent_private_key,
        "account_id": claims.account_id,
        "chatgpt_user_id": claims.chatgpt_user_id,
        "email": claims.email,
        "plan_type": "pro",
        "chatgpt_account_is_fedramp": claims.chatgpt_account_is_fedramp,
    })
}

fn test_header() -> Header {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-key".to_string());
    header
}

fn test_jwks(kid: &str) -> jsonwebtoken::jwk::JwkSet {
    serde_json::from_value(serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "kid": kid,
            "use": "sig",
            "alg": "RS256",
            "n": "1qQF2MqTrGAMDm7wXbjJP5sWqGA83tAGUs2ksy7iJXLJdhCg4AtwGm4SFl4f6kxhCSzlN1QdXuZjvRT2wZZiGUi9xUE28rf4WLrTxSnwqLuTy5knMP08yC0t_0YU_FGPZMcWb14hG05IvZr8UbmRaVagxSR8H4rSIymRoVwwmFSrqz068XrWGSYNIfLEASyo5GdAaqmk1JALINHgYGQJVxMxtwcvDxoVKmC7eltUNymMNBZhsv4E8sx9YNLpBoEibznfEpDU_DGzrM5eZCsQzaqbhBOlGd427ifud_Nnd9cPqzgCUc23-0FXSPfpbgksCXAwAmD0OFjQWrgqVdKL6Q",
            "e": "AQAB",
        }]
    }))
    .expect("test JWKS should parse")
}

fn sign_rs256_with_ring(payload: &serde_json::Value) -> String {
    let header = serde_json::to_vec(&serde_json::json!({
        "alg": "RS256",
        "kid": "test-key",
        "typ": "JWT",
    }))
    .expect("header should serialize");
    let payload = serde_json::to_vec(payload).expect("payload should serialize");
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(payload)
    );
    let key_pair = rsa_key_pair();
    let mut signature = vec![0u8; key_pair.public().modulus_len()];
    key_pair
        .sign(
            &RSA_PKCS1_SHA256,
            &SystemRandom::new(),
            signing_input.as_bytes(),
            &mut signature,
        )
        .expect("ring should sign RS256");
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn verify_rs256_with_ring(jwt: &str) {
    let (signing_input, signature) = jwt
        .rsplit_once('.')
        .expect("JWT should have a signature segment");
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .expect("signature should be base64url");
    let key_pair = rsa_key_pair();
    let public_key =
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key_pair.public().as_ref());
    public_key
        .verify(signing_input.as_bytes(), &signature)
        .expect("ring should verify aws-lc RS256 signature");
}

fn test_rsa_encoding_key() -> EncodingKey {
    EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM).expect("test RSA key should parse")
}

fn rsa_key_pair() -> RsaKeyPair {
    let pem = String::from_utf8(TEST_RSA_PRIVATE_KEY_PEM.to_vec()).expect("PEM should be utf-8");
    let der = BASE64_STANDARD
        .decode(
            pem.lines()
                .filter(|line| !line.starts_with("-----"))
                .collect::<String>(),
        )
        .expect("PEM body should be base64");
    RsaKeyPair::from_pkcs8(&der).expect("test RSA key should parse")
}

const TEST_RSA_PRIVATE_KEY_PEM: &[u8] = br#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDWpAXYypOsYAwO
bvBduMk/mxaoYDze0AZSzaSzLuIlcsl2EKDgC3AabhIWXh/qTGEJLOU3VB1e5mO9
FPbBlmIZSL3FQTbyt/hYutPFKfCou5PLmScw/TzILS3/RhT8UY9kxxZvXiEbTki9
mvxRuZFpVqDFJHwfitIjKZGhXDCYVKurPTrxetYZJg0h8sQBLKjkZ0BqqaTUkAsg
0eBgZAlXEzG3By8PGhUqYLt6W1Q3KYw0FmGy/gTyzH1g0ukGgSJvOd8SkNT8MbOs
zl5kKxDNqpuEE6UZ3jbuJ+5382d31w+rOAJRzbf7QVdI9+luCSwJcDACYPQ4WNBa
uCpV0ovpAgMBAAECggEAVu84LwZdqYN9XpswX8VoPYrjMm9IODapWQBRpQFoNyK2
1ksF3bjEPvA2Azk8U/l7k+vLKw22l6lY3EyRZPcz5GnB8xLm3ogE3mtNOp4yCyVu
RxhQ91aaN7mU17/a4BdorLi2LYVCg3zBmYociD1Q2AluNGsCmwPu+K7tfR2J0Sg8
NjqiTbDG1XDpR/icwgC9t6vh8lZpCHDhF4tbQfLLVLeA/OdcuzXDyMCXbmdVIdBQ
rm4aIFmr2e1/2ctTbCg85S6AGFTH+pSLjrwTzyvf+F6NW5uNjLQAQLFj+EznBDxj
Xdx90cySrjsKK6PVWQF4RiTvkSW8eWL7R6B2FZbGwQKBgQDuVQRj72hWloR7mbEL
aUEEv3pIXTMXWEsoMBNczos/1L1RnAN1AI44TurznasPZAWvQj+kVbLDR+TAeZrL
iA8HIWswQUI18hFmgKzSkwIXGtubcKVrgsKeS4lMDKCM/Ef6WAYdeq6ronoY5lCN
YrJFmGp81W5zcV7lyiycgbSiGwKBgQDmjWYf6pZjrK7Z+OJ3X1AZfi2vss15SCvL
3fPgzIDbViztpGyQhc3DQZIsBNIu0xZp/veGce9TEeTds2ro9NfdJFeou8+fC7Pq
sOsM3amGFFi+ZW/9BWyjZEM88bgWWAjqLHbpfHDxjAf5CSxddqxgHlbP0Ytyb1Vg
gmPDn9YKSwKBgQDbTi3hC35WFuDHn0/zcSHcDZmnFuOZeqyFyV83yfMGhGrEuqvP
sPgtRikajJ3IZsB4WZyYSidZXEFY/0z6NjOl2xF38MTNQPbT/FmK1q1Yt2UWrlv5
BvSwlk87RG9D7C0LZo4R+D7cPoDdgqjiwMvMEIkEX5zn641oI1ZTmWKuuwKBgQCD
KF+3unnRvHRAVoFnTZbA2fJdqMeRvogD04GhGlYX8V9f1hFY6nXTJaNlXVzA/J8c
r8ra9kgjJuPfZ+ljG58OFFW2DRohLcQtuHYPfK6rMzoFHqnl9EcIcMp7ijuionR3
29HOJFgQYgxLFXfit9d6WugiE+BTupiEbckZif13HwKBgE/lAlkVHP6YahOO2Ljc
J1bwkqKZTB5dHolX9A58e/xXnfZ5P8f3Z83+Izap3FwqQulk7b1WO1MQcHuVg2NN
5da0D4h2rYOXnbYIg0BVu4spQbaM6ewsp66b8+MzLOBvj8SzWdt1Oyw0q/MRyQAR
8U4M2TSWCKUY/A6sT4W8+mT9
-----END PRIVATE KEY-----"#;

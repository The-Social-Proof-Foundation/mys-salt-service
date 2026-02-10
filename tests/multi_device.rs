use myso_salt_service::security::{generate_master_seed, SaltManager};
use myso_salt_service::security::jwt::JwtValidator;
use myso_salt_service::models::JwtClaims;

#[test]
fn user_identifier_unified_across_audiences() {
    let claims_web = JwtClaims {
        iss: "https://accounts.google.com".into(),
        aud: "web-client-id".into(),
        sub: "111631294628286022835".into(),
        exp: 2000000000,
        iat: 1500000000,
        nonce: None,
        email: None,
        email_verified: None,
        name: None,
        picture: None,
        given_name: None,
        family_name: None,
    };

    let claims_ios = JwtClaims {
        iss: "https://accounts.google.com".into(),
        aud: "ios-client-id".into(),
        sub: "111631294628286022835".into(),
        exp: 2100000000,
        iat: 1600000000,
        nonce: Some("random".into()),
        email: None,
        email_verified: None,
        name: None,
        picture: None,
        given_name: None,
        family_name: None,
    };

    let id_web = JwtValidator::generate_user_identifier(&claims_web);
    let id_ios = JwtValidator::generate_user_identifier(&claims_ios);
    assert_eq!(id_web, id_ios, "Identifier must be the same across devices for the same user");
}

#[test]
fn salts_match_for_same_user_across_devices() {
    let seed = generate_master_seed();
    let manager = SaltManager::new(seed).unwrap();

    let claims_web = JwtClaims {
        iss: "https://accounts.google.com".into(),
        aud: "web-client-id".into(),
        sub: "111631294628286022835".into(),
        exp: 2000000000,
        iat: 1500000000,
        nonce: None,
        email: None,
        email_verified: None,
        name: None,
        picture: None,
        given_name: None,
        family_name: None,
    };

    let claims_ios = JwtClaims {
        iss: "https://accounts.google.com".into(),
        aud: "ios-client-id".into(),
        sub: "111631294628286022835".into(),
        exp: 2100000000,
        iat: 1600000000,
        nonce: Some("random".into()),
        email: None,
        email_verified: None,
        name: None,
        picture: None,
        given_name: None,
        family_name: None,
    };

    let salt_web = manager.generate_salt(&claims_web).unwrap();
    let salt_ios = manager.generate_salt(&claims_ios).unwrap();
    assert_eq!(salt_web, salt_ios, "Salts must match across devices for the same user");
}

// Intentionally no cross-issuer difference check: current design derives salts from `sub` only.

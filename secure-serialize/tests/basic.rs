use secure_serialize::SecureSerialize;
use serde::Deserialize;

#[derive(Debug, Deserialize, SecureSerialize)]
struct BasicConfig {
    pub host: String,
    #[redact]
    pub api_key: String,
    pub port: u16,
}

#[test]
fn test_basic_redaction() {
    let config = BasicConfig {
        host: "localhost".to_string(),
        api_key: "secret123".to_string(),
        port: 8080,
    };

    // Serialize should redact api_key
    let serialized = serde_json::to_value(&config).unwrap();
    assert_eq!(serialized["host"], "localhost");
    assert_eq!(serialized["api_key"], "<redacted>");
    assert_eq!(serialized["port"], 8080);
}

#[test]
fn test_redacted_keys() {
    assert_eq!(BasicConfig::redacted_keys(), &["api_key"]);
}

#[test]
fn test_unredacted_serialization() {
    let config = BasicConfig {
        host: "localhost".to_string(),
        api_key: "secret123".to_string(),
        port: 8080,
    };

    // to_json_unredacted should expose the real value
    let unredacted = config.to_json_unredacted().unwrap();
    assert_eq!(unredacted["host"], "localhost");
    assert_eq!(unredacted["api_key"], "secret123");
    assert_eq!(unredacted["port"], 8080);
}

#[test]
fn test_multiple_redacted_fields() {
    #[derive(Debug, Deserialize, SecureSerialize)]
    struct MultiSecretConfig {
        pub username: String,
        #[redact]
        pub password: String,
        #[redact]
        pub token: String,
        pub timeout: u32,
    }

    let config = MultiSecretConfig {
        username: "admin".to_string(),
        password: "pwd123".to_string(),
        token: "token456".to_string(),
        timeout: 30,
    };

    let serialized = serde_json::to_value(&config).unwrap();
    assert_eq!(serialized["username"], "admin");
    assert_eq!(serialized["password"], "<redacted>");
    assert_eq!(serialized["token"], "<redacted>");
    assert_eq!(serialized["timeout"], 30);

    let unredacted = config.to_json_unredacted().unwrap();
    assert_eq!(unredacted["password"], "pwd123");
    assert_eq!(unredacted["token"], "token456");
}

#[test]
fn test_no_redacted_fields() {
    #[derive(Debug, Deserialize, SecureSerialize)]
    struct PublicConfig {
        pub host: String,
        pub port: u16,
    }

    let config = PublicConfig {
        host: "localhost".to_string(),
        port: 8080,
    };

    assert_eq!(PublicConfig::redacted_keys(), &[] as &[&str]);

    let serialized = serde_json::to_value(&config).unwrap();
    assert_eq!(serialized["host"], "localhost");
    assert_eq!(serialized["port"], 8080);
}

#[test]
fn test_display_implementation() {
    let config = BasicConfig {
        host: "localhost".to_string(),
        api_key: "secret123".to_string(),
        port: 8080,
    };

    // Display via serde_json should also redact
    let display_str = serde_json::to_string_pretty(&config).unwrap();
    assert!(display_str.contains("\"<redacted>\""));
    assert!(!display_str.contains("secret123"));
}

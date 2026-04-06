use secure_serialize::SecureSerialize;
use serde::Deserialize;

#[derive(Deserialize, SecureSerialize)]
#[secure_serialize(debug)]
struct ConfigWithCustomRedaction {
    pub app_name: String,

    #[redact(with = "***")]
    pub database_password: String,

    #[redact]
    pub api_key: String,

    #[redact(with = "[REDACTED]")]
    pub private_key: String,
}

#[test]
fn test_custom_redaction_string() {
    let config = ConfigWithCustomRedaction {
        app_name: "myapp".to_string(),
        database_password: "pwd123".to_string(),
        api_key: "key456".to_string(),
        private_key: "priv789".to_string(),
    };

    let serialized = serde_json::to_value(&config).unwrap();
    assert_eq!(serialized["app_name"], "myapp");
    assert_eq!(serialized["database_password"], "***");
    assert_eq!(serialized["api_key"], "<redacted>");
    assert_eq!(serialized["private_key"], "[REDACTED]");
}

#[test]
fn test_custom_redaction_unredacted() {
    let config = ConfigWithCustomRedaction {
        app_name: "myapp".to_string(),
        database_password: "pwd123".to_string(),
        api_key: "key456".to_string(),
        private_key: "priv789".to_string(),
    };

    let unredacted = config.to_json_unredacted().unwrap();
    assert_eq!(unredacted["app_name"], "myapp");
    assert_eq!(unredacted["database_password"], "pwd123");
    assert_eq!(unredacted["api_key"], "key456");
    assert_eq!(unredacted["private_key"], "priv789");
}

#[test]
fn test_multiple_different_redactions() {
    #[derive(Deserialize, SecureSerialize)]
    #[secure_serialize(debug)]
    struct MixedConfig {
        #[redact]
        pub secret1: String,
        #[redact(with = "MASKED")]
        pub secret2: String,
        #[redact(with = "????")]
        pub secret3: String,
    }

    let config = MixedConfig {
        secret1: "value1".to_string(),
        secret2: "value2".to_string(),
        secret3: "value3".to_string(),
    };

    let serialized = serde_json::to_value(&config).unwrap();
    assert_eq!(serialized["secret1"], "<redacted>");
    assert_eq!(serialized["secret2"], "MASKED");
    assert_eq!(serialized["secret3"], "????");
}

#[test]
fn test_redacted_keys_with_custom_strings() {
    assert_eq!(
        ConfigWithCustomRedaction::redacted_keys(),
        &["database_password", "api_key", "private_key"]
    );
}

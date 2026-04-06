use secure_serialize::SecureSerialize;
use serde::Deserialize;
use std::collections::HashMap;

// Custom serializer for testing
fn serialize_hashmap<S>(map: &HashMap<String, String>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let json_str = serde_json::to_string(map).map_err(serde::ser::Error::custom)?;
    serializer.serialize_str(&json_str)
}

fn deserialize_hashmap<'de, D>(deserializer: D) -> Result<HashMap<String, String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    serde_json::from_str(&s).map_err(serde::de::Error::custom)
}

#[derive(Debug, Deserialize, SecureSerialize)]
struct ConfigWithCustomSerialize {
    pub service_name: String,

    #[redact]
    #[serde(
        serialize_with = "serialize_hashmap",
        deserialize_with = "deserialize_hashmap"
    )]
    pub secrets: HashMap<String, String>,

    #[serde(
        serialize_with = "serialize_hashmap",
        deserialize_with = "deserialize_hashmap"
    )]
    pub metadata: HashMap<String, String>,
}

#[test]
fn test_redacted_with_custom_serialize() {
    let mut secrets = HashMap::new();
    secrets.insert("api_key".to_string(), "secret123".to_string());
    secrets.insert("token".to_string(), "token456".to_string());

    let mut metadata = HashMap::new();
    metadata.insert("version".to_string(), "1.0.0".to_string());
    metadata.insert("region".to_string(), "us-east-1".to_string());

    let config = ConfigWithCustomSerialize {
        service_name: "my-service".to_string(),
        secrets,
        metadata,
    };

    // Serialize should redact secrets but not metadata
    let serialized = serde_json::to_value(&config).unwrap();
    assert_eq!(serialized["service_name"], "my-service");
    assert_eq!(serialized["secrets"], "<redacted>");
    // metadata should be serialized as a JSON string
    assert!(serialized["metadata"].is_string());
}

#[test]
fn test_unredacted_with_custom_serialize() {
    let mut secrets = HashMap::new();
    secrets.insert("api_key".to_string(), "secret123".to_string());

    let mut metadata = HashMap::new();
    metadata.insert("version".to_string(), "1.0.0".to_string());

    let config = ConfigWithCustomSerialize {
        service_name: "my-service".to_string(),
        secrets,
        metadata,
    };

    // to_json_unredacted should use custom serializer and expose all values
    let unredacted = config.to_json_unredacted().unwrap();
    assert_eq!(unredacted["service_name"], "my-service");

    // Both secrets and metadata should be serialized via the custom function
    assert!(unredacted["secrets"].is_string());
    assert!(unredacted["metadata"].is_string());

    // Verify we can parse the serialized values back
    let secrets_str = unredacted["secrets"].as_str().unwrap();
    let parsed_secrets: HashMap<String, String> = serde_json::from_str(secrets_str).unwrap();
    assert_eq!(parsed_secrets["api_key"], "secret123");
}

#[test]
fn test_redacted_keys_with_custom_serialize() {
    assert_eq!(ConfigWithCustomSerialize::redacted_keys(), &["secrets"]);
}

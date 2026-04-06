use secure_serialize::SecureSerialize;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize, SecureSerialize)]
#[secure_serialize(debug)]
struct TwoSecrets {
    pub host: String,
    #[redact]
    pub api_key: String,
    #[redact]
    pub token: String,
}

#[test]
fn reveal_one_redacted_other_stays_redacted() {
    let v = TwoSecrets {
        host: "localhost".to_string(),
        api_key: "key-real".to_string(),
        token: "token-real".to_string(),
    };

    let json = v.to_json_with_revealed_fields(&["api_key"]).unwrap();
    assert_eq!(json["host"], "localhost");
    assert_eq!(json["api_key"], "key-real");
    assert_eq!(json["token"], "<redacted>");
}

#[test]
fn empty_reveal_matches_plain_serialize() {
    let v = TwoSecrets {
        host: "localhost".to_string(),
        api_key: "key-real".to_string(),
        token: "token-real".to_string(),
    };

    let selective = v.to_json_with_revealed_fields(&[]).unwrap();
    let plain = serde_json::to_value(&v).unwrap();
    assert_eq!(selective, plain);
}

#[test]
fn reveal_includes_non_redacted_field_same_as_reveal_only_redacted() {
    let v = TwoSecrets {
        host: "localhost".to_string(),
        api_key: "key-real".to_string(),
        token: "token-real".to_string(),
    };

    let with_host = v
        .to_json_with_revealed_fields(&["host", "api_key"])
        .unwrap();
    let api_only = v.to_json_with_revealed_fields(&["api_key"]).unwrap();
    assert_eq!(with_host, api_only);
}

#[test]
fn custom_redaction_string_revealed_shows_real_value() {
    #[derive(Deserialize, SecureSerialize)]
    struct CustomRedact {
        #[redact(with = "***")]
        pub password: String,
    }

    let v = CustomRedact {
        password: "hunter2".to_string(),
    };

    let redacted = serde_json::to_value(&v).unwrap();
    assert_eq!(redacted["password"], "***");

    let revealed = v.to_json_with_revealed_fields(&["password"]).unwrap();
    assert_eq!(revealed["password"], "hunter2");
}

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

#[derive(Deserialize, SecureSerialize)]
#[secure_serialize(debug)]
struct RedactedCustomSerialize {
    #[redact]
    #[serde(
        serialize_with = "serialize_hashmap",
        deserialize_with = "deserialize_hashmap"
    )]
    pub secrets: HashMap<String, String>,
}

#[test]
fn reveal_redacted_field_with_serialize_with_matches_unredacted_value() {
    let mut secrets = HashMap::new();
    secrets.insert("k".to_string(), "v".to_string());

    let v = RedactedCustomSerialize { secrets };

    let redacted = serde_json::to_value(&v).unwrap();
    assert_eq!(redacted["secrets"], "<redacted>");

    let full = v.to_json_unredacted().unwrap();
    let selective = v.to_json_with_revealed_fields(&["secrets"]).unwrap();
    assert_eq!(selective["secrets"], full["secrets"]);
    assert!(selective["secrets"].is_string());
}

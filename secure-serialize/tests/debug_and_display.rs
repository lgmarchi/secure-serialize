//! Integration tests for opt-in `#[secure_serialize(debug)]` and `#[secure_serialize(display)]`.
//!
//! Run with:
//! `cargo test --test debug_and_display -- --nocapture`
//! to see `println!` output with and without those options.

use secure_serialize::SecureSerialize;
use serde::Deserialize;
use std::fmt;

#[derive(Deserialize, SecureSerialize)]
#[secure_serialize(debug, display)]
struct LoggableConfig {
    pub host: String,
    #[redact]
    pub api_key: String,
    #[redact(with = "***")]
    pub password: String,
    pub port: u16,
}

#[test]
fn test_debug_redacts_secrets() {
    let config = LoggableConfig {
        host: "localhost".to_string(),
        api_key: "super-secret-key".to_string(),
        password: "hunter2".to_string(),
        port: 443,
    };

    let dbg_one_line = format!("{:?}", config);
    println!("Debug one-line: {dbg_one_line}");

    assert!(
        dbg_one_line.contains("<redacted>"),
        "expected default redaction in Debug: {dbg_one_line}"
    );
    assert!(
        dbg_one_line.contains("***"),
        "expected custom redaction in Debug: {dbg_one_line}"
    );
    assert!(
        !dbg_one_line.contains("super-secret-key"),
        "secret must not appear in Debug: {dbg_one_line}"
    );
    assert!(
        !dbg_one_line.contains("hunter2"),
        "password must not appear in Debug: {dbg_one_line}"
    );
    assert!(dbg_one_line.contains("localhost"));
    assert!(dbg_one_line.contains("443"));
}

#[test]
fn test_debug_pretty_redacts() {
    let config = LoggableConfig {
        host: "app.example.com".to_string(),
        api_key: "key-xyz".to_string(),
        password: "pw-abc".to_string(),
        port: 8080,
    };

    let pretty = format!("{config:#?}");
    println!("Debug pretty:\n{pretty}");

    assert!(pretty.contains("<redacted>"));
    assert!(pretty.contains("***"));
    assert!(!pretty.contains("key-xyz"));
    assert!(!pretty.contains("pw-abc"));
    assert!(pretty.contains("app.example.com"));
}

#[test]
fn test_display_produces_redacted_json() {
    let config = LoggableConfig {
        host: "x".to_string(),
        api_key: "never-show".to_string(),
        password: "also-hidden".to_string(),
        port: 1,
    };

    let display = format!("{}", config);
    println!("Display (JSON): {display}");

    assert!(display.contains("<redacted>"));
    assert!(display.contains("***"));
    assert!(!display.contains("never-show"));
    assert!(!display.contains("also-hidden"));
    assert!(display.contains("\"host\":\"x\"") || display.contains(r#""host":"x""#));
}

#[test]
fn test_serde_json_string_and_pretty_redact() {
    let config = LoggableConfig {
        host: "h".to_string(),
        api_key: "json-secret".to_string(),
        password: "json-pw".to_string(),
        port: 2,
    };

    let compact = serde_json::to_string(&config).unwrap();
    let pretty = serde_json::to_string_pretty(&config).unwrap();
    println!("serde_json compact: {compact}");
    println!("serde_json pretty:\n{pretty}");

    assert!(compact.contains("<redacted>"));
    assert!(!compact.contains("json-secret"));
    assert!(!pretty.contains("json-pw"));
}

#[test]
fn test_log_line_simulation() {
    let config = LoggableConfig {
        host: "db.internal".to_string(),
        api_key: "token-123".to_string(),
        password: "db-pass".to_string(),
        port: 5432,
    };

    let line = format!("loaded config: {:?}", config);
    println!("{line}");

    assert!(!line.contains("token-123"));
    assert!(!line.contains("db-pass"));
    assert!(line.contains("<redacted>"));
}

/// Without `#[secure_serialize(debug)]`, standard `#[derive(Debug)]` still exposes secrets.
#[derive(Debug, Deserialize, SecureSerialize)]
struct LegacyDebugConfig {
    pub name: String,
    #[redact]
    pub token: String,
}

#[test]
fn test_backward_compat_standard_debug_leaks_secrets() {
    let config = LegacyDebugConfig {
        name: "svc".to_string(),
        token: "visible-in-debug".to_string(),
    };

    let dbg = format!("{:?}", config);
    println!("Standard Debug (no secure_serialize): {dbg}");

    assert!(
        dbg.contains("visible-in-debug"),
        "standard Debug shows real token; use #[secure_serialize(debug)] to redact"
    );

    let json = serde_json::to_value(&config).unwrap();
    assert_eq!(json["token"], "<redacted>");
}

#[derive(Deserialize, SecureSerialize)]
#[secure_serialize(debug)]
struct DebugOnlyConfig {
    pub id: u32,
    #[redact]
    pub secret: String,
}

#[test]
fn test_debug_only_no_display_trait() {
    let c = DebugOnlyConfig {
        id: 7,
        secret: "hidden".to_string(),
    };
    let d = format!("{:?}", c);
    println!("DebugOnlyConfig: {d}");
    assert!(d.contains("<redacted>"));
    assert!(!d.contains("hidden"));
}

// ---------------------------------------------------------------------------
// println demo: with `#[secure_serialize]` vs without (standard Debug / naive Display)
// ---------------------------------------------------------------------------

/// No `#[secure_serialize(debug)]`: `#[derive(Debug)]` prints the real value in `{:?}`.
#[derive(Debug, Deserialize, SecureSerialize)]
struct ConfigNoSecureSerializeDebug {
    pub host: String,
    #[redact]
    pub api_key: String,
}

/// No `#[secure_serialize(display)]`: a typical hand-written `Display` leaks the secret in `{}`.
#[derive(Deserialize, SecureSerialize)]
struct ConfigNaiveDisplay {
    pub host: String,
    #[redact]
    pub api_key: String,
}

impl fmt::Display for ConfigNaiveDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ConfigNaiveDisplay {{ host: {}, api_key: {} }}",
            self.host, self.api_key
        )
    }
}

#[test]
fn test_println_with_secure_serialize_redacts_debug_and_display() {
    let config = LoggableConfig {
        host: "api.example.com".to_string(),
        api_key: "SHOULD_NOT_APPEAR_IN_OUTPUT".to_string(),
        password: "ALSO_SECRET_PASSWORD".to_string(),
        port: 9000,
    };

    println!();
    println!("========== WITH #[secure_serialize(debug, display)] ==========");
    println!("println!(\"Debug: {{:?}}\", config) ->");
    println!("Debug: {:?}", config);
    println!();
    println!("println!(\"Display: {{}}\", config) ->");
    println!("Display: {}", config);
    println!("============================================================");

    let dbg = format!("{:?}", config);
    let disp = format!("{}", config);
    assert!(
        !dbg.contains("SHOULD_NOT_APPEAR_IN_OUTPUT"),
        "Debug must not leak api_key: {dbg}"
    );
    assert!(
        !dbg.contains("ALSO_SECRET_PASSWORD"),
        "Debug must not leak password: {dbg}"
    );
    assert!(!disp.contains("SHOULD_NOT_APPEAR_IN_OUTPUT"), "Display: {disp}");
    assert!(!disp.contains("ALSO_SECRET_PASSWORD"), "Display: {disp}");
    assert!(dbg.contains("<redacted>") && dbg.contains("***"));
    assert!(disp.contains("<redacted>") && disp.contains("***"));
}

#[test]
fn test_println_without_secure_serialize_debug_shows_secret() {
    let config = ConfigNoSecureSerializeDebug {
        host: "old-host".to_string(),
        api_key: "SECRET_SHOWN_IN_DEBUG".to_string(),
    };

    println!();
    println!("========== WITHOUT #[secure_serialize(debug)] (#[derive(Debug)] only) ==========");
    println!("println!(\"Debug: {{:?}}\", config) ->");
    println!("Debug: {:?}", config);
    println!("=================================================================================");

    let dbg = format!("{:?}", config);
    assert!(
        dbg.contains("SECRET_SHOWN_IN_DEBUG"),
        "standard Debug should show the secret; add #[secure_serialize(debug)] to redact: {dbg}"
    );

    let json = serde_json::to_value(&config).unwrap();
    assert_eq!(json["api_key"], "<redacted>", "JSON serialization still redacts");
}

#[test]
fn test_println_naive_display_without_option_leaks_secret() {
    let config = ConfigNaiveDisplay {
        host: "srv1".to_string(),
        api_key: "SECRET_SHOWN_IN_DISPLAY".to_string(),
    };

    println!();
    println!("========== WITHOUT #[secure_serialize(display)] (naive manual Display) ==========");
    println!("println!(\"Display: {{}}\", config) ->");
    println!("Display: {}", config);
    println!("=================================================================================");

    let disp = format!("{}", config);
    assert!(
        disp.contains("SECRET_SHOWN_IN_DISPLAY"),
        "naive Display leaks api_key; use #[secure_serialize(display)] or avoid formatting secrets: {disp}"
    );
}

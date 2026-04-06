# secure-serialize

A Rust proc-macro crate for automatic redaction of sensitive fields during serialization.

[![Crates.io](https://img.shields.io/crates/v/secure-serialize.svg)](https://crates.io/crates/secure-serialize)
[![License: MIT OR Apache-2.0](https://img.shields.io/crates/l/secure-serialize.svg)](https://github.com/yourusername/secure-serialize#license)
[![Docs.rs](https://docs.rs/secure-serialize/badge.svg)](https://docs.rs/secure-serialize)

## Overview

`secure-serialize` provides a procedural macro `#[derive(SecureSerialize)]` that automatically redacts sensitive fields when a struct is serialized. Fields marked with `#[redact]` are replaced with `"<redacted>"` (or a custom string) during serialization, preventing accidental exposure of secrets in logs, API responses, and debug output.

For internal operations that require actual secret values (e.g., config hot-reloading), the trait method `to_json_unredacted()` is available.

## Features

- ✅ Automatic redaction of sensitive fields during `serde::Serialize`
- ✅ Customizable redaction strings per field
- ✅ Works with `serde(serialize_with)` for custom serialization
- ✅ Supports `Display` and `Debug` automatically (via serde_json)
- ✅ Internal method `to_json_unredacted()` for accessing real values when needed
- ✅ Zero runtime overhead for redaction (compile-time generation)
- ✅ No additional dependencies beyond `serde` and `serde_json`

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
secure-serialize = "0.1"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
```

### Basic Example

```rust
use secure_serialize::SecureSerialize;
use serde::Deserialize;

#[derive(Deserialize, SecureSerialize)]
struct DatabaseConfig {
    pub host: String,
    pub port: u16,

    #[redact]
    pub password: String,

    #[redact]
    pub api_key: String,
}

fn main() {
    let config = DatabaseConfig {
        host: "localhost".to_string(),
        port: 5432,
        password: "super_secret_password".to_string(),
        api_key: "sk_live_1234567890".to_string(),
    };

    // Serialize normally - secrets are redacted
    let json = serde_json::to_string_pretty(&config).unwrap();
    println!("{}", json);
    // Output:
    // {
    //   "host": "localhost",
    //   "port": 5432,
    //   "password": "<redacted>",
    //   "api_key": "<redacted>"
    // }

    // For internal use (config merging, etc.)
    let unredacted = config.to_json_unredacted().unwrap();
    println!("API Key (internal only): {}", unredacted["api_key"]);
    // Output: API Key (internal only): "sk_live_1234567890"
}
```

### Custom Redaction Strings

```rust
use secure_serialize::SecureSerialize;
use serde::Deserialize;

#[derive(Deserialize, SecureSerialize)]
struct Config {
    #[redact]
    pub default_redacted: String,  // Will be "<redacted>"

    #[redact(with = "***")]
    pub asterisk_redacted: String, // Will be "***"

    #[redact(with = "[MASKED]")]
    pub masked: String,            // Will be "[MASKED]"
}
```

### With Custom Serializers

```rust
use secure_serialize::SecureSerialize;
use serde::Deserialize;
use std::collections::HashMap;

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
struct Config {
    #[redact]
    #[serde(serialize_with = "serialize_hashmap", deserialize_with = "deserialize_hashmap")]
    pub api_keys: HashMap<String, String>,
}
```

## API Reference

### `#[derive(SecureSerialize)]`

Generates three implementations:

1. **`impl serde::Serialize`** — Redacts all `#[redact]` fields
2. **`impl SecureSerialize`** — Provides metadata and unredacted serialization
3. **Auto `Display` and `Debug`** — Uses redacted serialization (when combined with serde_json)

### `#[redact]`

Marks a field for redaction. 

```rust
#[redact]                      // Redacts to "<redacted>"
pub secret: String,

#[redact(with = "***")]        // Redacts to "***"
pub password: String,
```

### Trait: `SecureSerialize`

```rust
pub trait SecureSerialize: serde::Serialize {
    /// Returns names of all redacted fields.
    fn redacted_keys() -> &'static [&'static str];

    /// Serializes with all real values (no redaction).
    /// ⚠️ Use only for internal operations.
    fn to_json_unredacted(&self) -> Result<serde_json::Value, serde_json::Error>;
}
```

### Constants

```rust
pub const REDACTED: &str = "<redacted>";
```

## Use Cases

### 1. Safe Logging

```rust
// This won't expose secrets
tracing::info!("Config: {}", serde_json::to_string_pretty(&config).unwrap());
```

### 2. API Responses

```rust
// Safe to return to clients
let response = serde_json::to_value(&config).unwrap();
HttpResponse::Ok().json(response)  // Secrets are redacted
```

### 3. Debug Output

```rust
// Debug trait automatically uses redacted serialization
dbg!(&config);  // Won't show real secrets
```

### 4. Config Hot-Reloading (Internal Use)

```rust
// Only use in internal operations where you control the data flow
let full_config = config.to_json_unredacted()?;
let merged = merge_configs(&full_config, &new_config)?;
```

## Important Notes

⚠️ **Never expose `to_json_unredacted()` output** externally. It contains all sensitive data without redaction. Use it only for:

- Internal config merging and validation
- Hot-reloading mechanisms
- Database seeding (in secure environments)

Always use regular `serde::Serialize` for:

- Logging
- API responses
- Debug output
- User-facing data

## Limitations

- **Only works with named-field structs**: Tuple structs and enums are not supported
- **String-based redaction only**: Custom types cannot be used as redaction strings (they must be compile-time literals)
- **No selective trait derivation**: All `#[redact]` fields use the same redaction mechanism

## Testing

Run the test suite:

```bash
cargo test
```

This includes:

- **Integration tests**: `tests/basic.rs`, `tests/custom_serialize.rs`, `tests/configurable_redaction.rs`
- **Compile-fail tests**: `tests/ui/` (using `trybuild`)

## Performance

`secure-serialize` has **zero runtime overhead** for redaction logic:

- All redaction happens at compile-time via code generation
- No runtime checks or dynamic branching
- Same performance as hand-written `impl Serialize`

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Changelog

### 0.1.0 (Initial Release)

- `#[derive(SecureSerialize)]` macro
- `#[redact]` attribute with customizable strings
- Support for `serde(serialize_with)`
- `to_json_unredacted()` for internal operations
- Comprehensive test suite

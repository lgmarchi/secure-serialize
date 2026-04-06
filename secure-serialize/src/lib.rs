//! # secure-serialize
//!
//! A proc-macro crate that automatically redacts sensitive fields during serialization.
//!
//! When a struct is derived with `#[derive(SecureSerialize)]`, all fields marked with
//! `#[redact]` will be replaced with `"<redacted>"` (or a custom string) when serialized via
//! `serde::Serialize`. For cases where you need the real values (internal operations like config
//! hot-reloading), the `to_json_unredacted()` method is available.
//!
//! ## Example
//!
//! ```
//! use secure_serialize::SecureSerialize;
//! use serde::Deserialize;
//!
//! #[derive(Deserialize, SecureSerialize)]
//! struct Config {
//!     pub host: String,
//!
//!     /// This field will be redacted to "<redacted>" when serialized
//!     #[redact]
//!     pub api_key: String,
//!
//!     /// This field will be redacted to "***" when serialized
//!     #[redact(with = "***")]
//!     pub password: String,
//! }
//!
//! let config = Config {
//!     host: "localhost".to_string(),
//!     api_key: "secret123".to_string(),
//!     password: "my_password".to_string(),
//! };
//!
//! // Serialized version has redacted fields
//! let serialized = serde_json::to_value(&config).unwrap();
//! assert_eq!(serialized["api_key"], "<redacted>");
//! assert_eq!(serialized["password"], "***");
//! assert_eq!(serialized["host"], "localhost");
//!
//! // Unredacted version has all real values (internal use only!)
//! let unredacted = config.to_json_unredacted().unwrap();
//! assert_eq!(unredacted["api_key"], "secret123");
//! assert_eq!(unredacted["password"], "my_password");
//! ```
//!
//! ## Attributes
//!
//! ### `#[redact]`
//!
//! Mark a field as sensitive. When serialized, it will be replaced with `"<redacted>"`.
//!
//! ```ignore
//! #[derive(SecureSerialize)]
//! struct Config {
//!     #[redact]
//!     pub secret: String,
//! }
//! ```
//!
//! ### `#[redact(with = "...")]`
//!
//! Mark a field as sensitive and specify a custom redaction string.
//!
//! ```ignore
//! #[derive(SecureSerialize)]
//! struct Config {
//!     #[redact(with = "***")]
//!     pub password: String,
//! }
//! ```
//!
//! ### `#[secure_serialize(debug)]` and `#[secure_serialize(display)]`
//!
//! Optional struct-level attributes (place them on the struct, next to `derive`):
//!
//! - **`debug`** — generates `impl std::fmt::Debug` where `#[redact]` fields show the redaction
//!   string instead of real values. Use this for `{:?}`, `dbg!`, and typical logging.
//! - **`display`** — generates `impl std::fmt::Display` as compact JSON with the same redaction as
//!   `serde_json::to_string` (requires `serde_json` in your crate’s dependency graph, same as
//!   `to_json_unredacted`).
//!
//! You can combine them: `#[secure_serialize(debug, display)]`.
//!
//! If you omit these, behavior stays as before: only `Serialize` redacts. `#[derive(Debug)]` alone
//! still prints real secrets — opt in to `#[secure_serialize(debug)]` when you want safe `Debug`.
//!
//! ```ignore
//! #[derive(Deserialize, SecureSerialize)]
//! #[secure_serialize(debug, display)]
//! struct Config {
//!     pub host: String,
//!     #[redact]
//!     pub api_key: String,
//! }
//! ```
//!
//! ## Trait Methods
//!
//! - `redacted_keys()` — Returns a static slice of all redacted field names.
//! - `to_json_unredacted()` — Returns a JSON value with all real values (no redaction).
//!   Use this only for internal operations where you need actual values.
//!
//! ⚠️ **Warning**: `to_json_unredacted()` exposes all sensitive data. Use it only internally,
//! never expose its output to logs, APIs, or external systems.

pub use secure_serialize_derive::SecureSerialize;

/// Constant string used for default redaction.
pub const REDACTED: &str = "<redacted>";

/// Trait for types that support secure serialization with automatic redaction of sensitive fields.
///
/// Implementors should derive `#[derive(SecureSerialize)]` to automatically generate implementations.
/// The trait requires `serde::Serialize`, so all redactable types can be serialized.
///
/// When a struct is serialized via `serde::Serialize`, fields marked with `#[redact]` are replaced
/// with redaction strings. For redacted `Debug` / JSON `Display`, add
/// `#[secure_serialize(debug)]` or `#[secure_serialize(display)]` on the struct.
///
/// For internal operations where you need real values, use `to_json_unredacted()`.
pub trait SecureSerialize: serde::Serialize {
    /// Returns the names of all redacted fields in this struct.
    ///
    /// These are the field names that will be redacted when the struct is serialized.
    /// Names are in snake_case.
    fn redacted_keys() -> &'static [&'static str];

    /// Serializes this struct to a JSON value with all real values exposed (no redaction).
    ///
    /// ⚠️ **Use only for internal operations** where you actually need the real sensitive values,
    /// such as config hot-reloading or merging. Never use this for display, logging, or API responses.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let config = load_config();
    /// // Safe: this is internal config merging logic
    /// let full_values = config.to_json_unredacted()?;
    /// ```
    fn to_json_unredacted(&self) -> Result<serde_json::Value, serde_json::Error>;
}

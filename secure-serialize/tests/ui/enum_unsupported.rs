use secure_serialize::SecureSerialize;
use serde::Deserialize;

#[derive(Deserialize, SecureSerialize)]
enum UnsupportedEnum {
    Variant1,
    Variant2,
}

fn main() {}

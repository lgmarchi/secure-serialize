use secure_serialize::SecureSerialize;
use serde::Deserialize;

#[derive(Deserialize, SecureSerialize)]
struct TupleStruct(String, String);

fn main() {}

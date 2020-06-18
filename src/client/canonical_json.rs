use serde_json;

pub fn serialize(input: &serde_json::value::Value) -> String {
    format!("{}", input)
}
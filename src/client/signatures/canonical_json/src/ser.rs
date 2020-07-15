use serde::ser::{Serialize};
use serde_json::ser::{Formatter, CharEscape};
use std::io::Write;
use log::{debug, error};

struct JSONFormatter {}

impl Formatter for JSONFormatter {
    fn write_f64<W: ?Sized>(&mut self, writer: &mut W, value: f64) -> Result<(), std::io::Error> where
        W: Write,
    {
        format_number(writer, value, 10.0_f64.powf(21.0), 10.0_f64.powf(-6.0))?;
        Ok(())
    }

    fn write_char_escape<W: ?Sized>(&mut self, writer: &mut W, char_escape: CharEscape) -> Result<(), std::io::Error> where
        W: Write, 
    {
        match char_escape {
            CharEscape::Quote => {
                writer.write("\"".as_bytes())?; 
            },
            CharEscape::ReverseSolidus => {
                writer.write("\\\\".as_bytes())?;
            },
            CharEscape::LineFeed => {
                writer.write("\n".as_bytes())?;
            },
            CharEscape::Tab => {
                writer.write("\t".as_bytes())?;
            },
            CharEscape::CarriageReturn => {
                writer.write("\r".as_bytes())?;
            },
            CharEscape::Backspace => {},
            CharEscape::FormFeed => {},
            CharEscape::Solidus => {},
            CharEscape::AsciiControl (_number) => {}
        }

        Ok(())
    }

    fn write_string_fragment<W: ?Sized>(&mut self, writer: &mut W, fragment: &str) -> Result<(), std::io::Error> where
        W: Write, 
    {
        let formatted_string = format!("{}", fragment).escape_default().to_string().replace("\\\"", "\"");
        format_unicode_in_string(writer, formatted_string)?;
        Ok(())
    }
}

fn format_number<W: ?Sized>(writer: &mut W, number: f64, lower_bound: f64, upper_bound: f64) -> Result<(), std::io::Error> where W: Write, {

    debug!("in format_number function");

    if (0.0 < number && number < upper_bound) || (number >= lower_bound) {
        debug!("converting number {} to scientific notation", number);
        let number_string = format!("{:e}", number);
        debug!("formatted_number {}", number_string);
        let mut prev_char = '\0';
        for curr_char in number_string.chars() {
            if prev_char == 'e' && curr_char != '-' {
                // its a positive exponent
                writer.write("+".as_bytes())?;
            }

            writer.write(curr_char.to_string().as_bytes())?;
            prev_char = curr_char;
        }

        return Ok(());
    }

    debug!("returning number {} without scientifc notation", number);
    writer.write(&format!("{}", number).into_bytes())?;
    Ok(())
}

/// looking for \u{X} \u{XX}, \u{XXX}, \u{XXXX} to remove the curly braces
fn format_unicode_in_string<W: ?Sized>(writer: &mut W, serialized_string: String) -> Result<(), std::io::Error> where W: Write, {

    let mut string_iter = serialized_string.chars().peekable();

    while let Some(curr_char) = string_iter.next() {

        if curr_char == '\\' && string_iter.peek() == Some(&'u') {
            
            writer.write(&"\\u".as_bytes())?;
            string_iter.next();

            if string_iter.peek() == Some(&'{') {
                // consume at most 4 characters till '}' is found
                let mut characters = String::new();
                string_iter.next(); // skip the '{' for now
                let mut index = 0;

                while index < 4 && string_iter.peek() != Some(&'}') && string_iter.peek() != None {

                    match string_iter.peek() {
                        Some(character) => characters.push(*character),
                        None => break
                    };

                    string_iter.next();
                    index += 1;
                }

                if string_iter.peek() == None {
                    // could not find '}' bracket so must include '{' and following characters
                    writer.write(&"{".as_bytes())?;
                    writer.write(&characters.into_bytes())?;
                } else if string_iter.peek() == Some(&'}') {
                    // found '}' - remove '{' and '}' but must pad zeros
                    if characters.len() == 0 {
                        writer.write(&"{}".as_bytes())?;
                    } else {
                        writer.write(&std::iter::repeat("0").take(4 - characters.len()).collect::<String>().into_bytes())?;
                        writer.write(&characters.into_bytes())?;
                        string_iter.next(); // skip '}' 
                    }
                }
            }

            continue;
        }

        writer.write(curr_char.to_string().as_bytes())?;
    }

    Ok(())
}

/// Serialize a JSON value to String
/// 
/// # Examples
/// ```rust
/// # use canonical_json::ser::to_canonical_json;
/// # use serde_json::json;
/// # fn main() {
///     to_canonical_json(&json!(null)); // returns "null"
/// 
///     to_canonical_json(&json!("test")); // returns "test"
/// 
///     to_canonical_json(&json!(10.0_f64.powf(21.0))); // returns "1e+21"
/// 
///     to_canonical_json(&json!({
///         "a": "a",
///         "id": "1",
///         "b": "b"
///     })); // returns "{"a":"a","b":"b","id":"1"}"; (orders object keys)
/// 
///     to_canonical_json(&json!(vec!["one", "two", "three"])); // returns "["one","two","three"]"
/// # }
/// 
/// ```
pub fn to_canonical_json(input: &serde_json::Value) -> String {

    let string = vec![];
    let null_string = "null".to_owned();
    let mut serializer = serde_json::Serializer::with_formatter(string, JSONFormatter{});
    match input.serialize(&mut serializer) {
        Ok(()) => match String::from_utf8(serializer.into_inner()) {
            Ok(serialized_string) => return serialized_string,
            Err(error) => {
                error!("Error converting bytes to string: {}", error);
                return null_string;
            }
        },
        Err(error) => {
            error!("Error serializing JSON : {}", error);
            return null_string;
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use log::{debug};
    use env_logger;
    use super::{to_canonical_json};

    struct Test<'a> {
        test_description: &'a str,
        input: serde_json::Value,
        output: &'a str
    }

    fn init() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn test_to_canonical_json_serialize_null_type() {
        init();
        let null_tests = [
            Test {
                test_description: "to_canonical_json_serializes_null",
                input: json!(null),
                output: "null"
            },
            Test {
                test_description: "to_canonical_json_serializes_nan_to_null",
                input: json!(std::f64::NAN),
                output: "null"
            },
            Test {
                test_description: "to_canonical_json_serializes_inf_to_null",
                input: json!(std::f64::INFINITY),
                output: "null"
            },
            Test {
                test_description: "to_canonical_json_serializes_negative_inf_to_null",
                input: json!(std::f64::NEG_INFINITY),
                output: "null"
            }
        ];

        for test in &null_tests {
            debug!("test: {}", test.test_description);
            assert_eq!(to_canonical_json(&test.input), test.output);
        }
    }

    #[test]
    fn test_to_canonical_json_serialize_bool_type() {
        init();
        let null_tests = [
            Test {
                test_description: "to_canonical_json_serializes_bool_when_true",
                input: json!(true),
                output: "true"
            },
            Test {
                test_description: "test_canonical_json_serializes_bool_when_false",
                input: json!(false),
                output: "false"
            }
        ];

        for test in &null_tests {
            debug!("test: {}", test.test_description);
            assert_eq!(to_canonical_json(&test.input), test.output);
        }
    }

    #[test]
    fn test_to_canonical_json_serialize_number_type() {
        init();
        let null_tests = [
            Test {
                test_description: "to_canonical_json_serializes_number_when_zero",
                input: json!(0),
                output: "0"
            },
            Test {
                test_description: "to_canonical_json_serializes_number_when_positive",
                input: json!(123),
                output: "123"
            },
            Test {
                test_description: "test_canonical_json_serializes_number_when_negative",
                input: json!(-123),
                output: "-123"
            },
            Test {
                test_description: "to_canotest_canonical_json_correctly_serializes_number_converting_to_scientific_notation_when_too_largenical_json_serializes_number_when_zero",
                input: json!(10.000_f64.powf(21.0)),
                output: "1e+21"
            },
            Test {
                test_description: "to_canonical_json_correctly_serializes_number_with_non_zero_decimals",
                input: json!(23.1),
                output: "23.1"
            },
            Test {
                test_description: "to_canonical_json_correctly_serializes_number_truncating_trailing_zeros_in_decimal",
                input: json!(23.0),
                output: "23"
            },
            Test {
                test_description: "to_canonical_json_serializes_number_preserving_trailing_zeros_when_number_not_too_large",
                input: json!(2300),
                output: "2300"
            },
            Test {
                test_description: "to_canonical_json_serializes_number_above_scientific_notation_lower_threshold_with_negative_4_exponent",
                input: json!(0.00099),
                output: "0.00099"
            },
            Test {
                test_description: "to_canonical_json_serializes_number_above_scientific_notation_lower_threshold_with_negative_5_exponent",
                input: json!(0.000011),
                output: "0.000011"
            },
            Test {
                test_description: "test_canonical_json_serializes_number_above_scientific_notation_lower_threshold_with_negative_6_exponent",
                input: json!(0.0000011),
                output: "0.0000011"
            },
            Test {
                test_description: "to_canonical_json_serializes_number_above_scientific_notation_lower_threshold_with_negative_6_exponent_and_one_nonzero_digit",
                input: json!(0.000001),
                output: "0.000001"
            },
            Test {
                test_description: "to_canonical_json_serializes_number_under_scientific_notation_lower_threshold_with_negative_7_exponent",
                input: json!(0.00000099),
                output: "9.9e-7"
            },
            Test {
                test_description: "to_canonical_json_serializes_number_under_scientific_notation_lower_threshold_with_negative_7_exponent_and_one_nonzero_digit",
                input: json!(0.0000001),
                output: "1e-7"
            },
            Test {
                test_description: "to_canonical_json_serializes_number_under_scientific_notation_lower_threshold_with_negative_7_preserves_decimals",
                input: json!(0.000000930258908),
                output: "9.30258908e-7"
            },
            Test {
                test_description: "to_canonical_json_serializes_number_under_scientific_notation_lower_threshold_with_negative_13_exponent",
                input: json!(0.00000000000068272),
                output: "6.8272e-13"
            },
            Test {
                test_description: "to_canonical_json_serializes_number_under_scientific_notation_upper_threshold_does_not_convert_to_scientific_notation",
                input: json!(10.0_f64.powi(20)),
                output: "100000000000000000000"
            },
            Test {
                test_description: "to_canonical_json_serializes_number_under_scientific_notation_upper_threshold_preserves_decimals",
                input: json!(10.0_f64.powi(15) + 0.1),
                output: "1000000000000000.1"
            },
            Test {
                test_description: "to_canonical_json_serializes_number_under_scientific_notation_upper_threshold_does_not_convert_to_scientific_notation_and_preserves_decimals",
                input: json!(10.0_f64.powi(16) * 1.1),
                output: "11000000000000000"
            }
        ];

        for test in &null_tests {
            debug!("test: {}", test.test_description);
            assert_eq!(to_canonical_json(&test.input), test.output);
        }
    }

    #[test]
    fn test_to_canonical_json_serialize_string_type() {
        init();
        let null_tests = [
            Test {
                test_description: "to_canonical_json_serializes_empty_string",
                input: json!(""),
                output: "\"\""
            },
            Test {
                test_description: "to_canonical_json_serializes_when_string_escapes_quotes",
                input: json!('"'),
                output: "\"\"\""
            },
            Test {
                test_description: "to_canonical_json_serializes_non_empty_string",
                input: json!("test"),
                output: "\"test\""
            },
            Test {
                test_description: "to_canonical_json_serializes_string_escapes_backslashes",
                input: json!("This\\and this"),
                output: "\"This\\\\and this\""
            },
            Test {
                test_description: "to_canonical_json_serializes_string_with_non_ascii_character_converts_to_lowercase_unicode",
                input: json!("I ❤ testing"),
                output: "\"I \\u2764 testing\""
            }
        ];

        for test in &null_tests {
            debug!("test: {}", test.test_description);
            assert_eq!(to_canonical_json(&test.input), test.output);
        }
    }

    #[test]
    fn test_to_canonical_json_preserves_certain_strings() {
        init();

        let tests = [
            Test {
                test_description: "to_canonical_json_serializes_string_preserves_newline",
                input: json!("This is a sentence.\n"),
                output: "\"This is a sentence.\n\""
            },
            Test {
                test_description: "to_canonical_json_serializes_string_preserves_tabs",
                input: json!("This is a \t tab."),
                output: "\"This is a \t tab.\""
            },
            Test {
                test_description: "to_canonical_json_serializes_string_preserves_carriagereturn",
                input: json!("This is a \r carriage return char."),
                output: "\"This is a \r carriage return char.\""
            },
            Test {
                test_description: "to_canonical_json_serializes_string_preserves_forwardslashes",
                input: json!("image/jpeg"),
                output: "\"image/jpeg\""
            },
            Test {
                test_description: "to_canonical_json_serializes_string_preserves_double_forwardslashes",
                input: json!("image//jpeg"),
                output: "\"image//jpeg\""
            },
            Test {
                test_description: "to_canonical_json_serializes_string_preserving_scientific_notation_number",
                input: json!("frequency at 10.0e+04"),
                output: "\"frequency at 10.0e+04\""
            },
            Test {
                test_description: "to_canonical_json_serializes_string_preserves_invalid_unicode_escape_sequence",
                input: json!("I \\u{} testing"),
                output: "\"I \\\\u{} testing\""
            },
            Test {
                test_description: "to_canonical_json_serializes_string_preserves_opening_curly_brackets_if_invalid_unicode_escape_sequence",
                input: json!("I \\u{1234 testing"),
                output: "\"I \\\\u{1234 testing\""
            },
            Test {
                test_description: "to_canonical_json_serializes_string_does_not_alter_if_more_than_hex_4_characters_in_unicode_escape_sequence",
                input: json!("I \\u{{12345}} testing"),
                output: "\"I \\\\u{{12345}} testing\""
            }
        ];
        
        for test in &tests {
            debug!("test: {}", test.test_description);
            assert_eq!(to_canonical_json(&test.input), test.output);
        }
    }


    #[test]
    fn test_to_canonical_json_serialize_object_type() {
        init();
        let null_tests = [
            Test {
                test_description: "to_canonical_json_serializes_empty_object",
                input: json!({
                    "a": {},
                    "b": "b"
                }),
                output: "{\"a\":{},\"b\":\"b\"}"
            },
            Test {
                test_description: "to_canonical_json_serializes_object_with_key_ordering",
                input: json!({
                    "a": "a",
                    "id": "1",
                    "b": "b"
                }),
                output: "{\"a\":\"a\",\"b\":\"b\",\"id\":\"1\"}"
            },
            Test {
                test_description: "to_canonical_json_serialize_with_deeply_nested_objects",
                input: json!({
                            "a": json!({
                                "b": "b",
                                "a": "a",
                                "c": json!({
                                    "b": "b",
                                    "a": "a",
                                    "c": ["b", "a", "c"],
                                    "d": json!({ "b": "b", "a": "a" }),
                                    "id": "1",
                                    "e": 1,
                                    "f": [2, 3, 1],
                                    "g": json!({
                                        "2": 2,
                                        "3": 3,
                                        "1": json!({
                                            "b": "b",
                                            "a": "a",
                                            "c": "c",
                                        })
                                    })
                                })
                            }),
                            "id": "1"
                        }),
                output: "{\"a\":{\"a\":\"a\",\"b\":\"b\",\"c\":{\"a\":\"a\",\"b\":\"b\",\"c\":[\"b\",\"a\",\"c\"],\
                \"d\":{\"a\":\"a\",\"b\":\"b\"},\"e\":1,\"f\":[2,3,1],\
                \"g\":{\"1\":{\"a\":\"a\",\"b\":\"b\",\"c\":\"c\"},\"2\":2,\"3\":3},\"id\":\"1\"}},\"id\":\"1\"}"
            },
            Test {
                test_description: "to_canonical_json_serializes_orders_object_keys",
                input: json!({
                    "b": vec!["two", "three"],
                    "a": vec!["zero", "one"]
                }),
                output: "{\"a\":[\"zero\",\"one\"],\"b\":[\"two\",\"three\"]}"
            },
            Test {
                test_description: "to_canonical_json_serialize_orders_nested_object_keys",
                input: json!({
                    "b": { "d": "d", "c": "c" },
                    "a": { "b": "b", "a": "a" },
                }),
                output: "{\"a\":{\"a\":\"a\",\"b\":\"b\"},\"b\":{\"c\":\"c\",\"d\":\"d\"}}"
            },
            Test {
                test_description: "to_canonical_json_serialize_escapes_unicode_object_keys",
                input: json!({"é": "check"}),
                output: "{\"\\u00e9\":\"check\"}"
            },
            Test {
                test_description: "to_canonical_json_serialize_multiple_nested_types",
                input: json!({
                    "def": "bar",
                    "abc": json!(0.000000930258908),
                    "ghi": json!(1000000000000000000000.0_f64),
                    "rust": "❤",
                    "zoo": [
                        "zorilla",
                        "anteater"
                    ]
                }),
                output: "{\"abc\":9.30258908e-7,\"def\":\"bar\",\"ghi\":1e+21,\"rust\":\"\\u2764\",\"zoo\":[\"zorilla\",\"anteater\"]}"
            }
        ];

        for test in &null_tests {
            debug!("test: {}", test.test_description);
            assert_eq!(to_canonical_json(&test.input), test.output);
        }
    }

    #[test]
    fn test_to_canonical_json_serialize_array_type() {
        init();
        let null_tests = [
            Test {
                test_description: "to_canonical_json_serializes_empty_array",
                input: json!([]),
                output: "[]"
            },
            Test {
                test_description: "to_canonical_json_serializes_array_should_preserve_array_order",
                input: json!(vec!["one", "two", "three"]),
                output: "[\"one\",\"two\",\"three\"]"
            },
            Test {
                test_description: "to_canonical_json_serializes_array_escapes_unicode_values",
                input: json!(vec![json!({ "key": "✓" })]),
                output: "[{\"key\":\"\\u2713\"}]"
            },
            Test {
                test_description: "to_canonical_json_serializes_array_escapes_unicode_values_with_1_preceding_zeros",
                input: json!(vec![json!({ "key": "ę" })]),
                output: "[{\"key\":\"\\u0119\"}]"
            },
            Test {
                test_description: "to_canonical_json_serializes_array_escapes_unicode_values_with_2_preceding_zeros",
                input: json!(vec![json!({ "key": "é" })]),
                output: "[{\"key\":\"\\u00e9\"}]"
            },
            Test {
                test_description: "to_canonical_json_serialize_array_preserves_data",
                input: json!(vec![
                    json!({ "foo": "bar", "last_modified": "12345", "id": "1" }),
                    json!({ "bar": "baz", "last_modified": "45678", "id": "2" }),
                ]),
                output: "[{\"foo\":\"bar\",\"id\":\"1\",\"last_modified\":\"12345\"},\
                {\"bar\":\"baz\",\"id\":\"2\",\"last_modified\":\"45678\"}]"
            },
            Test {
                test_description: "to_canonical_json_serialize_does_not_add_space_separators",
                input: json!(
                    vec![
                        json!({ "foo": "bar", "last_modified": "12345", "id": "1" }),
                        json!({ "bar": "baz", "last_modified": "45678", "id": "2" }),
                    ]
                ),
                output: "[{\"foo\":\"bar\",\"id\":\"1\",\"last_modified\":\"12345\"},\
                {\"bar\":\"baz\",\"id\":\"2\",\"last_modified\":\"45678\"}]"
            }
        ];

        for test in &null_tests {
            debug!("test: {}", test.test_description);
            assert_eq!(to_canonical_json(&test.input), test.output);
        }
    }
}

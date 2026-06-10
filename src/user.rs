/// Legacy-only username validation: alphanumeric plus a limited set of special characters,
/// with dots allowed (but not leading, trailing, or consecutive). This is the
/// unquoted local-part from RFC 5322 without the quoted-string alternative that
/// would allow control characters.
///
/// New Spark create/update validation uses the shared Blink Core-compatible
/// identifier parser instead of this regex.
#[allow(dead_code)]
pub const USERNAME_VALIDATION_REGEX: &str =
    "^[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+)*$";

pub struct User {
    pub domain: String,
    pub pubkey: String,
    pub name: String,
    pub description: String,
}

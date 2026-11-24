//! Spotify names an item two ways: 22 base62 characters in a URI, and the
//! same 128 bits as raw bytes (a "gid") in its protobuf messages.

const ALPHABET: &[u8; 62] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

pub fn gid_from_base62(id: &str) -> Option<[u8; 16]> {
    if id.len() != 22 {
        return None;
    }
    let mut value: u128 = 0;
    for byte in id.bytes() {
        let digit = ALPHABET.iter().position(|letter| *letter == byte)? as u128;
        value = value.checked_mul(62)?.checked_add(digit)?;
    }
    Some(value.to_be_bytes())
}

pub fn base62_from_gid(gid: &[u8]) -> Option<String> {
    let mut value = u128::from_be_bytes(gid.try_into().ok()?);
    let mut id = [b'0'; 22];
    for slot in id.iter_mut().rev() {
        *slot = ALPHABET[(value % 62) as usize];
        value /= 62;
    }
    Some(String::from_utf8_lossy(&id).into_owned())
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The id at the end of `spotify:<kind>:<id>`.
pub fn id_of_uri<'a>(uri: &'a str, kind: &str) -> Option<&'a str> {
    let mut parts = uri.split(':');
    (parts.next() == Some("spotify") && parts.next() == Some(kind))
        .then(|| parts.next())
        .flatten()
        .filter(|id| id.len() == 22 && parts.next().is_none())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_id_survives_both_spellings() {
        let id = "4uLU6hMCjMI75M1A2tKUQC";
        let gid = gid_from_base62(id).expect("a track id");
        assert_eq!(hex(&gid), "93bc414a606747b2b612491ef83d5a3e");
        assert_eq!(base62_from_gid(&gid).as_deref(), Some(id));
        assert_eq!(
            base62_from_gid(&[0; 16]).as_deref(),
            Some("0000000000000000000000")
        );
    }

    #[test]
    fn what_is_not_an_id_is_refused() {
        assert_eq!(gid_from_base62("short"), None);
        assert_eq!(gid_from_base62("4uLU6hMCjMI75M1A2tKUQ!"), None);
        // 22 characters can spell more than 128 bits.
        assert_eq!(gid_from_base62("ZZZZZZZZZZZZZZZZZZZZZZ"), None);
        assert_eq!(base62_from_gid(&[1, 2, 3]), None);
    }

    #[test]
    fn a_uri_names_its_kind() {
        let uri = "spotify:track:4uLU6hMCjMI75M1A2tKUQC";
        assert_eq!(id_of_uri(uri, "track"), Some("4uLU6hMCjMI75M1A2tKUQC"));
        assert_eq!(id_of_uri(uri, "album"), None);
        assert_eq!(id_of_uri("spotify:track:short", "track"), None);
        assert_eq!(id_of_uri("spotify:user:a:playlist:b", "user"), None);
    }
}

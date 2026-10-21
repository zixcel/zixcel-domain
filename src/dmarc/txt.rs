use crate::{Result, error};
/// Join quoted DNS character strings within one RR; never across separate records.
pub(super) fn decode(input: &str) -> Result<String> {
    if input.len() > 8192 || !input.is_ascii() {
        return Err(error("dmarc_txt_budget"));
    }
    let input = input.trim();
    if !input.starts_with('"') {
        if input.contains(['"', '\\']) {
            return Err(error("invalid_txt_encoding"));
        }
        return Ok(input.into());
    }
    let bytes = input.as_bytes();
    let mut cursor = 0;
    let mut result = Vec::new();
    let mut chunks = 0;
    while cursor < bytes.len() {
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if cursor == bytes.len() {
            break;
        }
        if bytes[cursor] != b'"' {
            return Err(error("invalid_txt_encoding"));
        }
        chunks += 1;
        if chunks > 32 {
            return Err(error("txt_chunk_budget"));
        }
        cursor += 1;
        let mut ended = false;
        while cursor < bytes.len() {
            let mut byte = bytes[cursor];
            cursor += 1;
            if byte == b'"' {
                ended = true;
                break;
            }
            if byte == b'\\' {
                byte = *bytes
                    .get(cursor)
                    .ok_or_else(|| error("invalid_txt_escape"))?;
                cursor += 1;
                if byte.is_ascii_digit() {
                    let tail = bytes
                        .get(cursor..cursor + 2)
                        .ok_or_else(|| error("invalid_txt_escape"))?;
                    if !tail.iter().all(u8::is_ascii_digit) {
                        return Err(error("invalid_txt_escape"));
                    }
                    let value = (byte - b'0') as u16 * 100
                        + (tail[0] - b'0') as u16 * 10
                        + (tail[1] - b'0') as u16;
                    byte = u8::try_from(value).map_err(|_| error("invalid_txt_escape"))?;
                    cursor += 2;
                }
            }
            if byte.is_ascii_control() || !byte.is_ascii() {
                return Err(error("invalid_txt_character"));
            }
            result.push(byte);
        }
        if !ended {
            return Err(error("unterminated_txt"));
        }
    }
    String::from_utf8(result).map_err(|_| error("invalid_txt_encoding"))
}

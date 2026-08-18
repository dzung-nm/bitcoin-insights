#[allow(dead_code)]
pub fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, String> {
    let hex_str = hex_str.trim_start_matches("0x").trim_start_matches("0X");

    if hex_str.len() % 2 != 0 {
        return Err("Hex string must have an even length".to_string());
    }

    (0..hex_str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).map_err(|_| "Invalid hex string".to_string()))
        .collect()
}

#[allow(dead_code)]
pub fn bytes_to_hex(bytes: &[u8], with_prefix: bool) -> String {
    let hex_str: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    if with_prefix {
        format!("0x{}", hex_str)
    } else {
        hex_str
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_to_hex() {
        assert_eq!(bytes_to_hex(&[], false), "");
        assert_eq!(bytes_to_hex(&[0x00], true), "0x00");
        assert_eq!(bytes_to_hex(&[0], false), "00");
        assert_eq!(bytes_to_hex(&[0], true), "0x00");
        assert_eq!(bytes_to_hex(&[1], false), "01");
        assert_eq!(bytes_to_hex(&[1], true), "0x01");

        assert_eq!(bytes_to_hex(&[10], false), "0a");
        assert_eq!(bytes_to_hex(&[255], false), "ff");
        assert_eq!(bytes_to_hex(&[18, 52], false), "1234");
        assert_eq!(bytes_to_hex(&[171, 205, 239], false), "abcdef");
    }

    #[test]
    fn test_hex_to_bytes() {
        assert_eq!(hex_to_bytes("0x").unwrap(), vec![]);
        assert_eq!(hex_to_bytes("0X").unwrap(), vec![]);
        assert_eq!(hex_to_bytes("0x00").unwrap(), vec![0]);
        assert_eq!(hex_to_bytes("0x01").unwrap(), vec![1]);
        assert_eq!(hex_to_bytes("0x0A").unwrap(), vec![10]);
        assert_eq!(hex_to_bytes("0xFF").unwrap(), vec![255]);
        assert_eq!(hex_to_bytes("0x1234").unwrap(), vec![18, 52]);
        assert_eq!(hex_to_bytes("0xabcdef").unwrap(), vec![171, 205, 239]);
        assert_eq!(hex_to_bytes("0xABCDEF").unwrap(), vec![171, 205, 239]);
    }

    #[test]
    fn test_hex_to_bytes_invalid() {
        assert_eq!(hex_to_bytes("0x1"), Err("Hex string must have an even length".to_string()));
        assert_eq!(hex_to_bytes("0xG1"), Err("Invalid hex string".to_string()));
    }
}
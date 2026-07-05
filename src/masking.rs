//! masking.

use alloc::string::String;
use alloc::vec::Vec;

// ---------------------------------------------------------------------------
// Masking
// ---------------------------------------------------------------------------

/// 文字列マスキング: 先頭n文字を残して'*'に置換
#[must_use]
pub fn mask_string(s: &str, keep_prefix: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut result = String::new();
    for (i, &c) in chars.iter().enumerate() {
        if i < keep_prefix {
            result.push(c);
        } else {
            result.push('*');
        }
    }
    result
}

/// メールアドレスマスキング: `user@domain` → `u***@domain`
#[must_use]
pub fn mask_email(email: &str) -> String {
    email.find('@').map_or_else(
        || mask_string(email, 1),
        |at_pos| {
            let user = &email[..at_pos];
            let domain = &email[at_pos..];
            let mut masked = String::new();
            if let Some(first) = user.chars().next() {
                masked.push(first);
                for _ in 1..user.len() {
                    masked.push('*');
                }
            }
            masked.push_str(domain);
            masked
        },
    )
}

/// クレジットカード番号マスキング: 末尾4桁のみ表示
#[must_use]
pub fn mask_card(number: &str) -> String {
    let digits: Vec<char> = number.chars().filter(char::is_ascii_digit).collect();
    if digits.len() < 4 {
        return mask_string(number, 0);
    }
    let mut result = String::new();
    for _ in 0..digits.len() - 4 {
        result.push('*');
    }
    for &d in &digits[digits.len() - 4..] {
        result.push(d);
    }
    result
}

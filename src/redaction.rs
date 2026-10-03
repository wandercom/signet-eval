//! Sanitization for diagnostic data, never for the policy input being adjudicated.
use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

pub const REVISION: &str = "signet-redaction-v1";
const MASK: &str = "[REDACTED]";

fn patterns() -> &'static Vec<Regex> {
    static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        [
            r"(?s)-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
            r"\bsk-(?:ant-(?:api03-)?|proj-)?[A-Za-z0-9_-]{20,}\b",
            r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{16,}|AKIA[A-Z0-9]{16})\b",
            r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        ].iter().map(|p| Regex::new(p).expect("static sanitizer pattern")).collect()
    })
}

pub fn text(input: &str) -> String {
    let mut output = input.to_owned();
    for pattern in patterns() {
        output = pattern.replace_all(&output, MASK).into_owned();
    }
    static HEADER: OnceLock<Regex> = OnceLock::new();
    let header = HEADER.get_or_init(|| {
        Regex::new(r"(?im)^(\s*(?:cookie|set-cookie|authorization)\s*:\s*)[^\r\n]+")
            .expect("static secret header")
    });
    output = header.replace_all(&output, "${1}[REDACTED]").into_owned();
    static QUOTED: OnceLock<Regex> = OnceLock::new();
    let quoted = QUOTED.get_or_init(|| Regex::new(r#"(?i)(\b(?:[a-z][a-z0-9]*[_-])*(?:api[_-]?key|secret[_-]?access[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|secret|token)\b["']?\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*')"#).expect("static quoted secret"));
    output = quoted.replace_all(&output, "${1}[REDACTED]").into_owned();
    static LABEL: OnceLock<Regex> = OnceLock::new();
    let label = LABEL.get_or_init(|| Regex::new(r#"(?i)(\b(?:[a-z][a-z0-9]*[_-])*(?:authorization|api[_-]?key|secret[_-]?access[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|password|passwd|secret|token)\b["']?\s*[:=]\s*["']?)(?:Bearer\s+)?([^\s"',;}]+)"#).expect("static secret label"));
    output = label.replace_all(&output, "${1}[REDACTED]").into_owned();
    static URL: OnceLock<Regex> = OnceLock::new();
    let url = URL.get_or_init(|| {
        Regex::new(r"(?i)([a-z][a-z0-9+.-]*://[^/\s:@]+:)[^@\s/]+(@)")
            .expect("static credential URL")
    });
    url.replace_all(&output, "${1}[REDACTED]${2}").into_owned()
}

fn sensitive_key(key: &str) -> bool {
    let normalized: String = key
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect();
    matches!(
        normalized.as_str(),
        "authorization"
            | "apikey"
            | "password"
            | "passwd"
            | "secret"
            | "clientsecret"
            | "token"
            | "accesstoken"
            | "refreshtoken"
            | "privatekey"
            | "cookie"
            | "setcookie"
    ) || [
        "apikey",
        "secretaccesskey",
        "accesstoken",
        "refreshtoken",
        "clientsecret",
        "password",
    ]
    .iter()
    .any(|suffix| normalized.ends_with(suffix))
}

pub fn value(input: &Value) -> Value {
    match input {
        Value::String(s) => Value::String(text(s)),
        Value::Array(items) => Value::Array(items.iter().map(value).collect()),
        Value::Object(items) => Value::Object(
            items
                .iter()
                .map(|(key, item)| {
                    (
                        text(key),
                        if sensitive_key(key) && !item.is_null() {
                            Value::String(MASK.into())
                        } else {
                            value(item)
                        },
                    )
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

pub fn summary(input: &str, max_chars: usize) -> String {
    diagnostic(input).chars().take(max_chars).collect()
}

/// Preserve field-aware masking when callers supply an already serialized log record.
pub fn diagnostic(input: &str) -> String {
    match serde_json::from_str::<Value>(input) {
        Ok(record @ (Value::Object(_) | Value::Array(_))) => value(&record).to_string(),
        _ => text(input),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn redacts_labeled_and_nested_secrets_without_erasing_evidence() {
        let hash = "0123456789abcdef".repeat(4);
        let input = serde_json::json!({"token":"opaque-value", "nested":["Authorization: Bearer private-value", "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890"],"sha256":hash,"ip":"127.0.0.1","email":"person@example.test"});
        let safe = value(&input);
        assert_eq!(safe["sha256"], hash);
        assert_eq!(safe["ip"], "127.0.0.1");
        assert_eq!(safe["email"], "person@example.test");
        let serialized = safe.to_string();
        for secret in [
            "opaque-value",
            "private-value",
            "abcdefghijklmnopqrstuvwxyz",
        ] {
            assert!(!serialized.contains(secret));
        }
        assert_eq!(summary("🔑password=private-value", 8), "🔑passwor");
        assert!(!text("ACME_ANTHROPIC_API_KEY=private AWS_SECRET_ACCESS_KEY=private postgres://user:private@db").contains("private"));
        assert!(
            !value(&serde_json::json!({"AWS_SECRET_ACCESS_KEY":"private"}))
                .to_string()
                .contains("private")
        );
        assert!(
            !diagnostic(r#"{"headers":{"Cookie":"first=private; second=private"}}"#)
                .contains("private")
        );
        assert!(
            !text("Cookie: first=private; second=private\npassword='private multi word'")
                .contains("private")
        );
    }
}

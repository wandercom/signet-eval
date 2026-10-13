//! Known-secret masking for diagnostic output.
//!
//! The user names shell env files (for example `~/.profile`) in
//! `SIGNET_DIR/secret_mask.yaml`:
//!
//! ```yaml
//! files: [~/.profile]
//! keys: [OPENAI, "AWS_*_KEY"]   # optional; DEFAULT_KEY_PATTERNS when omitted
//! min_length: 8                 # optional
//! ```
//!
//! Every selected `NAME=VALUE` line yields a known secret, and any occurrence of
//! VALUE in what signet-eval persists or displays becomes `$NAME`. Without the
//! config file the feature is off. Masking only touches diagnostic copies:
//! policy evaluates the original input, and the host runs the original command.
//! Nothing here logs, returns or errors with a secret value.

use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;

/// Name fragments selected when `keys` is omitted (case-insensitive substrings).
pub const DEFAULT_KEY_PATTERNS: &[&str] = &[
    "KEY",
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "PASS",
    "PW",
    "CREDENTIAL",
    "AUTH",
    "PRIVATE",
    "SID",
    "DSN",
    "WEBHOOK",
    "COOKIE",
    "CLIENT_ID",
    "ACCOUNT_ID",
    "API",
];
pub const DEFAULT_MIN_LENGTH: usize = 8;
/// Config file name inside the signet directory.
pub const CONFIG_FILE: &str = "secret_mask.yaml";

/// `(value, name)` replacements, longest value first.
pub type Table = Vec<(String, String)>;

fn default_min_length() -> usize {
    DEFAULT_MIN_LENGTH
}

/// User-level settings. An absent file means masking is off.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretMaskConfig {
    #[serde(default)]
    pub files: Vec<String>,
    #[serde(default)]
    pub keys: Option<Vec<String>>,
    #[serde(default = "default_min_length")]
    pub min_length: usize,
}

/// Whether `pattern` selects `name`: a case-insensitive substring match where
/// `*` matches any run of characters. A full name therefore selects itself.
fn selects(pattern: &str, name: &str) -> bool {
    let name = name.to_ascii_uppercase();
    let pattern = pattern.to_ascii_uppercase();
    let parts: Vec<&str> = pattern.split('*').filter(|p| !p.is_empty()).collect();
    if parts.is_empty() {
        return false;
    }
    let mut rest = name.as_str();
    for part in parts {
        match rest.find(part) {
            Some(i) => rest = &rest[i + part.len()..],
            None => return false,
        }
    }
    true
}

/// Whether `name` is a secret name under `keys` (the default patterns if None).
pub fn key_selected(name: &str, keys: Option<&[String]>) -> bool {
    match keys {
        Some(keys) => keys.iter().any(|p| selects(p, name)),
        None => DEFAULT_KEY_PATTERNS.iter().any(|p| selects(p, name)),
    }
}

fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The literal value of a `NAME=` right-hand side, or None when it is not a
/// plain literal (unterminated or concatenated quotes).
fn literal_value(raw: &str) -> Option<&str> {
    let raw = raw.trim();
    if let Some(quote) = raw.chars().next().filter(|c| *c == '"' || *c == '\'') {
        let body = &raw[1..];
        let end = body.find(quote)?;
        let rest = body[end + 1..].trim_start();
        if !rest.is_empty() && !rest.starts_with('#') {
            return None;
        }
        return Some(&body[..end]);
    }
    let cut = raw
        .char_indices()
        .find(|(i, c)| *c == '#' && raw[..*i].ends_with(char::is_whitespace))
        .map_or(raw.len(), |(i, _)| i);
    Some(raw[..cut].trim_end())
}

/// `(name, value)` pairs in file order for selected, literal values.
///
/// Lines are `[export ]NAME=VALUE`. Matching surrounding quotes are stripped;
/// an unquoted value loses a trailing ` #comment`. Values containing `$` or a
/// backtick (expansions signet cannot resolve) and values shorter than
/// `min_length` characters are skipped.
pub fn parse_env_text(
    text: &str,
    keys: Option<&[String]>,
    min_length: usize,
) -> Vec<(String, String)> {
    let min_length = min_length.max(1);
    let mut pairs = Vec::new();
    for line in text.lines() {
        let mut line = line.trim_start();
        if let Some(rest) = line.strip_prefix("export") {
            if rest.starts_with(char::is_whitespace) {
                line = rest.trim_start();
            }
        }
        let Some((name, raw)) = line.split_once('=') else {
            continue;
        };
        if !valid_name(name) || !key_selected(name, keys) {
            continue;
        }
        let Some(value) = literal_value(raw) else {
            continue;
        };
        if value.contains('$') || value.contains('`') || value.chars().count() < min_length {
            continue;
        }
        pairs.push((name.to_owned(), value.to_owned()));
    }
    pairs
}

/// Replacements for `pairs`, longest value first. The first name in file order
/// owns a value shared by several names. A value's JSON-escaped spelling (as
/// stored inside serialized parameters) maps to the same name.
pub fn build_table(pairs: &[(String, String)]) -> Table {
    let mut seen = HashSet::new();
    let mut table: Table = Vec::new();
    for (name, value) in pairs {
        if seen.insert(value.clone()) {
            table.push((value.clone(), name.clone()));
        }
    }
    let escaped: Vec<(String, String)> = table
        .iter()
        .filter_map(|(value, name)| {
            let json = serde_json::to_string(value).ok()?;
            let inner = json[1..json.len() - 1].to_owned();
            (inner != *value).then(|| (inner, name.clone()))
        })
        .collect();
    for (value, name) in escaped {
        if seen.insert(value.clone()) {
            table.push((value, name));
        }
    }
    // Stable: equal lengths keep file order.
    table.sort_by_key(|(value, _)| std::cmp::Reverse(value.len()));
    table
}

/// Replace every occurrence of each known value with `$NAME`.
pub fn mask_text(text: &str, table: &Table) -> String {
    let mut output = text.to_owned();
    for (value, name) in table {
        if output.contains(value.as_str()) {
            output = output.replace(value.as_str(), &format!("${name}"));
        }
    }
    output
}

/// Distinct names whose values occur in `text`, longest value first.
pub fn masked_names(text: &str, table: &Table) -> Vec<String> {
    let mut remaining = text.to_owned();
    let mut names: Vec<String> = Vec::new();
    for (value, name) in table {
        if remaining.contains(value.as_str()) {
            if !names.contains(name) {
                names.push(name.clone());
            }
            remaining = remaining.replace(value.as_str(), "");
        }
    }
    names
}

type Stamp = Option<(SystemTime, u64)>;

fn stamp(path: &Path) -> Stamp {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.modified().ok()?, meta.len()))
}

struct ReferenceFile {
    path: PathBuf,
    /// None until the first read.
    stamp: Option<Stamp>,
    pairs: Vec<(String, String)>,
}

/// Known secrets from one config file and the reference files it names,
/// re-read whenever a file's mtime or size changes.
pub struct SecretMask {
    config_path: PathBuf,
    config_stamp: Stamp,
    config: Option<SecretMaskConfig>,
    files: Vec<ReferenceFile>,
    table: Arc<Table>,
    dirty: bool,
    warned: HashSet<PathBuf>,
}

impl SecretMask {
    pub fn new(config_path: PathBuf) -> Self {
        Self {
            config_path,
            config_stamp: None,
            config: None,
            files: Vec::new(),
            table: Arc::new(Vec::new()),
            dirty: false,
            warned: HashSet::new(),
        }
    }

    /// Warn once per path, naming the file but never its contents.
    fn warn(&mut self, path: &Path, message: &str) {
        if self.warned.insert(path.to_path_buf()) {
            eprintln!("signet-eval: secret_mask: {}: {message}", path.display());
        }
    }

    fn resolve(&self, entry: &str) -> PathBuf {
        let home = || PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into()));
        if entry == "~" {
            return home();
        }
        if let Some(rest) = entry.strip_prefix("~/") {
            return home().join(rest);
        }
        let path = PathBuf::from(entry);
        if path.is_absolute() {
            return path;
        }
        self.config_path
            .parent()
            .map_or(path.clone(), |dir| dir.join(&path))
    }

    fn reload_config(&mut self) {
        let current = stamp(&self.config_path);
        if current == self.config_stamp {
            return;
        }
        self.config_stamp = current;
        self.files.clear();
        self.config = None;
        self.dirty = true;
        if current.is_none() {
            return;
        }
        let parsed = std::fs::read_to_string(&self.config_path)
            .ok()
            .and_then(|text| serde_yaml::from_str::<SecretMaskConfig>(&text).ok());
        let Some(config) = parsed else {
            let path = self.config_path.clone();
            self.warn(&path, "invalid config; secret masking is off");
            return;
        };
        self.files = config
            .files
            .iter()
            .map(|entry| ReferenceFile {
                path: self.resolve(entry),
                stamp: None,
                pairs: Vec::new(),
            })
            .collect();
        self.config = Some(config);
    }

    /// The current replacement table, refreshed from changed files.
    pub fn table(&mut self) -> Arc<Table> {
        self.reload_config();
        let (keys, min_length) = match &self.config {
            Some(config) => (config.keys.clone(), config.min_length),
            None => (None, DEFAULT_MIN_LENGTH),
        };
        let mut unreadable = Vec::new();
        for file in &mut self.files {
            let current = stamp(&file.path);
            if file.stamp == Some(current) {
                continue;
            }
            self.dirty = true;
            file.stamp = Some(current);
            file.pairs = match std::fs::read(&file.path) {
                Ok(bytes) => parse_env_text(
                    &String::from_utf8_lossy(&bytes),
                    keys.as_deref(),
                    min_length,
                ),
                Err(_) => {
                    unreadable.push(file.path.clone());
                    Vec::new()
                }
            };
        }
        for path in unreadable {
            self.warn(&path, "cannot read reference file; masking nothing from it");
        }
        if self.dirty {
            self.dirty = false;
            let pairs: Vec<(String, String)> = self
                .files
                .iter()
                .flat_map(|file| file.pairs.iter().cloned())
                .collect();
            self.table = Arc::new(build_table(&pairs));
        }
        Arc::clone(&self.table)
    }

    /// Distinct names with a masked value, in file order, and the number of
    /// configured reference files. Never exposes a value.
    pub fn summary(&mut self) -> Option<(Vec<String>, usize)> {
        self.table();
        self.config.as_ref()?;
        let mut names: Vec<String> = Vec::new();
        for file in &self.files {
            for (name, _) in &file.pairs {
                if !names.contains(name) {
                    names.push(name.clone());
                }
            }
        }
        Some((names, self.files.len()))
    }
}

fn global() -> &'static Mutex<SecretMask> {
    static GLOBAL: OnceLock<Mutex<SecretMask>> = OnceLock::new();
    GLOBAL.get_or_init(|| Mutex::new(SecretMask::new(config_path())))
}

/// `SIGNET_DIR/secret_mask.yaml` (normally `~/.signet/secret_mask.yaml`).
pub fn config_path() -> PathBuf {
    crate::vault::signet_dir().join(CONFIG_FILE)
}

#[cfg(test)]
thread_local! {
    static TEST_TABLE: std::cell::RefCell<Option<Arc<Table>>> =
        const { std::cell::RefCell::new(None) };
}

/// Replace the active table on this test thread (None restores the config).
#[cfg(test)]
pub(crate) fn set_test_pairs(pairs: Option<&[(&str, &str)]>) {
    let table = pairs.map(|pairs| {
        let owned: Vec<(String, String)> = pairs
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();
        Arc::new(build_table(&owned))
    });
    TEST_TABLE.with(|cell| *cell.borrow_mut() = table);
}

/// The active replacement table; empty when masking is off.
pub fn table() -> Arc<Table> {
    #[cfg(test)]
    if let Some(table) = TEST_TABLE.with(|cell| cell.borrow().clone()) {
        return table;
    }
    let mut mask = match global().lock() {
        Ok(mask) => mask,
        Err(poisoned) => poisoned.into_inner(),
    };
    let path = config_path();
    if mask.config_path != path {
        *mask = SecretMask::new(path);
    }
    mask.table()
}

/// Mask `text` with the active table; unchanged when masking is off.
pub fn mask(text: &str) -> String {
    mask_text(text, &table())
}

/// Masked key names and reference file count, or None when masking is off.
pub fn summary() -> Option<(Vec<String>, usize)> {
    let mut mask = match global().lock() {
        Ok(mask) => mask,
        Err(poisoned) => poisoned.into_inner(),
    };
    let path = config_path();
    if mask.config_path != path {
        *mask = SecretMask::new(path);
    }
    mask.summary()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(keys: &[&str]) -> Vec<String> {
        keys.iter().map(|k| k.to_string()).collect()
    }

    #[test]
    fn parses_export_quotes_comments_and_skips_expansions() {
        let text = "\
export OPENAI_API_KEY=sk-test-synthetic-0001
GITHUB_TOKEN=\"ghp-synthetic-value-0002\"
  export DB_PASSWORD='single quoted value'  # trailing comment
STRIPE_SECRET=unquoted-value-0003 # comment
HASH_SECRET=abc#def-not-a-comment
SHORT_TOKEN=tiny
EXPANDED_TOKEN=$HOME/token-value
BACKTICK_TOKEN=`cat /dev/null`-value
UNTERMINATED_TOKEN=\"never closed value
CONCAT_TOKEN=\"first part\"second
PATH=/usr/local/bin:/usr/bin
1BAD_KEY=leading-digit-value
BAD-NAME_KEY=hyphenated-name-value
export
# COMMENTED_TOKEN=commented-out-value
";
        let pairs = parse_env_text(text, None, DEFAULT_MIN_LENGTH);
        let expected = [
            ("OPENAI_API_KEY", "sk-test-synthetic-0001"),
            ("GITHUB_TOKEN", "ghp-synthetic-value-0002"),
            ("DB_PASSWORD", "single quoted value"),
            ("STRIPE_SECRET", "unquoted-value-0003"),
            ("HASH_SECRET", "abc#def-not-a-comment"),
        ];
        assert_eq!(
            pairs,
            expected
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn min_length_counts_characters_and_never_admits_empty_values() {
        let text = "API_KEY=abcdefg\nAPI_TOKEN=abcdefgh\nEMPTY_KEY=\nQUOTED_KEY=\"\"";
        let names = |min| {
            parse_env_text(text, None, min)
                .into_iter()
                .map(|(n, _)| n)
                .collect::<Vec<_>>()
        };
        assert_eq!(names(8), ["API_TOKEN"]);
        assert_eq!(names(7), ["API_KEY", "API_TOKEN"]);
        assert_eq!(names(0), ["API_KEY", "API_TOKEN"]);
    }

    #[test]
    fn default_selectors_cover_the_documented_fragments() {
        for name in [
            "OPENAI_API_KEY",
            "github_token",
            "Client_Secret",
            "DB_PASSWORD",
            "MYSQL_PASSWD",
            "SMTP_PASS",
            "REDIS_PW",
            "GCP_CREDENTIALS",
            "BASIC_AUTH",
            "PRIVATE_PEM",
            "TWILIO_SID",
            "SENTRY_DSN",
            "SLACK_WEBHOOK",
            "SESSION_COOKIE",
            "OAUTH_CLIENT_ID",
            "AWS_ACCOUNT_ID",
            "APIURL",
        ] {
            assert!(key_selected(name, None), "{name}");
        }
        for name in ["HOME", "EDITOR", "LANG", "PATH", "GOPATH"] {
            assert!(!key_selected(name, None), "{name}");
        }
    }

    #[test]
    fn custom_selectors_match_full_names_substrings_and_globs() {
        let keys = owned(&["openai_api_key", "STRIPE", "AWS_*_KEY", "*", ""]);
        let keys = Some(keys.as_slice());
        assert!(key_selected("OPENAI_API_KEY", keys));
        assert!(key_selected("stripe_live", keys));
        assert!(key_selected("AWS_SECRET_ACCESS_KEY", keys));
        assert!(!key_selected("AWS_REGION", keys));
        assert!(
            !key_selected("GITHUB_TOKEN", keys),
            "custom keys replace the defaults"
        );
        assert!(!key_selected(
            "ANYTHING",
            Some(owned(&["*", ""]).as_slice())
        ));
    }

    #[test]
    fn replaces_longest_first_and_first_name_owns_a_shared_value() {
        let pairs = vec![
            (
                "FIRST_TOKEN".to_string(),
                "shared-synthetic-value".to_string(),
            ),
            (
                "SECOND_TOKEN".to_string(),
                "shared-synthetic-value".to_string(),
            ),
            ("SHORT_TOKEN".to_string(), "synthetic".to_string()),
            ("QUOTE_TOKEN".to_string(), "has\"quote-value".to_string()),
        ];
        let table = build_table(&pairs);
        let text = "a=shared-synthetic-value b=synthetic-x";
        assert_eq!(mask_text(text, &table), "a=$FIRST_TOKEN b=$SHORT_TOKEN-x");
        let json = serde_json::json!({"command": "echo has\"quote-value"}).to_string();
        assert!(!mask_text(&json, &table).contains("quote-value"));
        assert!(mask_text(&json, &table).contains("$QUOTE_TOKEN"));
        assert_eq!(
            masked_names("x shared-synthetic-value y", &table),
            ["FIRST_TOKEN"]
        );
        assert!(masked_names("nothing here", &table).is_empty());
    }

    #[test]
    fn a_name_defined_twice_masks_both_values() {
        let pairs = parse_env_text(
            "API_TOKEN=first-synthetic-0001\nexport API_TOKEN=second-synthetic-0002\n",
            None,
            DEFAULT_MIN_LENGTH,
        );
        let table = build_table(&pairs);
        assert_eq!(
            mask_text("first-synthetic-0001 second-synthetic-0002", &table),
            "$API_TOKEN $API_TOKEN"
        );
    }

    #[test]
    fn reloads_on_change_and_warns_once_for_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join(CONFIG_FILE);
        let profile = dir.path().join("profile");
        let mut mask = SecretMask::new(config.clone());
        assert!(mask.table().is_empty(), "no config: off");

        std::fs::write(&config, "files: [profile, missing-profile]\n").unwrap();
        std::fs::write(&profile, "export API_TOKEN=first-synthetic-value\n").unwrap();
        assert_eq!(
            mask_text("first-synthetic-value", &mask.table()),
            "$API_TOKEN"
        );
        assert_eq!(mask.warned.len(), 1, "missing file warns once");
        mask.table();
        assert_eq!(mask.warned.len(), 1);

        std::fs::write(&profile, "export API_TOKEN=second-synthetic-value-longer\n").unwrap();
        let table = mask.table();
        assert_eq!(
            mask_text("second-synthetic-value-longer", &table),
            "$API_TOKEN"
        );
        assert_eq!(
            mask_text("first-synthetic-value", &table),
            "first-synthetic-value"
        );
        assert_eq!(mask.summary(), Some((vec!["API_TOKEN".to_string()], 2)));

        std::fs::write(&config, "files: [profile]\nunknown_field: 1\n").unwrap();
        assert!(mask.table().is_empty(), "invalid config: off");
        std::fs::remove_file(&config).unwrap();
        assert!(mask.table().is_empty());
        assert_eq!(mask.summary(), None);
    }
}

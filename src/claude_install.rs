//! Explicit, recoverable installation of the adapter embedded in the binary.
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

const NAME: &str = "signet-eval-functions";
/// The one Claude Code build the embedded adapter was qualified against. The
/// function-hook API is early access and renames events between releases, so a
/// module written for one build can fail to load on the next.
const QUALIFIED_CLAUDE_VERSION: &str = "2.1.274";
const ASSETS: [(&str, &str); 3] = [
    (
        ".claude-plugin/plugin.json",
        include_str!("../adapters/claude-function/.claude-plugin/plugin.json"),
    ),
    (
        "hooks/hooks.json",
        include_str!("../adapters/claude-function/hooks/hooks.json"),
    ),
    (
        "hooks/signet.ts",
        include_str!("../adapters/claude-function/hooks/signet.ts"),
    ),
];

fn no_links(path: &Path) -> Result<(), &'static str> {
    for ancestor in path.ancestors() {
        if ancestor.is_symlink() {
            return Err("linked_install_path");
        }
    }
    Ok(())
}

fn read_settings(path: &Path) -> Result<(Option<Vec<u8>>, Value), &'static str> {
    match fs::read(path) {
        Ok(bytes) => {
            let value: Value = serde_json::from_slice(&bytes).map_err(|_| "invalid_settings")?;
            if !value.is_object() {
                return Err("invalid_settings");
            }
            Ok((Some(bytes), value))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok((None, json!({}))),
        Err(_) => Err("settings_unreadable"),
    }
}

fn section<'a>(
    data: &'a mut Value,
    name: &str,
) -> Result<&'a mut serde_json::Map<String, Value>, &'static str> {
    if data.get(name).is_none() {
        data[name] = json!({});
    }
    data[name].as_object_mut().ok_or("invalid_settings_section")
}

fn retire_handlers(data: &mut Value, executable: &str) -> Result<usize, &'static str> {
    let mut retired = 0;
    if let Some(hooks) = data.get_mut("hooks") {
        for entries in hooks.as_object_mut().ok_or("invalid_hooks")?.values_mut() {
            let entries = entries.as_array_mut().ok_or("invalid_hooks")?;
            for entry in entries.iter_mut() {
                let handlers = entry
                    .get_mut("hooks")
                    .and_then(Value::as_array_mut)
                    .ok_or("invalid_hooks")?;
                handlers.retain(|handler| {
                    let owned = handler["type"] == "command"
                        && handler["command"].as_str().is_some_and(|command| {
                            ["signet-eval", executable].iter().any(|binary| {
                                ["", " eval", " --adapter claude"]
                                    .iter()
                                    .any(|suffix| command == format!("{binary}{suffix}"))
                            })
                        });
                    if owned {
                        retired += 1;
                    }
                    !owned
                });
                if handlers.iter().any(|handler| {
                    handler["command"].as_str().is_some_and(|command| {
                        command.contains("signet-eval") || command.contains("signet_eval")
                    })
                }) {
                    return Err("unrecognized_signet_handler_requires_manual_review");
                }
            }
            entries.retain(|entry| !entry["hooks"].as_array().is_some_and(Vec::is_empty));
        }
    }
    if data["enabledPlugins"].as_object().is_some_and(|plugins| {
        plugins.iter().any(|(name, enabled)| {
            enabled == true && (name == "signet-eval" || name.starts_with("signet-eval@"))
        })
    }) {
        return Err("legacy_signet_plugin_requires_manual_review");
    }
    Ok(retired)
}

fn write_synced(path: &Path, bytes: &[u8]) -> Result<(), &'static str> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "install_write_failed")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| "install_write_failed")?;
    }
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "install_write_failed")
}

pub fn install_modern() -> Result<Value, &'static str> {
    let version = Command::new("claude")
        .arg("--version")
        .output()
        .map_err(|_| "claude_unavailable")?;
    if !version.status.success()
        || String::from_utf8_lossy(&version.stdout)
            .split_whitespace()
            .next()
            != Some(QUALIFIED_CLAUDE_VERSION)
    {
        return Err("unqualified_claude_version_use_legacy");
    }
    let base = std::env::var("CLAUDE_CONFIG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(".claude")
        });
    if !base.is_absolute() {
        return Err("absolute_config_directory_required");
    }
    let settings = base.join("settings.json");
    let plugin = base.join("skills").join(NAME);
    no_links(&settings)?;
    no_links(&plugin)?;
    let (before, mut data) = read_settings(&settings)?;
    let executable = std::env::current_exe().map_err(|_| "executable_unavailable")?;
    let executable = executable.to_str().ok_or("invalid_executable_path")?;
    let retired = retire_handlers(&mut data, executable)?;
    if plugin.exists() {
        let manifest = plugin.join(".claude-plugin/plugin.json");
        no_links(&manifest)?;
        let (_, existing) = read_settings(&manifest)?;
        if existing["name"] != NAME {
            return Err("unowned_plugin_directory");
        }
    }
    section(&mut data, "env")?.insert("CLAUDE_CODE_ENABLE_FUNCTION_HOOKS".into(), json!("1"));
    section(&mut data, "enabledPlugins")?.insert(format!("{NAME}@skills-dir"), json!(true));
    let config = section(&mut data, "pluginConfigs")?
        .entry(format!("{NAME}@skills-dir"))
        .or_insert(json!({}));
    let options = section(config, "options")?;
    options.insert("enabled".into(), json!(true));
    options.insert("executable".into(), json!(executable));

    // Stage outside skills discovery. Only complete embedded assets become visible.
    fs::create_dir_all(&base).map_err(|_| "install_write_failed")?;
    let id = crate::vault::random_hex_id();
    let backup = base.join("signet-adapter-backups").join(&id);
    no_links(&backup)?;
    fs::create_dir_all(&backup).map_err(|_| "install_write_failed")?;
    let staged = backup.join("new-plugin");
    for (relative, contents) in ASSETS {
        let path = staged.join(relative);
        fs::create_dir_all(path.parent().ok_or("invalid_asset_path")?)
            .map_err(|_| "install_write_failed")?;
        write_synced(&path, contents.as_bytes())?;
    }
    if let Some(bytes) = &before {
        write_synced(&backup.join("settings.json"), bytes)?;
    }
    let next = backup.join("new-settings.json");
    write_synced(
        &next,
        serde_json::to_string_pretty(&data)
            .map_err(|_| "invalid_settings")?
            .as_bytes(),
    )?;
    if read_settings(&settings)?.0 != before {
        return Err("settings_changed_retry_install");
    }
    fs::create_dir_all(plugin.parent().ok_or("invalid_plugin_path")?)
        .map_err(|_| "install_write_failed")?;
    let previous = backup.join("previous-plugin");
    if plugin.exists() {
        fs::rename(&plugin, &previous).map_err(|_| "plugin_backup_failed")?;
    }
    if fs::rename(&staged, &plugin).is_err() {
        if previous.exists() {
            let _ = fs::rename(&previous, &plugin);
        }
        return Err("plugin_install_failed_backup_retained");
    }
    if fs::rename(&next, &settings).is_err() {
        let _ = fs::rename(&plugin, &staged);
        if previous.exists() {
            let _ = fs::rename(&previous, &plugin);
        }
        return Err("settings_install_failed_backup_retained");
    }
    Ok(
        json!({"protocol_version":1,"owner":"signet-eval","status":"installed",
        "plugin_path":plugin,"backup_path":backup,"legacy_handlers_retired":retired,
        "enforcement_disabled":crate::vault::is_disabled_file(),
        "message":"Embedded modern adapter installed. Restart Claude; enforcement disabled state was not changed."}),
    )
}

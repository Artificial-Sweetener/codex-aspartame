use std::path::Path;

use anyhow::Result;
use assert_cmd::Command;
use base64::Engine;
use chrono::Duration as ChronoDuration;
use chrono::Utc;
use codex_app_server_protocol::AuthMode;
use codex_core::auth::AccountAuth;
use codex_core::auth::AuthDotJson;
use codex_core::auth::UsageLogEntry;
use codex_core::auth::append_usage_log;
use codex_core::auth::get_auth_file;
use codex_core::auth::load_auth_accounts;
use codex_core::auth::write_auth_json;
use codex_core::token_data::TokenData;
use codex_core::token_data::parse_id_token;
use pretty_assertions::assert_eq;
use serde_json::Value as JsonValue;
use tempfile::TempDir;
use uuid::Uuid;

use codex_core::auth::TokenCounters;

fn codex_command(codex_home: &Path) -> Result<Command> {
    let mut cmd = Command::cargo_bin("codex")?;
    cmd.env("CODEX_HOME", codex_home);
    Ok(cmd)
}

fn fake_jwt(plan: &str, account_id: &str) -> String {
    let header = serde_json::json!({ "alg": "none", "typ": "JWT" });
    let payload = serde_json::json!({
        "email": "user@example.com",
        "https://api.openai.com/auth": {
            "chatgpt_plan_type": plan,
            "chatgpt_account_id": account_id
        }
    });
    let encode = |value: &serde_json::Value| {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(value).unwrap_or_else(|err| panic!("serialize json: {err}")))
    };
    let header_b64 = encode(&header);
    let payload_b64 = encode(&payload);
    let signature_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"sig");
    format!("{header_b64}.{payload_b64}.{signature_b64}")
}

fn chatgpt_account(label: &str, plan: &str) -> AccountAuth {
    let account_id = Uuid::new_v4().to_string();
    let fake_jwt = fake_jwt(plan, &account_id);
    let token_data = TokenData {
        id_token: parse_id_token(&fake_jwt).unwrap_or_else(|err| panic!("parse fake jwt: {err}")),
        access_token: format!("access-{account_id}"),
        refresh_token: format!("refresh-{account_id}"),
        account_id: Some(account_id),
    };
    let auth = AuthDotJson {
        openai_api_key: None,
        tokens: Some(token_data),
        last_refresh: Some(Utc::now()),
    };
    let mut account = AccountAuth::new(AuthMode::ChatGPT, auth);
    account.label = Some(label.to_string());
    account
}

fn api_key_account(label: &str) -> AccountAuth {
    let auth = AuthDotJson {
        openai_api_key: Some("sk-test".to_string()),
        tokens: None,
        last_refresh: None,
    };
    let mut account = AccountAuth::new(AuthMode::ApiKey, auth);
    account.label = Some(label.to_string());
    account
}

#[test]
fn auth_list_and_status_json() -> Result<()> {
    let codex_home = TempDir::new()?;

    let mut chatgpt = chatgpt_account("Primary", "pro");
    chatgpt.priority = 1;
    chatgpt.lifetime_usage.total_input_tokens = 900;
    chatgpt.lifetime_usage.total_output_tokens = 600;
    chatgpt.lifetime_usage.total_combined_tokens = 1500;
    chatgpt.lifetime_usage.cooldown_window_input = 100;
    chatgpt.lifetime_usage.cooldown_window_output = 50;
    chatgpt.cooldown_until = Some(Utc::now() + ChronoDuration::minutes(30));
    chatgpt.last_error = Some("rate limited".to_string());

    let mut api_key = api_key_account("API Key");
    api_key.priority = 5;
    api_key.lifetime_usage.total_combined_tokens = 250;

    write_auth_json(&get_auth_file(codex_home.path()), &[chatgpt, api_key])?;

    let mut list_cmd = codex_command(codex_home.path())?;
    let list_output = list_cmd.args(["auth", "list"]).output()?;
    assert!(list_output.status.success());
    let stdout = String::from_utf8(list_output.stdout)?;
    assert!(stdout.contains("Primary"));
    assert!(stdout.contains("ChatGPT Pro"));
    assert!(stdout.contains("cooldown"));
    assert!(stdout.contains("API Key"));

    let mut status_cmd = codex_command(codex_home.path())?;
    let status_output = status_cmd.args(["auth", "status", "--json"]).output()?;
    assert!(status_output.status.success());
    let status_stdout = String::from_utf8(status_output.stdout)?;
    let parsed: JsonValue = serde_json::from_str(&status_stdout)?;

    assert!(parsed["schema"].is_object());
    assert!(parsed["schema"]["properties"].is_object() || parsed["schema"]["schema"].is_object());

    let accounts = parsed["status"]["accounts"]
        .as_array()
        .expect("accounts array");
    assert_eq!(accounts.len(), 2);
    let primary = accounts
        .iter()
        .find(|entry| entry["label"].as_str() == Some("Primary"))
        .expect("primary account present");
    assert_eq!(primary["cooldown"]["active"], JsonValue::Bool(true));
    assert_eq!(
        primary["since_last_cooldown"]["total"],
        JsonValue::from(150)
    );
    assert_eq!(
        primary["cooldown"]["last_cooldown"]["total"],
        JsonValue::from(150)
    );

    Ok(())
}

#[test]
fn auth_history_and_clear_cooldown() -> Result<()> {
    let codex_home = TempDir::new()?;

    let mut account = chatgpt_account("History", "plus");
    account.lifetime_usage.cooldown_window_input = 75;
    account.lifetime_usage.cooldown_window_output = 25;
    account.cooldown_until = Some(Utc::now() + ChronoDuration::minutes(10));
    account.last_error = Some("previous limit".to_string());

    let account_id = account.id;
    write_auth_json(&get_auth_file(codex_home.path()), &[account])?;

    append_usage_log(
        codex_home.path(),
        &UsageLogEntry {
            timestamp: Utc::now() - ChronoDuration::minutes(5),
            account_id,
            tokens_since_last_cooldown: TokenCounters {
                total_input_tokens: 40,
                total_output_tokens: 20,
                total_combined_tokens: 60,
                cooldown_window_input: 40,
                cooldown_window_output: 20,
            },
            resets_in_seconds: 120,
            reason: Some("first".to_string()),
            usage_snapshot: None,
            plan_type: Some("Plus".to_string()),
        },
    )?;

    append_usage_log(
        codex_home.path(),
        &UsageLogEntry {
            timestamp: Utc::now(),
            account_id,
            tokens_since_last_cooldown: TokenCounters {
                total_input_tokens: 55,
                total_output_tokens: 15,
                total_combined_tokens: 70,
                cooldown_window_input: 55,
                cooldown_window_output: 15,
            },
            resets_in_seconds: 60,
            reason: Some("latest".to_string()),
            usage_snapshot: None,
            plan_type: Some("Plus".to_string()),
        },
    )?;

    let mut history_cmd = codex_command(codex_home.path())?;
    let history_output = history_cmd
        .args(["auth", "history", "--limit", "1"])
        .output()?;
    assert!(history_output.status.success());
    let history_stdout = String::from_utf8(history_output.stdout)?;
    assert!(history_stdout.contains("latest"));
    assert!(!history_stdout.contains("first"));

    let mut clear_cmd = codex_command(codex_home.path())?;
    clear_cmd
        .args(["auth", "clear-cooldown", &account_id.to_string()])
        .assert()
        .success()
        .stdout(predicates::str::contains("Cleared cooldown"));

    let accounts = load_auth_accounts(&get_auth_file(codex_home.path()))?;
    assert_eq!(accounts.len(), 1);
    let cleared = &accounts[0];
    assert!(cleared.cooldown_until.is_none());
    assert!(cleared.last_error.is_none());
    assert_eq!(cleared.lifetime_usage.cooldown_window_input, 0);
    assert_eq!(cleared.lifetime_usage.cooldown_window_output, 0);

    Ok(())
}

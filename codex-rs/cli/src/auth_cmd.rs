use anyhow::{Context, Result, anyhow, bail};
use chrono::Duration as ChronoDuration;
use chrono::Utc;
use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;
use codex_app_server_protocol::AuthMode;
use codex_cli::login::login_with_chatgpt;
use codex_cli::login::read_api_key_from_stdin;
use codex_common::CliConfigOverrides;
use codex_core::auth;
use codex_core::auth::AccountAuth;
use codex_core::auth::AccountSummary;
use codex_core::auth::AuthDotJson;
use codex_core::auth::AuthManager;
use codex_core::config::Config;
use codex_core::config::ConfigOverrides;
use schemars::JsonSchema;
use schemars::schema::RootSchema;
use schemars::schema_for;
use serde::Serialize;
use std::collections::HashMap;
use tempfile::TempDir;
use uuid::Uuid;

const DEFAULT_HISTORY_LIMIT: usize = 10;

#[derive(Debug, Parser)]
pub struct AuthCommand {
    #[clap(skip)]
    pub config_overrides: CliConfigOverrides,

    #[command(subcommand)]
    pub action: AuthSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum AuthSubcommand {
    /// Add a new authentication account.
    Add(AuthAddCommand),
    /// Remove an existing authentication account by id.
    Remove { id: String },
    /// List configured accounts.
    List,
    /// Show detailed account status.
    Status(AuthStatusCommand),
    /// Show recent usage history entries.
    History(AuthHistoryCommand),
    /// Clear cooldown information for an account.
    ClearCooldown { id: String },
}

#[derive(Debug, Parser)]
pub struct AuthAddCommand {
    /// Type of authentication to add.
    #[clap(long, value_enum)]
    pub mode: AuthAddMode,

    /// Optional label to associate with the account.
    #[clap(long)]
    pub label: Option<String>,

    /// Optional priority for account selection (lower values win).
    #[clap(long)]
    pub priority: Option<u32>,
}

#[derive(Debug, Parser)]
pub struct AuthStatusCommand {
    /// Emit JSON (with schema) instead of a human-readable summary.
    #[clap(long)]
    pub json: bool,
}

#[derive(Debug, Parser)]
pub struct AuthHistoryCommand {
    /// Maximum number of entries to display (0 shows all entries).
    #[clap(long)]
    pub limit: Option<usize>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum AuthAddMode {
    Chatgpt,
    ApiKey,
}

pub async fn run_auth_command(command: AuthCommand) -> Result<()> {
    let AuthCommand {
        config_overrides,
        action,
    } = command;

    let cli_overrides = config_overrides.parse_overrides().map_err(|e| anyhow!(e))?;

    let config = Config::load_with_cli_overrides(cli_overrides, ConfigOverrides::default())
        .await
        .context("loading configuration")?;

    let manager = AuthManager::new(config.codex_home.clone(), true);

    match action {
        AuthSubcommand::Add(args) => handle_add(&manager, args).await?,
        AuthSubcommand::Remove { id } => handle_remove(&manager, &id)?,
        AuthSubcommand::List => handle_list(&manager),
        AuthSubcommand::Status(args) => handle_status(&manager, args)?,
        AuthSubcommand::History(args) => handle_history(&manager, args)?,
        AuthSubcommand::ClearCooldown { id } => handle_clear_cooldown(&manager, &id)?,
    }

    Ok(())
}

async fn handle_add(manager: &AuthManager, args: AuthAddCommand) -> Result<()> {
    let AuthAddCommand {
        mode,
        label,
        priority,
    } = args;

    let label = normalize_label(label);

    let mut account = match mode {
        AuthAddMode::ApiKey => create_api_key_account(),
        AuthAddMode::Chatgpt => Ok(create_chatgpt_account().await?),
    }?;

    if let Some(label) = label.clone() {
        account.label = Some(label);
    }
    if let Some(priority) = priority {
        account.priority = priority;
    }

    let id = manager.add_account(account)?;
    let label_suffix = label
        .as_deref()
        .map(|label| format!(" ({label})"))
        .unwrap_or_default();
    println!("Added account {id}{label_suffix}");
    Ok(())
}

fn create_api_key_account() -> Result<AccountAuth> {
    let api_key = read_api_key_from_stdin();
    let auth = AuthDotJson {
        openai_api_key: Some(api_key),
        tokens: None,
        last_refresh: None,
    };
    Ok(AccountAuth::new(AuthMode::ApiKey, auth))
}

async fn create_chatgpt_account() -> Result<AccountAuth> {
    let temp_dir = TempDir::new().context("creating temporary directory for login")?;
    login_with_chatgpt(temp_dir.path().to_path_buf())
        .await
        .context("chatgpt login flow failed")?;

    let auth_file = auth::get_auth_file(temp_dir.path());
    let accounts = auth::load_auth_accounts(&auth_file)
        .context("reading login credentials from temporary auth.json")?;
    accounts
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("login did not produce authentication credentials"))
}

fn normalize_label(label: Option<String>) -> Option<String> {
    label.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn handle_remove(manager: &AuthManager, id: &str) -> Result<()> {
    let uuid = parse_account_id(id)?;
    if manager.logout(uuid)? {
        println!("Removed account {uuid}");
        Ok(())
    } else {
        bail!("Account {uuid} not found");
    }
}

fn handle_list(manager: &AuthManager) {
    let accounts = manager.accounts();
    if accounts.is_empty() {
        println!("No accounts configured.");
        return;
    }

    println!(
        "{:<45} {:<16} {:<24} {:>16}",
        "Label (id)", "Plan", "Status", "Lifetime total"
    );
    for summary in accounts {
        let label = display_label(&summary);
        let plan = display_plan(&summary);
        let status = display_status(&summary);
        let total = summary.lifetime_usage.total_combined_tokens;
        println!("{label:<45} {plan:<16} {status:<24} {total:>16}");
    }
}

fn handle_status(manager: &AuthManager, args: AuthStatusCommand) -> Result<()> {
    let accounts = manager.accounts();
    if args.json {
        let now = Utc::now();
        let data = AuthStatusData {
            generated_at: now.to_rfc3339(),
            accounts: accounts
                .iter()
                .map(|summary| build_status_account(summary, now))
                .collect(),
        };
        let schema: RootSchema = schema_for!(AuthStatusData);
        let output = AuthStatusOutput {
            schema: serde_json::to_value(schema).context("serializing status schema")?,
            status: data,
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&output).context("serializing status JSON")?
        );
        return Ok(());
    }

    if accounts.is_empty() {
        println!("No accounts configured.");
        return Ok(());
    }

    let now = Utc::now();
    for summary in accounts {
        println!("ID: {}", summary.id);
        println!("Label: {}", summary.label.as_deref().unwrap_or("(none)"));
        println!(
            "Mode: {}  Priority: {}",
            display_mode(summary.mode),
            summary.priority
        );
        let plan_display = display_plan(&summary);
        if let Some(plan) = plan_display.strip_prefix("ChatGPT ") {
            println!("Plan: ChatGPT {plan}");
        } else {
            println!("Plan: {plan_display}");
        }
        if let Some(refresh) = summary.last_refresh {
            println!("Last refresh: {}", refresh.to_rfc3339());
        }

        let cooldown_text = if let Some(until) = summary.cooldown_until {
            if until > now {
                let remaining = until - now;
                format!(
                    "active until {} ({} remaining)",
                    until.to_rfc3339(),
                    format_duration(remaining)
                )
            } else {
                "expired".to_string()
            }
        } else {
            "inactive".to_string()
        };
        println!("Cooldown: {cooldown_text}");
        if let Some(reason) = &summary.last_error {
            println!("Last cooldown reason: {reason}");
        }

        println!(
            "Lifetime tokens: input={} output={} total={}",
            summary.lifetime_usage.total_input_tokens,
            summary.lifetime_usage.total_output_tokens,
            summary.lifetime_usage.total_combined_tokens
        );

        let last_cooldown_total = summary.lifetime_usage.cooldown_window_input
            + summary.lifetime_usage.cooldown_window_output;
        println!(
            "Last cooldown tokens: input={} output={} total={}",
            summary.lifetime_usage.cooldown_window_input,
            summary.lifetime_usage.cooldown_window_output,
            last_cooldown_total
        );

        let usage = &summary.tokens_since_last_cooldown;
        println!(
            "Tokens since last cooldown: input={} cached={} output={} reasoning={} total={}",
            usage.input_tokens,
            usage.cached_input_tokens,
            usage.output_tokens,
            usage.reasoning_output_tokens,
            usage.total_tokens
        );
        println!();
    }

    Ok(())
}

fn handle_history(manager: &AuthManager, args: AuthHistoryCommand) -> Result<()> {
    let limit = args.limit.unwrap_or(DEFAULT_HISTORY_LIMIT);
    let entries = if limit == 0 {
        manager.usage_history(None)?
    } else {
        manager.usage_history(Some(limit))?
    };

    if entries.is_empty() {
        println!("No usage history recorded.");
        return Ok(());
    }

    let accounts = manager.accounts();
    let mut labels: HashMap<Uuid, AccountSummary> = HashMap::new();
    for summary in accounts {
        labels.insert(summary.id, summary);
    }

    for entry in entries {
        let label = labels
            .get(&entry.account_id)
            .map(display_label)
            .unwrap_or_else(|| entry.account_id.to_string());
        let counters = &entry.tokens_since_last_cooldown;
        let mut extras = String::new();
        if let Some(plan) = entry.plan_type.as_deref() {
            extras.push_str(&format!(" plan={plan}"));
        }
        if let Some(reason) = entry.reason.as_deref() {
            extras.push_str(&format!(" reason={reason}"));
        }
        println!(
            "{} {} total={} input={} output={} resets_in={}s{}",
            entry.timestamp.to_rfc3339(),
            label,
            counters.total_combined_tokens,
            counters.total_input_tokens,
            counters.total_output_tokens,
            entry.resets_in_seconds,
            extras
        );
    }

    Ok(())
}

fn handle_clear_cooldown(manager: &AuthManager, id: &str) -> Result<()> {
    let uuid = parse_account_id(id)?;
    if manager.clear_cooldown(uuid)? {
        println!("Cleared cooldown for {uuid}");
        Ok(())
    } else {
        bail!("Account {uuid} not found");
    }
}

fn parse_account_id(id: &str) -> Result<Uuid> {
    Uuid::parse_str(id).map_err(|e| anyhow!("invalid account id '{id}': {e}"))
}

fn display_label(summary: &AccountSummary) -> String {
    match summary.label.as_deref() {
        Some(label) => format!("{label} ({})", summary.id),
        None => summary.id.to_string(),
    }
}

fn display_plan(summary: &AccountSummary) -> String {
    match (&summary.plan, summary.mode) {
        (Some(plan), AuthMode::ChatGPT) => format!("ChatGPT {plan}"),
        (Some(plan), _) => plan.clone(),
        (None, AuthMode::ApiKey) => "API key".to_string(),
        (None, AuthMode::ChatGPT) => "ChatGPT".to_string(),
    }
}

fn display_mode(mode: AuthMode) -> &'static str {
    match mode {
        AuthMode::ApiKey => "api-key",
        AuthMode::ChatGPT => "chatgpt",
    }
}

fn display_status(summary: &AccountSummary) -> String {
    match summary.cooldown_until {
        Some(until) => {
            if until > Utc::now() {
                let remaining = until - Utc::now();
                format!("cooldown ({})", format_duration(remaining))
            } else {
                "active".to_string()
            }
        }
        None => "active".to_string(),
    }
}

fn format_duration(duration: ChronoDuration) -> String {
    let mut seconds = duration.num_seconds();
    if seconds < 0 {
        seconds = 0;
    }
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let secs = seconds % 60;

    let mut parts = Vec::new();
    if hours > 0 {
        parts.push(format!("{hours}h"));
    }
    if minutes > 0 {
        parts.push(format!("{minutes}m"));
    }
    if hours == 0 && minutes == 0 {
        parts.push(format!("{secs}s"));
    }

    parts.join(" ")
}

fn build_status_account(summary: &AccountSummary, now: chrono::DateTime<Utc>) -> AuthStatusAccount {
    let cooldown_active = summary
        .cooldown_until
        .map(|until| until > now)
        .unwrap_or(false);
    let remaining_seconds = summary.cooldown_until.and_then(|until| {
        if until > now {
            Some((until - now).num_seconds().max(0) as u64)
        } else {
            None
        }
    });
    let cooldown_until = summary.cooldown_until.map(|until| until.to_rfc3339());
    let last_refresh = summary.last_refresh.map(|value| value.to_rfc3339());
    let last_cooldown = CooldownTokens {
        input: summary.lifetime_usage.cooldown_window_input,
        output: summary.lifetime_usage.cooldown_window_output,
        total: summary.lifetime_usage.cooldown_window_input
            + summary.lifetime_usage.cooldown_window_output,
    };

    AuthStatusAccount {
        id: summary.id.to_string(),
        label: summary.label.clone(),
        mode: display_mode(summary.mode).to_string(),
        plan: match (&summary.plan, summary.mode) {
            (Some(plan), AuthMode::ChatGPT) => Some(format!("ChatGPT {plan}")),
            (Some(plan), _) => Some(plan.clone()),
            (None, AuthMode::ApiKey) => Some("API key".to_string()),
            (None, AuthMode::ChatGPT) => Some("ChatGPT".to_string()),
        },
        priority: summary.priority,
        cooldown: CooldownInfo {
            active: cooldown_active,
            until: cooldown_until,
            remaining_seconds,
            reason: summary.last_error.clone(),
            last_cooldown,
        },
        lifetime: LifetimeUsage {
            total_input: summary.lifetime_usage.total_input_tokens,
            total_output: summary.lifetime_usage.total_output_tokens,
            total_combined: summary.lifetime_usage.total_combined_tokens,
        },
        since_last_cooldown: TokenUsageJson {
            input: summary.tokens_since_last_cooldown.input_tokens,
            cached_input: summary.tokens_since_last_cooldown.cached_input_tokens,
            output: summary.tokens_since_last_cooldown.output_tokens,
            reasoning_output: summary.tokens_since_last_cooldown.reasoning_output_tokens,
            total: summary.tokens_since_last_cooldown.total_tokens,
        },
        last_refresh,
    }
}

#[derive(Debug, Serialize)]
struct AuthStatusOutput {
    schema: serde_json::Value,
    status: AuthStatusData,
}

#[derive(Debug, Serialize, JsonSchema)]
struct AuthStatusData {
    generated_at: String,
    accounts: Vec<AuthStatusAccount>,
}

#[derive(Debug, Serialize, JsonSchema)]
struct AuthStatusAccount {
    id: String,
    label: Option<String>,
    mode: String,
    plan: Option<String>,
    priority: u32,
    cooldown: CooldownInfo,
    lifetime: LifetimeUsage,
    since_last_cooldown: TokenUsageJson,
    last_refresh: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
struct CooldownInfo {
    active: bool,
    until: Option<String>,
    remaining_seconds: Option<u64>,
    reason: Option<String>,
    last_cooldown: CooldownTokens,
}

#[derive(Debug, Serialize, JsonSchema)]
struct CooldownTokens {
    total: u64,
    input: u64,
    output: u64,
}

#[derive(Debug, Serialize, JsonSchema)]
struct LifetimeUsage {
    total_input: u64,
    total_output: u64,
    total_combined: u64,
}

#[derive(Debug, Serialize, JsonSchema)]
struct TokenUsageJson {
    input: u64,
    cached_input: u64,
    output: u64,
    reasoning_output: u64,
    total: u64,
}

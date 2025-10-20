use chrono::DateTime;
use chrono::Utc;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::cmp::Ordering;
use std::env;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Error;
use std::io::Read;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use uuid::Uuid;

use codex_app_server_protocol::AuthMode;

use crate::protocol::RateLimitSnapshot;
use crate::protocol::RateLimitWindow;
use crate::protocol::TokenUsage;
use crate::token_data::PlanType;
use crate::token_data::TokenData;
use crate::token_data::parse_id_token;

#[derive(Debug, Clone)]
pub struct CodexAuth {
    pub mode: AuthMode,

    pub(crate) account_auth_id: Option<Uuid>,

    pub(crate) api_key: Option<String>,
    pub(crate) auth_dot_json: Arc<Mutex<Option<AuthDotJson>>>,
    pub(crate) auth_file: PathBuf,
    pub(crate) client: reqwest::Client,
}

impl PartialEq for CodexAuth {
    fn eq(&self, other: &Self) -> bool {
        self.mode == other.mode && self.account_auth_id == other.account_auth_id
    }
}

impl CodexAuth {
    pub async fn refresh_token(&self) -> Result<String, std::io::Error> {
        let token_data = self
            .get_current_token_data()
            .ok_or(std::io::Error::other("Token data is not available."))?;
        let token = token_data.refresh_token;

        let refresh_response = try_refresh_token(token, &self.client)
            .await
            .map_err(std::io::Error::other)?;

        let updated = update_tokens(
            &self.auth_file,
            self.account_auth_id,
            refresh_response.id_token,
            refresh_response.access_token,
            refresh_response.refresh_token,
        )
        .await?;

        if let Ok(mut auth_lock) = self.auth_dot_json.lock() {
            *auth_lock = Some(updated.auth_dot_json.clone());
        }

        let access = match updated.auth_dot_json.tokens {
            Some(t) => t.access_token,
            None => {
                return Err(std::io::Error::other(
                    "Token data is not available after refresh.",
                ));
            }
        };
        Ok(access)
    }

    /// Loads the available auth information from the auth.json.
    pub fn from_codex_home(codex_home: &Path) -> std::io::Result<Option<CodexAuth>> {
        load_auth(codex_home, false)
    }

    pub async fn get_token_data(&self) -> Result<TokenData, std::io::Error> {
        let auth_dot_json: Option<AuthDotJson> = self.get_current_auth_json();
        match auth_dot_json {
            Some(AuthDotJson {
                tokens: Some(mut tokens),
                last_refresh: Some(last_refresh),
                ..
            }) => {
                if last_refresh < Utc::now() - chrono::Duration::days(28) {
                    let refresh_response = tokio::time::timeout(
                        Duration::from_secs(60),
                        try_refresh_token(tokens.refresh_token.clone(), &self.client),
                    )
                    .await
                    .map_err(|_| {
                        std::io::Error::other("timed out while refreshing OpenAI API key")
                    })?
                    .map_err(std::io::Error::other)?;

                    let updated_account = update_tokens(
                        &self.auth_file,
                        self.account_auth_id,
                        refresh_response.id_token,
                        refresh_response.access_token,
                        refresh_response.refresh_token,
                    )
                    .await?;

                    tokens = updated_account.auth_dot_json.tokens.clone().ok_or(
                        std::io::Error::other("Token data is not available after refresh."),
                    )?;

                    #[expect(clippy::unwrap_used)]
                    let mut auth_lock = self.auth_dot_json.lock().unwrap();
                    *auth_lock = Some(updated_account.auth_dot_json);
                }

                Ok(tokens)
            }
            _ => Err(std::io::Error::other("Token data is not available.")),
        }
    }

    pub async fn get_token(&self) -> Result<String, std::io::Error> {
        match self.mode {
            AuthMode::ApiKey => Ok(self.api_key.clone().unwrap_or_default()),
            AuthMode::ChatGPT => {
                let id_token = self.get_token_data().await?.access_token;
                Ok(id_token)
            }
        }
    }

    pub fn get_account_id(&self) -> Option<String> {
        self.get_current_token_data().and_then(|t| t.account_id)
    }

    pub fn get_account_email(&self) -> Option<String> {
        self.get_current_token_data().and_then(|t| t.id_token.email)
    }

    pub(crate) fn get_plan_type(&self) -> Option<PlanType> {
        self.get_current_token_data()
            .and_then(|t| t.id_token.chatgpt_plan_type)
    }

    fn get_current_auth_json(&self) -> Option<AuthDotJson> {
        #[expect(clippy::unwrap_used)]
        self.auth_dot_json.lock().unwrap().clone()
    }

    fn get_current_token_data(&self) -> Option<TokenData> {
        self.get_current_auth_json().and_then(|t| t.tokens)
    }

    /// Consider this private to integration tests.
    pub fn create_dummy_chatgpt_auth_for_testing() -> Self {
        let auth_dot_json = AuthDotJson {
            openai_api_key: None,
            tokens: Some(TokenData {
                id_token: Default::default(),
                access_token: "Access Token".to_string(),
                refresh_token: "test".to_string(),
                account_id: Some("account_id".to_string()),
            }),
            last_refresh: Some(Utc::now()),
        };

        let auth_dot_json = Arc::new(Mutex::new(Some(auth_dot_json)));
        Self {
            account_auth_id: None,
            api_key: None,
            mode: AuthMode::ChatGPT,
            auth_file: PathBuf::new(),
            auth_dot_json,
            client: crate::default_client::create_client(),
        }
    }

    fn from_api_key_with_client(api_key: &str, client: reqwest::Client) -> Self {
        Self {
            account_auth_id: None,
            api_key: Some(api_key.to_owned()),
            mode: AuthMode::ApiKey,
            auth_file: PathBuf::new(),
            auth_dot_json: Arc::new(Mutex::new(None)),
            client,
        }
    }

    pub fn from_api_key(api_key: &str) -> Self {
        Self::from_api_key_with_client(api_key, crate::default_client::create_client())
    }
}

pub const OPENAI_API_KEY_ENV_VAR: &str = "OPENAI_API_KEY";
pub const CODEX_API_KEY_ENV_VAR: &str = "CODEX_API_KEY";

pub fn read_openai_api_key_from_env() -> Option<String> {
    env::var(OPENAI_API_KEY_ENV_VAR)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub fn read_codex_api_key_from_env() -> Option<String> {
    env::var(CODEX_API_KEY_ENV_VAR)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub fn get_auth_file(codex_home: &Path) -> PathBuf {
    codex_home.join("auth.json")
}

fn get_multi_auth_dir(codex_home: &Path) -> PathBuf {
    codex_home.join("multi_auth")
}

fn get_usage_log_file(codex_home: &Path) -> PathBuf {
    get_multi_auth_dir(codex_home).join("usage_log.jsonl")
}

/// Delete the auth.json file inside `codex_home` if it exists. Returns `Ok(true)`
/// if a file was removed, `Ok(false)` if no auth file was present.
pub fn logout(codex_home: &Path) -> std::io::Result<bool> {
    let auth_file = get_auth_file(codex_home);
    match std::fs::remove_file(&auth_file) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

/// Writes an `auth.json` that contains only the API key.
pub fn login_with_api_key(codex_home: &Path, api_key: &str) -> std::io::Result<()> {
    let auth_dot_json = AuthDotJson {
        openai_api_key: Some(api_key.to_string()),
        tokens: None,
        last_refresh: None,
    };
    let account = AccountAuth::new(AuthMode::ApiKey, auth_dot_json);
    write_auth_json(&get_auth_file(codex_home), &[account])
}

fn load_auth(
    codex_home: &Path,
    enable_codex_api_key_env: bool,
) -> std::io::Result<Option<CodexAuth>> {
    let accounts = load_account_states(codex_home, enable_codex_api_key_env)?;
    Ok(accounts.into_iter().next().map(|state| state.auth))
}

/// Attempt to read and refresh the `auth.json` file in the given `CODEX_HOME` directory.
/// Returns the full AuthDotJson structure after refreshing if necessary.
pub fn try_read_auth_json(auth_file: &Path) -> std::io::Result<AuthDotJson> {
    let accounts = load_auth_accounts(auth_file)?;
    accounts
        .into_iter()
        .next()
        .map(|account| account.auth_dot_json)
        .ok_or_else(|| std::io::Error::other("auth.json contains no accounts"))
}

pub fn write_auth_json(auth_file: &Path, accounts: &[AccountAuth]) -> std::io::Result<()> {
    if let Some(parent) = auth_file.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let data = AuthAccountsFile {
        version: AuthFileVersion::V2,
        accounts: accounts.to_vec(),
    };
    let json_data = serde_json::to_string_pretty(&data)?;

    let tmp_path = auth_file.with_file_name(format!(
        "{}.tmp",
        auth_file.file_name().unwrap().to_string_lossy()
    ));

    let mut options = OpenOptions::new();
    options.truncate(true).write(true).create(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options.open(&tmp_path)?;
    file.write_all(json_data.as_bytes())?;
    file.flush()?;
    file.sync_all()?;
    match std::fs::rename(&tmp_path, auth_file) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::remove_file(auth_file)?;
            std::fs::rename(&tmp_path, auth_file)?;
        }
        Err(err) => return Err(err),
    }
    Ok(())
}

async fn update_tokens(
    auth_file: &Path,
    account_auth_id: Option<Uuid>,
    id_token: String,
    access_token: Option<String>,
    refresh_token: Option<String>,
) -> std::io::Result<AccountAuth> {
    let account_id = account_auth_id
        .ok_or_else(|| std::io::Error::other("account identifier is required for update"))?;

    let mut accounts = load_auth_accounts(auth_file)?;
    let updated_account = {
        let account = accounts
            .iter_mut()
            .find(|a| a.id == account_id)
            .ok_or_else(|| std::io::Error::other("account not found"))?;

        let tokens = account
            .auth_dot_json
            .tokens
            .get_or_insert_with(TokenData::default);
        tokens.id_token = parse_id_token(&id_token).map_err(std::io::Error::other)?;
        if let Some(access_token) = access_token {
            tokens.access_token = access_token;
        }
        if let Some(refresh_token) = refresh_token {
            tokens.refresh_token = refresh_token;
        }
        account.auth_dot_json.last_refresh = Some(Utc::now());
        account.clone()
    };
    write_auth_json(auth_file, &accounts)?;
    Ok(updated_account)
}

async fn try_refresh_token(
    refresh_token: String,
    client: &reqwest::Client,
) -> std::io::Result<RefreshResponse> {
    let refresh_request = RefreshRequest {
        client_id: CLIENT_ID,
        grant_type: "refresh_token",
        refresh_token,
        scope: "openid profile email",
    };

    // Use shared client factory to include standard headers
    let response = client
        .post("https://auth.openai.com/oauth/token")
        .header("Content-Type", "application/json")
        .json(&refresh_request)
        .send()
        .await
        .map_err(std::io::Error::other)?;

    if response.status().is_success() {
        let refresh_response = response
            .json::<RefreshResponse>()
            .await
            .map_err(std::io::Error::other)?;
        Ok(refresh_response)
    } else {
        Err(std::io::Error::other(format!(
            "Failed to refresh token: {}",
            response.status()
        )))
    }
}

#[derive(Serialize)]
struct RefreshRequest {
    client_id: &'static str,
    grant_type: &'static str,
    refresh_token: String,
    scope: &'static str,
}

#[derive(Deserialize, Clone)]
struct RefreshResponse {
    id_token: String,
    access_token: Option<String>,
    refresh_token: Option<String>,
}

/// Expected structure for $CODEX_HOME/auth.json.
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq)]
pub struct AuthDotJson {
    #[serde(rename = "OPENAI_API_KEY")]
    pub openai_api_key: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<TokenData>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_refresh: Option<DateTime<Utc>>,
}

// Shared constant for token refresh (client id used for oauth token refresh flow)
pub const CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";

use std::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccountAuth {
    pub id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub mode: AuthMode,
    pub auth_dot_json: AuthDotJson,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cooldown_until: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default)]
    pub priority: u32,
    #[serde(default)]
    pub lifetime_usage: TokenCounters,
}

impl AccountAuth {
    pub fn new(mode: AuthMode, auth_dot_json: AuthDotJson) -> Self {
        Self {
            id: Uuid::new_v4(),
            label: None,
            mode,
            auth_dot_json,
            cooldown_until: None,
            last_error: None,
            priority: 0,
            lifetime_usage: TokenCounters::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
#[derive(Default)]
pub struct TokenCounters {
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_combined_tokens: u64,
    pub cooldown_window_input: u64,
    pub cooldown_window_output: u64,
}

impl TokenCounters {
    fn add_lifetime_usage(&mut self, usage: &TokenUsage) {
        self.total_input_tokens = self.total_input_tokens.saturating_add(usage.input_tokens);
        self.total_output_tokens = self.total_output_tokens.saturating_add(usage.output_tokens);
        self.total_combined_tokens = self
            .total_combined_tokens
            .saturating_add(usage.total_tokens);
    }

    fn set_cooldown_window(&mut self, usage: &TokenUsage) {
        self.cooldown_window_input = usage.input_tokens;
        self.cooldown_window_output = usage.output_tokens;
    }
}

fn add_usage(lhs: &mut TokenUsage, rhs: &TokenUsage) {
    lhs.input_tokens = lhs.input_tokens.saturating_add(rhs.input_tokens);
    lhs.cached_input_tokens = lhs
        .cached_input_tokens
        .saturating_add(rhs.cached_input_tokens);
    lhs.output_tokens = lhs.output_tokens.saturating_add(rhs.output_tokens);
    lhs.reasoning_output_tokens = lhs
        .reasoning_output_tokens
        .saturating_add(rhs.reasoning_output_tokens);
    lhs.total_tokens = lhs.total_tokens.saturating_add(rhs.total_tokens);
}

fn subtract_usage(lhs: &TokenUsage, rhs: &TokenUsage) -> TokenUsage {
    TokenUsage {
        input_tokens: lhs.input_tokens.saturating_sub(rhs.input_tokens),
        cached_input_tokens: lhs
            .cached_input_tokens
            .saturating_sub(rhs.cached_input_tokens),
        output_tokens: lhs.output_tokens.saturating_sub(rhs.output_tokens),
        reasoning_output_tokens: lhs
            .reasoning_output_tokens
            .saturating_sub(rhs.reasoning_output_tokens),
        total_tokens: lhs.total_tokens.saturating_sub(rhs.total_tokens),
    }
}

fn usage_to_counters(usage: &TokenUsage) -> TokenCounters {
    let mut counters = TokenCounters::default();
    counters.total_input_tokens = usage.input_tokens;
    counters.total_output_tokens = usage.output_tokens;
    counters.total_combined_tokens = usage.total_tokens;
    counters.cooldown_window_input = usage.input_tokens;
    counters.cooldown_window_output = usage.output_tokens;
    counters
}

fn usage_equals(lhs: &TokenUsage, rhs: &TokenUsage) -> bool {
    lhs.input_tokens == rhs.input_tokens
        && lhs.cached_input_tokens == rhs.cached_input_tokens
        && lhs.output_tokens == rhs.output_tokens
        && lhs.reasoning_output_tokens == rhs.reasoning_output_tokens
        && lhs.total_tokens == rhs.total_tokens
}

fn snapshot_equals(lhs: &Option<RateLimitSnapshot>, rhs: &Option<RateLimitSnapshot>) -> bool {
    match (lhs, rhs) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            rate_limit_window_equals(&left.primary, &right.primary)
                && rate_limit_window_equals(&left.secondary, &right.secondary)
        }
        _ => false,
    }
}

fn rate_limit_window_equals(lhs: &Option<RateLimitWindow>, rhs: &Option<RateLimitWindow>) -> bool {
    match (lhs, rhs) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            (left.used_percent - right.used_percent).abs() < f64::EPSILON
                && left.window_minutes == right.window_minutes
                && left.resets_at == right.resets_at
        }
        _ => false,
    }
}

fn lock_poisoned() -> std::io::Error {
    std::io::Error::other("auth cache lock poisoned")
}

#[derive(Clone, Debug)]
struct AccountState {
    id: Uuid,
    label: Option<String>,
    mode: AuthMode,
    auth: CodexAuth,
    cooldown_until: Option<DateTime<Utc>>,
    last_error: Option<String>,
    priority: u32,
    lifetime_usage: TokenCounters,
    tokens_since_last_cooldown: TokenUsage,
    last_refresh: Option<DateTime<Utc>>,
    usage_snapshot: Option<RateLimitSnapshot>,
    persisted: bool,
    cached_auth_dot_json: Option<AuthDotJson>,
}

impl AccountState {
    fn new(codex_home: &Path, mut account: AccountAuth, persisted: bool) -> std::io::Result<Self> {
        let auth_file = get_auth_file(codex_home);
        let client = crate::default_client::create_client();
        let auth = if account.mode == AuthMode::ApiKey {
            if let Some(api_key) = &account.auth_dot_json.openai_api_key {
                CodexAuth::from_api_key_with_client(api_key, client)
            } else {
                return Err(std::io::Error::other("API key account missing key"));
            }
        } else {
            CodexAuth {
                api_key: account.auth_dot_json.openai_api_key.clone(),
                mode: account.mode,
                account_auth_id: Some(account.id),
                auth_file,
                auth_dot_json: Arc::new(Mutex::new(Some(account.auth_dot_json.clone()))),
                client,
            }
        };

        let tokens_since_last_cooldown = TokenUsage {
            input_tokens: account.lifetime_usage.cooldown_window_input,
            output_tokens: account.lifetime_usage.cooldown_window_output,
            total_tokens: account
                .lifetime_usage
                .cooldown_window_input
                .saturating_add(account.lifetime_usage.cooldown_window_output),
            ..TokenUsage::default()
        };

        let last_refresh = account.auth_dot_json.last_refresh;
        let cached_auth_dot_json = Some(account.auth_dot_json.clone());
        let lifetime_usage = account.lifetime_usage.clone();
        let label = account.label.take();
        let last_error = account.last_error.take();
        let cooldown_until = account.cooldown_until;
        let priority = account.priority;
        let mode = account.mode;
        let id = account.id;

        Ok(Self {
            id,
            label,
            mode,
            auth,
            cooldown_until,
            last_error,
            priority,
            lifetime_usage,
            tokens_since_last_cooldown,
            last_refresh,
            usage_snapshot: None,
            persisted,
            cached_auth_dot_json,
        })
    }

    fn new_from_api_key(api_key: String) -> Self {
        let client = crate::default_client::create_client();
        let auth = CodexAuth::from_api_key_with_client(&api_key, client);
        Self {
            id: Uuid::new_v4(),
            label: None,
            mode: AuthMode::ApiKey,
            auth,
            cooldown_until: None,
            last_error: None,
            priority: 0,
            lifetime_usage: TokenCounters::default(),
            tokens_since_last_cooldown: TokenUsage::default(),
            last_refresh: None,
            usage_snapshot: None,
            persisted: false,
            cached_auth_dot_json: Some(AuthDotJson {
                openai_api_key: Some(api_key),
                tokens: None,
                last_refresh: None,
            }),
        }
    }

    fn summary(&self) -> AccountSummary {
        let plan = self.auth.get_plan_type().map(|plan| match plan {
            PlanType::Known(plan) => format!("{plan:?}"),
            PlanType::Unknown(raw) => raw,
        });

        AccountSummary {
            id: self.id,
            label: self.label.clone(),
            plan,
            mode: self.mode,
            priority: self.priority,
            cooldown_until: self.cooldown_until,
            last_error: self.last_error.clone(),
            last_refresh: self.last_refresh,
            lifetime_usage: self.lifetime_usage.clone(),
            tokens_since_last_cooldown: self.tokens_since_last_cooldown.clone(),
            usage_snapshot: self.usage_snapshot.clone(),
        }
    }

    fn selection(&self) -> AccountSelection {
        AccountSelection {
            id: self.id,
            label: self.label.clone(),
            auth: self.auth.clone(),
            cooldown_until: self.cooldown_until,
            last_refresh: self.last_refresh,
            usage_snapshot: self.usage_snapshot.clone(),
            tokens_since_last_cooldown: self.tokens_since_last_cooldown.clone(),
        }
    }

    fn apply_usage(&mut self, usage: &TokenUsage) {
        self.lifetime_usage.add_lifetime_usage(usage);
        add_usage(&mut self.tokens_since_last_cooldown, usage);
    }

    fn current_auth_dot_json(&self) -> Option<AuthDotJson> {
        self.auth
            .get_current_auth_json()
            .or_else(|| self.cached_auth_dot_json.clone())
    }

    fn to_account_auth(&mut self) -> Option<AccountAuth> {
        if !self.persisted {
            return None;
        }
        let auth_dot_json = self.current_auth_dot_json()?;
        self.last_refresh = auth_dot_json.last_refresh;
        self.cached_auth_dot_json = Some(auth_dot_json.clone());
        Some(AccountAuth {
            id: self.id,
            label: self.label.clone(),
            mode: self.mode,
            auth_dot_json,
            cooldown_until: self.cooldown_until,
            last_error: self.last_error.clone(),
            priority: self.priority,
            lifetime_usage: self.lifetime_usage.clone(),
        })
    }
}

impl PartialEq for AccountState {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.label == other.label
            && self.mode == other.mode
            && self.cooldown_until == other.cooldown_until
            && self.last_error == other.last_error
            && self.priority == other.priority
            && self.lifetime_usage == other.lifetime_usage
            && usage_equals(
                &self.tokens_since_last_cooldown,
                &other.tokens_since_last_cooldown,
            )
            && self.last_refresh == other.last_refresh
            && snapshot_equals(&self.usage_snapshot, &other.usage_snapshot)
            && self.persisted == other.persisted
            && self.auth == other.auth
    }
}

#[derive(Clone, Debug)]
pub struct AccountSummary {
    pub id: Uuid,
    pub label: Option<String>,
    pub plan: Option<String>,
    pub mode: AuthMode,
    pub priority: u32,
    pub cooldown_until: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub last_refresh: Option<DateTime<Utc>>,
    pub lifetime_usage: TokenCounters,
    pub tokens_since_last_cooldown: TokenUsage,
    pub usage_snapshot: Option<RateLimitSnapshot>,
}

#[derive(Clone, Debug)]
pub struct AccountSelection {
    pub id: Uuid,
    pub label: Option<String>,
    pub auth: CodexAuth,
    pub cooldown_until: Option<DateTime<Utc>>,
    pub last_refresh: Option<DateTime<Utc>>,
    pub usage_snapshot: Option<RateLimitSnapshot>,
    pub tokens_since_last_cooldown: TokenUsage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFileVersion {
    V2,
}

impl AuthFileVersion {
    fn as_u32(self) -> u32 {
        match self {
            AuthFileVersion::V2 => 2,
        }
    }
}

impl Serialize for AuthFileVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u32(self.as_u32())
    }
}

impl<'de> Deserialize<'de> for AuthFileVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u32::deserialize(deserializer)?;
        match value {
            2 => Ok(AuthFileVersion::V2),
            _ => Err(serde::de::Error::custom(format!(
                "unsupported auth file version {value}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct AuthAccountsFile {
    version: AuthFileVersion,
    #[serde(default)]
    accounts: Vec<AccountAuth>,
}

pub fn load_auth_accounts(auth_file: &Path) -> std::io::Result<Vec<AccountAuth>> {
    let mut file = File::open(auth_file)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;

    let value: Value = serde_json::from_str(&contents)?;
    if value.get("version").is_none() {
        let auth_dot_json: AuthDotJson = serde_json::from_value(value)?;
        let mode = if auth_dot_json.openai_api_key.is_some() {
            AuthMode::ApiKey
        } else {
            AuthMode::ChatGPT
        };
        return Ok(vec![AccountAuth {
            id: Uuid::new_v4(),
            label: None,
            mode,
            auth_dot_json,
            cooldown_until: None,
            last_error: None,
            priority: 0,
            lifetime_usage: TokenCounters::default(),
        }]);
    }

    let accounts_file: AuthAccountsFile = serde_json::from_str(&contents)?;
    Ok(accounts_file.accounts)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageLogEntry {
    pub timestamp: DateTime<Utc>,
    pub account_id: Uuid,
    pub tokens_since_last_cooldown: TokenCounters,
    pub resets_in_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_snapshot: Option<RateLimitSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_type: Option<String>,
}

pub fn append_usage_log(codex_home: &Path, entry: &UsageLogEntry) -> std::io::Result<()> {
    let log_file = get_usage_log_file(codex_home);
    if let Some(parent) = log_file.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options.open(&log_file)?;
    let line = serde_json::to_string(entry)?;
    file.write_all(line.as_bytes())?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}

fn load_account_states(
    codex_home: &Path,
    enable_codex_api_key_env: bool,
) -> std::io::Result<Vec<AccountState>> {
    let mut accounts = Vec::new();
    if enable_codex_api_key_env && let Some(api_key) = read_codex_api_key_from_env() {
        accounts.push(AccountState::new_from_api_key(api_key));
    }

    let auth_file = get_auth_file(codex_home);
    match load_auth_accounts(&auth_file) {
        Ok(on_disk_accounts) => {
            for account in on_disk_accounts {
                accounts.push(AccountState::new(codex_home, account, true)?);
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }

    sort_accounts(&mut accounts);

    Ok(accounts)
}

fn sort_accounts(accounts: &mut Vec<AccountState>) {
    accounts.sort_by(|a, b| {
        let persisted_cmp = b.persisted.cmp(&a.persisted);
        if persisted_cmp != Ordering::Equal {
            return persisted_cmp;
        }
        let priority_cmp = a.priority.cmp(&b.priority);
        if priority_cmp != Ordering::Equal {
            return priority_cmp;
        }
        let label_cmp = a.label.cmp(&b.label);
        if label_cmp != Ordering::Equal {
            return label_cmp;
        }
        a.id.cmp(&b.id)
    });
}

/// Internal cached auth state.
#[derive(Clone, Debug)]
struct CachedAuth {
    accounts: Vec<AccountState>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token_data::IdTokenInfo;
    use crate::token_data::KnownPlan;
    use crate::token_data::PlanType;
    use crate::token_data::parse_id_token;
    use base64::Engine;
    use chrono::Duration as ChronoDuration;
    use futures::future::join_all;
    use pretty_assertions::assert_eq;
    use serde::Serialize;
    use serde_json::json;
    use std::sync::Arc;
    use tempfile::tempdir;

    const LAST_REFRESH: &str = "2025-08-06T20:41:36.232376Z";

    #[tokio::test]
    async fn roundtrip_auth_dot_json() {
        let codex_home = tempdir().unwrap();
        let _ = write_auth_file(
            AuthFileParams {
                openai_api_key: None,
                chatgpt_plan_type: "pro".to_string(),
            },
            codex_home.path(),
        )
        .expect("failed to write auth file");

        let file = get_auth_file(codex_home.path());
        let auth_dot_json = try_read_auth_json(&file).unwrap();
        let account = AccountAuth::new(AuthMode::ChatGPT, auth_dot_json.clone());
        write_auth_json(&file, &[account]).unwrap();

        let same_auth_dot_json = try_read_auth_json(&file).unwrap();
        assert_eq!(auth_dot_json, same_auth_dot_json);
    }

    #[test]
    fn login_with_api_key_overwrites_existing_auth_json() {
        let dir = tempdir().unwrap();
        let auth_path = dir.path().join("auth.json");
        let stale_auth = json!({
            "OPENAI_API_KEY": "sk-old",
            "tokens": {
                "id_token": "stale.header.payload",
                "access_token": "stale-access",
                "refresh_token": "stale-refresh",
                "account_id": "stale-acc"
            }
        });
        std::fs::write(
            &auth_path,
            serde_json::to_string_pretty(&stale_auth).unwrap(),
        )
        .unwrap();

        super::login_with_api_key(dir.path(), "sk-new").expect("login_with_api_key should succeed");

        let auth = super::try_read_auth_json(&auth_path).expect("auth.json should parse");
        assert_eq!(auth.openai_api_key.as_deref(), Some("sk-new"));
        assert!(auth.tokens.is_none(), "tokens should be cleared");
    }

    #[tokio::test]
    async fn pro_account_with_no_api_key_uses_chatgpt_auth() {
        let codex_home = tempdir().unwrap();
        let fake_jwt = write_auth_file(
            AuthFileParams {
                openai_api_key: None,
                chatgpt_plan_type: "pro".to_string(),
            },
            codex_home.path(),
        )
        .expect("failed to write auth file");

        let CodexAuth {
            api_key,
            mode,
            auth_dot_json,
            auth_file: _,
            ..
        } = super::load_auth(codex_home.path(), false).unwrap().unwrap();
        assert_eq!(None, api_key);
        assert_eq!(AuthMode::ChatGPT, mode);

        let guard = auth_dot_json.lock().unwrap();
        let auth_dot_json = guard.as_ref().expect("AuthDotJson should exist");
        assert_eq!(
            &AuthDotJson {
                openai_api_key: None,
                tokens: Some(TokenData {
                    id_token: IdTokenInfo {
                        email: Some("user@example.com".to_string()),
                        chatgpt_plan_type: Some(PlanType::Known(KnownPlan::Pro)),
                        raw_jwt: fake_jwt,
                    },
                    access_token: "test-access-token".to_string(),
                    refresh_token: "test-refresh-token".to_string(),
                    account_id: None,
                }),
                last_refresh: Some(
                    DateTime::parse_from_rfc3339(LAST_REFRESH)
                        .unwrap()
                        .with_timezone(&Utc)
                ),
            },
            auth_dot_json
        )
    }

    #[tokio::test]
    async fn loads_api_key_from_auth_json() {
        let dir = tempdir().unwrap();
        let auth_file = dir.path().join("auth.json");
        std::fs::write(
            auth_file,
            r#"{"OPENAI_API_KEY":"sk-test-key","tokens":null,"last_refresh":null}"#,
        )
        .unwrap();

        let auth = super::load_auth(dir.path(), false).unwrap().unwrap();
        assert_eq!(auth.mode, AuthMode::ApiKey);
        assert_eq!(auth.api_key, Some("sk-test-key".to_string()));

        assert!(auth.get_token_data().await.is_err());
    }

    #[test]
    fn logout_removes_auth_file() -> Result<(), std::io::Error> {
        let dir = tempdir()?;
        let auth_dot_json = AuthDotJson {
            openai_api_key: Some("sk-test-key".to_string()),
            tokens: None,
            last_refresh: None,
        };
        let account = AccountAuth::new(AuthMode::ApiKey, auth_dot_json);
        write_auth_json(&get_auth_file(dir.path()), &[account])?;
        assert!(dir.path().join("auth.json").exists());
        let removed = logout(dir.path())?;
        assert!(removed);
        assert!(!dir.path().join("auth.json").exists());
        Ok(())
    }

    struct AuthFileParams {
        openai_api_key: Option<String>,
        chatgpt_plan_type: String,
    }

    fn generate_fake_jwt(chatgpt_plan_type: &str) -> String {
        #[derive(Serialize)]
        struct Header {
            alg: &'static str,
            typ: &'static str,
        }
        let header = Header {
            alg: "none",
            typ: "JWT",
        };
        let payload = serde_json::json!({
            "email": "user@example.com",
            "email_verified": true,
            "https://api.openai.com/auth": {
                "chatgpt_account_id": "bc3618e3-489d-4d49-9362-1561dc53ba53",
                "chatgpt_plan_type": chatgpt_plan_type,
                "chatgpt_user_id": "user-12345",
                "user_id": "user-12345",
            }
        });
        let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let header_b64 = b64(&serde_json::to_vec(&header).expect("serialize header"));
        let payload_b64 = b64(&serde_json::to_vec(&payload).expect("serialize payload"));
        let signature_b64 = b64(b"sig");
        format!("{header_b64}.{payload_b64}.{signature_b64}")
    }

    fn write_auth_file(params: AuthFileParams, codex_home: &Path) -> std::io::Result<String> {
        let auth_file = get_auth_file(codex_home);
        let fake_jwt = generate_fake_jwt(&params.chatgpt_plan_type);
        let auth_json_data = json!({
            "OPENAI_API_KEY": params.openai_api_key,
            "tokens": {
                "id_token": fake_jwt,
                "access_token": "test-access-token",
                "refresh_token": "test-refresh-token"
            },
            "last_refresh": LAST_REFRESH,
        });
        let auth: AuthDotJson =
            serde_json::from_value(auth_json_data).map_err(std::io::Error::other)?;
        let mode = if params.openai_api_key.is_some() {
            AuthMode::ApiKey
        } else {
            AuthMode::ChatGPT
        };
        let account = AccountAuth::new(mode, auth);
        write_auth_json(&auth_file, &[account])?;
        Ok(fake_jwt)
    }

    fn create_test_account(account_id: &str, priority: u32) -> AccountAuth {
        let mut token_data = TokenData::default();
        let fake_jwt = generate_fake_jwt("pro");
        token_data.id_token = parse_id_token(&fake_jwt).expect("fake jwt");
        token_data.access_token = format!("access-{account_id}");
        token_data.refresh_token = format!("refresh-{account_id}");
        token_data.account_id = Some(account_id.to_string());

        let auth_dot_json = AuthDotJson {
            openai_api_key: None,
            tokens: Some(token_data),
            last_refresh: Some(Utc::now()),
        };

        let mut account = AccountAuth::new(AuthMode::ChatGPT, auth_dot_json);
        account.priority = priority;
        account
    }

    fn create_manager_with_accounts(
        accounts: Vec<AccountAuth>,
    ) -> (tempfile::TempDir, Arc<AuthManager>, Vec<Uuid>) {
        let dir = tempdir().unwrap();
        let auth_path = get_auth_file(dir.path());
        let account_ids: Vec<Uuid> = accounts.iter().map(|account| account.id).collect();
        write_auth_json(&auth_path, &accounts).expect("write auth.json");
        let manager = Arc::new(AuthManager::new(dir.path().to_path_buf(), false));
        (dir, manager, account_ids)
    }

    #[tokio::test]
    async fn next_available_skips_accounts_on_cooldown() {
        let accounts = vec![
            create_test_account("primary", 0),
            create_test_account("secondary", 1),
        ];
        let (_dir, manager, ids) = create_manager_with_accounts(accounts);
        let first_id = ids[0];
        let second_id = ids[1];

        manager
            .mark_cooldown(
                first_id,
                Utc::now() + ChronoDuration::minutes(5),
                Some("rate limited".to_string()),
                TokenUsage::default(),
                None,
            )
            .expect("mark cooldown");

        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let manager = Arc::clone(&manager);
                tokio::spawn(async move {
                    manager
                        .next_available(Utc::now())
                        .map(|selection| selection.id)
                })
            })
            .collect();

        let results = join_all(tasks).await;
        for handle in results {
            let id = handle.expect("task failed");
            assert_eq!(Some(second_id), id);
        }
    }

    #[tokio::test]
    async fn register_usage_accumulates_across_tasks() {
        let accounts = vec![create_test_account("primary", 0)];
        let (_dir, manager, ids) = create_manager_with_accounts(accounts);
        let account_id = ids[0];

        let usages = vec![
            TokenUsage {
                input_tokens: 10,
                output_tokens: 5,
                total_tokens: 15,
                ..TokenUsage::default()
            },
            TokenUsage {
                input_tokens: 7,
                output_tokens: 3,
                total_tokens: 10,
                ..TokenUsage::default()
            },
            TokenUsage {
                input_tokens: 2,
                output_tokens: 8,
                total_tokens: 10,
                ..TokenUsage::default()
            },
        ];

        let tasks: Vec<_> = usages
            .into_iter()
            .map(|usage| {
                let manager = Arc::clone(&manager);
                tokio::spawn(async move {
                    manager
                        .register_usage(account_id, usage)
                        .expect("register usage");
                })
            })
            .collect();

        for handle in tasks {
            handle.await.expect("usage task");
        }

        let summary = manager.accounts();
        let account_summary = summary
            .into_iter()
            .find(|summary| summary.id == account_id)
            .expect("account summary");
        assert_eq!(19, account_summary.lifetime_usage.total_input_tokens);
        assert_eq!(16, account_summary.lifetime_usage.total_output_tokens);
        assert_eq!(35, account_summary.lifetime_usage.total_combined_tokens);
        assert_eq!(35, account_summary.tokens_since_last_cooldown.total_tokens);
    }

    #[test]
    fn add_account_persists_account() {
        let dir = tempdir().unwrap();
        let manager = AuthManager::new(dir.path().to_path_buf(), false);

        let mut account = AccountAuth::new(
            AuthMode::ApiKey,
            AuthDotJson {
                openai_api_key: Some("sk-test".to_string()),
                tokens: None,
                last_refresh: None,
            },
        );
        account.label = Some("Primary".to_string());
        account.priority = 5;

        let id = manager
            .add_account(account.clone())
            .expect("add account to succeed");

        let summaries = manager.accounts();
        assert_eq!(summaries.len(), 1);
        let summary = &summaries[0];
        assert_eq!(summary.id, id);
        assert_eq!(summary.label.as_deref(), Some("Primary"));
        assert_eq!(summary.priority, 5);
        assert!(summary.plan.is_none());

        let persisted = load_auth_accounts(&get_auth_file(dir.path())).expect("read auth.json");
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].id, id);
        assert_eq!(persisted[0].label.as_deref(), Some("Primary"));
    }

    #[test]
    fn clear_cooldown_resets_state_and_persists() {
        let dir = tempdir().unwrap();
        let mut account = create_test_account("primary", 0);
        account.label = Some("Main".to_string());
        account.cooldown_until = Some(Utc::now() + ChronoDuration::minutes(15));
        account.last_error = Some("rate limited".to_string());
        account.lifetime_usage.cooldown_window_input = 42;
        account.lifetime_usage.cooldown_window_output = 24;

        let manager = AuthManager::new(dir.path().to_path_buf(), false);
        let id = manager
            .add_account(account.clone())
            .expect("add account with cooldown");

        assert!(manager.clear_cooldown(id).expect("clear cooldown"));

        let summary = manager
            .accounts()
            .into_iter()
            .find(|summary| summary.id == id)
            .expect("account summary present");
        assert!(summary.cooldown_until.is_none());
        assert!(summary.last_error.is_none());
        assert_eq!(summary.lifetime_usage.cooldown_window_input, 0);
        assert_eq!(summary.lifetime_usage.cooldown_window_output, 0);
        assert_eq!(summary.tokens_since_last_cooldown.total_tokens, 0);

        let persisted = load_auth_accounts(&get_auth_file(dir.path())).expect("read auth.json");
        assert!(persisted[0].cooldown_until.is_none());
        assert!(persisted[0].last_error.is_none());
        assert_eq!(persisted[0].lifetime_usage.cooldown_window_input, 0);
        assert_eq!(persisted[0].lifetime_usage.cooldown_window_output, 0);
    }

    #[test]
    fn usage_history_returns_newest_first() {
        let dir = tempdir().unwrap();
        let manager = AuthManager::new(dir.path().to_path_buf(), false);
        let account = create_test_account("primary", 0);
        let account_id = manager
            .add_account(account)
            .expect("add account for history");

        let mut counters_first = TokenCounters::default();
        counters_first.total_combined_tokens = 10;
        counters_first.total_input_tokens = 6;
        counters_first.total_output_tokens = 4;

        let mut counters_second = TokenCounters::default();
        counters_second.total_combined_tokens = 20;
        counters_second.total_input_tokens = 12;
        counters_second.total_output_tokens = 8;

        append_usage_log(
            dir.path(),
            &UsageLogEntry {
                timestamp: Utc::now() - ChronoDuration::minutes(5),
                account_id,
                tokens_since_last_cooldown: counters_first.clone(),
                resets_in_seconds: 120,
                reason: Some("test".to_string()),
                usage_snapshot: None,
                plan_type: Some("Pro".to_string()),
            },
        )
        .expect("write first log entry");

        append_usage_log(
            dir.path(),
            &UsageLogEntry {
                timestamp: Utc::now(),
                account_id,
                tokens_since_last_cooldown: counters_second.clone(),
                resets_in_seconds: 60,
                reason: None,
                usage_snapshot: None,
                plan_type: Some("Pro".to_string()),
            },
        )
        .expect("write second log entry");

        let history = manager
            .usage_history(Some(1))
            .expect("read limited usage history");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].tokens_since_last_cooldown, counters_second);

        let full_history = manager.usage_history(None).expect("read full history");
        assert_eq!(full_history.len(), 2);
        assert_eq!(full_history[0].tokens_since_last_cooldown, counters_second);
        assert_eq!(full_history[1].tokens_since_last_cooldown, counters_first);
    }
}

/// Central manager providing a single source of truth for auth.json derived
/// authentication data. It loads once (or on preference change) and then
/// hands out cloned `CodexAuth` values so the rest of the program has a
/// consistent snapshot.
///
/// External modifications to `auth.json` will NOT be observed until
/// `reload()` is called explicitly. This matches the design goal of avoiding
/// different parts of the program seeing inconsistent auth data mid‑run.
#[derive(Debug)]
pub struct AuthManager {
    codex_home: PathBuf,
    inner: RwLock<CachedAuth>,
    enable_codex_api_key_env: bool,
}

impl AuthManager {
    /// Create a new manager loading the initial auth using the provided
    /// preferred auth method. Errors loading auth are swallowed; `auth()` will
    /// simply return `None` in that case so callers can treat it as an
    /// unauthenticated state.
    pub fn new(codex_home: PathBuf, enable_codex_api_key_env: bool) -> Self {
        let accounts =
            load_account_states(&codex_home, enable_codex_api_key_env).unwrap_or_default();
        Self {
            codex_home,
            inner: RwLock::new(CachedAuth { accounts }),
            enable_codex_api_key_env,
        }
    }

    /// Create an AuthManager with a specific CodexAuth, for testing only.
    pub fn from_auth_for_testing(auth: CodexAuth) -> Arc<Self> {
        let mut state = AccountState {
            id: auth.account_auth_id.unwrap_or_else(Uuid::new_v4),
            label: None,
            mode: auth.mode,
            auth,
            cooldown_until: None,
            last_error: None,
            priority: 0,
            lifetime_usage: TokenCounters::default(),
            tokens_since_last_cooldown: TokenUsage::default(),
            last_refresh: None,
            usage_snapshot: None,
            persisted: false,
            cached_auth_dot_json: None,
        };
        if let Some(auth_dot_json) = state.auth.get_current_auth_json() {
            state.last_refresh = auth_dot_json.last_refresh;
            state.cached_auth_dot_json = Some(auth_dot_json);
        }
        let cached = CachedAuth {
            accounts: vec![state],
        };
        Arc::new(Self {
            codex_home: PathBuf::new(),
            inner: RwLock::new(cached),
            enable_codex_api_key_env: false,
        })
    }

    /// Current cached auth (clone). May be `None` if not logged in or load failed.
    pub fn auth(&self) -> Option<CodexAuth> {
        self.next_available(Utc::now())
            .map(|selection| selection.auth)
    }

    /// Snapshot of known account metadata, suitable for CLI/TUI display.
    pub fn accounts(&self) -> Vec<AccountSummary> {
        self.inner
            .read()
            .map(|guard| guard.accounts.iter().map(AccountState::summary).collect())
            .unwrap_or_default()
    }

    /// Select the next available account whose cooldown has expired.
    pub fn next_available(&self, now: DateTime<Utc>) -> Option<AccountSelection> {
        self.inner.read().ok().and_then(|guard| {
            guard
                .accounts
                .iter()
                .find(|account| account.cooldown_until.is_none_or(|c| c <= now))
                .map(AccountState::selection)
        })
    }

    pub fn available_accounts(&self, now: DateTime<Utc>) -> Vec<AccountSelection> {
        self.inner
            .read()
            .map(|guard| {
                guard
                    .accounts
                    .iter()
                    .filter(|account| account.cooldown_until.is_none_or(|c| c <= now))
                    .map(AccountState::selection)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Force a reload of the auth information from auth.json. Returns
    /// whether the auth value changed. When `account_id` is `Some`, only that
    /// account is reloaded.
    pub fn reload(&self, account_id: Option<Uuid>) -> bool {
        if let Some(id) = account_id {
            let loaded = load_account_states(&self.codex_home, self.enable_codex_api_key_env)
                .ok()
                .and_then(|accounts| accounts.into_iter().find(|a| a.id == id));
            if let Ok(mut guard) = self.inner.write() {
                let mut changed = false;
                match (
                    guard.accounts.iter().position(|account| account.id == id),
                    loaded,
                ) {
                    (Some(idx), Some(state)) => {
                        if guard.accounts[idx] != state {
                            guard.accounts[idx] = state;
                            changed = true;
                        }
                    }
                    (Some(idx), None) => {
                        guard.accounts.remove(idx);
                        changed = true;
                    }
                    (None, Some(state)) => {
                        guard.accounts.push(state);
                        changed = true;
                    }
                    (None, None) => {}
                }
                if changed {
                    sort_accounts(&mut guard.accounts);
                }
                changed
            } else {
                false
            }
        } else {
            let accounts = load_account_states(&self.codex_home, self.enable_codex_api_key_env)
                .unwrap_or_default();
            if let Ok(mut guard) = self.inner.write() {
                let changed = guard.accounts != accounts;
                guard.accounts = accounts;
                changed
            } else {
                false
            }
        }
    }

    /// Record a cooldown for the given account.
    pub fn mark_cooldown(
        &self,
        id: Uuid,
        expires_at: DateTime<Utc>,
        reason: Option<String>,
        tokens_used_since_last: TokenUsage,
        usage_snapshot: Option<RateLimitSnapshot>,
    ) -> std::io::Result<()> {
        let mut guard = self.inner.write().map_err(|_| lock_poisoned())?;
        let plan_type = {
            let account = guard
                .accounts
                .iter_mut()
                .find(|account| account.id == id)
                .ok_or_else(|| std::io::Error::other("account not found"))?;

            let recorded = account.tokens_since_last_cooldown.clone();
            let missing = subtract_usage(&tokens_used_since_last, &recorded);
            if missing.total_tokens > 0
                || missing.input_tokens > 0
                || missing.output_tokens > 0
                || missing.cached_input_tokens > 0
                || missing.reasoning_output_tokens > 0
            {
                account.apply_usage(&missing);
            }

            account
                .lifetime_usage
                .set_cooldown_window(&tokens_used_since_last);
            account.tokens_since_last_cooldown = TokenUsage::default();
            account.cooldown_until = Some(expires_at);
            account.last_error = reason.clone();
            account.usage_snapshot = usage_snapshot.clone();

            account.auth.get_plan_type().map(|plan| match plan {
                PlanType::Known(plan) => format!("{plan:?}"),
                PlanType::Unknown(raw) => raw,
            })
        };

        self.persist_accounts(&mut guard.accounts)?;

        let now = Utc::now();
        let resets_in_seconds = if expires_at > now {
            (expires_at - now).num_seconds().max(0) as u64
        } else {
            0
        };
        let entry = UsageLogEntry {
            timestamp: now,
            account_id: id,
            tokens_since_last_cooldown: usage_to_counters(&tokens_used_since_last),
            resets_in_seconds,
            reason,
            usage_snapshot,
            plan_type,
        };
        append_usage_log(&self.codex_home, &entry)?;
        Ok(())
    }

    /// Increment token usage counters for the given account.
    pub fn register_usage(&self, id: Uuid, usage: TokenUsage) -> std::io::Result<()> {
        let mut guard = self.inner.write().map_err(|_| lock_poisoned())?;
        let account = guard
            .accounts
            .iter_mut()
            .find(|account| account.id == id)
            .ok_or_else(|| std::io::Error::other("account not found"))?;
        account.apply_usage(&usage);
        self.persist_accounts(&mut guard.accounts)
    }

    /// Attempt to refresh the current auth token (if any). On success, reload
    /// the auth state from disk so other components observe refreshed token.
    pub async fn refresh_token(&self, id: Uuid) -> std::io::Result<Option<String>> {
        let auth = {
            let guard = self.inner.read().map_err(|_| lock_poisoned())?;
            guard
                .accounts
                .iter()
                .find(|account| account.id == id)
                .map(|account| account.auth.clone())
        };
        let Some(auth) = auth else {
            return Ok(None);
        };
        match auth.refresh_token().await {
            Ok(token) => {
                // Reload to pick up persisted changes.
                self.reload(Some(id));
                Ok(Some(token))
            }
            Err(e) => Err(e),
        }
    }

    /// Log out by deleting the on‑disk auth.json (if present). Returns Ok(true)
    /// if a file was removed, Ok(false) if no auth file existed. On success,
    /// reloads the in‑memory auth cache so callers immediately observe the
    /// unauthenticated state.
    pub fn logout(&self, id: Uuid) -> std::io::Result<bool> {
        let mut guard = self.inner.write().map_err(|_| lock_poisoned())?;
        let len_before = guard.accounts.len();
        let mut removed_persisted = false;
        guard.accounts.retain(|account| {
            let keep = account.id != id;
            if !keep {
                removed_persisted = account.persisted;
            }
            keep
        });
        if len_before == guard.accounts.len() {
            return Ok(false);
        }

        if removed_persisted {
            self.persist_accounts(&mut guard.accounts)?;
        } else if guard.accounts.iter().any(|account| account.persisted) {
            self.persist_accounts(&mut guard.accounts)?;
        } else {
            let auth_file = get_auth_file(&self.codex_home);
            if let Err(err) = std::fs::remove_file(&auth_file)
                && err.kind() != std::io::ErrorKind::NotFound
            {
                return Err(err);
            }
        }

        Ok(true)
    }

    /// Add a new persisted account to the manager and save it to disk.
    pub fn add_account(&self, account: AccountAuth) -> std::io::Result<Uuid> {
        let mut guard = self.inner.write().map_err(|_| lock_poisoned())?;
        if guard
            .accounts
            .iter()
            .any(|existing| existing.id == account.id)
        {
            return Err(Error::other("account already exists"));
        }

        let state = AccountState::new(&self.codex_home, account, true)?;
        let id = state.id;
        guard.accounts.push(state);
        sort_accounts(&mut guard.accounts);
        self.persist_accounts(&mut guard.accounts)?;
        Ok(id)
    }

    /// Clear any active cooldown on the account and reset usage counters for the window.
    pub fn clear_cooldown(&self, id: Uuid) -> std::io::Result<bool> {
        let mut guard = self.inner.write().map_err(|_| lock_poisoned())?;
        let Some(account) = guard.accounts.iter_mut().find(|account| account.id == id) else {
            return Ok(false);
        };

        account.cooldown_until = None;
        account.last_error = None;
        account.tokens_since_last_cooldown = TokenUsage::default();
        account.lifetime_usage.cooldown_window_input = 0;
        account.lifetime_usage.cooldown_window_output = 0;

        self.persist_accounts(&mut guard.accounts)?;
        Ok(true)
    }

    /// Return recent usage history entries, newest first.
    pub fn usage_history(&self, limit: Option<usize>) -> std::io::Result<Vec<UsageLogEntry>> {
        let log_file = get_usage_log_file(&self.codex_home);
        let file = match File::open(&log_file) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err),
        };

        let reader = BufReader::new(file);
        let mut entries = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let entry: UsageLogEntry = serde_json::from_str(&line).map_err(Error::other)?;
            entries.push(entry);
        }

        entries.reverse();
        if let Some(limit) = limit {
            if entries.len() > limit {
                entries.truncate(limit);
            }
        }

        Ok(entries)
    }

    /// Convenience constructor returning an `Arc` wrapper.
    pub fn shared(codex_home: PathBuf, enable_codex_api_key_env: bool) -> Arc<Self> {
        Arc::new(Self::new(codex_home, enable_codex_api_key_env))
    }

    fn persist_accounts(&self, accounts: &mut [AccountState]) -> std::io::Result<()> {
        let mut persisted = Vec::new();
        for account in accounts.iter_mut() {
            if let Some(account_auth) = account.to_account_auth() {
                persisted.push(account_auth);
            }
        }

        let auth_file = get_auth_file(&self.codex_home);
        if persisted.is_empty() {
            if let Err(err) = std::fs::remove_file(&auth_file)
                && err.kind() != std::io::ErrorKind::NotFound
            {
                return Err(err);
            }
            return Ok(());
        }

        write_auth_json(&auth_file, &persisted)
    }
}

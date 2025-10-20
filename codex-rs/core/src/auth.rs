use chrono::DateTime;
use chrono::Utc;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::env;
use std::fs::File;
use std::fs::OpenOptions;
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
                    *auth_lock = Some(updated_account.auth_dot_json.clone());
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
    if enable_codex_api_key_env && let Some(api_key) = read_codex_api_key_from_env() {
        let client = crate::default_client::create_client();
        return Ok(Some(CodexAuth::from_api_key_with_client(
            api_key.as_str(),
            client,
        )));
    }

    let auth_file = get_auth_file(codex_home);
    let client = crate::default_client::create_client();
    let accounts = load_auth_accounts(&auth_file)?;
    let account = match accounts.into_iter().next() {
        Some(account) => account,
        None => return Ok(None),
    };

    if account.mode == AuthMode::ApiKey {
        if let Some(api_key) = &account.auth_dot_json.openai_api_key {
            return Ok(Some(CodexAuth::from_api_key_with_client(api_key, client)));
        }
    }

    Ok(Some(CodexAuth {
        api_key: account.auth_dot_json.openai_api_key.clone(),
        mode: account.mode,
        account_auth_id: Some(account.id),
        auth_file,
        auth_dot_json: Arc::new(Mutex::new(Some(account.auth_dot_json))),
        client,
    }))
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
pub struct TokenCounters {
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_combined_tokens: u64,
    pub cooldown_window_input: u64,
    pub cooldown_window_output: u64,
}

impl Default for TokenCounters {
    fn default() -> Self {
        Self {
            total_input_tokens: 0,
            total_output_tokens: 0,
            total_combined_tokens: 0,
            cooldown_window_input: 0,
            cooldown_window_output: 0,
        }
    }
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

/// Internal cached auth state.
#[derive(Clone, Debug)]
struct CachedAuth {
    auth: Option<CodexAuth>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token_data::IdTokenInfo;
    use crate::token_data::KnownPlan;
    use crate::token_data::PlanType;
    use base64::Engine;
    use pretty_assertions::assert_eq;
    use serde::Serialize;
    use serde_json::json;
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

    fn write_auth_file(params: AuthFileParams, codex_home: &Path) -> std::io::Result<String> {
        let auth_file = get_auth_file(codex_home);
        // Create a minimal valid JWT for the id_token field.
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
                "chatgpt_plan_type": params.chatgpt_plan_type,
                "chatgpt_user_id": "user-12345",
                "user_id": "user-12345",
            }
        });
        let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
        let header_b64 = b64(&serde_json::to_vec(&header)?);
        let payload_b64 = b64(&serde_json::to_vec(&payload)?);
        let signature_b64 = b64(b"sig");
        let fake_jwt = format!("{header_b64}.{payload_b64}.{signature_b64}");

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
        let auth = load_auth(&codex_home, enable_codex_api_key_env)
            .ok()
            .flatten();
        Self {
            codex_home,
            inner: RwLock::new(CachedAuth { auth }),
            enable_codex_api_key_env,
        }
    }

    /// Create an AuthManager with a specific CodexAuth, for testing only.
    pub fn from_auth_for_testing(auth: CodexAuth) -> Arc<Self> {
        let cached = CachedAuth { auth: Some(auth) };
        Arc::new(Self {
            codex_home: PathBuf::new(),
            inner: RwLock::new(cached),
            enable_codex_api_key_env: false,
        })
    }

    /// Current cached auth (clone). May be `None` if not logged in or load failed.
    pub fn auth(&self) -> Option<CodexAuth> {
        self.inner.read().ok().and_then(|c| c.auth.clone())
    }

    /// Force a reload of the auth information from auth.json. Returns
    /// whether the auth value changed.
    pub fn reload(&self) -> bool {
        let new_auth = load_auth(&self.codex_home, self.enable_codex_api_key_env)
            .ok()
            .flatten();
        if let Ok(mut guard) = self.inner.write() {
            let changed = !AuthManager::auths_equal(&guard.auth, &new_auth);
            guard.auth = new_auth;
            changed
        } else {
            false
        }
    }

    fn auths_equal(a: &Option<CodexAuth>, b: &Option<CodexAuth>) -> bool {
        match (a, b) {
            (None, None) => true,
            (Some(a), Some(b)) => a == b,
            _ => false,
        }
    }

    /// Convenience constructor returning an `Arc` wrapper.
    pub fn shared(codex_home: PathBuf, enable_codex_api_key_env: bool) -> Arc<Self> {
        Arc::new(Self::new(codex_home, enable_codex_api_key_env))
    }

    /// Attempt to refresh the current auth token (if any). On success, reload
    /// the auth state from disk so other components observe refreshed token.
    pub async fn refresh_token(&self) -> std::io::Result<Option<String>> {
        let auth = match self.auth() {
            Some(a) => a,
            None => return Ok(None),
        };
        match auth.refresh_token().await {
            Ok(token) => {
                // Reload to pick up persisted changes.
                self.reload();
                Ok(Some(token))
            }
            Err(e) => Err(e),
        }
    }

    /// Log out by deleting the on‑disk auth.json (if present). Returns Ok(true)
    /// if a file was removed, Ok(false) if no auth file existed. On success,
    /// reloads the in‑memory auth cache so callers immediately observe the
    /// unauthenticated state.
    pub fn logout(&self) -> std::io::Result<bool> {
        let removed = super::auth::logout(&self.codex_home)?;
        // Always reload to clear any cached auth (even if file absent).
        self.reload();
        Ok(removed)
    }
}

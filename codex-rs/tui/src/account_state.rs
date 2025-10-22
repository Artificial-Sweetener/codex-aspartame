use std::collections::HashMap;
use std::time::Duration;

use chrono::DateTime;
use chrono::Local;
use chrono::Utc;
use codex_app_server_protocol::AuthMode;
use codex_core::auth::AccountSummary;
use codex_core::auth::TokenCounters;
use codex_core::auth::UsageLogEntry;
use codex_core::protocol::AccountEvent;
use codex_core::protocol::AccountEventKind;
use codex_core::protocol::TokenUsage;
use tracing::warn;
use uuid::Uuid;

use crate::status::{format_tokens_compact, title_case};

pub(crate) const HISTORY_LIMIT: usize = 50;

#[derive(Debug, Clone, Default)]
pub(crate) struct AccountsState {
    pub active_account_id: Option<Uuid>,
    pub accounts: Vec<AccountDisplay>,
    pub history: Vec<CooldownHistoryEntry>,
    pub last_event: Option<AccountEventSummary>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct AccountDisplay {
    pub id: Uuid,
    pub label: String,
    pub plan: Option<String>,
    pub mode_label: String,
    pub status: AccountStatus,
    pub lifetime: TokenCounters,
    pub tokens_since_last: TokenUsage,
}

#[derive(Debug, Clone)]
pub(crate) enum AccountStatus {
    Ready,
    CoolingDown { cooldown_until: DateTime<Utc> },
    Error(String),
}

#[derive(Debug, Clone)]
pub(crate) struct CooldownHistoryEntry {
    pub label: String,
    pub plan: Option<String>,
    pub timestamp: DateTime<Local>,
    pub tokens_total: u64,
    pub tokens_input: u64,
    pub tokens_output: u64,
    pub resets_in: Duration,
    pub reason: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct AccountEventSummary {
    pub timestamp: DateTime<Local>,
    pub message: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct AccountsSnapshot {
    pub accounts: Vec<AccountDisplay>,
    pub history: Vec<CooldownHistoryEntry>,
}

pub(crate) fn build_accounts_snapshot(
    accounts: Vec<AccountSummary>,
    history: Vec<UsageLogEntry>,
) -> AccountsSnapshot {
    let now = Utc::now();
    let displays: Vec<AccountDisplay> = accounts
        .into_iter()
        .map(|summary| map_account_summary(summary, now))
        .collect();

    let label_map: HashMap<Uuid, (String, Option<String>)> = displays
        .iter()
        .map(|display| (display.id, (display.label.clone(), display.plan.clone())))
        .collect();

    let history_entries = history
        .into_iter()
        .map(|entry| map_usage_entry(entry, &label_map))
        .collect();

    AccountsSnapshot {
        accounts: displays,
        history: history_entries,
    }
}

impl AccountsState {
    pub(crate) fn apply_snapshot(&mut self, snapshot: AccountsSnapshot) {
        self.accounts = snapshot.accounts;
        self.history = snapshot.history;
    }

    pub(crate) fn record_event(&mut self, event: &AccountEvent) {
        let account_id = Uuid::parse_str(&event.account_id).ok();
        if matches!(event.kind, AccountEventKind::Selected) {
            self.active_account_id = account_id;
        }
        if let Some(summary) = AccountEventSummary::from_event(event) {
            self.last_event = Some(summary);
        }
    }

    pub(crate) fn set_error(&mut self, message: String) {
        self.error_message = Some(message);
    }

    pub(crate) fn clear_error(&mut self) {
        self.error_message = None;
    }
}

impl AccountEventSummary {
    fn from_event(event: &AccountEvent) -> Option<Self> {
        let timestamp = match DateTime::parse_from_rfc3339(&event.timestamp) {
            Ok(dt) => dt.with_timezone(&Local),
            Err(err) => {
                warn!(error = %err, "failed to parse account event timestamp");
                Local::now()
            }
        };
        let label = event
            .label
            .clone()
            .unwrap_or_else(|| event.account_id.clone());
        let plan = event.plan_type.as_ref().map(|plan| title_case(plan));
        let decorated_label = if let Some(plan) = plan.as_ref() {
            format!("{label} ({plan})")
        } else {
            label.clone()
        };

        let (message, detail) = match &event.kind {
            AccountEventKind::Selected => (format!("Selected {decorated_label}"), None),
            AccountEventKind::UsageRecorded { usage } => {
                let total = format_tokens_compact(usage.total_tokens);
                let detail = format!(
                    "input {} • output {}",
                    format_tokens_compact(usage.input_tokens),
                    format_tokens_compact(usage.output_tokens)
                );
                (format!("Recorded {total} tokens"), Some(detail))
            }
            AccountEventKind::CooldownStarted {
                cooldown_until,
                tokens_since_last,
                resets_in_seconds,
                reason,
                ..
            } => {
                let total = format_tokens_compact(tokens_since_last.total_tokens);
                let duration = format_duration_short(*resets_in_seconds);
                let mut details: Vec<String> = Vec::new();
                if let Some(until) = cooldown_until
                    .as_ref()
                    .and_then(|ts| DateTime::parse_from_rfc3339(ts).ok())
                {
                    let local = until.with_timezone(&Local);
                    details.push(format!("resets at {}", local.format("%H:%M")));
                }
                if let Some(reason) = reason.as_ref().filter(|r| !r.is_empty()) {
                    details.push(format!("reason: {reason}"));
                }
                let detail = if details.is_empty() {
                    None
                } else {
                    Some(details.join(" · "))
                };
                (
                    format!("Cooldown for {decorated_label}: {duration} after {total}"),
                    detail,
                )
            }
        };

        Some(Self {
            timestamp,
            message,
            detail,
        })
    }
}

fn map_account_summary(summary: AccountSummary, now: DateTime<Utc>) -> AccountDisplay {
    let label = summary.label.unwrap_or_else(|| summary.id.to_string());
    let plan = summary
        .plan
        .filter(|s| !s.is_empty())
        .map(|plan| title_case(&plan));
    let mode_label = format_auth_mode(summary.mode);
    let status = match summary.cooldown_until.filter(|until| *until > now) {
        Some(until) => AccountStatus::CoolingDown {
            cooldown_until: until,
        },
        None => match summary.last_error.clone().filter(|s| !s.is_empty()) {
            Some(err) => AccountStatus::Error(err),
            None => AccountStatus::Ready,
        },
    };

    AccountDisplay {
        id: summary.id,
        label,
        plan,
        mode_label,
        status,
        lifetime: summary.lifetime_usage,
        tokens_since_last: summary.tokens_since_last_cooldown,
    }
}

fn map_usage_entry(
    entry: UsageLogEntry,
    labels: &HashMap<Uuid, (String, Option<String>)>,
) -> CooldownHistoryEntry {
    let label = labels
        .get(&entry.account_id)
        .map(|(label, _)| label.clone())
        .unwrap_or_else(|| entry.account_id.to_string());
    let plan_from_entry = entry
        .plan_type
        .as_ref()
        .filter(|s| !s.is_empty())
        .map(|plan| title_case(plan));
    let plan = plan_from_entry.or_else(|| {
        labels
            .get(&entry.account_id)
            .and_then(|(_, plan)| plan.clone())
    });

    CooldownHistoryEntry {
        label,
        plan,
        timestamp: entry.timestamp.with_timezone(&Local),
        tokens_total: entry.tokens_since_last_cooldown.total_combined_tokens,
        tokens_input: entry.tokens_since_last_cooldown.cooldown_window_input,
        tokens_output: entry.tokens_since_last_cooldown.cooldown_window_output,
        resets_in: Duration::from_secs(entry.resets_in_seconds),
        reason: entry.reason.filter(|r| !r.is_empty()),
    }
}

fn format_auth_mode(mode: AuthMode) -> String {
    match mode {
        AuthMode::ApiKey => "API key".to_string(),
        AuthMode::ChatGPT => "ChatGPT".to_string(),
    }
}

pub(crate) fn format_duration_short(seconds: u64) -> String {
    if seconds >= 3600 {
        let hours = seconds / 3600;
        let minutes = (seconds % 3600) / 60;
        let secs = seconds % 60;
        return format!("{hours}h {minutes:02}m {secs:02}s");
    }
    if seconds >= 60 {
        let minutes = seconds / 60;
        let secs = seconds % 60;
        return format!("{minutes}m {secs:02}s");
    }
    format!("{seconds}s")
}

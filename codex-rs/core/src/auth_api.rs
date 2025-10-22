use crate::auth::{AccountSummary, AuthManager, AuthMode};
use chrono::{Duration as ChronoDuration, Utc};

pub fn format_account_list(manager: &AuthManager) -> String {
    let accounts = manager.accounts();
    if accounts.is_empty() {
        return "No accounts configured.".to_string();
    }

    let mut output = format!(
        "{:<45} {:<16} {:<24} { >16}\n",
        "Label (id)", "Plan", "Status", "Lifetime total"
    );

    for summary in accounts {
        let label = display_label(&summary);
        let plan = display_plan(&summary);
        let status = display_status(&summary);
        let total = summary.lifetime_usage.total_combined_tokens;
        output.push_str(&format!("{label: <45} {plan: <16} {status: <24} {total: >16}\n"));
    }
    output
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
        parts.push(format!("{}h", hours));
    }
    if minutes > 0 {
        parts.push(format!("{}m", minutes));
    }
    if hours == 0 && minutes == 0 {
        parts.push(format!("{}s", secs));
    }

    parts.join(" ")
}

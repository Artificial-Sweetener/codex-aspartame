use chrono::Local;
use ratatui::style::Stylize;
use ratatui::text::Line;
use ratatui::text::Span;
use ratatui::widgets::Paragraph;
use ratatui::widgets::Wrap;

use crate::account_state::AccountDisplay;
use crate::account_state::AccountEventSummary;
use crate::account_state::AccountStatus;
use crate::account_state::AccountsState;
use crate::account_state::CooldownHistoryEntry;
use crate::account_state::format_duration_short;
use crate::render::renderable::ColumnRenderable;
use crate::render::renderable::Renderable;
use crate::status::format_tokens_compact;

pub(crate) fn build_overlay(state: &AccountsState) -> Vec<Box<dyn Renderable>> {
    let mut column = ColumnRenderable::new();

    column.push(Line::from("Accounts".bold()));
    column.push(blank_line());

    if let Some(error) = &state.error_message {
        column.push(Span::from(error.clone()).red());
        column.push(blank_line());
    }

    if let Some(summary) = &state.last_event {
        column.push(event_summary_block(summary));
        column.push(blank_line());
    }

    if state.accounts.is_empty() {
        column.push("No authenticated accounts configured.".dim());
    } else {
        for account in &state.accounts {
            column.push(account_block(
                account,
                state.active_account_id == Some(account.id),
            ));
            column.push(blank_line());
        }
    }

    column.push(blank_line());
    column.push(Line::from("Cooldown history".bold()));
    column.push(blank_line());

    if state.history.is_empty() {
        column.push("No cooldown events recorded.".dim());
    } else {
        for entry in &state.history {
            column.push(history_block(entry));
            column.push(blank_line());
        }
    }

    vec![Box::new(column)]
}

fn account_block(account: &AccountDisplay, is_active: bool) -> Box<dyn Renderable> {
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(account_header_line(account, is_active));
    lines.push(account_state_line(account));
    lines.push(lifetime_line(account));
    lines.push(window_line(account));

    Paragraph::new(lines).wrap(Wrap { trim: false }).into()
}

fn account_header_line(account: &AccountDisplay, is_active: bool) -> Line<'static> {
    let mut spans: Vec<Span<'static>> = Vec::new();
    if is_active {
        spans.push("●".green().bold());
        spans.push(" ".into());
    }

    let label_span = Span::from(account.label.clone()).bold();
    spans.push(if is_active {
        label_span.green()
    } else {
        label_span
    });

    let mut meta_parts: Vec<String> = Vec::new();
    if account.email != account.label {
        meta_parts.push(account.email.clone());
    }
    if let Some(plan) = &account.plan {
        meta_parts.push(plan.clone());
    }
    if !account.mode_label.is_empty() {
        meta_parts.push(account.mode_label.clone());
    }
    if !meta_parts.is_empty() {
        spans.push("  ".into());
        spans.push(Span::from(format!("({})", meta_parts.join(" • "))).dim());
    }

    Line::from(spans)
}

fn account_state_line(account: &AccountDisplay) -> Line<'static> {
    match &account.status {
        AccountStatus::Ready => Line::from(vec!["State: ".dim(), "Ready".green()]),
        AccountStatus::CoolingDown { cooldown_until } => {
            let local_until = cooldown_until.with_timezone(&Local);
            let remaining_secs = local_until
                .signed_duration_since(Local::now())
                .num_seconds()
                .max(0) as u64;
            let message = if remaining_secs == 0 {
                "Cooling down".to_string()
            } else {
                format!(
                    "Cooling down for {} (resets at {})",
                    format_duration_short(remaining_secs),
                    local_until.format("%H:%M")
                )
            };
            Line::from(vec!["State: ".dim(), message.yellow()])
        }
        AccountStatus::Error(message) => {
            Line::from(vec!["State: ".dim(), Span::from(message.clone()).red()])
        }
    }
}

fn lifetime_line(account: &AccountDisplay) -> Line<'static> {
    let total = format_tokens_compact(account.lifetime.total_combined_tokens);
    let input = format_tokens_compact(account.lifetime.total_input_tokens);
    let output = format_tokens_compact(account.lifetime.total_output_tokens);
    Line::from(vec![
        "Lifetime: ".dim(),
        Span::from(total).bold(),
        Span::from(format!(" total (in {input} / out {output})")).dim(),
    ])
}

fn window_line(account: &AccountDisplay) -> Line<'static> {
    let usage = &account.tokens_since_last;
    let total = format_tokens_compact(usage.total_tokens);
    let input = format_tokens_compact(usage.non_cached_input());
    let cached = usage.cached_input();
    let output = format_tokens_compact(usage.output_tokens);
    let mut detail = format!("in {input} / out {output}");
    if cached > 0 {
        detail.push_str(&format!(" (cached {})", format_tokens_compact(cached)));
    }
    Line::from(vec![
        "Window: ".dim(),
        Span::from(total).bold(),
        Span::from(format!(" total ({detail})")).dim(),
    ])
}

fn history_block(entry: &CooldownHistoryEntry) -> Box<dyn Renderable> {
    let timestamp = entry.timestamp.format("%b %-d %H:%M").to_string();
    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut header_spans: Vec<Span<'static>> = vec![Span::from(timestamp).dim(), "  ".into()];
    let label_span = Span::from(entry.label.clone()).bold();
    header_spans.push(label_span);
    if let Some(plan) = &entry.plan {
        header_spans.push("  ".into());
        header_spans.push(Span::from(format!("({plan})")).dim());
    }
    lines.push(Line::from(header_spans));

    let total = format_tokens_compact(entry.tokens_total);
    let input = format_tokens_compact(entry.tokens_input);
    let output = format_tokens_compact(entry.tokens_output);
    lines.push(Line::from(vec![
        "Tokens: ".dim(),
        Span::from(total).bold(),
        Span::from(format!(" total (in {input} / out {output})")).dim(),
    ]));

    let resets = format_duration_short(entry.resets_in.as_secs());
    let mut reset_spans: Vec<Span<'static>> = vec!["Reset: ".dim(), resets.bold()];
    if let Some(reason) = entry.reason.as_ref() {
        reset_spans.push("  ".into());
        reset_spans.push(Span::from(format!("reason: {reason}")).dim());
    }
    lines.push(Line::from(reset_spans));

    Paragraph::new(lines).wrap(Wrap { trim: false }).into()
}

fn event_summary_block(summary: &AccountEventSummary) -> Box<dyn Renderable> {
    let timestamp = summary.timestamp.format("%b %-d %H:%M").to_string();
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(Line::from(vec![
        Span::from(timestamp).dim(),
        "  ".into(),
        Span::from(summary.message.clone()).bold(),
    ]));
    if let Some(detail) = summary.detail.as_ref() {
        lines.push(Line::from(detail.clone()).dim());
    }
    Paragraph::new(lines).wrap(Wrap { trim: false }).into()
}

fn blank_line() -> Line<'static> {
    Line::from(Vec::<Span<'static>>::new())
}

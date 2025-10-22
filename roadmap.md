# Auth Management Roadmap

## 0. Remove the stray CLI auth commands (after the TUI feature ships)
- Delete `codex-rs/cli/src/auth_cmd.rs`, drop the `mod auth_cmd;` import, and remove the `Subcommand::Auth` arm in `codex-rs/cli/src/main.rs`.
- Remove `codex-rs/cli/tests/auth.rs` and any related fixtures; these currently exercise the `/auth` CLI path (commit `d626aee6`).
- Prune the extra dependencies added in that commit from `codex-rs/cli/Cargo.toml` and `Cargo.lock`.
- Grep for `run_auth_command` / `AuthSubcommand` to ensure no other code relies on the deleted module.

## 1. Core auth hooks needed by the TUI
- Extend `codex-rs/core/src/auth.rs` (building on the multi-account work in commits `5116fc36`, `4c5e9c7a`, `605ae102`):
  - Add an `email: Option<String>` field to `AccountSummary` so the UI can show real addresses (update `AccountState::summary`, `build_status_account`, serde derives, and tests).
  - Introduce `pub fn set_preferred_account(&self, id: Uuid) -> std::io::Result<()>` that demotes other accounts/priorities, sorts the list, and persists—this will let `/auth` re-order accounts cleanly.
  - Ensure `AuthManager::available_accounts` returns results in the updated priority order (call `sort_accounts` after changes).
  - Expose `pub fn usage_history_for(&self, id: Uuid, limit: Option<usize>) -> std::io::Result<Vec<UsageLogEntry>>` so `/auth info` can request a single account’s cooldown timeline without loading the full log.
- Update any necessary re-exports in `codex-rs/core/src/lib.rs` so the TUI crate can call the new helpers.
- Once changes are in, plan to run `cargo test -p codex-core` and the existing `core/tests/suite/client.rs` coverage to confirm the earlier assistant-authored logic still passes.

## 2. TUI data plumbing (respecting the existing overlay work from `dc0cf503`)
- Extend `codex-rs/tui/src/app.rs`:
  - Add `AppEvent` variants: `OpenAuthSwitcher`, `OpenAuthInfo`, `LinkChatgptAccount`, `SwitchToAccount(Uuid)`, `ShowAccountHistory(Uuid)`, `RefreshAuthState`.
  - Handle those events by calling `refresh_accounts_state`, invoking the new `AuthManager::set_preferred_account`, and fetching per-account history via `usage_history_for`.
- Update `codex-rs/tui/src/account_state.rs`:
  - Include the new email field (falling back to the label/UUID when absent).
  - Add per-account history storage (e.g., `HashMap<Uuid, Vec<CooldownHistoryEntry>>`) so the drill-down can avoid recomputation.
  - Introduce selection/loading flags for the detail view (e.g., `selected_history_account`).
- Decide how to evolve the existing `account_overlay.rs` from `dc0cf503`: either refactor it into the new `/auth info` view or delete it once the replacement is live to avoid duplicate overlays.

## 3. `/auth` quick switch command (slash command + popup)
- `codex-rs/tui/src/slash_command.rs`: add an `Auth` command entry, description, and `available_during_task` behavior consistent with other configuration commands.
- `codex-rs/tui/src/chatwidget.rs`:
  - Handle `/auth` by calling a new `open_auth_switcher_popup()` using the existing `SelectionView` infrastructure (follow `open_model_popup()` for structure and styling).
  - Build selection items for each account using data from `AccountsState` (email, plan, cooldown time remaining via `format_duration_short`). Mark the currently active account via `SelectionItem::is_current`.
  - Append a "Link new ChatGPT+ account" option that triggers `AppEvent::LinkChatgptAccount`.
- If we keep the overlay layout consistent with upstream, consider placing the switcher popup in `bottom_pane` (similar to the model/approvals selectors) so keyboard hints and dismissal match.

## 4. `/auth info` detail command + history drill-down
- `slash_command.rs`: add `AuthInfo` with description "show detailed account usage and cooldown history".
- `chatwidget.rs`: on `/auth info`, send `AppEvent::OpenAuthInfo` to the app layer.
- Create `codex-rs/tui/src/components/auth_info.rs` (or repurpose `account_overlay.rs`):
  - Render a scrollable static overlay with one section per account (header: label/email/plan; body: lifetime totals, tokens since last cooldown, cooldown status, priority).
  - Allow the user to focus a section (up/down + enter) and request history via `AppEvent::ShowAccountHistory(account_id)`.
  - Display the returned history timeline using the same formatting helpers as the existing overlay (`format_tokens_compact`, `format_duration_short`), and reuse portions of `history_block` where possible.
- Hook the component into `App::overlay` so it mirrors the visual style of the existing `A C C O U N T S` modal from `dc0cf503`. If we replace the old overlay entirely, remove the unused file once migration is complete.

## 5. ChatGPT linking flow inside the TUI
- Create a helper (e.g., `codex-rs/tui/src/auth_link.rs`) that wraps the CLI login flow introduced earlier:
  - Spawn `codex_login::run_login_server(ServerOptions::new(codex_home, CLIENT_ID.to_string()))` (same as `cli/src/login.rs::login_with_chatgpt`).
  - While awaiting the future, surface status text in the popup (e.g., send an info message through `chatwidget` or a dedicated modal).
  - On success, call `AuthManager::reload(None)` and raise `AppEvent::RefreshAuthState` so the UI updates immediately; on failure, show a red error message and keep the popup open for retry.
  - Ensure the temporary directory lifecycle matches the CLI implementation.

## 6. Polish, tests, and docs
- Update or create insta snapshots under `codex-rs/tui/src/snapshots/` for the `/auth` switcher and `/auth info` overlays so regressions are caught.
- Add unit tests for `AuthManager::set_preferred_account` / `usage_history_for`, and verify the existing client tests (from `5116fc36`, `4c5e9c7a`, `605ae102`) still pass.
- Document the new commands in `docs/getting-started.md` (TUI command section) or create a dedicated `/auth` command reference; remove mentions of the CLI auth subcommands.
- After the new UI ships, delete any leftover overlay code (if replaced) and rerun `just fmt` / `just fix -p codex-tui` / targeted tests (`cargo test -p codex-tui`).

This plan leverages everything already in the repo (multi-account auth, cooldown events, the existing overlay) and makes sure anything we don’t reuse—like the CLI subcommands or the old overlay—gets removed once the TUI experience replaces it.
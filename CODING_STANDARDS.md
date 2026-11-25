# Coding standards

**The bar:** a person reads any file in this repo (code, tests, docs, commit messages) and understands it without hesitation. The reviewer asks "can I understand this quickly?", not "how many lines is it?"

Tools enforce everything they can, and CI fails on it. This file covers what they cannot check.

## Enforced by tools

Fix their failures; don't argue with them.

- **Formatting:** `rustfmt` with default settings.
- **Lints:** `clippy` with `-D warnings`. Override a lint with `#[expect(..., reason = "...")]`, never a bare `allow`.
- **No `unsafe`:** `unsafe_code = "forbid"`.
- **Licences and advisories:** `cargo deny check`.
- **Commit subjects:** 72 characters or fewer, checked on every pull request.

## Rust guidelines

Follow [Microsoft's Pragmatic Rust Guidelines](https://microsoft.github.io/rust-guidelines/). Agents read the condensed version at <https://microsoft.github.io/rust-guidelines/agents/all.txt>. Cite a guideline by its ID (`M-PANIC-ON-BUG`, `M-CONCISE-NAMES`) in reviews. The rules that matter most here:

- **Errors:** `thiserror` types in the library, `anyhow` only in `main.rs`. A detected programming bug panics; anything a user can cause is an error.
- **Secrets:** every password and token is a `secrecy` type, so it can't be printed by accident.
- **No weasel names:** no `Manager`, `Service`, `Factory` or `Helper`.
- **Teardown is explicit.** `Drop` can't run async network calls, so a run ends with an explicit async teardown, and the sweep catches what it missed.

## Names

**Names say what a thing is or does, so the reader never has to look it up.** Name a value whose meaning isn't obvious.

```rust
// ❌
interval(Duration::from_secs(300))
// ✅
const EXPIRY_PUSH_INTERVAL: Duration = Duration::from_secs(5 * 60);
interval(EXPIRY_PUSH_INTERVAL)
```

## One job each

**A function or test does one thing you can sum up in one sentence.** If the summary needs "and", split it.

## Comments

- **A comment explains why, never what.** The code already says what.
- **Code never mentions tickets, sessions or history** ("fixed in #12"). History belongs in commits and issues.
- **Doc comments only where the name and signature don't already say it.**

## Tests

- **A test name is a sentence: a scenario plus its outcome**, e.g. `a_killed_run_leaves_no_login_after_the_next_sweep`.
- **Assert what a user or the database observes**, not how the code is built.
- **No logic in tests.** Write expected values out. Repeating a few clear lines beats a shared helper the reader must open.

## Commit messages

**The subject is one sentence of 72 characters or fewer, describing the change in behaviour.** Then a blank line and a body explaining why, when that isn't obvious.

```text
❌ Update proxy
✅ Drop the temporary login when the agent exits on SIGTERM
```

## Review

- **A different model from the author reviews** (see `AGENTS.md`).
- **Every pull request quotes 2–3 short excerpts of new code** for the owner: the most complex function and one test.
- **A change is approved once it clearly improves the code's overall health.** It doesn't need to be perfect.

# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Reviewer TOTP second factor. `issue -totp` stores a per-invitation secret
  and prints an `otpauth://` URI. The maintenance page asks for the current
  code; each code admits once with one period of allowed clock drift, and the
  `list` command shows which invitations require a code.
- Failure limits on the invitation exchange: 20 failures per client IP and 5
  per TOTP invitation in fifteen minutes. Locked keys receive `429` with a
  `Retry-After` header.

## [0.2.0] - 2026-11-03

### Added

- Per-invitation usage counters. The store now records `uses` and
  `last_used_at` for each invitation, and the `list` command prints both. The
  counters live in the invitation store and are never part of the invitation
  token.
- Optional use limits. `issue -max-uses N` sets `max_uses` on an invitation.
  When the limit is reached the gate refuses the link as invalid, logs
  `launchgate: invitation ... refused: maximum uses reached`, and keeps the
  invitation in the store for audit. The default `0` means unlimited.
- Optional access webhook. `LAUNCH_WEBHOOK_URL` makes the gate POST a JSON
  event (`invitation_id`, `result`, `timestamp`, `client_ip`, `user_agent`) for
  every invitation admission and refusal. Events are delivered in the
  background with a three-second timeout; failures are logged and never change
  the HTTP response. The webhook is opt-in and unset by default.
- Tests for counter persistence, use-limit exhaustion, webhook payloads,
  webhook failures, and disabled-feature defaults.

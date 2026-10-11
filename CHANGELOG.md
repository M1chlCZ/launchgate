# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

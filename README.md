# launchgate

Access control for a site that is not public yet.

## Modes

| Mode | Behavior |
| --- | --- |
| `closed` | The gate serves the maintenance page. Visitors have no access. |
| `preview` | The gate serves the maintenance page. An invitation link admits one reviewer. |
| `public` | The gate proxies the application. Private paths stay out of search results. |

The gate does not send email. You deliver the invitation URL.

## Quick start

Run these commands from the repository root. The gate listens on port 8090.

1. Create the invitation store:

   ```sh
   mkdir -p state
   LAUNCH_STATE_DIR=$PWD/state go run . init
   ```

2. Select the preview mode:

   ```sh
   LAUNCH_STATE_DIR=$PWD/state go run . mode preview
   ```

3. Start the gate. Point the upstreams to your application:

   ```sh
   LAUNCH_ORIGIN=http://localhost:8090 \
   LAUNCH_FRONTEND=http://localhost:3000 \
   LAUNCH_BACKEND=http://localhost:8080 \
   LAUNCH_STATE_DIR=$PWD/state \
   go run . serve
   ```

4. Issue an invitation in a second terminal:

   ```sh
   LAUNCH_STATE_DIR=$PWD/state go run . issue -label Reviewer
   ```

   The command prints an invitation URL. Open the URL in a browser.

5. Open the site to all visitors:

   ```sh
   LAUNCH_STATE_DIR=$PWD/state go run . mode public
   ```

## Commands

| Command | Result |
| --- | --- |
| `serve` | Start the gate. |
| `init` | Create the invitation store in the closed mode. |
| `mode closed\|preview\|public` | Set the access mode. |
| `issue -label NAME [-ttl 168h] [-max-uses N] [-totp]` | Create an invitation and print the URL. |
| `revoke INVITATION_ID` | Delete one invitation. |
| `list` | Show the mode and all active invitations. |
| `healthcheck` | Probe the local health endpoint. |

## Configuration

Only `LAUNCH_ORIGIN` is mandatory. The gate validates the origin before it starts.

| Variable | Default | Purpose |
| --- | --- | --- |
| `LAUNCH_ORIGIN` | none | The canonical origin, for example `https://shop.example`. HTTPS is mandatory, except for loopback addresses. |
| `LAUNCH_FRONTEND` | `http://frontend:3000` | The frontend upstream. |
| `LAUNCH_BACKEND` | `http://backend:8080` | The backend upstream. Paths below `/api` and `/media` use this upstream. |
| `LAUNCH_STATE_DIR` | `/data/launch` | The directory for the invitation store. |
| `LAUNCH_TRUSTED_PROXY` | empty | One proxy address in CIDR form. Only this peer can set `X-Real-IP`. Empty means that the gate ignores the header. |
| `LAUNCH_BYPASS_ROUTES` | empty | Exact POST paths that bypass the gate, for example a payment webhook. |
| `LAUNCH_PAGE_DIR` | empty | A directory with your own page files. Empty uses the built-in page. |
| `LAUNCH_WEBHOOK_URL` | empty | The audit endpoint for invitation events. It must be an `http` or `https` URL. Empty disables the webhook. The timeout is three seconds. |

## Invitations

1. The gate creates a 32-byte token. It stores the SHA-256 hash and discards the token.
2. The reviewer opens the invitation URL. The page reads the token from the URL fragment.
3. The page sends the token to the gate. When the invitation requires a TOTP code, the page asks for it first. The gate sets a secure cookie.
4. The reviewer sees the application until the invitation expires or you revoke it.
5. The cookie lifetime is at most seven days. It is never longer than the invitation.
6. Each successful exchange updates the invitation counters. See [Counters and use limits](#counters-and-use-limits).

## Counters and use limits

The gate counts every successful invitation exchange and records the last-used
time. The counters live in the invitation store next to the invitation record.
The invitation token does not carry them. The `list` command shows the count,
the limit, and the last use:

```sh
LAUNCH_STATE_DIR=$PWD/state go run . list
```

```text
Mode: preview
4a1c8d2f...	2026-11-10T12:00:00Z	Reviewer	2/3	2026-11-03T09:15:00Z	-
```

The last column is `totp` when the invitation requires a verification code,
and `-` otherwise.

An invitation can carry a use limit with `-max-uses`. When the limit is
reached, the gate refuses the link as invalid and logs this line:

```text
launchgate: invitation 4a1c8d2f... refused: maximum uses reached
```

The gate keeps the invitation in the store for audit.

```sh
LAUNCH_STATE_DIR=$PWD/state go run . issue -label Reviewer -max-uses 3
```

One use is one successful exchange of the invitation link at `/_launch/access`.
Requests with the resulting cookie do not consume uses. The default `0` means
unlimited, and an invitation without a limit always admits. The limit is at
most 100000.

## TOTP verification

An invitation can require a time-based verification code. Create it with
`-totp`:

```sh
LAUNCH_STATE_DIR=$PWD/state go run . issue -label Reviewer -totp
```

The command prints the invitation URL and an `otpauth://` URI. Add the URI to
an authenticator app. The reviewer opens the invitation URL; the page then
asks for the current six-digit code. The code uses SHA-1, six digits and a
30-second period, with one period of allowed clock drift.

Each code admits once. A replayed or incorrect code is refused. Five incorrect
codes in fifteen minutes lock the invitation until the window passes.

The TOTP secret lives in the invitation store next to the token hash. The
store file is owner-only, like the token hashes.

## Access webhook

Set `LAUNCH_WEBHOOK_URL` to send a small JSON event for every invitation
admission and refusal:

```sh
LAUNCH_WEBHOOK_URL=https://audit.example/launchgate go run . serve
```

```json
{
  "invitation_id": "4a1c8d2f...",
  "result": "admit",
  "timestamp": "2026-11-03T09:15:00Z",
  "client_ip": "203.0.113.9",
  "user_agent": "Mozilla/5.0 ..."
}
```

The `result` is `admit` or `refuse`. A refusal with no identifiable invitation
carries an empty `invitation_id`. The gate sends events in the background with
a three-second timeout. Delivery failures are logged and never change the HTTP
response. Events come only from the invitation exchange endpoint, not from
browse requests. The webhook is opt-in: when `LAUNCH_WEBHOOK_URL` is empty, the
gate sends nothing.

**Privacy:** `client_ip` and `user_agent` are personal data. Configure the
webhook only when the receiving endpoint is trusted and its retention policy is
appropriate.

## Custom page

The gate serves a built-in maintenance page by default. To use your own page, set `LAUNCH_PAGE_DIR` to a directory. The directory can contain these files:

| File | Required | Purpose |
| --- | --- | --- |
| `page.html` | yes | The page template. |
| `page.css` | no | The styles for the `{{.CSS}}` placeholder. |
| `page.js` | no | The script for the `{{.JS}}` placeholder. |

The gate computes the content security policy from the file contents. The page cannot load external resources.

## Crawler policy

The gate controls indexing in each mode.

- In `closed` and `preview` modes, `robots.txt` disallows all crawlers. Every response carries `X-Robots-Tag: noindex`.
- In `public` mode, the gate proxies `robots.txt` to the frontend. Public pages carry no gate header.

Private paths keep the header in every mode. The list is `/account`, `/admin`, `/api`, `/cart`, `/checkout`, `/healthz`, `/login`, `/media`, `/orders`, `/register`, `/_launch`, and `/_next`. A locale prefix such as `/en` does not change the match.

## Security

- The invitation cookie uses the `__Host-` prefix. It is `Secure`, `HttpOnly`, and `SameSite=Lax`.
- The gate removes the invitation cookie and all client forwarding headers before it proxies a request.
- A bypass route must match the method, the exact path, and an empty query string. The body limit is 64 KiB.
- All gate responses are `no-store`.
- A corrupt or missing store fails closed. The gate denies access.
- The gate stores invitation tokens as hashes only.
- The gate limits failed invitation exchanges to 20 per client IP and 5 per
  TOTP invitation in fifteen minutes. A locked key receives `429` with a
  `Retry-After` header. The limits live in memory and reset on restart.
- The access webhook is opt-in. The gate sends the client IP and the user agent
  only to the configured endpoint, and only for invitation exchanges.

## Docker

Run the example stack:

```sh
docker compose run --rm gate init
docker compose up -d --build
```

The example uses `nginx:alpine` as the demo upstream. The file `compose.yaml` shows the volume and the hardening options.

## Development

```sh
make test
make vet
make build
```

## License

MIT. See `LICENSE`.

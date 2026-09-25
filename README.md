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
| `issue -label NAME [-ttl 168h]` | Create an invitation and print the URL. |
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

## Invitations

1. The gate creates a 32-byte token. It stores the SHA-256 hash and discards the token.
2. The reviewer opens the invitation URL. The page reads the token from the URL fragment.
3. The page sends the token to the gate. The gate sets a secure cookie.
4. The reviewer sees the application until the invitation expires or you revoke it.
5. The cookie lifetime is at most seven days. It is never longer than the invitation.

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

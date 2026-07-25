<p align="center">
  <img src="priv/static/logo.png" width="120" alt="gleam-pds star logo">
</p>

# gleam-pds

An [AT Protocol](https://atproto.com) Personal Data Server, written in
[Gleam](https://gleam.run) on the BEAM. The package and module name is
`gleam_pds`, since Gleam names can't contain hyphens.

It is a real, federating PDS: accounts created on it are ingested by the
official `bsky.network` relay and indexed by the Bluesky appview. A running
instance serves [pds.readifur.gay](https://pds.readifur.gay).

Everything lives in one OTP application and one SQLite file: no Postgres, no
Redis, no sidecars. It is small enough to read end to end.

## Status

Working and deployed, but young. Treat it as a hobbyist/self-hoster PDS rather
than something to put other people's accounts on:

- Blob bytes are stored inline in SQLite, so **the database file is the entire
  server**. Back it up (Litestream or equivalent) before relying on it.
- There is no blob garbage collection yet (`blob_refs` exists but is unswept).
- Without `GLEAM_PDS_ROTATION_KEY` set, PLC operations fall back to reusing
  the account signing key as the rotation key. Set it (see below).
- Test coverage is thin: crypto and repo units only, no HTTP or federation
  tests.

## What works

**Repo & sync:** canonical MST built through a single shared builder, dag-cbor
blocks, P-256 signed commits, `getRepo` CARs from a full reachability walk,
`applyWrites`, swap-commit/swap-record enforcement, blobs with raw-codec
(`bafkrei…`) CIDs.

**Firehose:** durable `firehose_events` sequencer that survives restarts,
`subscribeRepos` over WebSocket with cursor backfill, `#commit` / `#account` /
`#identity` / `#sync` / `#info` frames, throttled `requestCrawl` to relays on
write.

**Identity:** `did:plc` creation and updates, `did:web` for the server itself,
wildcard subdomain handles resolved via `/.well-known/atproto-did`,
`resolveHandle` / `resolveDid` / `resolveIdentity` / `updateHandle`,
`signPlcOperation` / `submitPlcOperation`.

**Accounts & auth:** password login by handle, DID, or email; app passwords
(scoped so they cannot manage the account); passkeys/WebAuthn with challenge,
origin, and counter verification; deactivate / activate / delete with cascade;
per-IP and per-credential rate limiting; optional Cloudflare Turnstile on
registration, verified server-side before any account work.

**OAuth:** authorization-code flow with mandatory PAR and S256 PKCE;
client-metadata documents fetched and validated at PAR time (registered
redirect URIs, declared grants and scopes, `dpop_bound_access_tokens`, with
the spec's `http://localhost` dev-client exception); DPoP-bound tokens with
server-issued nonces (stateless, rotating every 5 minutes) and the standard
`use_dpop_nonce` retry flow on both the token endpoint and resource requests;
`login_hint` prefill on the authorize form.

Anything under `app.bsky.*` or `chat.bsky.*` that is not stored locally is
proxied to the appview.

## Layout

```
src/
  gleam_pds.gleam              entry point: config, migrations, firehose, HTTP+WS
  gleam_pds/router.gleam       every route, and where rate limits are applied
  gleam_pds/config.gleam       environment configuration (fails fast on a weak secret)
  gleam_pds/db.gleam           schema + migrations; ALL SQLite access goes through here
  gleam_pds/ratelimit.gleam    fixed-window limits over an ETS table
  gleam_pds/crypto.gleam       JWT, P-256, PBKDF2, CIDs, DPoP
  gleam_pds/firehose.gleam     sequencer actor + subscribeRepos WebSocket
  gleam_pds/plc.gleam          did:plc registration and operations
  gleam_pds/xrpc/              com.atproto.* handlers (server, repo, sync, identity, account)
  gleam_pds/oauth/             OAuth 2.1 authorization server
  gleam_pds/passkey/           WebAuthn registration and login
  gleam_pds/web/               landing/login/register pages, response helpers
  *_ffi.erl                    Erlang FFI: CBOR, MST, crypto, WebAuthn, PLC, rate limits
```

One rule worth knowing before you touch the FFI: **Erlang FFI modules must not
talk to SQLite directly.** `sqlight`'s connection is an opaque
`{esqlite3, Ref}` that `esqlite3:q/2` rejects. Go through the `ffi_*` helpers in
`gleam_pds/db.gleam` (`gleam_pds@db:ffi_get_block/2` and friends) instead.

## Running it

Requires Gleam 1.15+ and Erlang/OTP 27+.

```sh
gleam deps download
GLEAM_PDS_SECRET=$(openssl rand -hex 32) gleam run
gleam test
```

### Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `GLEAM_PDS_SECRET` | none | **Required.** HMAC key for session/OAuth JWTs. Must be ≥ 16 chars and not a known-weak value; the server refuses to boot otherwise. |
| `GLEAM_PDS_ROTATION_KEY` | unset | Dedicated PLC rotation key: a 32-byte P-256 private key as 64 hex chars (`openssl rand -hex 32`). Accounts list only this key in their DID's `rotationKeys`, so a compromised signing key cannot rewrite the DID. Keep a copy somewhere safe; losing it means losing rotation control. |
| `GLEAM_PDS_HOSTNAME` | `gleam-pds.exe.xyz` | Public hostname of the PDS; also its `did:web` identity. |
| `GLEAM_PDS_HANDLE_DOMAIN` | `$GLEAM_PDS_HOSTNAME` | Domain new handles are issued under (`alice.example.com`). |
| `GLEAM_PDS_PUBLIC_URL` | `https://$GLEAM_PDS_HOSTNAME` | Service endpoint published in DID documents. |
| `GLEAM_PDS_PORT` | `8000` | Listen port. |
| `GLEAM_PDS_DB_PATH` | `gleam_pds.db` | SQLite file. |
| `GLEAM_PDS_SIGNUPS_DISABLED` | `false` | `true` makes `createAccount` return 403. |
| `GLEAM_PDS_RATELIMIT_DISABLED` | `false` | `true` disables rate limiting (local dev / load tests). |
| `GLEAM_PDS_TURNSTILE_SITE_KEY` | unset | Cloudflare Turnstile sitekey; renders the captcha widget on the registration page. Unset disables the captcha. |
| `GLEAM_PDS_TURNSTILE_SECRET_KEY` | unset | Matching Turnstile secret; `createAccount` verifies tokens against Cloudflare's siteverify directly. Keep it out of source and inject it like `GLEAM_PDS_SECRET`. |

### Handle DNS

For wildcard handles, point `*.example.com` at the server and get a wildcard
TLS certificate (DNS-01, via a `_acme-challenge` CNAME). Each handle is then
served from `alice.example.com/.well-known/atproto-did`.

### Deploying

The included `Dockerfile` produces a ~67 MB image, and `fly.example.toml`
deploys it to Fly.io with a persistent volume at `/data`. Copy it to `fly.toml`
and set your own app name and hostnames; the real `fly.toml` is gitignored so
deployment details stay out of the repo.

```sh
cp fly.example.toml fly.toml
fly secrets set GLEAM_PDS_SECRET=$(openssl rand -hex 32)
fly secrets set GLEAM_PDS_ROTATION_KEY=$(openssl rand -hex 32)
fly deploy
```

Keep `auto_stop_machines = 'off'`: this is a stateful server, and stopping it
drops every firehose subscriber. To type-check a change without releasing it,
`fly deploy --build-only --remote-only`.

`gleam-pds.example.service` is a systemd unit for running it outside a
container; copy it to `gleam-pds.service` and adjust the user and paths.

## Rate limits

Applied in `router.gleam`, counted in memory per node (they reset on restart
and are not shared between machines).

| Endpoint | Limit | Keyed by |
| --- | --- | --- |
| `createAccount` | 3 / 10 min, 10 / day | client IP |
| `createSession`, passkey login, `/oauth/token` | 30 / 5 min, 300 / day | client IP |
| `refreshSession` | 60 / 5 min | credential |
| Repo writes (`createRecord`, `putRecord`, `deleteRecord`, `applyWrites`, `uploadBlob`) | 60 / min, 1500 / hour | credential |

Exceeding one returns `429 RateLimitExceeded` with a `Retry-After` header. The
client IP is taken from `fly-client-ip`, falling back to the last
`x-forwarded-for` entry; behind a different proxy, check that assumption.

## Credentials and scopes

A session created from the account password carries scope
`com.atproto.access`; one created from an app password carries
`com.atproto.appPass`. App-password sessions can read and write repo content
but are refused (403) on account management: creating or revoking app
passwords, deleting/deactivating/activating the account, changing the handle,
signing PLC operations, and registering passkeys. Refreshing a session
preserves its scope, so an app password cannot escalate itself.

Deactivated accounts can still sign in (the response carries
`active: false`), but every endpoint other than `getSession`,
`getAccountStatus`, `activateAccount`, and `deleteAccount` returns
`400 AccountDeactivated`.

## License

[Apache 2.0](LICENSE), same as Gleam itself.

<p align="center">
  <img src="priv/static/og.png" alt="Gleam PDS. It's your PDS. It's Gleam. pds.readifur.gay">
</p>

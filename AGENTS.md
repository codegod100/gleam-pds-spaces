# AGENTS.md

## Cursor Cloud specific instructions

`gleam-pds` is a single OTP application: an AT Protocol Personal Data Server
written in Gleam on the BEAM (Erlang/OTP). There is one process and one SQLite
file — no Postgres/Redis/sidecars and no separate frontend. See `README.md` for
the full architecture and configuration reference.

### Toolchain (already installed in the VM snapshot)

- Gleam `1.15.2` (`/usr/local/bin/gleam`) and Erlang/OTP `27` (`esl-erlang`).
- `rebar3` is required and installed: the `esqlite` dependency (used by
  `sqlight`) compiles a native SQLite C driver via rebar3 during the first
  build. Without `rebar3` on `PATH`, `gleam build`/`gleam test` fail with
  "The program `rebar3` was not found".
- `eunit` was compiled from the matching OTP source into
  `/usr/lib/erlang/lib/eunit-2.9.1/` because the packaged `esl-erlang` ships
  **without** eunit. `gleeunit` (the test runner) needs it. If `gleam test`
  ever reports "EUnit libraries not found. Your Erlang installation seems to be
  incomplete", eunit is missing from the Erlang lib dir and must be reinstalled.

### Standard commands (from `README.md`)

- Install deps: `gleam deps download` (this is the startup update script).
- Type-check: `gleam check`. Build/run: `gleam run`. Tests: `gleam test`.
- There is no separate linter; `gleam check` / `gleam build` surface warnings.

### Running the server (non-obvious caveats)

- `GLEAM_PDS_SECRET` is **required** and must be ≥16 chars, or the server
  refuses to boot. Generate one: `openssl rand -hex 32`.
- Default listen port is `8000` (the Dockerfile/Fly config override it to
  8080). Health check: `GET /xrpc/_health`. Web UI at `/`, `/login`,
  `/register`, `/account`.
- For local dev/testing set `GLEAM_PDS_RATELIMIT_DISABLED=true` so repeated
  `createAccount`/`createSession`/write calls are not throttled.
- Example dev invocation:
  `GLEAM_PDS_SECRET=$(openssl rand -hex 32) GLEAM_PDS_RATELIMIT_DISABLED=true GLEAM_PDS_HOSTNAME=localhost:8000 GLEAM_PDS_HANDLE_DOMAIN=test GLEAM_PDS_PUBLIC_URL=http://localhost:8000 gleam run`

### Real external side effect of account creation

`com.atproto.server.createAccount` (and the `/register` web form) calls
`plc.create_and_register`, which **POSTs a genesis operation to the public
`https://plc.directory`** to mint a real `did:plc`. This requires outbound
HTTPS and creates a permanent, public entry in the PLC ledger — even for
"local" test accounts. It is not mocked. Keep test-account churn minimal.
Writes also trigger a throttled `requestCrawl` to the `bsky.network` relay.

### Testing note

Automated coverage is thin (crypto/repo/schema/account-security units only,
run by `gleam test`). There are no HTTP/federation tests, so exercise HTTP
flows manually against a running server (XRPC via `curl` or the web UI).

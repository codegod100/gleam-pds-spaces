# Using permissioned data (spaces) on gleam-pds

This fork scaffolds [AT Protocol permissioned data](https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data) — shared data with an access perimeter — on gleam-pds.

**Status:** scaffold only. Lexicons, SQLite tables, and XRPC routes exist; handlers do not yet create spaces, write records, sync repos, or issue credentials. Treat the flows below as the **intended** protocol surface this fork is aligned to, plus what you can hit today against the stubs.

## Concepts

Permissioned data runs alongside public atproto repos. Public broadcast is for open redistribution; permissioned data is for party-to-party sync inside an access boundary. It is **access control, not confidentiality** — hosts and authorized apps can read the data they handle. E2EE is out of scope.

| Term | Meaning |
| --- | --- |
| **Space** | Authorization + sync boundary for a shared context, identified by `(authority DID, type NSID, skey)` |
| **Permissioned repo** | One user's records inside one space, hosted on that user's repo host (usually their PDS) |
| **Space host** | Answers for a space as a whole: credentials, writer set, notify routing |
| **Repo host** | Stores and serves a user's permissioned repos |
| **Space credential** | JWT from the space authority granting read/sync access to a space |
| **Delegation token** | Short-lived JWT from the user's PDS proving an app acts for that user |
| **Simplespace** | PDS-hosted space-management implementation (create/update/delete, members, access policy) |

A PDS plays both **repo host** and **space host**. Those roles are separate in the protocol even when one process implements both.

## Addressing

Space and record URIs reuse `at://` with a literal `space` path segment:

```
Space:  at://{spaceDid}/space/{spaceType}/{skey}
Record: at://{spaceDid}/space/{spaceType}/{skey}/{authorDid}/{collection}/{rkey}
```

Example space URI:

```
at://did:plc:alice/space/app.bsky.group/forum-42
```

## Roles this PDS exposes

| Role | Namespace | What it is for |
| --- | --- | --- |
| Space / repo host | `com.atproto.space.*` | Credentials, CRUD on permissioned repos, sync, notify |
| Simplespace host | `com.atproto.simplespace.*` | Create/configure spaces, member list, managing-app access checks |

Lexicons live under `lexicons/com/atproto/{space,simplespace}/` (vendored JSON; not codegen'd).

## Intended app flow

```
User ──OAuth──► User's PDS ──OAuth token──► App
App ──getDelegationToken──► User's PDS ──delegation JWT──► App
App ──getSpaceCredential(delegation [+ clientAttestation])──► Space authority
App ──space credential──► Repo hosts (getRepo / listRecords / …)
```

1. User consents via OAuth (covering a `space:` scope for the space type).
2. App calls `com.atproto.space.getDelegationToken?space=…` on the **user's PDS**.
3. App calls `com.atproto.space.getSpaceCredential` on the **space authority**, presenting the delegation token as auth (and a client attestation JWT when the space gates on app identity).
4. App uses the space credential to sync/read repos from each writer's repo host.
5. Writes go to the writer's own repo host with the user's session (OAuth / access JWT), not the space credential.

Writes and reads use different auth paths: **session auth to write your own repo**; **space credential to read/sync within the space**.

### Credential shapes (protocol)

| Token | Minted by | Typical lifetime | Used for |
| --- | --- | --- | --- |
| Delegation (`typ: atproto-space-delegation+jwt`) | User's PDS | ~60s, single-use | Exchange at space authority |
| Client attestation (`typ: atproto-client-attestation+jwt`) | App (confidential client key) | Short-lived | Prove app identity when required |
| Space credential (`typ: atproto-space-credential+jwt`) | Space authority | ~2h, multi-use | Read/sync any repo in the space |

## Simplespace: manage a space

Hosted by the space authority's PDS when using the simplespace implementation.

### Create

`POST /xrpc/com.atproto.simplespace.createSpace`

```json
{
  "did": "did:plc:alice",
  "type": "app.bsky.group",
  "skey": "forum-42",
  "config": {
    "policy": "member-list",
    "appAccess": { "$type": "com.atproto.simplespace.defs#open" }
  }
}
```

| Field | Notes |
| --- | --- |
| `did` | Space authority DID (authenticated user becomes owner) |
| `type` | Space type NSID (modality / OAuth consent boundary) |
| `skey` | Optional; auto TID if omitted |
| `config.policy` | `member-list` (default), `public`, or `managing-app` |
| `config.appAccess` | `#open` (any app) or `#allowList` with OAuth `client_id`s |
| `config.managingApp` | Service id consulted when `policy` is `managing-app` |

Returns `{ "uri": "at://…" }`.

### Members and access

| Method | Purpose |
| --- | --- |
| `addMember` / `removeMember` | Mutate host-internal member list (owner only; not a synced protocol structure) |
| `listMembers` | List members (owner / host) |
| `updateSpace` / `deleteSpace` | Change config or delete |
| `checkUserAccess` | Managing app answers whether to authorize a user (service-auth from authority) |

`policy: member-list` consults `space_member` at credential-mint time. `managing-app` calls the app's `checkUserAccess`. `public` authorizes any user (app access still applies).

## Space: write and sync

### Write your permissioned repo

Session-authenticated on the writer's repo host:

| Method | Role |
| --- | --- |
| `createRecord` / `putRecord` / `deleteRecord` | Single-record CRUD |
| `applyWrites` | Batch create/update/delete |

`applyWrites` body shape:

```json
{
  "space": "at://did:plc:alice/space/app.bsky.group/forum-42",
  "repo": "did:plc:bob",
  "writes": [
    {
      "$type": "com.atproto.space.applyWrites#create",
      "collection": "app.bsky.feed.post",
      "value": { "$type": "app.bsky.feed.post", "text": "hello", "createdAt": "…" }
    }
  ]
}
```

`repo` must be the authenticated member. After a write, the repo host notifies the space host via `notifyWrite` (service auth) so the writer set / rev / hash stay current.

### Read / sync with a space credential

| Method | Host | Purpose |
| --- | --- | --- |
| `listRepos` | Space host | Writer set + last-known rev/hash (sync boundary, not ACL) |
| `getLatestCommit` | Repo host | Current signed commit for one repo |
| `getRepo` | Repo host | Full repo export (CAR) |
| `listRepoOps` | Repo host | Incremental ops since a rev |
| `getRecord` / `listRecords` | Repo host | Point reads |
| `getBlob` | Repo host | Blob bytes |
| `registerNotify` | Space or repo host | Subscribe for `notifyWrite` fan-out |
| `listSpaces` | Repo host | Spaces this user has written to (not “spaces I'm a member of”) |
| `getSpace` | Space host | URI + host-specific `config` union |

### Commits

Permissioned repos use **LtHash** set-hash commits (`com.atproto.space.defs#signedCommit`), not MST roots. The signature covers context `(space, author, rev, ikm)` only; the repo hash is bound with an HMAC so a leaked commit is deniable on rebroadcast. This fork does not compute or verify those commits yet.

## What works on this fork today

Every registered `space` / `simplespace` route requires auth via `server.get_auth_did` (session or OAuth access token). Unauthenticated calls get `401 AuthenticationRequired`.

| After auth | Response |
| --- | --- |
| `listSpaces`, `listRecords`, `listRepos`, `listRepoOps`, `listMembers` | Empty arrays (`{"spaces":[]}`, etc.) |
| `checkUserAccess` | `{"authorized":false}` |
| All other space / simplespace methods | `400 MethodNotImplemented` |

Handlers do **not** read or write the `space*` SQLite tables yet.

### Smoke-test the stubs

With a running PDS and a session JWT (`$TOKEN`):

```sh
# Empty list (auth required)
curl -sS -H "Authorization: Bearer $TOKEN" \
  "$PDS/xrpc/com.atproto.space.listSpaces"

# Stub create (auth ok, then MethodNotImplemented)
curl -sS -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"did":"did:plc:example","type":"app.bsky.group"}' \
  "$PDS/xrpc/com.atproto.simplespace.createSpace"
```

Unauthenticated:

```sh
curl -sS -o /dev/null -w "%{http_code}\n" \
  "$PDS/xrpc/com.atproto.space.listSpaces"
# → 401
```

## Storage layout (ready for a real host)

Schema version **4** creates these tables in `gleam_pds/db.gleam` (shaped after upstream `002-space.ts`):

| Table | Role |
| --- | --- |
| `space` | Space URI, ownership, policy, app-access config, soft-delete |
| `space_member` | `(space, did)` member list for simplespace |
| `space_record` | Records keyed by `(space, collection, rkey)` |
| `space_record_oplog` | Incremental ops by `(space, rev, idx)` |
| `space_repo` | Per-space set hash + rev for this account's repo |
| `space_writer` | Writer-set cache for spaces this PDS hosts |
| `space_credential_recipient` | Notify registration targets |

There are no Gleam CRUD helpers yet — only DDL on migrate. The migration smoke test is `test/space_schema_test.gleam`.

## Code map

| Piece | Path |
| --- | --- |
| Routes | `src/gleam_pds/router.gleam` (`com.atproto.space.*`, `simplespace.*`) |
| Space stubs | `src/gleam_pds/xrpc/space.gleam` |
| Simplespace stubs | `src/gleam_pds/xrpc/simplespace.gleam` |
| Schema | `src/gleam_pds/db.gleam` (`create_space_tables`, `schema_version = 4`) |
| Lexicons | `lexicons/com/atproto/{space,simplespace}/` |

When filling in handlers: keep auth via `server.get_auth_did` (or service-auth / space-credential verification for the endpoints that require them), persist through `db.gleam` helpers (not Erlang FFI talking to SQLite directly), and wrap mutating routes in `write_guard` for rate limits once they write.

## Not implemented (yet)

- Creating / updating / deleting spaces and members
- Record writes, CIDs, CAR `getRepo`, oplog sync
- LtHash commit state and writer-set maintenance
- Delegation tokens, space credentials, client-attestation checks
- `notifyWrite` / `registerNotify` fan-out and service-auth
- Lexicon codegen or runtime validation against the vendored JSON
- OAuth `space:` scope enforcement

## Upstream reference

- Proposal: [bluesky-social/proposals `0016-permissioned-data`](https://github.com/bluesky-social/proposals/tree/main/0016-permissioned-data)
- Reference PDS / lexicons: [`bluesky-social/atproto` branch `permissioned-data`](https://github.com/bluesky-social/atproto/tree/permissioned-data) @ `c5962d7ab23d0f42ccb835e7014a9d38f24ad002`
  - Lexicons: `lexicons/com/atproto/space`, `simplespace`
  - Migration: `packages/pds/src/actor-store/db/migrations/002-space.ts`
- Base PDS: [tangled.org/brookie.blog/gleam-pds](https://tangled.org/brookie.blog/gleam-pds)

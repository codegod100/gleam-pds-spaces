# Permissioned data / spaces scaffold

This fork scaffolds [AT Protocol permissioned data (spaces)](https://github.com/bluesky-social/atproto/tree/permissioned-data) on gleam-pds.

## Reference

Vendored lexicons and schema shape are taken from the Bluesky TypeScript PDS on the **`permissioned-data`** branch of [`bluesky-social/atproto`](https://github.com/bluesky-social/atproto):

- Lexicons: `lexicons/com/atproto/space/*.json`, `lexicons/com/atproto/simplespace/*.json`
- Actor-store migration: `packages/pds/src/actor-store/db/migrations/002-space.ts`
- Snapshot commit used when scaffolding: `c5962d7ab23d0f42ccb835e7014a9d38f24ad002`

Upstream gleam-pds (this fork’s base): [tangled.org/brookie.blog/gleam-pds](https://tangled.org/brookie.blog/gleam-pds).

## What is in this scaffold

| Piece | Location | Status |
| --- | --- | --- |
| Lexicons | `lexicons/com/atproto/{space,simplespace}/` | Vendored JSON only (not codegen’d) |
| SQLite tables | `gleam_pds/db.gleam` schema_version **4** | Created on migrate; unused by handlers yet |
| XRPC routes | `gleam_pds/xrpc/space.gleam`, `simplespace.gleam` + `router.gleam` | Wired; **stubs** |

### Stub behaviour

Every registered space / simplespace method requires auth (`server.get_auth_did`). Unauthenticated requests get `401 AuthenticationRequired` (gleam-pds’s equivalent of the reference PDS `AuthMissing`).

After auth:

- Empty-collection reads return minimal valid JSON (`listSpaces` → `{"spaces":[]}`, same idea for `listRecords` / `listRepos` / `listRepoOps` / `listMembers`; `checkUserAccess` → `{"authorized":false}`).
- Everything else returns `400 MethodNotImplemented` (same error name/status as other unimplemented XRPC methods in gleam-pds).

## What is deliberately not done

This is **not** a working spaces host. Missing pieces include (non-exhaustive):

- Creating / updating / deleting spaces and members
- Space record writes, CIDs, and CAR export (`getRepo`)
- LtHash commit state and writer-set sync
- Space credentials, delegation tokens, and notify fan-out
- Service-auth for `notifyWrite` / `notifySpaceDeleted`
- Lexicon codegen or runtime validation against the vendored JSON

See the README for the same honesty at a glance.

/// XRPC com.atproto.server.* account-lifecycle handlers:
/// deactivate / activate / status, deleteAccount, and app passwords.
///
/// Auth policy: account management requires a full-access session (see
/// `server.get_auth_did_full`) — an app-password session must not be able to
/// mint or revoke credentials or delete the account. `activateAccount`,
/// `deleteAccount` and `getAccountStatus` additionally have to work while the
/// account is deactivated, so they use the `*_any_status` variants.

import gleam_pds/context.{type Context}
import gleam_pds/crypto
import gleam_pds/firehose
import gleam_pds/web/response
import gleam_pds/xrpc/server
import gleam/dynamic/decode
import gleam/erlang/process
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import sqlight
import wisp.{type Request, type Response}

// ---------------------------------------------------------------------------
// deactivateAccount / activateAccount
// ---------------------------------------------------------------------------

pub fn deactivate_account(req: Request, ctx: Context) -> Response {
  case server.get_auth_did_full(req, ctx) {
    Error(resp) -> resp
    Ok(user_did) -> {
      let _ =
        sqlight.query(
          "UPDATE accounts SET deactivated_at = datetime('now') WHERE did = ? RETURNING did",
          ctx.db,
          [sqlight.text(user_did)],
          decode.at([0], decode.string),
        )
      process.send(
        ctx.firehose,
        firehose.Emit(firehose.AccountEvent(user_did, False)),
      )
      wisp.ok()
    }
  }
}

pub fn activate_account(req: Request, ctx: Context) -> Response {
  case server.get_auth_did_full_any_status(req, ctx) {
    Error(resp) -> resp
    Ok(user_did) -> {
      let _ =
        sqlight.query(
          "UPDATE accounts SET deactivated_at = NULL WHERE did = ? RETURNING did",
          ctx.db,
          [sqlight.text(user_did)],
          decode.at([0], decode.string),
        )
      process.send(
        ctx.firehose,
        firehose.Emit(firehose.AccountEvent(user_did, True)),
      )
      wisp.ok()
    }
  }
}

// ---------------------------------------------------------------------------
// getAccountStatus / checkAccountStatus
// ---------------------------------------------------------------------------

pub fn get_account_status(req: Request, ctx: Context) -> Response {
  case server.get_auth_did_any_status(req, ctx) {
    Error(resp) -> resp
    Ok(user_did) -> {
      let deactivated_at =
        sqlight.query(
          "SELECT deactivated_at FROM accounts WHERE did = ? LIMIT 1",
          ctx.db,
          [sqlight.text(user_did)],
          decode.at([0], decode.optional(decode.string)),
        )
      case deactivated_at {
        Ok([maybe_deactivated]) -> {
          let active = case maybe_deactivated {
            Some(_) -> False
            None -> True
          }

          let repo_decoder = {
            use head <- decode.field(0, decode.optional(decode.string))
            use rev <- decode.field(1, decode.optional(decode.string))
            decode.success(#(head, rev))
          }
          let #(head, rev) = case
            sqlight.query(
              "SELECT head, rev FROM repos WHERE did = ? LIMIT 1",
              ctx.db,
              [sqlight.text(user_did)],
              repo_decoder,
            )
          {
            Ok([pair]) -> pair
            _ -> #(None, None)
          }

          let indexed_records = count(ctx, "records", user_did)
          let imported_blobs = count(ctx, "blobs", user_did)
          let repo_blocks = count(ctx, "blocks", user_did)

          response.json_response(
            200,
            json.object([
              #("activated", json.bool(active)),
              #("active", json.bool(active)),
              #("validDid", json.bool(True)),
              #(
                "repoCommit",
                case head {
                  Some(h) -> json.string(h)
                  None -> json.null()
                },
              ),
              #(
                "repoRev",
                case rev {
                  Some(r) -> json.string(r)
                  None -> json.null()
                },
              ),
              #("repoBlocks", json.int(repo_blocks)),
              #("indexedRecords", json.int(indexed_records)),
              #("privateStateValues", json.int(0)),
              #("expectedBlobs", json.int(imported_blobs)),
              #("importedBlobs", json.int(imported_blobs)),
            ]),
          )
        }
        _ ->
          response.xrpc_error(404, "NotFound", "Account not found")
      }
    }
  }
}

fn count(ctx: Context, table: String, did: String) -> Int {
  let sql = "SELECT COUNT(*) FROM " <> table <> " WHERE did = ?"
  case
    sqlight.query(sql, ctx.db, [sqlight.text(did)], decode.at([0], decode.int))
  {
    Ok([n]) -> n
    _ -> 0
  }
}

// ---------------------------------------------------------------------------
// deleteAccount — auth required, password confirmation, cascade delete
// ---------------------------------------------------------------------------

pub fn delete_account(req: Request, ctx: Context) -> Response {
  case server.get_auth_did_full_any_status(req, ctx) {
    Error(resp) -> resp
    Ok(user_did) -> {
      use body <- wisp.require_json(req)
      let decoder = {
        use password <- decode.field("password", decode.string)
        decode.success(password)
      }
      case decode.run(body, decoder) {
        Error(_) ->
          response.xrpc_error(400, "InvalidRequest", "Missing password")
        Ok(password) -> {
          // Confirm the password matches the account
          let pw_result =
            sqlight.query(
              "SELECT password_hash FROM accounts WHERE did = ? LIMIT 1",
              ctx.db,
              [sqlight.text(user_did)],
              decode.at([0], decode.optional(decode.string)),
            )
          case pw_result {
            Ok([Some(pw_hash)]) ->
              case crypto.verify_password(password, pw_hash) {
                True -> {
                  cascade_delete(ctx, user_did)
                  process.send(
                    ctx.firehose,
                    firehose.Emit(firehose.AccountEvent(user_did, False)),
                  )
                  wisp.ok()
                }
                False ->
                  response.xrpc_error(
                    401,
                    "AuthenticationRequired",
                    "Invalid password",
                  )
              }
            _ ->
              response.xrpc_error(
                401,
                "AuthenticationRequired",
                "Password confirmation required",
              )
          }
        }
      }
    }
  }
}

fn cascade_delete(ctx: Context, did: String) -> Nil {
  // Delete all rows keyed on this DID across the schema.
  let tables = [
    "records", "blobs", "blocks", "sessions", "oauth_tokens", "oauth_codes",
    "oauth_auth_requests", "passkeys", "webauthn_challenges",
    "actor_preferences", "app_passwords", "repos", "accounts",
  ]
  list.each(tables, fn(table) {
    let _ =
      sqlight.query(
        "DELETE FROM " <> table <> " WHERE did = ?",
        ctx.db,
        [sqlight.text(did)],
        decode.at([0], decode.string),
      )
    Nil
  })
  Nil
}

// ---------------------------------------------------------------------------
// App passwords: createAppPassword / listAppPasswords / revokeAppPassword
// ---------------------------------------------------------------------------

pub fn create_app_password(req: Request, ctx: Context) -> Response {
  case server.get_auth_did_full(req, ctx) {
    Error(resp) -> resp
    Ok(user_did) -> {
      use body <- wisp.require_json(req)
      let decoder = {
        use name <- decode.field("name", decode.string)
        decode.success(name)
      }
      case decode.run(body, decoder) {
        Error(_) ->
          response.xrpc_error(400, "InvalidRequest", "Missing name")
        Ok(name) -> {
          // Reject duplicate names for this account
          let existing =
            sqlight.query(
              "SELECT name FROM app_passwords WHERE did = ? AND name = ? LIMIT 1",
              ctx.db,
              [sqlight.text(user_did), sqlight.text(name)],
              decode.at([0], decode.string),
            )
          case existing {
            Ok([_]) ->
              response.xrpc_error(
                400,
                "AppPasswordNameExists",
                "An app password with this name already exists",
              )
            _ -> {
              // Generate an app password of the form xxxx-xxxx-xxxx-xxxx
              let password = generate_app_password()
              let pw_hash = crypto.hash_password(password)
              let insert =
                sqlight.query(
                  "INSERT INTO app_passwords (did, name, password_hash, created_at) VALUES (?, ?, ?, datetime('now')) RETURNING created_at",
                  ctx.db,
                  [
                    sqlight.text(user_did),
                    sqlight.text(name),
                    sqlight.text(pw_hash),
                  ],
                  decode.at([0], decode.string),
                )
              case insert {
                Ok([created_at]) ->
                  response.json_response(
                    200,
                    json.object([
                      #("name", json.string(name)),
                      #("password", json.string(password)),
                      #("createdAt", json.string(created_at)),
                    ]),
                  )
                _ ->
                  response.xrpc_error(
                    500,
                    "InternalError",
                    "Failed to create app password",
                  )
              }
            }
          }
        }
      }
    }
  }
}

pub fn list_app_passwords(req: Request, ctx: Context) -> Response {
  case server.get_auth_did_full(req, ctx) {
    Error(resp) -> resp
    Ok(user_did) -> {
      let row_decoder = {
        use name <- decode.field(0, decode.string)
        use created_at <- decode.field(1, decode.optional(decode.string))
        decode.success(#(name, created_at))
      }
      let rows =
        sqlight.query(
          "SELECT name, created_at FROM app_passwords WHERE did = ? ORDER BY created_at",
          ctx.db,
          [sqlight.text(user_did)],
          row_decoder,
        )
      case rows {
        Ok(passwords) ->
          response.json_response(
            200,
            json.object([
              #(
                "passwords",
                json.array(passwords, fn(p) {
                  let #(name, created_at) = p
                  json.object([
                    #("name", json.string(name)),
                    #(
                      "createdAt",
                      case created_at {
                        Some(c) -> json.string(c)
                        None -> json.null()
                      },
                    ),
                  ])
                }),
              ),
            ]),
          )
        _ ->
          response.json_response(
            200,
            json.object([#("passwords", json.preprocessed_array([]))]),
          )
      }
    }
  }
}

pub fn revoke_app_password(req: Request, ctx: Context) -> Response {
  case server.get_auth_did_full(req, ctx) {
    Error(resp) -> resp
    Ok(user_did) -> {
      use body <- wisp.require_json(req)
      let decoder = {
        use name <- decode.field("name", decode.string)
        decode.success(name)
      }
      case decode.run(body, decoder) {
        Error(_) ->
          response.xrpc_error(400, "InvalidRequest", "Missing name")
        Ok(name) -> {
          let _ =
            sqlight.query(
              "DELETE FROM app_passwords WHERE did = ? AND name = ?",
              ctx.db,
              [sqlight.text(user_did), sqlight.text(name)],
              decode.at([0], decode.string),
            )
          wisp.ok()
        }
      }
    }
  }
}

fn generate_app_password() -> String {
  let group = fn() { string.lowercase(crypto.random_string(4)) }
  group() <> "-" <> group() <> "-" <> group() <> "-" <> group()
}

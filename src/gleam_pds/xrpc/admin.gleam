/// XRPC com.atproto.admin.* + createInviteCode for PDS Operator and similar
/// dashboards. Auth is HTTP Basic with username `admin` and the password from
/// `GLEAM_PDS_ADMIN_PASSWORD`. When that env var is unset, every admin call
/// returns 401.

import gleam_pds/context.{type Context}
import gleam_pds/crypto
import gleam_pds/firehose
import gleam_pds/web/response
import gleam/bit_array
import gleam/dynamic/decode
import gleam/erlang/process
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import sqlight
import wisp.{type Request, type Response}

// ---------------------------------------------------------------------------
// Admin auth (Basic admin:<password>)
// ---------------------------------------------------------------------------

fn require_admin(req: Request, ctx: Context) -> Result(Nil, Response) {
  case ctx.config.admin_password {
    None ->
      Error(response.xrpc_error(
        401,
        "AuthenticationRequired",
        "Admin API disabled (GLEAM_PDS_ADMIN_PASSWORD not set)",
      ))
    Some(expected) ->
      case list.key_find(req.headers, "authorization") {
        Ok(header) ->
          case string.starts_with(string.lowercase(header), "basic ") {
            False ->
              Error(response.xrpc_error(
                401,
                "AuthenticationRequired",
                "Admin endpoints require HTTP Basic auth",
              ))
            True -> {
              // Drop the "Basic " prefix case-insensitively (6 chars).
              let encoded =
                string.trim(string.drop_start(header, string.length("Basic ")))
              case crypto.base64_decode(encoded) {
                Error(_) ->
                  Error(response.xrpc_error(
                    401,
                    "AuthenticationRequired",
                    "Invalid Basic auth encoding",
                  ))
                Ok(bytes) ->
                  case bit_array.to_string(bytes) {
                    Error(_) ->
                      Error(response.xrpc_error(
                        401,
                        "AuthenticationRequired",
                        "Invalid Basic auth encoding",
                      ))
                    Ok(decoded) ->
                      case string.split_once(decoded, ":") {
                        Ok(#("admin", password)) ->
                          case
                            crypto.secure_compare(
                              bit_array.from_string(password),
                              bit_array.from_string(expected),
                            )
                          {
                            True -> Ok(Nil)
                            False ->
                              Error(response.xrpc_error(
                                401,
                                "AuthenticationRequired",
                                "Invalid admin credentials",
                              ))
                          }
                        _ ->
                          Error(response.xrpc_error(
                            401,
                            "AuthenticationRequired",
                            "Admin Basic auth username must be 'admin'",
                          ))
                      }
                  }
              }
            }
          }
        Error(_) ->
          Error(response.xrpc_error(
            401,
            "AuthenticationRequired",
            "Admin endpoints require HTTP Basic auth",
          ))
      }
  }
}

/// Convert Result-style admin auth into a continuation, matching wisp's `use`.
fn require_admin_resp(
  req: Request,
  ctx: Context,
  next: fn() -> Response,
) -> Response {
  case require_admin(req, ctx) {
    Error(resp) -> resp
    Ok(_) -> next()
  }
}

// ---------------------------------------------------------------------------
// getAccountInfos / getAccountInfo
// ---------------------------------------------------------------------------

pub fn get_account_infos(req: Request, ctx: Context) -> Response {
  case require_admin(req, ctx) {
    Error(resp) -> resp
    Ok(_) -> {
      let query = wisp.get_query(req)
      let dids =
        list.filter_map(query, fn(pair) {
          case pair {
            #("dids", did) -> Ok(did)
            _ -> Error(Nil)
          }
        })
      let infos = list.filter_map(dids, fn(did) { account_view(ctx, did) })
      response.json_response(
        200,
        json.object([#("infos", json.preprocessed_array(infos))]),
      )
    }
  }
}

pub fn get_account_info(req: Request, ctx: Context) -> Response {
  case require_admin(req, ctx) {
    Error(resp) -> resp
    Ok(_) -> {
      case list.key_find(wisp.get_query(req), "did") {
        Error(_) ->
          response.xrpc_error(400, "InvalidRequest", "did is required")
        Ok(did) ->
          case account_view(ctx, did) {
            Ok(view) -> response.json_response(200, view)
            Error(_) ->
              response.xrpc_error(400, "AccountNotFound", "Account not found")
          }
      }
    }
  }
}

fn account_view(ctx: Context, did: String) -> Result(json.Json, Nil) {
  let row_decoder = {
    use handle <- decode.field(0, decode.string)
    use email <- decode.field(1, decode.optional(decode.string))
    use created <- decode.field(2, decode.optional(decode.string))
    use deactivated <- decode.field(3, decode.optional(decode.string))
    use takedown <- decode.field(4, decode.optional(decode.string))
    decode.success(#(handle, email, created, deactivated, takedown))
  }
  case
    sqlight.query(
      "SELECT handle, email, created_at, deactivated_at, takedown_ref
       FROM accounts WHERE did = ? LIMIT 1",
      ctx.db,
      [sqlight.text(did)],
      row_decoder,
    )
  {
    Ok([#(handle, email, created, deactivated, _takedown)]) -> {
      let indexed = case created {
        Some(c) -> c
        None -> "1970-01-01T00:00:00.000Z"
      }
      let fields = [
        #("did", json.string(did)),
        #("handle", json.string(handle)),
        #("indexedAt", json.string(indexed)),
      ]
      let fields = case email {
        Some(e) -> list.append(fields, [#("email", json.string(e))])
        None -> fields
      }
      let fields = case deactivated {
        Some(at) -> list.append(fields, [#("deactivatedAt", json.string(at))])
        None -> fields
      }
      Ok(json.object(fields))
    }
    _ -> Error(Nil)
  }
}

// ---------------------------------------------------------------------------
// updateSubjectStatus (takedown / deactivate on a repo)
// ---------------------------------------------------------------------------

pub fn update_subject_status(req: Request, ctx: Context) -> Response {
  use <- require_admin_resp(req, ctx)
  use body <- wisp.require_json(req)

  let decoder = {
    use subject <- decode.field("subject", decode.dynamic)
    use takedown <- decode.optional_field(
      "takedown",
      None,
      decode.optional(status_attr_decoder()),
    )
    use deactivated <- decode.optional_field(
      "deactivated",
      None,
      decode.optional(status_attr_decoder()),
    )
    decode.success(#(subject, takedown, deactivated))
  }

  case decode.run(body, decoder) {
    Error(_) ->
      response.xrpc_error(
        400,
        "InvalidRequest",
        "Invalid updateSubjectStatus body",
      )
    Ok(#(subject_dyn, takedown, deactivated)) -> {
      case decode_repo_did(subject_dyn) {
        Error(_) ->
          response.xrpc_error(
            400,
            "InvalidRequest",
            "subject must be com.atproto.admin.defs#repoRef",
          )
        Ok(did) -> {
          case takedown {
            Some(#(True, ref)) -> {
              let ref_val = case ref {
                Some(r) -> r
                None -> "takedown"
              }
              let _ =
                sqlight.query(
                  "UPDATE accounts SET takedown_ref = ? WHERE did = ? RETURNING did",
                  ctx.db,
                  [sqlight.text(ref_val), sqlight.text(did)],
                  decode.at([0], decode.string),
                )
              process.send(
                ctx.firehose,
                firehose.Emit(firehose.AccountEvent(did, False)),
              )
            }
            Some(#(False, _)) -> {
              let _ =
                sqlight.query(
                  "UPDATE accounts SET takedown_ref = NULL WHERE did = ? RETURNING did",
                  ctx.db,
                  [sqlight.text(did)],
                  decode.at([0], decode.string),
                )
              case account_is_active(ctx, did) {
                True ->
                  process.send(
                    ctx.firehose,
                    firehose.Emit(firehose.AccountEvent(did, True)),
                  )
                False -> Nil
              }
            }
            None -> Nil
          }

          case deactivated {
            Some(#(True, _)) -> {
              let _ =
                sqlight.query(
                  "UPDATE accounts SET deactivated_at = datetime('now') WHERE did = ? RETURNING did",
                  ctx.db,
                  [sqlight.text(did)],
                  decode.at([0], decode.string),
                )
              process.send(
                ctx.firehose,
                firehose.Emit(firehose.AccountEvent(did, False)),
              )
            }
            Some(#(False, _)) -> {
              let _ =
                sqlight.query(
                  "UPDATE accounts SET deactivated_at = NULL WHERE did = ? RETURNING did",
                  ctx.db,
                  [sqlight.text(did)],
                  decode.at([0], decode.string),
                )
              case account_is_active(ctx, did) {
                True ->
                  process.send(
                    ctx.firehose,
                    firehose.Emit(firehose.AccountEvent(did, True)),
                  )
                False -> Nil
              }
            }
            None -> Nil
          }

          let fields = [
            #(
              "subject",
              json.object([
                #("$type", json.string("com.atproto.admin.defs#repoRef")),
                #("did", json.string(did)),
              ]),
            ),
          ]
          let fields = case takedown {
            Some(#(applied, ref)) ->
              list.append(fields, [#("takedown", status_attr_json(applied, ref))])
            None -> fields
          }
          response.json_response(200, json.object(fields))
        }
      }
    }
  }
}

fn status_attr_decoder() -> decode.Decoder(#(Bool, Option(String))) {
  use applied <- decode.field("applied", decode.bool)
  use ref <- decode.optional_field("ref", None, decode.optional(decode.string))
  decode.success(#(applied, ref))
}

fn status_attr_json(applied: Bool, ref: Option(String)) -> json.Json {
  let fields = [#("applied", json.bool(applied))]
  case ref {
    Some(r) -> json.object(list.append(fields, [#("ref", json.string(r))]))
    None -> json.object(fields)
  }
}

fn decode_repo_did(subject: decode.Dynamic) -> Result(String, Nil) {
  let decoder = {
    use did <- decode.field("did", decode.string)
    decode.success(did)
  }
  decode.run(subject, decoder) |> result.replace_error(Nil)
}

fn account_is_active(ctx: Context, did: String) -> Bool {
  case
    sqlight.query(
      "SELECT deactivated_at, takedown_ref FROM accounts WHERE did = ? LIMIT 1",
      ctx.db,
      [sqlight.text(did)],
      {
        use d <- decode.field(0, decode.optional(decode.string))
        use t <- decode.field(1, decode.optional(decode.string))
        decode.success(#(d, t))
      },
    )
  {
    Ok([#(None, None)]) -> True
    _ -> False
  }
}

// ---------------------------------------------------------------------------
// updateAccountPassword
// ---------------------------------------------------------------------------

pub fn update_account_password(req: Request, ctx: Context) -> Response {
  use <- require_admin_resp(req, ctx)
  use body <- wisp.require_json(req)
  let decoder = {
    use did <- decode.field("did", decode.string)
    use password <- decode.field("password", decode.string)
    decode.success(#(did, password))
  }
  case decode.run(body, decoder) {
    Error(_) ->
      response.xrpc_error(400, "InvalidRequest", "did and password required")
    Ok(#(did, password)) -> {
      let hash = crypto.hash_password(password)
      case
        sqlight.query(
          "UPDATE accounts SET password_hash = ? WHERE did = ? RETURNING did",
          ctx.db,
          [sqlight.text(hash), sqlight.text(did)],
          decode.at([0], decode.string),
        )
      {
        Ok([_]) -> wisp.ok()
        _ -> response.xrpc_error(400, "AccountNotFound", "Account not found")
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Invite codes
// ---------------------------------------------------------------------------

pub fn get_invite_codes(req: Request, ctx: Context) -> Response {
  use <- require_admin_resp(req, ctx)
  let query = wisp.get_query(req)
  let limit =
    list.key_find(query, "limit")
    |> result.try(int.parse)
    |> result.unwrap(100)
  let limit = int.clamp(limit, 1, 500)

  let row_decoder = {
    use code <- decode.field(0, decode.string)
    use available <- decode.field(1, decode.int)
    use disabled <- decode.field(2, decode.int)
    use for_account <- decode.field(3, decode.string)
    use created_by <- decode.field(4, decode.string)
    use created_at <- decode.field(5, decode.string)
    decode.success(#(
      code,
      available,
      disabled,
      for_account,
      created_by,
      created_at,
    ))
  }

  case
    sqlight.query(
      "SELECT code, available, disabled, for_account, created_by, created_at
       FROM invite_codes ORDER BY created_at DESC LIMIT ?",
      ctx.db,
      [sqlight.int(limit)],
      row_decoder,
    )
  {
    Error(_) ->
      response.json_response(
        200,
        json.object([#("codes", json.preprocessed_array([]))]),
      )
    Ok(rows) -> {
      let codes =
        list.map(rows, fn(row) {
          let #(code, available, disabled, for_account, created_by, created_at) =
            row
          let uses = invite_uses(ctx, code)
          json.object([
            #("code", json.string(code)),
            #("available", json.int(available)),
            #("disabled", json.bool(disabled != 0)),
            #("forAccount", json.string(for_account)),
            #("createdBy", json.string(created_by)),
            #("createdAt", json.string(created_at)),
            #("uses", json.preprocessed_array(uses)),
          ])
        })
      response.json_response(
        200,
        json.object([#("codes", json.preprocessed_array(codes))]),
      )
    }
  }
}

fn invite_uses(ctx: Context, code: String) -> List(json.Json) {
  case
    sqlight.query(
      "SELECT used_by, used_at FROM invite_code_uses WHERE code = ?",
      ctx.db,
      [sqlight.text(code)],
      {
        use used_by <- decode.field(0, decode.string)
        use used_at <- decode.field(1, decode.string)
        decode.success(#(used_by, used_at))
      },
    )
  {
    Ok(rows) ->
      list.map(rows, fn(row) {
        let #(used_by, used_at) = row
        json.object([
          #("usedBy", json.string(used_by)),
          #("usedAt", json.string(used_at)),
        ])
      })
    Error(_) -> []
  }
}

pub fn create_invite_code(req: Request, ctx: Context) -> Response {
  use <- require_admin_resp(req, ctx)
  use body <- wisp.require_json(req)
  let decoder = {
    use use_count <- decode.field("useCount", decode.int)
    use for_account <- decode.optional_field(
      "forAccount",
      None,
      decode.optional(decode.string),
    )
    decode.success(#(use_count, for_account))
  }
  case decode.run(body, decoder) {
    Error(_) ->
      response.xrpc_error(400, "InvalidRequest", "useCount is required")
    Ok(#(use_count, for_account)) -> {
      let use_count = int.clamp(use_count, 1, 100)
      let code = "gleam-pds-" <> crypto.random_string(10)
      let for_acc = case for_account {
        Some(a) -> a
        None -> "admin"
      }
      let _ =
        sqlight.query(
          "INSERT INTO invite_codes (code, available, disabled, for_account, created_by, created_at)
           VALUES (?, ?, 0, ?, 'admin', datetime('now')) RETURNING code",
          ctx.db,
          [
            sqlight.text(code),
            sqlight.int(use_count),
            sqlight.text(for_acc),
          ],
          decode.at([0], decode.string),
        )
      response.json_response(200, json.object([#("code", json.string(code))]))
    }
  }
}

pub fn disable_invite_codes(req: Request, ctx: Context) -> Response {
  use <- require_admin_resp(req, ctx)
  use body <- wisp.require_json(req)
  let decoder = {
    use codes <- decode.optional_field(
      "codes",
      [],
      decode.list(decode.string),
    )
    use accounts <- decode.optional_field(
      "accounts",
      [],
      decode.list(decode.string),
    )
    decode.success(#(codes, accounts))
  }
  case decode.run(body, decoder) {
    Error(_) ->
      response.xrpc_error(
        400,
        "InvalidRequest",
        "Invalid disableInviteCodes body",
      )
    Ok(#(codes, accounts)) -> {
      list.each(codes, fn(code) {
        let _ =
          sqlight.query(
            "UPDATE invite_codes SET disabled = 1 WHERE code = ?",
            ctx.db,
            [sqlight.text(code)],
            decode.at([0], decode.int),
          )
        Nil
      })
      list.each(accounts, fn(account) {
        let _ =
          sqlight.query(
            "UPDATE invite_codes SET disabled = 1 WHERE for_account = ?",
            ctx.db,
            [sqlight.text(account)],
            decode.at([0], decode.int),
          )
        Nil
      })
      wisp.ok()
    }
  }
}
